-- 174_request_approval_lifecycle_epoch.sql
--
-- Approval evidence is valid only for the lifecycle cycle whose plan was
-- reviewed. Rework starts a new cycle; prior decisions remain immutable audit
-- history but cannot satisfy the new cycle's quorum.
--
-- Deployment posture is deliberately fail closed and non-overlapping. Old
-- readers do not understand approval_epoch and can count historical decisions
-- as current, so every old API replica must be drained before this migration is
-- applied and may not restart until the epoch-aware release is active. The
-- write-side guards below additionally fail closed during that drained handoff:
--   * decision rows have NO approval_epoch default, so an old replica that
--     omits the new column cannot write an epochless current decision;
--   * the old (request_id, role) conflict target is removed;
--   * a trigger serializes every decision write with the request row and rejects
--     any epoch other than the request's current epoch; and
--   * a request trigger advances the epoch on every supported rework transition,
--     including writes from an old replica that does not know the new column.

ALTER TABLE requests
    ADD COLUMN IF NOT EXISTS approval_epoch BIGINT NOT NULL DEFAULT 1;

ALTER TABLE request_approval_decisions
    ADD COLUMN IF NOT EXISTS approval_epoch BIGINT;

-- Existing decision rows have no trustworthy lifecycle provenance. Preserve
-- them as epoch-1 history, then invalidate every in-flight decision set. Rows
-- already Approved/Locked or terminal are not in-flight; their decision history
-- remains attached until a future rework advances the request epoch.
DO $$
BEGIN
    -- The new uniqueness constraint is this migration's durable installation
    -- marker. Guarding the one-time provenance backfill keeps a direct rerun
    -- from invalidating legitimate post-migration epoch-1 approvals.
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint AS constraint_catalog
        WHERE constraint_catalog.conname = 'uq_request_approval_epoch_role'
          AND constraint_catalog.conrelid =
              'public.request_approval_decisions'::regclass
          AND constraint_catalog.connamespace = 'public'::regnamespace
    ) THEN
        UPDATE request_approval_decisions
        SET approval_epoch = 1
        WHERE approval_epoch IS NULL;

        UPDATE requests AS r
        SET approval_epoch = 2
        WHERE r.approval_epoch = 1
          AND r.status IN ('draft', 'intake', 'validated', 'planned')
          AND EXISTS (
              SELECT 1
              FROM request_approval_decisions AS d
              WHERE d.request_id = r.id
          );
    END IF;
END $$;

ALTER TABLE request_approval_decisions
    ALTER COLUMN approval_epoch SET NOT NULL,
    ALTER COLUMN approval_epoch DROP DEFAULT;

ALTER TABLE request_approval_decisions
    DROP CONSTRAINT IF EXISTS uq_request_role;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint AS constraint_catalog
        WHERE constraint_catalog.conname = 'requests_approval_epoch_positive'
          AND constraint_catalog.conrelid = 'public.requests'::regclass
          AND constraint_catalog.connamespace = 'public'::regnamespace
    ) THEN
        ALTER TABLE requests
            ADD CONSTRAINT requests_approval_epoch_positive
            CHECK (approval_epoch > 0);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint AS constraint_catalog
        WHERE constraint_catalog.conname =
              'request_approval_decisions_epoch_positive'
          AND constraint_catalog.conrelid =
              'public.request_approval_decisions'::regclass
          AND constraint_catalog.connamespace = 'public'::regnamespace
    ) THEN
        ALTER TABLE request_approval_decisions
            ADD CONSTRAINT request_approval_decisions_epoch_positive
            CHECK (approval_epoch > 0);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint AS constraint_catalog
        WHERE constraint_catalog.conname = 'uq_request_approval_epoch_role'
          AND constraint_catalog.conrelid =
              'public.request_approval_decisions'::regclass
          AND constraint_catalog.connamespace = 'public'::regnamespace
    ) THEN
        ALTER TABLE request_approval_decisions
            ADD CONSTRAINT uq_request_approval_epoch_role
            UNIQUE (request_id, approval_epoch, role);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_rad_request_epoch
    ON request_approval_decisions (request_id, approval_epoch, decided_at, id);

CREATE OR REPLACE FUNCTION enforce_request_rework_approval_epoch()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    is_rework BOOLEAN;
    review_basis_changed BOOLEAN;
    has_current_decisions BOOLEAN;
    approved_role_count BIGINT;
    approved_actor_count BIGINT;
    has_current_rejection BOOLEAN;
    request_table_owner OID;
    enforce_runtime_contract BOOLEAN;
    transition_allowed BOOLEAN;
BEGIN
    SELECT relowner
    INTO request_table_owner
    FROM pg_catalog.pg_class
    WHERE oid = 'public.requests'::regclass;

    -- Disposable/local databases intentionally use the table owner for broad
    -- fixture seeding.  Production startup proves that the application role is
    -- not an owner, so every production write takes the strict branch.  The
    -- setting below can only force the strict branch for owner-backed tests; it
    -- can never grant a non-owner a bypass.
    enforce_runtime_contract := request_table_owner IS NULL
        OR CURRENT_USER::regrole::oid <> request_table_owner
        OR COALESCE(
            current_setting('ryuki.force_request_runtime_contract', TRUE) =
                'runtime-v1',
            FALSE
        );

    IF TG_OP = 'INSERT' THEN
        IF enforce_runtime_contract
           AND (
                NEW.status <> 'intake'
                OR NEW.stage <> 'intake'
                OR NEW.approval_epoch <> 1
           ) THEN
            RAISE EXCEPTION
                'new requests must enter the canonical intake state at approval epoch 1'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'request lifecycle identity is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.created_by IS DISTINCT FROM OLD.created_by
       OR NEW.requester IS DISTINCT FROM OLD.requester THEN
        RAISE EXCEPTION 'request maker identity is immutable'
            USING ERRCODE = '23514';
    END IF;

    is_rework := OLD.status IN ('validated', 'planned', 'approved', 'locked')
                 AND NEW.status = 'intake';
    IF is_rework THEN
        IF NEW.approval_epoch = OLD.approval_epoch THEN
            -- Defense in depth if a stale writer escaped the mandatory drain.
            NEW.approval_epoch := OLD.approval_epoch + 1;
        ELSIF NEW.approval_epoch <> OLD.approval_epoch + 1 THEN
            RAISE EXCEPTION 'rework must advance approval_epoch exactly once'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.approval_epoch <> OLD.approval_epoch THEN
        RAISE EXCEPTION 'approval_epoch may change only during rework'
            USING ERRCODE = '23514';
    END IF;

    -- Decisions review this exact request authority tuple. Lifecycle-only
    -- progress (`status`, `stage`, `stages`, `approval_route`, `updated_at`) may
    -- advance within an epoch, but changing any input, plan, validation,
    -- ownership, evidence, or quorum rule after the first decision requires a
    -- rework transition that rotates the epoch.
    review_basis_changed :=
        ROW(
            NEW.request_type,
            NEW.site,
            NEW.environment,
            NEW.name,
            NEW.cpu,
            NEW.memory_gb,
            NEW.justification,
            NEW.created_by,
            NEW.payload,
            NEW.plan,
            NEW.validation_results,
            NEW.criticality,
            NEW.required_approval_roles,
            NEW.requester,
            NEW.owner,
            NEW.evidence_manifest_id
        ) IS DISTINCT FROM ROW(
            OLD.request_type,
            OLD.site,
            OLD.environment,
            OLD.name,
            OLD.cpu,
            OLD.memory_gb,
            OLD.justification,
            OLD.created_by,
            OLD.payload,
            OLD.plan,
            OLD.validation_results,
            OLD.criticality,
            OLD.required_approval_roles,
            OLD.requester,
            OLD.owner,
            OLD.evidence_manifest_id
        );

    IF review_basis_changed AND NOT is_rework THEN
        IF OLD.status IN ('planned', 'approved', 'locked') THEN
            RAISE EXCEPTION
                'reviewed request authority is immutable until an epoch-rotating rework'
                USING ERRCODE = '23514';
        ELSE
            SELECT EXISTS (
                SELECT 1
                FROM request_approval_decisions AS decision
                WHERE decision.request_id = OLD.id
                  AND decision.approval_epoch = OLD.approval_epoch
            )
            INTO has_current_decisions;
            IF has_current_decisions THEN
                RAISE EXCEPTION
                    'reviewed request authority is immutable until an epoch-rotating rework'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
    END IF;

    -- Only two canonical ordinary approval roles currently exist.  A larger
    -- frozen quorum would make the request permanently unapprovable; reject it
    -- at the planning boundary while intake/rework can still correct policy.
    IF NEW.status = 'planned'
       AND NEW.status IS DISTINCT FROM OLD.status
       AND NEW.required_approval_roles > 2 THEN
        RAISE EXCEPTION
            'planned requests may require at most two canonical approval roles'
            USING ERRCODE = '23514';
    END IF;

    -- The application inserts the final immutable decision while holding this
    -- request row, then performs Planned -> Approved in the same transaction.
    -- Repeat the quorum decision at the database boundary so another runtime
    -- query cannot flip status without the complete current-epoch evidence.
    IF NEW.status IS DISTINCT FROM OLD.status
       AND NEW.status IN ('approved', 'locked') THEN
        IF NEW.status = 'approved' AND OLD.status <> 'planned' THEN
            RAISE EXCEPTION 'approved state may be entered only from planned'
                USING ERRCODE = '23514';
        ELSIF NEW.status = 'locked' AND OLD.status <> 'approved' THEN
            RAISE EXCEPTION 'locked state may be entered only from approved'
                USING ERRCODE = '23514';
        END IF;

        SELECT
            COUNT(DISTINCT BTRIM(decision.role))
                FILTER (
                    WHERE decision.decision = 'approved'
                      AND BTRIM(decision.role) IN (
                          'DatacenterApprover', 'PlatformAdmin'
                      )
                ),
            COUNT(DISTINCT BTRIM(decision.actor))
                FILTER (
                    WHERE decision.decision = 'approved'
                      AND BTRIM(decision.role) IN (
                          'DatacenterApprover', 'PlatformAdmin'
                      )
                ),
            COALESCE(BOOL_OR(decision.decision = 'rejected'), FALSE)
        INTO approved_role_count, approved_actor_count, has_current_rejection
        FROM request_approval_decisions AS decision
        WHERE decision.request_id = OLD.id
          AND decision.approval_epoch = OLD.approval_epoch;

        IF has_current_rejection
           OR approved_role_count < NEW.required_approval_roles
           OR approved_actor_count < NEW.required_approval_roles THEN
            RAISE EXCEPTION
                'approved or locked state requires current-epoch role and actor quorum'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    -- Mirror every status edge admitted by the request engine and API.  Same-
    -- state writes remain legal because partial approvals and lifecycle
    -- artifacts update the row without advancing status.  `executed` and
    -- `verified` are legacy read aliases retained by migration 109; only the
    -- handler-supported fail/complete exits remain available to those rows.
    IF enforce_runtime_contract
       AND NEW.status IS DISTINCT FROM OLD.status THEN
        transition_allowed := CASE OLD.status
            WHEN 'draft' THEN
                NEW.status IN ('intake', 'validated', 'failed', 'cancelled')
            WHEN 'intake' THEN
                NEW.status IN ('validated', 'failed', 'cancelled')
            WHEN 'validated' THEN
                NEW.status IN ('planned', 'intake', 'failed', 'cancelled')
            WHEN 'planned' THEN
                NEW.status IN (
                    'approved', 'rejected', 'intake', 'failed', 'cancelled'
                )
            WHEN 'approved' THEN
                NEW.status IN ('locked', 'intake', 'failed', 'cancelled')
            WHEN 'locked' THEN
                NEW.status IN ('executing', 'intake', 'failed', 'cancelled')
            WHEN 'executing' THEN NEW.status IN ('verifying', 'failed')
            WHEN 'executed' THEN NEW.status IN ('verifying', 'failed')
            WHEN 'verifying' THEN NEW.status IN ('completed', 'failed')
            WHEN 'verified' THEN NEW.status IN ('completed', 'failed')
            WHEN 'completed' THEN NEW.status = 'protecting'
            WHEN 'protecting' THEN NEW.status = 'operational'
            WHEN 'operational' THEN NEW.status = 'retired'
            ELSE FALSE
        END;
        IF NOT transition_allowed THEN
            RAISE EXCEPTION
                'invalid request lifecycle transition from % to %',
                OLD.status, NEW.status
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_requests_rework_approval_epoch ON requests;
CREATE TRIGGER trg_requests_rework_approval_epoch
BEFORE INSERT OR UPDATE ON requests
FOR EACH ROW
EXECUTE FUNCTION enforce_request_rework_approval_epoch();

CREATE OR REPLACE FUNCTION enforce_current_request_approval_epoch()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    current_epoch BIGINT;
    current_status TEXT;
    request_table_owner OID;
    enforce_runtime_contract BOOLEAN;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF ROW(NEW.request_id, NEW.approval_epoch, NEW.role)
           IS DISTINCT FROM
           ROW(OLD.request_id, OLD.approval_epoch, OLD.role) THEN
            RAISE EXCEPTION 'approval decision identity is immutable'
                USING ERRCODE = '23514';
        END IF;

        -- A role's first decision in one lifecycle epoch is the durable fact.
        -- Retries use INSERT .. ON CONFLICT DO NOTHING and application code
        -- rejects a conflicting first-writer outcome before commit; no ordinary
        -- writer may rewrite the decision, actor, time, or reason in place.
        RAISE EXCEPTION 'approval decision evidence is immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.decision NOT IN ('approved', 'rejected')
       OR NEW.role NOT IN ('DatacenterApprover', 'PlatformAdmin')
       OR NULLIF(BTRIM(NEW.role), '') IS NULL
       OR NEW.role <> BTRIM(NEW.role)
       OR char_length(NEW.role) > 255
       OR NULLIF(BTRIM(NEW.actor), '') IS NULL
       OR NEW.actor <> BTRIM(NEW.actor)
       OR char_length(NEW.actor) > 512
       OR (NEW.decision = 'approved' AND NEW.reason IS NOT NULL)
       OR (
           NEW.decision = 'rejected'
           AND (
               NULLIF(BTRIM(NEW.reason), '') IS NULL
               OR NEW.reason <> BTRIM(NEW.reason)
           )
       ) THEN
        RAISE EXCEPTION 'approval decision evidence has an invalid canonical shape'
            USING ERRCODE = '23514';
    END IF;
    NEW.decided_at := statement_timestamp();

    -- FOR UPDATE serializes direct/legacy writers with rework and approval, just
    -- like the application-level approval transaction's request-row lock.
    SELECT approval_epoch, status
    INTO current_epoch, current_status
    FROM requests
    WHERE id = NEW.request_id
    FOR UPDATE;

    IF current_epoch IS NULL
       OR NEW.approval_epoch IS NULL
       OR NEW.approval_epoch <> current_epoch THEN
        RAISE EXCEPTION 'approval decision epoch is not the request current epoch'
            USING ERRCODE = '23514';
    END IF;

    SELECT relowner
    INTO request_table_owner
    FROM pg_catalog.pg_class
    WHERE oid = 'public.requests'::regclass;
    enforce_runtime_contract := request_table_owner IS NULL
        OR CURRENT_USER::regrole::oid <> request_table_owner
        OR COALESCE(
            current_setting('ryuki.force_request_runtime_contract', TRUE) =
                'runtime-v1',
            FALSE
        );
    IF enforce_runtime_contract
       AND (
            (NEW.decision = 'approved' AND current_status <> 'planned')
            OR (NEW.decision = 'rejected' AND current_status <> 'rejected')
       ) THEN
        RAISE EXCEPTION
            'approval decisions must follow the canonical request decision order'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_request_approval_decision_current_epoch
    ON request_approval_decisions;
CREATE TRIGGER trg_request_approval_decision_current_epoch
BEFORE INSERT OR UPDATE ON request_approval_decisions
FOR EACH ROW
EXECUTE FUNCTION enforce_current_request_approval_epoch();

-- Rejection writes intentionally update the request before inserting their
-- immutable decision in the same transaction.  Validate that ordering at commit
-- so a direct Planned -> Rejected write cannot land without its current-epoch
-- evidence while the application keeps its existing atomic sequence.
CREATE OR REPLACE FUNCTION enforce_rejected_request_decision()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    request_table_owner OID;
    enforce_runtime_contract BOOLEAN;
    has_rejection BOOLEAN;
BEGIN
    IF NEW.status = 'rejected'
       AND NEW.status IS DISTINCT FROM OLD.status THEN
        SELECT relowner
        INTO request_table_owner
        FROM pg_catalog.pg_class
        WHERE oid = 'public.requests'::regclass;
        enforce_runtime_contract := request_table_owner IS NULL
            OR CURRENT_USER::regrole::oid <> request_table_owner
            OR COALESCE(
                current_setting(
                    'ryuki.force_request_runtime_contract', TRUE
                ) = 'runtime-v1',
                FALSE
            );

        IF enforce_runtime_contract THEN
            SELECT EXISTS (
                SELECT 1
                FROM request_approval_decisions AS decision
                WHERE decision.request_id = NEW.id
                  AND decision.approval_epoch = NEW.approval_epoch
                  AND decision.decision = 'rejected'
            )
            INTO has_rejection;
            IF NOT has_rejection THEN
                RAISE EXCEPTION
                    'request rejection requires current-epoch rejection evidence'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_requests_rejection_evidence ON requests;
CREATE CONSTRAINT TRIGGER trg_requests_rejection_evidence
AFTER UPDATE OF status ON requests
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION enforce_rejected_request_decision();

-- Approval rows are retained evidence.  Ordinary application/database writers
-- cannot hard-delete or truncate them.  A narrowly scoped SECURITY DEFINER
-- maintenance function permits the schema owner to remove one request's rows
-- for disposable-test or explicitly approved data-retention maintenance; the
-- production application role is not granted this function.
CREATE OR REPLACE FUNCTION reject_request_approval_decision_removal()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    table_owner OID;
BEGIN
    SELECT relowner
    INTO table_owner
    FROM pg_class
    WHERE oid = 'public.request_approval_decisions'::regclass;

    IF TG_OP = 'DELETE'
       AND current_setting('ryuki.approval_ledger_maintenance', TRUE) =
           'owner-request-purge-v1'
       AND CURRENT_USER::regrole::oid = table_owner THEN
        RETURN OLD;
    END IF;

    RAISE EXCEPTION 'approval decision history is append-only'
        USING ERRCODE = '55000';
END;
$$;

DROP TRIGGER IF EXISTS trg_request_approval_decision_no_delete
    ON request_approval_decisions;
CREATE TRIGGER trg_request_approval_decision_no_delete
BEFORE DELETE ON request_approval_decisions
FOR EACH ROW
EXECUTE FUNCTION reject_request_approval_decision_removal();

DROP TRIGGER IF EXISTS trg_request_approval_decision_no_truncate
    ON request_approval_decisions;
CREATE TRIGGER trg_request_approval_decision_no_truncate
BEFORE TRUNCATE ON request_approval_decisions
FOR EACH STATEMENT
EXECUTE FUNCTION reject_request_approval_decision_removal();

CREATE OR REPLACE FUNCTION purge_request_approval_decisions_for_maintenance(
    target_request_id UUID
)
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    removed BIGINT;
BEGIN
    PERFORM set_config(
        'ryuki.approval_ledger_maintenance',
        'owner-request-purge-v1',
        TRUE
    );
    DELETE FROM public.request_approval_decisions
    WHERE request_id = target_request_id;
    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed;
END;
$$;

REVOKE ALL ON FUNCTION purge_request_approval_decisions_for_maintenance(UUID)
    FROM PUBLIC;
