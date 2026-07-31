-- 196_request_authority_version_bindings.sql
--
-- Bind durable approval evidence and dispatched work to the exact monotonic
-- request authority version they reviewed or inherited.  Version 1 is the
-- conservative baseline established for every pre-versioning request by
-- migration 194, so metadata-only DEFAULT 1 additions safely classify legacy
-- rows without pretending they were created against a later request version.
-- The defaults are removed after the INSERT guards are installed: omission is
-- then handled only by the database while an explicit mismatched value fails.

ALTER TABLE request_approval_decisions
    ADD COLUMN approval_basis_resource_version BIGINT NOT NULL DEFAULT 1;

ALTER TABLE agent_jobs
    ADD COLUMN request_resource_version BIGINT NOT NULL DEFAULT 1;

ALTER TABLE request_approval_decisions
    ADD CONSTRAINT request_approval_decisions_basis_version_positive
    CHECK (approval_basis_resource_version > 0) NOT VALID;

ALTER TABLE agent_jobs
    ADD CONSTRAINT agent_jobs_request_resource_version_positive
    CHECK (request_resource_version > 0) NOT VALID;

ALTER TABLE request_approval_decisions
    VALIDATE CONSTRAINT request_approval_decisions_basis_version_positive;

ALTER TABLE agent_jobs
    VALIDATE CONSTRAINT agent_jobs_request_resource_version_positive;

-- Migration 054 seeded two inert, orphaned protocol-v1 harness rows. They are
-- not deployable work and cannot truthfully acquire protocol-v7 authority.
-- Remove only those exact legacy fixtures before enforcing the open-job drain
-- gate so a fresh database can migrate without weakening that gate for real
-- queued work.
DELETE FROM agent_jobs
WHERE platform = 'ci-test'
  AND mode = 'OfflineDryRun'
  AND status = 'Pending'
  AND request_resource_version = 1
  AND agent_id IS NULL
  AND attempt_id IS NULL
  AND lease_generation = 0
  AND fencing_token IS NULL
  AND cp_nonce IS NULL
  AND lease_deadline IS NULL
  AND (
      (
          request_id = '00000000-0000-0000-0000-000000000001'::UUID
          AND spec = '{"request_id":"00000000-0000-0000-0000-000000000001","offering_id":"00000000-0000-0000-0000-000000000002","iac_ref":"linux-server-deployment@v1","iac_digest":"0000000000000000000000000000000000000000000000000000000000000000","vars":{},"mode":"offline_dry_run"}'::JSONB
      )
      OR
      (
          request_id = '00000000-0000-0000-0000-000000000003'::UUID
          AND spec = '{"request_id":"00000000-0000-0000-0000-000000000003","offering_id":"00000000-0000-0000-0000-000000000004","iac_ref":"patch-maintenance@v2","iac_digest":"0000000000000000000000000000000000000000000000000000000000000000","vars":{},"mode":"offline_dry_run"}'::JSONB
      )
  );

-- Protocol v7 makes the request version a required signed field. Rewriting an
-- already leased/running job would invalidate its stored digest and any live
-- grant, so rollout must drain or explicitly reconcile pre-v7 work instead of
-- silently rebinding it. A fully v7-compatible open row may survive a resumed
-- rollout only when all durable copies still match the current request.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM agent_jobs AS job
        LEFT JOIN requests AS request ON request.id = job.request_id
        WHERE job.status IN ('Pending', 'Leased', 'Running')
          AND NOT CASE
              WHEN request.id IS NOT NULL
               AND jsonb_typeof(job.spec) = 'object'
               AND jsonb_typeof(job.spec -> 'request_id') = 'string'
               AND job.spec ->> 'request_id' = job.request_id::TEXT
               AND jsonb_typeof(job.spec -> 'request_resource_version') = 'number'
               AND job.spec ->> 'request_resource_version' ~ '^[1-9][0-9]*$'
               AND jsonb_typeof(job.spec -> 'mode') = 'string'
               AND job.spec ->> 'mode' = CASE job.mode
                   WHEN 'OfflineDryRun' THEN 'offline_dry_run'
                   WHEN 'LivePlan' THEN 'live_plan'
                   WHEN 'LiveApply' THEN 'live_apply'
                   WHEN 'LiveDestroy' THEN 'live_destroy'
                   ELSE NULL
               END
              THEN (job.spec ->> 'request_resource_version')::NUMERIC =
                       job.request_resource_version::NUMERIC
               AND job.request_resource_version = request.resource_version
              ELSE FALSE
          END
    ) THEN
        RAISE EXCEPTION
            'open pre-v7 or stale agent jobs must be drained or reconciled before migration 196'
            USING ERRCODE = '55000';
    END IF;
END;
$$;

COMMENT ON COLUMN request_approval_decisions.approval_basis_resource_version IS
    'Database-verified requests.resource_version reviewed by this immutable approval decision; rejection binds the pre-transition version.';

COMMENT ON COLUMN agent_jobs.request_resource_version IS
    'Database-verified requests.resource_version current when this immutable job binding was inserted.';

CREATE OR REPLACE FUNCTION bind_request_approval_basis_resource_version()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    current_resource_version BIGINT;
    current_status TEXT;
    expected_basis_version BIGINT;
    request_table_owner OID;
    enforce_runtime_contract BOOLEAN;
BEGIN
    SELECT request.resource_version, request.status
    INTO current_resource_version, current_status
    FROM requests AS request
    WHERE request.id = NEW.request_id
    FOR UPDATE;

    IF current_resource_version IS NULL THEN
        RAISE EXCEPTION 'approval decision request does not exist'
            USING ERRCODE = '23503';
    END IF;

    SELECT relation_catalog.relowner
    INTO request_table_owner
    FROM pg_catalog.pg_class AS relation_catalog
    WHERE relation_catalog.oid = 'public.requests'::regclass;

    enforce_runtime_contract := request_table_owner IS NULL
        OR CURRENT_USER::regrole::oid <> request_table_owner
        OR COALESCE(
            current_setting('ryuki.force_request_runtime_contract', TRUE) =
                'runtime-v1',
            FALSE
        );

    IF NEW.decision = 'approved' THEN
        IF enforce_runtime_contract AND current_status <> 'planned' THEN
            RAISE EXCEPTION
                'approved decision must bind the current planned request version'
                USING ERRCODE = '23514';
        END IF;
        expected_basis_version := current_resource_version;
    ELSIF NEW.decision = 'rejected' THEN
        -- Rejection follows the atomic Planned -> Rejected request UPDATE.
        -- Migration 194 advances the resource version exactly once, so the
        -- reviewed pre-transition basis is current - 1.  Owner-backed fixtures
        -- may retain their legacy insertion order, but production never may.
        IF current_status = 'rejected' THEN
            IF current_resource_version <= 1 THEN
                IF enforce_runtime_contract THEN
                    RAISE EXCEPTION
                        'rejected decision basis resource version underflow'
                        USING ERRCODE = '22003';
                END IF;
                expected_basis_version := current_resource_version;
            ELSE
                expected_basis_version := current_resource_version - 1;
            END IF;
        ELSIF enforce_runtime_contract THEN
            RAISE EXCEPTION
                'rejected decision must bind the pre-transition request version'
                USING ERRCODE = '23514';
        ELSE
            expected_basis_version := current_resource_version;
        END IF;
    ELSE
        -- The canonical-shape trigger from migration 174 also rejects this;
        -- fail here so an unknown operation can never select a version rule.
        RAISE EXCEPTION 'approval decision has no resource-version binding rule'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.approval_basis_resource_version IS NULL THEN
        NEW.approval_basis_resource_version := expected_basis_version;
    ELSIF NEW.approval_basis_resource_version <> expected_basis_version THEN
        RAISE EXCEPTION 'approval decision resource version does not match its review basis'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_request_approval_decision_basis_version
BEFORE INSERT ON request_approval_decisions
FOR EACH ROW
EXECUTE FUNCTION bind_request_approval_basis_resource_version();

ALTER TABLE request_approval_decisions
    ENABLE ALWAYS TRIGGER trg_request_approval_decision_basis_version;

CREATE OR REPLACE FUNCTION reject_request_approval_basis_version_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'approval decision resource-version binding is immutable'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER trg_request_approval_decision_basis_version_owned
BEFORE UPDATE OF approval_basis_resource_version ON request_approval_decisions
FOR EACH ROW
EXECUTE FUNCTION reject_request_approval_basis_version_update();

ALTER TABLE request_approval_decisions
    ENABLE ALWAYS TRIGGER trg_request_approval_decision_basis_version_owned;

CREATE OR REPLACE FUNCTION bind_agent_job_request_resource_version()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    current_resource_version BIGINT;
    spec_request_id_text TEXT;
    spec_request_resource_version_text TEXT;
    spec_request_resource_version BIGINT;
    spec_mode_text TEXT;
    request_table_owner OID;
    enforce_runtime_contract BOOLEAN;
BEGIN
    IF jsonb_typeof(NEW.spec) IS DISTINCT FROM 'object'
        OR jsonb_typeof(NEW.spec -> 'request_id') IS DISTINCT FROM 'string'
        OR jsonb_typeof(NEW.spec -> 'request_resource_version') IS DISTINCT FROM 'number'
        OR jsonb_typeof(NEW.spec -> 'mode') IS DISTINCT FROM 'string'
    THEN
        RAISE EXCEPTION 'agent job spec has no typed request resource binding'
            USING ERRCODE = '23514';
    END IF;

    spec_request_id_text := NEW.spec ->> 'request_id';
    IF spec_request_id_text IS DISTINCT FROM NEW.request_id::TEXT THEN
        RAISE EXCEPTION 'agent job spec request_id does not match its row binding'
            USING ERRCODE = '23514';
    END IF;

    spec_mode_text := NEW.spec ->> 'mode';
    -- Keep the SQL CASE grouped inside the PL/pgSQL IF expression.  Without
    -- these parentheses the PL/pgSQL reader treats the first CASE-arm THEN as
    -- the end of the IF condition and submits a truncated expression.
    IF spec_mode_text IS DISTINCT FROM (
        CASE NEW.mode
            WHEN 'OfflineDryRun' THEN 'offline_dry_run'
            WHEN 'LivePlan' THEN 'live_plan'
            WHEN 'LiveApply' THEN 'live_apply'
            WHEN 'LiveDestroy' THEN 'live_destroy'
            ELSE NULL
        END
    ) THEN
        RAISE EXCEPTION 'agent job spec mode does not match its row binding'
            USING ERRCODE = '23514';
    END IF;

    spec_request_resource_version_text :=
        NEW.spec ->> 'request_resource_version';
    IF spec_request_resource_version_text IS NULL
        OR spec_request_resource_version_text !~ '^[1-9][0-9]*$'
    THEN
        RAISE EXCEPTION 'agent job spec request_resource_version is not a positive integer'
            USING ERRCODE = '23514';
    END IF;
    BEGIN
        spec_request_resource_version :=
            spec_request_resource_version_text::BIGINT;
    EXCEPTION
        WHEN numeric_value_out_of_range THEN
            RAISE EXCEPTION 'agent job spec request_resource_version exceeds BIGINT'
                USING ERRCODE = '22003';
    END;

    -- FOR SHARE conflicts with request UPDATE/DELETE row locks.  The selected
    -- version therefore cannot change between this check and job insertion;
    -- both locks remain held until the surrounding transaction completes.
    SELECT request.resource_version
    INTO current_resource_version
    FROM requests AS request
    WHERE request.id = NEW.request_id
    FOR SHARE;

    IF current_resource_version IS NULL THEN
        SELECT relation_catalog.relowner
        INTO request_table_owner
        FROM pg_catalog.pg_class AS relation_catalog
        WHERE relation_catalog.oid = 'public.requests'::regclass;

        enforce_runtime_contract := request_table_owner IS NULL
            OR CURRENT_USER::regrole::oid <> request_table_owner
            OR COALESCE(
                current_setting('ryuki.force_request_runtime_contract', TRUE) =
                    'runtime-v1',
                FALSE
            );

        IF enforce_runtime_contract THEN
            RAISE EXCEPTION 'agent job request does not exist'
                USING ERRCODE = '23503';
        END IF;

        -- Migration 054 intentionally retains owner-backed orphan fixtures.
        -- They carry the inert version-1 baseline and are never admissible
        -- through the production role contract.
        IF NEW.request_resource_version IS NULL THEN
            NEW.request_resource_version := spec_request_resource_version;
        END IF;
        IF NEW.request_resource_version <> 1 THEN
            RAISE EXCEPTION 'orphan fixture job must use resource version 1'
                USING ERRCODE = '23514';
        END IF;
        IF spec_request_resource_version IS DISTINCT FROM NEW.request_resource_version THEN
            RAISE EXCEPTION 'orphan fixture job spec version does not match its row binding'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.request_resource_version IS NULL THEN
        NEW.request_resource_version := current_resource_version;
    ELSIF NEW.request_resource_version <> current_resource_version THEN
        RAISE EXCEPTION 'agent job resource version is not current'
            USING ERRCODE = '23514';
    END IF;
    IF spec_request_resource_version IS DISTINCT FROM NEW.request_resource_version THEN
        RAISE EXCEPTION 'agent job spec version does not match its row binding'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_agent_jobs_request_resource_version
BEFORE INSERT ON agent_jobs
FOR EACH ROW
EXECUTE FUNCTION bind_agent_job_request_resource_version();

ALTER TABLE agent_jobs
    ENABLE ALWAYS TRIGGER trg_agent_jobs_request_resource_version;

CREATE OR REPLACE FUNCTION reject_agent_job_request_binding_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'agent job execution authority is immutable'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER trg_agent_jobs_request_resource_version_owned
BEFORE UPDATE OF
    id,
    request_id,
    platform,
    spec,
    mode,
    live_context,
    origin,
    step_scoped,
    request_resource_version
ON agent_jobs
FOR EACH ROW
EXECUTE FUNCTION reject_agent_job_request_binding_update();

ALTER TABLE agent_jobs
    ENABLE ALWAYS TRIGGER trg_agent_jobs_request_resource_version_owned;

-- Database-enforced scheduler deduplication. The request-row lock keeps
-- freshness atomic; this partial unique index remains the final arbiter if a
-- future writer omits that lock or runs under a different transaction shape.
-- Existing duplicates deliberately make this migration fail for explicit
-- operator reconciliation rather than silently choosing a winner.
CREATE UNIQUE INDEX idx_agent_jobs_one_open_drift_recheck_per_request
ON agent_jobs (request_id)
WHERE origin = 'drift_recheck'
  AND status IN ('Pending', 'Leased', 'Running');

-- No ordinary default remains.  Rolling old INSERT column lists continue to
-- work because the BEFORE INSERT guards populate NULL; direct callers cannot
-- silently receive a constant version that bypasses current-version checks.
ALTER TABLE request_approval_decisions
    ALTER COLUMN approval_basis_resource_version DROP DEFAULT;

ALTER TABLE agent_jobs
    ALTER COLUMN request_resource_version DROP DEFAULT;
