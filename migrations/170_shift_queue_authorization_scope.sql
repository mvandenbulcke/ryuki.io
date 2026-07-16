-- 170_shift_queue_authorization_scope.sql
--
-- Shift work is execute-tier data, but `execute` only answers WHAT a principal
-- may do. These typed, immutable columns answer WHERE and (when present) WHO.
-- Free-form metadata is retained as descriptive payload only; it is never an
-- authorization identity or a uniqueness key.
--
-- Mixed-version rollout fence
-- ---------------------------
-- Stop every old reader and writer and drain its database sessions before this
-- migration. The ACCESS EXCLUSIVE lock prevents an old metadata-only writer
-- from overlapping the index cutover, but it cannot make an old reader enforce
-- the new authority semantics. If a stale writer escapes the operational drain
-- after commit, its omitted fields default to
-- `quarantined`/`unresolved-legacy`; that is a defense-in-depth data fence, not
-- rolling compatibility. Such a row is outside every new authority index and
-- can never suppress verified resource work. Deploying the new binary before
-- this schema fails closed on missing columns rather than falling back to
-- metadata authority. The old partial indexes are removed only while the table
-- is locked, and the replacement indexes exist before unlock.

ALTER TABLE shift_queue
    ADD COLUMN IF NOT EXISTS visibility_kind TEXT NOT NULL DEFAULT 'quarantined',
    ADD COLUMN IF NOT EXISTS site TEXT,
    ADD COLUMN IF NOT EXISTS environment TEXT,
    ADD COLUMN IF NOT EXISTS owner_principal TEXT,
    ADD COLUMN IF NOT EXISTS source_ci_key TEXT,
    ADD COLUMN IF NOT EXISTS scope_provenance TEXT NOT NULL DEFAULT 'unresolved-legacy';

LOCK TABLE shift_queue IN ACCESS EXCLUSIVE MODE;

-- Never infer authorization from legacy JSON. Every pre-migration row remains
-- quarantined, including rows whose metadata happens to spell an active site or
-- a source key. A human-reviewed mapping below is the only release path.

ALTER TABLE shift_queue
    DROP CONSTRAINT IF EXISTS shift_queue_visibility_kind_check,
    DROP CONSTRAINT IF EXISTS shift_queue_site_shape_check,
    DROP CONSTRAINT IF EXISTS shift_queue_environment_shape_check,
    DROP CONSTRAINT IF EXISTS shift_queue_owner_shape_check,
    DROP CONSTRAINT IF EXISTS shift_queue_source_ci_key_shape_check,
    DROP CONSTRAINT IF EXISTS shift_queue_scope_provenance_check,
    DROP CONSTRAINT IF EXISTS shift_queue_visibility_shape_check,
    DROP CONSTRAINT IF EXISTS shift_queue_site_fk;

ALTER TABLE shift_queue
    ADD CONSTRAINT shift_queue_visibility_kind_check
        CHECK (visibility_kind IN ('resource', 'global', 'quarantined')),
    ADD CONSTRAINT shift_queue_site_shape_check
        CHECK (site IS NULL OR (site = BTRIM(site) AND site <> '')),
    ADD CONSTRAINT shift_queue_environment_shape_check
        CHECK (environment IS NULL OR (environment = BTRIM(environment) AND environment <> '')),
    ADD CONSTRAINT shift_queue_owner_shape_check
        CHECK (owner_principal IS NULL OR (owner_principal = BTRIM(owner_principal) AND owner_principal <> '')),
    ADD CONSTRAINT shift_queue_source_ci_key_shape_check
        CHECK (source_ci_key IS NULL OR (source_ci_key = BTRIM(source_ci_key) AND source_ci_key <> '')),
    ADD CONSTRAINT shift_queue_scope_provenance_check
        CHECK (scope_provenance IN (
            'unresolved-legacy',
            'scheduler-resource-v1',
            'scheduler-global-v1',
            'reviewed-reconciliation-v1'
        )),
    ADD CONSTRAINT shift_queue_visibility_shape_check
        CHECK (
            (visibility_kind = 'resource'
             AND source_ci_key IS NOT NULL
             AND site IS NOT NULL
             AND scope_provenance IN ('scheduler-resource-v1', 'reviewed-reconciliation-v1'))
            OR
            (visibility_kind = 'global'
             AND source_ci_key IS NOT NULL
             AND site IS NULL
             AND environment IS NULL
             AND owner_principal IS NULL
             AND scope_provenance IN ('scheduler-global-v1', 'reviewed-reconciliation-v1'))
            OR
            (visibility_kind = 'quarantined'
             AND source_ci_key IS NULL
             AND site IS NULL
             AND environment IS NULL
             AND owner_principal IS NULL
             AND scope_provenance = 'unresolved-legacy')
        ),
    ADD CONSTRAINT shift_queue_site_fk
        FOREIGN KEY (site) REFERENCES site_registry(unlocode)
        ON UPDATE RESTRICT ON DELETE RESTRICT;

-- Preserve the untrusted legacy hints in a review queue without promoting
-- them. Candidate fields are evidence for an operator, never authority. A
-- reviewer must set the complete approved tuple plus identity, rationale, and
-- timestamp in one update. The subsequent shift_queue UPDATE is accepted only
-- when it exactly matches that unapplied review; the trigger marks it applied
-- in the same transaction. A uniqueness collision aborts both writes and leaves
-- the review pending for explicit duplicate resolution.
CREATE TABLE IF NOT EXISTS shift_queue_scope_reconciliation_reviews (
    shift_queue_id UUID PRIMARY KEY
        REFERENCES shift_queue(id) ON DELETE CASCADE,
    candidate_source_ci_key TEXT,
    candidate_site TEXT,
    candidate_environment TEXT,
    approved_visibility_kind TEXT,
    approved_source_ci_key TEXT,
    approved_site TEXT REFERENCES site_registry(unlocode)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    approved_environment TEXT,
    reviewed_by TEXT,
    review_reason TEXT,
    reviewed_at TIMESTAMPTZ,
    applied_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT shift_queue_scope_review_candidate_shape_check CHECK (
        (candidate_source_ci_key IS NULL
         OR (candidate_source_ci_key = BTRIM(candidate_source_ci_key)
             AND candidate_source_ci_key <> ''))
        AND (candidate_site IS NULL
             OR (candidate_site = BTRIM(candidate_site) AND candidate_site <> ''))
        AND (candidate_environment IS NULL
             OR (candidate_environment = BTRIM(candidate_environment)
                 AND candidate_environment <> ''))
    ),
    CONSTRAINT shift_queue_scope_review_decision_shape_check CHECK (
        (approved_visibility_kind IS NULL
         AND approved_source_ci_key IS NULL
         AND approved_site IS NULL
         AND approved_environment IS NULL
         AND reviewed_by IS NULL
         AND review_reason IS NULL
         AND reviewed_at IS NULL
        AND applied_at IS NULL)
        OR
        (approved_visibility_kind IS NOT NULL
         AND approved_visibility_kind IN ('resource', 'global')
         AND approved_source_ci_key IS NOT NULL
         AND approved_source_ci_key = BTRIM(approved_source_ci_key)
         AND approved_source_ci_key <> ''
         AND reviewed_by = BTRIM(reviewed_by)
         AND reviewed_by <> ''
         AND review_reason = BTRIM(review_reason)
         AND review_reason <> ''
         AND reviewed_at IS NOT NULL
         AND (applied_at IS NULL OR applied_at >= reviewed_at)
         AND (
             (approved_visibility_kind = 'resource'
              AND approved_site IS NOT NULL
              AND approved_site = BTRIM(approved_site)
              AND approved_site <> ''
              AND (approved_environment IS NULL
                   OR (approved_environment = BTRIM(approved_environment)
                       AND approved_environment <> '')))
             OR
             (approved_visibility_kind = 'global'
              AND approved_site IS NULL
              AND approved_environment IS NULL)
         ))
    )
);

INSERT INTO shift_queue_scope_reconciliation_reviews (
    shift_queue_id,
    candidate_source_ci_key,
    candidate_site,
    candidate_environment
)
SELECT id,
       CASE
           WHEN jsonb_typeof(metadata->'source_ci_key') = 'string'
            AND metadata->>'source_ci_key' = BTRIM(metadata->>'source_ci_key')
            AND metadata->>'source_ci_key' <> ''
           THEN metadata->>'source_ci_key'
           ELSE NULL
       END,
       CASE
           WHEN jsonb_typeof(metadata->'site') = 'string'
            AND metadata->>'site' = BTRIM(metadata->>'site')
            AND metadata->>'site' <> ''
           THEN metadata->>'site'
           ELSE NULL
       END,
       CASE
           WHEN jsonb_typeof(metadata->'environment') = 'string'
            AND metadata->>'environment' = BTRIM(metadata->>'environment')
            AND metadata->>'environment' <> ''
           THEN metadata->>'environment'
           ELSE NULL
       END
FROM shift_queue
WHERE visibility_kind = 'quarantined'
ON CONFLICT (shift_queue_id) DO NOTHING;

-- Old binaries must not serve after this migration commits. If a stale writer
-- nevertheless escapes the mandatory drain, its metadata-only insert defaults
-- to quarantine and this trigger makes the row reviewable without letting it
-- enter an authority index.
CREATE OR REPLACE FUNCTION capture_shift_queue_scope_review_candidate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.visibility_kind = 'quarantined' THEN
        INSERT INTO shift_queue_scope_reconciliation_reviews (
            shift_queue_id,
            candidate_source_ci_key,
            candidate_site,
            candidate_environment
        ) VALUES (
            NEW.id,
            CASE
                WHEN jsonb_typeof(NEW.metadata->'source_ci_key') = 'string'
                 AND NEW.metadata->>'source_ci_key' = BTRIM(NEW.metadata->>'source_ci_key')
                 AND NEW.metadata->>'source_ci_key' <> ''
                THEN NEW.metadata->>'source_ci_key'
                ELSE NULL
            END,
            CASE
                WHEN jsonb_typeof(NEW.metadata->'site') = 'string'
                 AND NEW.metadata->>'site' = BTRIM(NEW.metadata->>'site')
                 AND NEW.metadata->>'site' <> ''
                THEN NEW.metadata->>'site'
                ELSE NULL
            END,
            CASE
                WHEN jsonb_typeof(NEW.metadata->'environment') = 'string'
                 AND NEW.metadata->>'environment' = BTRIM(NEW.metadata->>'environment')
                 AND NEW.metadata->>'environment' <> ''
                THEN NEW.metadata->>'environment'
                ELSE NULL
            END
        )
        ON CONFLICT (shift_queue_id) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_shift_queue_capture_scope_review ON shift_queue;
CREATE TRIGGER trg_shift_queue_capture_scope_review
AFTER INSERT ON shift_queue
FOR EACH ROW
EXECUTE FUNCTION capture_shift_queue_scope_review_candidate();

-- A resource insert must observe and hold the exact active canonical site row
-- until its transaction commits. This is the database backstop for every
-- writer, including direct SQL that bypasses the repository helper.
CREATE OR REPLACE FUNCTION enforce_shift_queue_insert_authority()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.visibility_kind = 'resource' THEN
        PERFORM 1
        FROM site_registry
        WHERE unlocode = NEW.site AND active = true
        FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'shift_queue resource authority requires an active canonical site';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_shift_queue_insert_authority ON shift_queue;
CREATE TRIGGER trg_shift_queue_insert_authority
BEFORE INSERT ON shift_queue
FOR EACH ROW
EXECUTE FUNCTION enforce_shift_queue_insert_authority();

CREATE OR REPLACE FUNCTION reject_shift_queue_scope_rebind()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.visibility_kind IS NOT DISTINCT FROM OLD.visibility_kind
       AND NEW.site IS NOT DISTINCT FROM OLD.site
       AND NEW.environment IS NOT DISTINCT FROM OLD.environment
       AND NEW.owner_principal IS NOT DISTINCT FROM OLD.owner_principal
       AND NEW.source_ci_key IS NOT DISTINCT FROM OLD.source_ci_key
       AND NEW.scope_provenance IS NOT DISTINCT FROM OLD.scope_provenance
    THEN
        RETURN NEW;
    END IF;

    IF OLD.visibility_kind = 'quarantined'
       AND OLD.scope_provenance = 'unresolved-legacy'
       AND NEW.scope_provenance = 'reviewed-reconciliation-v1'
       AND NEW.owner_principal IS NULL
    THEN
        IF NEW.visibility_kind = 'resource' THEN
            PERFORM 1
            FROM site_registry
            WHERE unlocode = NEW.site AND active = true
            FOR SHARE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'shift_queue reviewed resource authority requires an active canonical site';
            END IF;
        END IF;
        UPDATE shift_queue_scope_reconciliation_reviews
        SET applied_at = clock_timestamp()
        WHERE shift_queue_id = OLD.id
          AND applied_at IS NULL
          AND approved_visibility_kind = NEW.visibility_kind
          AND approved_source_ci_key = NEW.source_ci_key
          AND approved_site IS NOT DISTINCT FROM NEW.site
          AND approved_environment IS NOT DISTINCT FROM NEW.environment
          AND reviewed_by IS NOT NULL
          AND review_reason IS NOT NULL
          AND reviewed_at IS NOT NULL;
        IF FOUND THEN
            RETURN NEW;
        END IF;
    END IF;

    RAISE EXCEPTION 'shift_queue authorization scope is immutable without an exact pending review';
END;
$$;

DROP TRIGGER IF EXISTS trg_shift_queue_scope_immutable ON shift_queue;
CREATE TRIGGER trg_shift_queue_scope_immutable
BEFORE UPDATE OF visibility_kind, site, environment, owner_principal,
                 source_ci_key, scope_provenance
ON shift_queue
FOR EACH ROW
EXECUTE FUNCTION reject_shift_queue_scope_rebind();

-- Retire every metadata-only uniqueness contract. Keeping even one old index
-- would let an unresolved/quarantined row suppress a legitimate scoped row.
DROP INDEX IF EXISTS uq_shift_queue_open_restore_overdue;
DROP INDEX IF EXISTS uq_shift_queue_open_restore_failed;
DROP INDEX IF EXISTS uq_shift_queue_open_secret_rotation_due;
DROP INDEX IF EXISTS uq_shift_queue_open_secret_rotation_invalid;
DROP INDEX IF EXISTS uq_shift_queue_open_legal_hold_expiring;
DROP INDEX IF EXISTS uq_shift_queue_open_recertification_overdue;
DROP INDEX IF EXISTS uq_shift_queue_open_certificate_expiring;
DROP INDEX IF EXISTS uq_shift_queue_open_gmsa_expiring;
DROP INDEX IF EXISTS uq_shift_queue_open_oob_cert_expiring;
DROP INDEX IF EXISTS uq_shift_queue_open_dr_test_overdue;
DROP INDEX IF EXISTS uq_shift_queue_open_patch_wave_overdue;
DROP INDEX IF EXISTS uq_shift_queue_open_golden_image_stale;
DROP INDEX IF EXISTS uq_shift_queue_open_drift_recheck_overdue;

-- NULL and empty environments cannot collide because empty strings are
-- rejected. COALESCE therefore gives the nullable environment axis normal
-- uniqueness semantics. Quarantined rows are deliberately excluded.
CREATE UNIQUE INDEX IF NOT EXISTS uq_shift_queue_open_resource_authority
    ON shift_queue (item_type, source_ci_key, site, COALESCE(environment, ''))
    WHERE visibility_kind = 'resource' AND resolved = false;

CREATE UNIQUE INDEX IF NOT EXISTS uq_shift_queue_open_global_authority
    ON shift_queue (item_type, source_ci_key)
    WHERE visibility_kind = 'global' AND resolved = false;

CREATE INDEX IF NOT EXISTS idx_shift_queue_scope_open_keyset
    ON shift_queue (site, environment, owner_principal, created_at, id)
    WHERE visibility_kind = 'resource' AND resolved = false;

CREATE INDEX IF NOT EXISTS idx_shift_queue_scope_resolved_keyset
    ON shift_queue (site, environment, owner_principal, resolved_at DESC, id DESC)
    WHERE visibility_kind = 'resource' AND resolved = true;

CREATE INDEX IF NOT EXISTS idx_shift_queue_scope_assignee_keyset
    ON shift_queue (assigned_to, site, environment, created_at, id)
    WHERE visibility_kind = 'resource' AND resolved = false;

COMMENT ON COLUMN shift_queue.source_ci_key IS
    'Typed scheduler source identity used with item_type/site/environment for authority-scoped dedup; metadata is descriptive only.';
COMMENT ON COLUMN shift_queue.scope_provenance IS
    'How the immutable queue authorization tuple was established; unresolved legacy rows remain quarantined.';
COMMENT ON TABLE shift_queue_scope_reconciliation_reviews IS
    'Pending and applied human-reviewed mappings for releasing legacy quarantined shift work; candidate metadata is never authority.';
