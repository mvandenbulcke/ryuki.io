-- Restore authority and maker/checker provenance are executable security
-- inputs.  Legacy rows predate those contracts, so classify them explicitly
-- instead of silently treating unproved data as operational authority.

SET LOCAL lock_timeout = '30s';

LOCK TABLE restore_requests IN ACCESS EXCLUSIVE MODE;

ALTER TABLE restore_requests
    ADD COLUMN authority_state TEXT NOT NULL DEFAULT 'Quarantined',
    ADD COLUMN authority_reason TEXT DEFAULT 'writer-contract-required';

-- A row is verified only when its complete resource tuple and planner identity
-- are canonical.  Approved-or-later rows additionally need a canonical,
-- distinct approver in both the typed column and metadata.  Everything else is
-- retained for evidence but is permanently quarantined and must be replanned.
UPDATE restore_requests
SET authority_state = CASE
        WHEN source_ci_key <> ''
         AND source_ci_key = btrim(source_ci_key, E' \t\n\r\013\f')
         AND octet_length(source_ci_key) <= 512
         AND target_site <> ''
         AND target_site = btrim(target_site, E' \t\n\r\013\f')
         AND octet_length(target_site) <= 512
         AND target_environment <> ''
         AND target_environment = btrim(target_environment, E' \t\n\r\013\f')
         AND octet_length(target_environment) <= 512
         AND jsonb_typeof(metadata->'planned_by') = 'string'
         AND metadata->>'planned_by' <> ''
         AND metadata->>'planned_by' =
             btrim(metadata->>'planned_by', E' \t\n\r\013\f')
         AND octet_length(metadata->>'planned_by') <= 512
         AND (
             (status IN ('Draft', 'Validated', 'Planned')
              AND approver IS NULL
              AND NOT (metadata ? 'approver'))
             OR
             (status IN ('Approved', 'Locked', 'Executed', 'Verified',
                         'Completed', 'Failed')
              AND approver IS NOT NULL
              AND approver <> ''
              AND approver = btrim(approver, E' \t\n\r\013\f')
              AND octet_length(approver) <= 512
              AND jsonb_typeof(metadata->'approver') = 'string'
              AND metadata->>'approver' = approver
              AND approver <> metadata->>'planned_by')
         )
        THEN 'Verified'
        ELSE 'Quarantined'
    END,
    authority_reason = CASE
        WHEN source_ci_key <> ''
         AND source_ci_key = btrim(source_ci_key, E' \t\n\r\013\f')
         AND octet_length(source_ci_key) <= 512
         AND target_site <> ''
         AND target_site = btrim(target_site, E' \t\n\r\013\f')
         AND octet_length(target_site) <= 512
         AND target_environment <> ''
         AND target_environment = btrim(target_environment, E' \t\n\r\013\f')
         AND octet_length(target_environment) <= 512
         AND jsonb_typeof(metadata->'planned_by') = 'string'
         AND metadata->>'planned_by' <> ''
         AND metadata->>'planned_by' =
             btrim(metadata->>'planned_by', E' \t\n\r\013\f')
         AND octet_length(metadata->>'planned_by') <= 512
         AND (
             (status IN ('Draft', 'Validated', 'Planned')
              AND approver IS NULL
              AND NOT (metadata ? 'approver'))
             OR
             (status IN ('Approved', 'Locked', 'Executed', 'Verified',
                         'Completed', 'Failed')
              AND approver IS NOT NULL
              AND approver <> ''
              AND approver = btrim(approver, E' \t\n\r\013\f')
              AND octet_length(approver) <= 512
              AND jsonb_typeof(metadata->'approver') = 'string'
              AND metadata->>'approver' = approver
              AND approver <> metadata->>'planned_by')
         )
        THEN NULL
        ELSE 'legacy-restore-authority-requires-replan'
    END;

ALTER TABLE restore_requests
    ADD CONSTRAINT restore_requests_authority_state_check
        CHECK (authority_state IN ('Verified', 'Quarantined')),
    ADD CONSTRAINT restore_requests_authority_reason_check
        CHECK (
            (authority_state = 'Verified' AND authority_reason IS NULL)
            OR
            (authority_state = 'Quarantined'
             AND authority_reason IS NOT NULL
             AND authority_reason <> ''
             AND authority_reason =
                 btrim(authority_reason, E' \t\n\r\013\f')
             AND octet_length(authority_reason) <= 255)
        ),
    ADD CONSTRAINT restore_requests_verified_authority_check
        CHECK (
            authority_state <> 'Verified'
            OR (
                source_ci_key <> ''
                AND source_ci_key = btrim(source_ci_key, E' \t\n\r\013\f')
                AND octet_length(source_ci_key) <= 512
                AND target_site <> ''
                AND target_site = btrim(target_site, E' \t\n\r\013\f')
                AND octet_length(target_site) <= 512
                AND target_environment <> ''
                AND target_environment =
                    btrim(target_environment, E' \t\n\r\013\f')
                AND octet_length(target_environment) <= 512
                AND jsonb_typeof(metadata->'planned_by') = 'string'
                AND metadata->>'planned_by' <> ''
                AND metadata->>'planned_by' =
                    btrim(metadata->>'planned_by', E' \t\n\r\013\f')
                AND octet_length(metadata->>'planned_by') <= 512
            )
        ),
    ADD CONSTRAINT restore_requests_verified_approval_check
        CHECK (
            authority_state <> 'Verified'
            OR status NOT IN ('Approved', 'Locked', 'Executed', 'Verified',
                              'Completed', 'Failed')
            OR (
                approver IS NOT NULL
                AND approver <> ''
                AND approver = btrim(approver, E' \t\n\r\013\f')
                AND octet_length(approver) <= 512
                AND jsonb_typeof(metadata->'approver') = 'string'
                AND metadata->>'approver' = approver
                AND approver <> metadata->>'planned_by'
            )
        ),
    ADD CONSTRAINT restore_requests_unapproved_has_no_approver_check
        CHECK (
            authority_state <> 'Verified'
            OR status NOT IN ('Draft', 'Validated', 'Planned')
            OR (approver IS NULL AND NOT (metadata ? 'approver'))
        );

-- Keep lookup of quarantined members of one scheduler tuple bounded.  Exact
-- equality is still checked by the query, so MD5 is only an index accelerator.
CREATE INDEX idx_restore_requests_quarantined_authority_tuple
ON restore_requests (
    md5(source_ci_key), md5(target_site), md5(target_environment)
)
WHERE authority_state = 'Quarantined';

CREATE OR REPLACE FUNCTION enforce_restore_authority_immutability()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.authority_state = 'Quarantined' THEN
        RAISE EXCEPTION
            'quarantined restore request must be replanned, not transitioned'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.authority_state IS DISTINCT FROM OLD.authority_state
       OR NEW.authority_reason IS DISTINCT FROM OLD.authority_reason THEN
        RAISE EXCEPTION
            'restore authority classification is immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.source_ci_key IS DISTINCT FROM OLD.source_ci_key
       OR NEW.target_site IS DISTINCT FROM OLD.target_site
       OR NEW.target_environment IS DISTINCT FROM OLD.target_environment
       OR NEW.metadata->>'planned_by'
            IS DISTINCT FROM OLD.metadata->>'planned_by' THEN
        RAISE EXCEPTION
            'verified restore authority tuple and planner are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.approver IS NOT NULL
       AND (NEW.approver IS DISTINCT FROM OLD.approver
            OR NEW.metadata->>'approver'
                IS DISTINCT FROM OLD.metadata->>'approver') THEN
        RAISE EXCEPTION
            'restore approver provenance is immutable once recorded'
            USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS restore_requests_authority_immutability
ON restore_requests;
CREATE TRIGGER restore_requests_authority_immutability
BEFORE UPDATE ON restore_requests
FOR EACH ROW
EXECUTE FUNCTION enforce_restore_authority_immutability();

REVOKE ALL ON FUNCTION enforce_restore_authority_immutability() FROM PUBLIC;
DO $$
BEGIN
    IF pg_catalog.to_regrole('ryuki_app_runtime') IS NOT NULL THEN
        EXECUTE 'REVOKE ALL ON FUNCTION public.enforce_restore_authority_immutability() '
             || 'FROM ryuki_app_runtime';
    END IF;
END;
$$;
