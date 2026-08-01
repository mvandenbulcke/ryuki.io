-- 206_restore_source_authority.sql
--
-- A caller-supplied CI name and timestamp are lookup hints, not restore
-- authority. New restore requests must bind an immutable configuration-item
-- UUID and an exact persisted backup restore-point UUID. Existing rows predate
-- that proof and remain as quarantined evidence; familiar text is never
-- backfilled into trusted object identity.

SET LOCAL lock_timeout = '30s';

CREATE TABLE backup_restore_points (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    configuration_item_id UUID NOT NULL
        REFERENCES configuration_items(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    captured_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'Available'
        CHECK (status IN ('Available', 'Expired', 'Quarantined')),
    source_system TEXT NOT NULL CHECK (
        source_system = btrim(source_system)
        AND source_system <> ''
        AND octet_length(source_system) <= 128
    ),
    source_reference TEXT NOT NULL CHECK (
        source_reference = btrim(source_reference)
        AND source_reference <> ''
        AND octet_length(source_reference) <= 512
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (configuration_item_id, captured_at),
    UNIQUE (id, configuration_item_id)
);

CREATE INDEX idx_backup_restore_points_available_ci_time
    ON backup_restore_points(configuration_item_id, captured_at DESC, id)
    WHERE status = 'Available';

-- Point ingestion itself proves a current canonical source asset. No public API
-- writes this relation; provider inventory or reviewed migrations populate it.
CREATE OR REPLACE FUNCTION enforce_backup_restore_point_authority()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    source_environment TEXT;
BEGIN
    -- Expiry/quarantine is a protective revocation and remains available even
    -- after the source site is deactivated. Admission/reactivation is the path
    -- that must prove current source authority.
    IF TG_OP = 'UPDATE' AND NEW.status <> 'Available' THEN
        RETURN NEW;
    END IF;

    SELECT ci.environment
    INTO source_environment
    FROM public.configuration_items AS ci
    JOIN public.site_registry AS registry
      ON registry.unlocode COLLATE "C" = ci.site COLLATE "C"
     AND registry.active = TRUE
    WHERE ci.id = NEW.configuration_item_id
    FOR NO KEY UPDATE OF ci
    FOR SHARE OF registry;

    IF NOT FOUND OR source_environment IS NULL OR btrim(source_environment) = '' THEN
        RAISE EXCEPTION
            'backup restore point requires an active, environment-classified source asset'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER backup_restore_points_authority
BEFORE INSERT OR UPDATE OF configuration_item_id, status
ON backup_restore_points
FOR EACH ROW
EXECUTE FUNCTION enforce_backup_restore_point_authority();

CREATE OR REPLACE FUNCTION reject_backup_restore_point_rebind()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.configuration_item_id IS DISTINCT FROM OLD.configuration_item_id
       OR NEW.captured_at IS DISTINCT FROM OLD.captured_at
       OR NEW.source_system COLLATE "C"
            IS DISTINCT FROM OLD.source_system COLLATE "C"
       OR NEW.source_reference COLLATE "C"
            IS DISTINCT FROM OLD.source_reference COLLATE "C"
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'backup restore-point provenance is immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER backup_restore_points_provenance_immutable
BEFORE UPDATE ON backup_restore_points
FOR EACH ROW
EXECUTE FUNCTION reject_backup_restore_point_rebind();

ALTER TABLE backup_restore_points
    ENABLE ALWAYS TRIGGER backup_restore_points_authority;
ALTER TABLE backup_restore_points
    ENABLE ALWAYS TRIGGER backup_restore_points_provenance_immutable;

-- Preserve runtime lock order: source/target site authority before restore
-- state. This prevents the cutover from observing a changing CMDB/site tuple.
LOCK TABLE site_registry IN SHARE MODE;
LOCK TABLE configuration_items IN SHARE MODE;
LOCK TABLE backup_restore_points IN SHARE MODE;
LOCK TABLE restore_requests IN ACCESS EXCLUSIVE MODE;

ALTER TABLE restore_requests
    ADD COLUMN source_configuration_item_id UUID,
    ADD COLUMN restore_point_id UUID,
    ADD COLUMN source_site TEXT,
    ADD COLUMN source_environment TEXT,
    ADD COLUMN source_scope_provenance TEXT NOT NULL DEFAULT 'unresolved-legacy';

DROP TRIGGER IF EXISTS restore_requests_authority_immutability
ON restore_requests;

-- Do not infer UUID authority by matching legacy names or timestamps. Every
-- pre-cutover Verified row needs a new authorized plan.
UPDATE restore_requests
SET authority_state = 'Quarantined',
    authority_reason = 'unverified-source-asset-requires-replan'
WHERE authority_state = 'Verified';

CREATE TRIGGER restore_requests_authority_immutability
BEFORE UPDATE ON restore_requests
FOR EACH ROW
EXECUTE FUNCTION enforce_restore_authority_immutability();

ALTER TABLE restore_requests
    ENABLE ALWAYS TRIGGER restore_requests_authority_immutability;

ALTER TABLE restore_requests
    ADD CONSTRAINT restore_requests_source_scope_provenance_check
        CHECK (source_scope_provenance IN (
            'unresolved-legacy',
            'backup-restore-point'
        )),
    ADD CONSTRAINT restore_requests_verified_source_authority_check
        CHECK (
            authority_state <> 'Verified'
            OR (
                source_configuration_item_id IS NOT NULL
                AND restore_point_id IS NOT NULL
                AND source_site IS NOT NULL
                AND source_site <> ''
                AND source_site = btrim(source_site, E' \t\n\r\013\f')
                AND octet_length(source_site) <= 512
                AND source_environment IS NOT NULL
                AND source_environment <> ''
                AND source_environment =
                    btrim(source_environment, E' \t\n\r\013\f')
                AND octet_length(source_environment) <= 512
                AND source_scope_provenance = 'backup-restore-point'
            )
        ),
    ADD CONSTRAINT restore_requests_restore_point_source_fk
        FOREIGN KEY (restore_point_id, source_configuration_item_id)
        REFERENCES backup_restore_points(id, configuration_item_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT;

CREATE INDEX idx_restore_requests_verified_source_authority
    ON restore_requests(source_configuration_item_id, restore_point_id, created_at DESC, id DESC)
    WHERE authority_state = 'Verified';

COMMENT ON COLUMN restore_requests.source_configuration_item_id IS
    'Immutable CMDB UUID authorized as the restore source at planning time.';
COMMENT ON COLUMN restore_requests.restore_point_id IS
    'Immutable persisted backup restore-point UUID; restore_point remains descriptive display data.';
COMMENT ON COLUMN restore_requests.source_site IS
    'Immutable exact source site authorized from the CMDB at planning time.';
COMMENT ON COLUMN restore_requests.source_environment IS
    'Immutable exact source environment authorized from the CMDB at planning time.';
COMMENT ON COLUMN restore_requests.source_scope_provenance IS
    'How the source object and restore point were authorized; legacy text is never trusted.';

CREATE OR REPLACE FUNCTION reject_restore_source_authority_rebind()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.source_configuration_item_id
            IS DISTINCT FROM OLD.source_configuration_item_id
       OR NEW.restore_point_id IS DISTINCT FROM OLD.restore_point_id
       OR NEW.source_ci_key COLLATE "C"
            IS DISTINCT FROM OLD.source_ci_key COLLATE "C"
       OR NEW.restore_point COLLATE "C"
            IS DISTINCT FROM OLD.restore_point COLLATE "C"
       OR NEW.source_site COLLATE "C"
            IS DISTINCT FROM OLD.source_site COLLATE "C"
       OR NEW.source_environment COLLATE "C"
            IS DISTINCT FROM OLD.source_environment COLLATE "C"
       OR NEW.source_scope_provenance COLLATE "C"
            IS DISTINCT FROM OLD.source_scope_provenance COLLATE "C" THEN
        RAISE EXCEPTION 'restore source authority provenance is immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER restore_requests_source_authority_immutable
BEFORE UPDATE OF source_configuration_item_id, restore_point_id, source_ci_key,
                 restore_point, source_site, source_environment,
                 source_scope_provenance
ON restore_requests
FOR EACH ROW
EXECUTE FUNCTION reject_restore_source_authority_rebind();

-- Recheck the typed source at every decisive status transition. The point, CI,
-- and active source-site rows are locked with the restore write, so revocation,
-- expiry, CI movement, and site deactivation cannot race approval/execution.
CREATE OR REPLACE FUNCTION enforce_restore_source_authority()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    canonical_ci_name TEXT;
    canonical_restore_point TIMESTAMPTZ;
    canonical_source_site TEXT;
    canonical_source_environment TEXT;
BEGIN
    IF NEW.authority_state <> 'Verified' THEN
        RETURN NEW;
    END IF;

    IF TG_OP = 'UPDATE'
       AND NEW.status IS NOT DISTINCT FROM OLD.status
       AND NEW.source_configuration_item_id
            IS NOT DISTINCT FROM OLD.source_configuration_item_id
       AND NEW.restore_point_id IS NOT DISTINCT FROM OLD.restore_point_id
       AND NEW.authority_state IS NOT DISTINCT FROM OLD.authority_state THEN
        RETURN NEW;
    END IF;

    SELECT ci.ci_name, point.captured_at, ci.site, ci.environment
    INTO canonical_ci_name, canonical_restore_point, canonical_source_site,
         canonical_source_environment
    FROM public.backup_restore_points AS point
    JOIN public.configuration_items AS ci
      ON ci.id = point.configuration_item_id
    JOIN public.site_registry AS registry
      ON registry.unlocode COLLATE "C" = ci.site COLLATE "C"
     AND registry.active = TRUE
    WHERE point.id = NEW.restore_point_id
      AND point.configuration_item_id = NEW.source_configuration_item_id
      AND point.status = 'Available'
      AND ci.ci_name COLLATE "C" = NEW.source_ci_key COLLATE "C"
      AND ci.site COLLATE "C" = NEW.source_site COLLATE "C"
      AND ci.environment COLLATE "C" = NEW.source_environment COLLATE "C"
    FOR NO KEY UPDATE OF point, ci
    FOR SHARE OF registry;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'verified restore requires a current authorized source asset and restore point'
            USING ERRCODE = '23514';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.source_ci_key IS DISTINCT FROM canonical_ci_name
           OR NEW.source_site IS DISTINCT FROM canonical_source_site
           OR NEW.source_environment
                IS DISTINCT FROM canonical_source_environment THEN
            RAISE EXCEPTION
                'restore source display fields do not match typed source authority'
                USING ERRCODE = '23514';
        END IF;

        -- PostgreSQL does not promise short-circuit evaluation for boolean
        -- expressions. Validate the descriptive timestamp before casting it so
        -- malformed direct-SQL input deterministically fails with the authority
        -- constraint error instead of leaking a parser-specific error class.
        IF NOT pg_catalog.pg_input_is_valid(NEW.restore_point, 'timestamptz') THEN
            RAISE EXCEPTION
                'restore source display fields do not match typed source authority'
                USING ERRCODE = '23514';
        END IF;

        IF NEW.restore_point::timestamptz
                IS DISTINCT FROM canonical_restore_point THEN
            RAISE EXCEPTION
                'restore source display fields do not match typed source authority'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER restore_requests_source_authority
BEFORE INSERT OR UPDATE ON restore_requests
FOR EACH ROW
EXECUTE FUNCTION enforce_restore_source_authority();

ALTER TABLE restore_requests
    ENABLE ALWAYS TRIGGER restore_requests_source_authority_immutable;
ALTER TABLE restore_requests
    ENABLE ALWAYS TRIGGER restore_requests_source_authority;

REVOKE ALL ON FUNCTION enforce_backup_restore_point_authority() FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_backup_restore_point_rebind() FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_restore_source_authority_rebind() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_restore_source_authority() FROM PUBLIC;
DO $$
BEGIN
    IF pg_catalog.to_regrole('ryuki_app_runtime') IS NOT NULL THEN
        EXECUTE 'REVOKE ALL ON FUNCTION public.enforce_backup_restore_point_authority() FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.reject_backup_restore_point_rebind() FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.reject_restore_source_authority_rebind() FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.enforce_restore_source_authority() FROM ryuki_app_runtime';
    END IF;
END;
$$;

-- Seal the cutover with an executable invariant. A Verified row must resolve
-- through the exact typed point/CI tuple to a currently active source site;
-- no descriptive legacy field can satisfy this proof.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM restore_requests AS request
        WHERE request.authority_state = 'Verified'
          AND NOT EXISTS (
              SELECT 1
              FROM backup_restore_points AS point
              JOIN configuration_items AS ci
                ON ci.id = point.configuration_item_id
              JOIN site_registry AS registry
                ON registry.unlocode COLLATE "C" = ci.site COLLATE "C"
               AND registry.active = TRUE
              WHERE point.id = request.restore_point_id
                AND point.configuration_item_id =
                    request.source_configuration_item_id
                AND point.status = 'Available'
                AND ci.ci_name COLLATE "C" = request.source_ci_key COLLATE "C"
                AND ci.site COLLATE "C" = request.source_site COLLATE "C"
                AND ci.environment COLLATE "C" =
                    request.source_environment COLLATE "C"
          )
    ) THEN
        RAISE EXCEPTION
            'verified restore authority remains without a current typed source';
    END IF;
END;
$$;
