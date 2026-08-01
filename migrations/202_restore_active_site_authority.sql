-- 202_restore_active_site_authority.sql
--
-- Restore authority is the immutable target tuple plus a current, exact active
-- site-registry relation. Migration 186 proved the tuple's shape and
-- maker/checker provenance, but it could not prove that a legacy target still
-- named an active durable site. Quarantine that unproved population without
-- rewriting its evidence, then keep future operational writes behind the same
-- active-site row lock used by the HTTP handlers.

SET LOCAL lock_timeout = '30s';

-- Match runtime lock order: site authority first, then restore state. The SHARE
-- lock prevents a site activation/deactivation from changing the migration's
-- classification snapshot while legacy rows are reclassified.
LOCK TABLE site_registry IN SHARE MODE;
LOCK TABLE restore_requests IN ACCESS EXCLUSIVE MODE;

-- Migration 186 deliberately makes authority classification immutable at
-- runtime. Temporarily remove only that trigger while this forward migration
-- narrows the set of rows that may remain Verified.
DROP TRIGGER IF EXISTS restore_requests_authority_immutability
ON restore_requests;

UPDATE restore_requests AS request
SET authority_state = 'Quarantined',
    authority_reason = 'inactive-or-missing-target-site-requires-replan'
WHERE request.authority_state = 'Verified'
  AND NOT EXISTS (
      SELECT 1
      FROM site_registry AS registry
      WHERE registry.unlocode COLLATE "C" = request.target_site COLLATE "C"
        AND registry.active = TRUE
  );

CREATE TRIGGER restore_requests_authority_immutability
BEFORE UPDATE ON restore_requests
FOR EACH ROW
EXECUTE FUNCTION enforce_restore_authority_immutability();

ALTER TABLE restore_requests
    ENABLE ALWAYS TRIGGER restore_requests_authority_immutability;

-- A direct writer must not bypass the application transaction. Verified
-- inserts and every authority/status transition lock the exact active target
-- row FOR SHARE. Concurrent deactivation therefore waits for the restore write,
-- while a deactivation that wins first makes the restore write fail closed.
CREATE OR REPLACE FUNCTION enforce_restore_active_site_authority()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    IF NEW.authority_state <> 'Verified' THEN
        RETURN NEW;
    END IF;

    IF TG_OP = 'UPDATE'
       AND NEW.target_site COLLATE "C"
            IS DISTINCT FROM OLD.target_site COLLATE "C" THEN
        RAISE EXCEPTION 'verified restore target authority is immutable'
            USING ERRCODE = '55000';
    END IF;

    IF TG_OP = 'UPDATE'
       AND NEW.status IS NOT DISTINCT FROM OLD.status
       AND NEW.target_site COLLATE "C"
            IS NOT DISTINCT FROM OLD.target_site COLLATE "C"
       AND NEW.authority_state IS NOT DISTINCT FROM OLD.authority_state THEN
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM public.site_registry AS registry
    WHERE registry.unlocode COLLATE "C" = NEW.target_site COLLATE "C"
      AND registry.active = TRUE
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'verified restore target must reference a current active canonical site'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS restore_requests_active_site_authority
ON restore_requests;
CREATE TRIGGER restore_requests_active_site_authority
BEFORE INSERT OR UPDATE ON restore_requests
FOR EACH ROW
EXECUTE FUNCTION enforce_restore_active_site_authority();

ALTER TABLE restore_requests
    ENABLE ALWAYS TRIGGER restore_requests_active_site_authority;

REVOKE ALL ON FUNCTION enforce_restore_active_site_authority() FROM PUBLIC;
DO $$
BEGIN
    IF pg_catalog.to_regrole('ryuki_app_runtime') IS NOT NULL THEN
        EXECUTE 'REVOKE ALL ON FUNCTION public.enforce_restore_active_site_authority() '
             || 'FROM ryuki_app_runtime';
    END IF;
END;
$$;

-- Migration completion itself is evidence: no syntactically Verified row may
-- remain without the current exact durable site authority proved above.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM restore_requests AS request
        WHERE request.authority_state = 'Verified'
          AND NOT EXISTS (
              SELECT 1
              FROM site_registry AS registry
              WHERE registry.unlocode COLLATE "C" = request.target_site COLLATE "C"
                AND registry.active = TRUE
          )
    ) THEN
        RAISE EXCEPTION
            'verified restore authority remains without an active canonical site'
            USING ERRCODE = '55000';
    END IF;
END;
$$;
