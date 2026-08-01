-- Prevent a runbook lifecycle from starting or advancing after its canonical
-- site is deactivated or removed. Application writers take the same site row
-- FOR SHARE before creation and every forward mutation; this trigger repeats
-- the invariant at the durable boundary so direct SQL and future callers
-- cannot bypass it. Protective failure and rollback remain available.

CREATE OR REPLACE FUNCTION enforce_runbook_active_site_authority()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    -- Deactivation must stop new/forward work, not prevent an operator from
    -- terminally failing or rolling back an already-open execution.
    IF TG_OP = 'UPDATE' AND NEW.status IN ('failed', 'rolled-back') THEN
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM public.site_registry
    WHERE unlocode COLLATE "C" = NEW.site COLLATE "C"
      AND active = TRUE
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'runbook execution requires a current active canonical site'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS runbook_executions_active_site_authority
ON public.runbook_executions;

CREATE TRIGGER runbook_executions_active_site_authority
BEFORE INSERT OR UPDATE OF status, execution_json
ON public.runbook_executions
FOR EACH ROW
EXECUTE FUNCTION enforce_runbook_active_site_authority();

ALTER TABLE public.runbook_executions
    ENABLE ALWAYS TRIGGER runbook_executions_active_site_authority;

REVOKE ALL ON FUNCTION enforce_runbook_active_site_authority() FROM PUBLIC;

DO $$
BEGIN
    IF pg_catalog.to_regrole('ryuki_app_runtime') IS NOT NULL THEN
        EXECUTE 'REVOKE ALL ON FUNCTION public.enforce_runbook_active_site_authority() '
             || 'FROM ryuki_app_runtime';
    END IF;
END;
$$;

COMMENT ON FUNCTION enforce_runbook_active_site_authority() IS
    'Serializes runbook creation and forward lifecycle writes with one exact active site_registry row while preserving protective terminalization.';
