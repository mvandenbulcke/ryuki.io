-- Bind every persisted runbook execution to one exact lifetime of its
-- canonical site. Active-only lookup is insufficient: deactivation followed
-- by reactivation, or deletion followed by recreation of the same unlocode,
-- must never revive authority for an older execution.

LOCK TABLE public.site_registry IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.runbook_executions IN ACCESS EXCLUSIVE MODE;

-- A global, non-cycling sequence gives every site lifetime/activation epoch a
-- value that cannot be reused by deleting and recreating a registry row.
CREATE SEQUENCE public.site_registry_authority_epoch_seq
    AS BIGINT
    MINVALUE 1
    NO MAXVALUE
    START WITH 1
    INCREMENT BY 1
    NO CYCLE
    CACHE 1;

ALTER TABLE public.site_registry
    ADD COLUMN authority_epoch BIGINT;

UPDATE public.site_registry
SET authority_epoch = pg_catalog.nextval(
    'public.site_registry_authority_epoch_seq'::regclass
);

ALTER TABLE public.site_registry
    ALTER COLUMN authority_epoch SET NOT NULL,
    ADD CONSTRAINT site_registry_authority_epoch_positive
        CHECK (authority_epoch > 0),
    ADD CONSTRAINT site_registry_authority_epoch_unique
        UNIQUE (authority_epoch);

-- Deliberately do not OWN this sequence by the registry column: PostgreSQL's
-- `TRUNCATE ... RESTART IDENTITY` resets owned sequences and could otherwise
-- reuse an epoch while historical runbook rows survive.

CREATE OR REPLACE FUNCTION public.assign_site_registry_authority_epoch()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- Ignore any caller-supplied value. Only this owner-executed trigger
        -- may mint the durable authority token.
        NEW.authority_epoch := pg_catalog.nextval(
            'public.site_registry_authority_epoch_seq'::regclass
        );
        RETURN NEW;
    END IF;

    IF NEW.authority_epoch IS DISTINCT FROM OLD.authority_epoch THEN
        RAISE EXCEPTION 'site registry authority epoch is server-owned'
            USING ERRCODE = '55000';
    END IF;

    -- Active-state changes invalidate all existing work. Canonical-code
    -- changes also mint a new lifetime so rename-away/rename-back cannot
    -- resurrect an execution bound to the earlier name.
    IF NEW.active IS DISTINCT FROM OLD.active
       OR NEW.unlocode COLLATE "C" IS DISTINCT FROM OLD.unlocode COLLATE "C"
    THEN
        NEW.authority_epoch := pg_catalog.nextval(
            'public.site_registry_authority_epoch_seq'::regclass
        );
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_site_registry_authority_epoch
BEFORE INSERT OR UPDATE OF unlocode, active, authority_epoch
ON public.site_registry
FOR EACH ROW
EXECUTE FUNCTION public.assign_site_registry_authority_epoch();

ALTER TABLE public.site_registry
    ENABLE ALWAYS TRIGGER trg_site_registry_authority_epoch;

REVOKE ALL ON SEQUENCE public.site_registry_authority_epoch_seq FROM PUBLIC;
REVOKE ALL ON FUNCTION public.assign_site_registry_authority_epoch() FROM PUBLIC;

DO $$
BEGIN
    IF pg_catalog.to_regrole('ryuki_app_runtime') IS NOT NULL THEN
        EXECUTE 'REVOKE ALL ON SEQUENCE public.site_registry_authority_epoch_seq '
             || 'FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.assign_site_registry_authority_epoch() '
             || 'FROM ryuki_app_runtime';
    END IF;
END;
$$;

ALTER TABLE public.runbook_executions
    ADD COLUMN site_authority_epoch BIGINT,
    ADD CONSTRAINT runbook_executions_site_authority_epoch_positive
        CHECK (
            site_authority_epoch IS NULL
            OR site_authority_epoch > 0
        );

-- No historical row contains trustworthy creation-time epoch evidence. Reuse
-- the existing immutable quarantine classification rather than fabricating a
-- current binding that could authorize stale work. History remains readable;
-- every ordinary transition remains fail closed.
DROP TRIGGER IF EXISTS runbook_executions_enforce_invariants
ON public.runbook_executions;

UPDATE public.runbook_executions
SET invariant_state = 'Quarantined',
    invariant_reason = 'legacy-site-authority-epoch-unbound-restart-required'
WHERE site_authority_epoch IS NULL;

CREATE TRIGGER runbook_executions_enforce_invariants
BEFORE INSERT OR UPDATE ON public.runbook_executions
FOR EACH ROW
EXECUTE FUNCTION public.enforce_runbook_execution_invariants();

ALTER TABLE public.runbook_executions
    ADD CONSTRAINT runbook_executions_verified_site_authority_epoch
        CHECK (
            invariant_state <> 'Verified'
            OR site_authority_epoch IS NOT NULL
        );

-- Replace migration 208's active-only fence with an exact epoch relation.
-- Every Verified scalar binding must match the JSON evidence. Inserts and
-- forward transitions then lock the current active registry row at that exact
-- epoch. Failure and rollback remain available as protective terminalization,
-- but cannot rewrite or forge the captured epoch.
CREATE OR REPLACE FUNCTION public.enforce_runbook_active_site_authority()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.site_authority_epoch IS DISTINCT FROM OLD.site_authority_epoch
    THEN
        RAISE EXCEPTION 'runbook site authority epoch is immutable'
            USING ERRCODE = '55000';
    END IF;

    IF TG_OP = 'INSERT' AND NEW.invariant_state <> 'Verified' THEN
        RAISE EXCEPTION 'new runbook execution must have verified authority'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.invariant_state = 'Verified' THEN
        IF NEW.site_authority_epoch IS NULL
           OR pg_catalog.to_jsonb(NEW.site_authority_epoch)
                IS DISTINCT FROM NEW.execution_json->'site_authority_epoch'
        THEN
            RAISE EXCEPTION
                'verified runbook execution requires an exact embedded site authority epoch'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    -- Deactivation/recreation must not prevent an operator from stopping or
    -- unwinding work. The invariant trigger still rejects quarantined legacy
    -- rows, illegal status changes, and malformed execution snapshots.
    IF TG_OP = 'UPDATE' AND NEW.status IN ('failed', 'rolled-back') THEN
        RETURN NEW;
    END IF;

    IF NEW.invariant_state <> 'Verified' THEN
        RAISE EXCEPTION 'quarantined runbook execution must be restarted'
            USING ERRCODE = '55000';
    END IF;

    PERFORM 1
    FROM public.site_registry AS registry
    WHERE registry.unlocode COLLATE "C" = NEW.site COLLATE "C"
      AND registry.active = TRUE
      AND registry.authority_epoch = NEW.site_authority_epoch
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'runbook execution requires the exact current active site authority epoch'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS runbook_executions_active_site_authority
ON public.runbook_executions;

CREATE TRIGGER runbook_executions_active_site_authority
BEFORE INSERT OR UPDATE OF status, execution_json, site_authority_epoch
ON public.runbook_executions
FOR EACH ROW
EXECUTE FUNCTION public.enforce_runbook_active_site_authority();

ALTER TABLE public.runbook_executions
    ENABLE ALWAYS TRIGGER runbook_executions_active_site_authority;

REVOKE ALL ON FUNCTION public.enforce_runbook_active_site_authority() FROM PUBLIC;

DO $$
BEGIN
    IF pg_catalog.to_regrole('ryuki_app_runtime') IS NOT NULL THEN
        EXECUTE 'REVOKE ALL ON FUNCTION public.enforce_runbook_active_site_authority() '
             || 'FROM ryuki_app_runtime';
    END IF;
END;
$$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM public.runbook_executions AS execution
        WHERE execution.invariant_state = 'Verified'
          AND (
              execution.site_authority_epoch IS NULL
              OR pg_catalog.to_jsonb(execution.site_authority_epoch)
                    IS DISTINCT FROM
                    execution.execution_json->'site_authority_epoch'
              OR NOT EXISTS (
                  SELECT 1
                  FROM public.site_registry AS registry
                  WHERE registry.unlocode COLLATE "C" =
                        execution.site COLLATE "C"
                    AND registry.active = TRUE
                    AND registry.authority_epoch =
                        execution.site_authority_epoch
              )
          )
    ) THEN
        RAISE EXCEPTION
            'verified runbook execution remains without exact active site authority'
            USING ERRCODE = '55000';
    END IF;
END;
$$;

COMMENT ON COLUMN public.site_registry.authority_epoch IS
    'Server-minted non-reusable canonical-site lifetime/activation epoch.';
COMMENT ON COLUMN public.runbook_executions.site_authority_epoch IS
    'Immutable site_registry authority_epoch captured when the execution was created; NULL is quarantined legacy history.';
COMMENT ON FUNCTION public.enforce_runbook_active_site_authority() IS
    'Requires the exact captured active site epoch on creation and every forward runbook transition while preserving protective terminalization.';
