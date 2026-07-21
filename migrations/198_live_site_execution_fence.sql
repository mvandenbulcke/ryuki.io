-- 198_live_site_execution_fence.sql
--
-- Bind every live mutation to one exact, fresh site-health authority epoch.
-- The prior HTTP precheck was outside the grant-mint transaction and a
-- Pending grant could later be leased after the site degraded.  These database
-- primitives are consumed at grant mint, lease, acknowledgement, renewal, and
-- first result acceptance so every decisive transition observes one canonical
-- authority relation.

-- Five minutes is the repository security-limit profile's registered
-- `limit:live-site-status.maximum-age`.  Keep the value in one SQL symbol so
-- triggers and transaction predicates cannot silently diverge.
CREATE OR REPLACE FUNCTION ryuki_live_site_status_max_age_seconds()
RETURNS BIGINT
LANGUAGE SQL
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public
AS $$
    SELECT 300::BIGINT
$$;

ALTER TABLE site_status
    ADD COLUMN authority_epoch BIGINT NOT NULL DEFAULT 1;

ALTER TABLE site_status
    ADD CONSTRAINT site_status_authority_epoch_positive
    CHECK (authority_epoch > 0);

-- New status rows must pass through an explicit recovery observation before
-- they can authorize writes.  Existing rows retain their historical state but
-- become subject to the freshness cutoff immediately.
ALTER TABLE site_status
    ALTER COLUMN state SET DEFAULT 'recovering';

ALTER TABLE site_status
    ADD CONSTRAINT site_status_canonical_site_fk
    FOREIGN KEY (site) REFERENCES site_registry(unlocode)
    ON UPDATE RESTRICT ON DELETE RESTRICT;

ALTER TABLE component_status
    ADD CONSTRAINT component_status_one_adapter_per_site
    UNIQUE (site, adapter_name);

-- Existing open live work has no truthful observation epoch.  Never invent
-- one during migration: operators must drain or explicitly reconcile it before
-- this cutover.  Terminal history remains readable with a NULL binding.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM agent_jobs
        WHERE mode IN ('LiveApply', 'LiveDestroy')
          AND status IN ('Pending', 'Leased', 'Running')
    ) THEN
        RAISE EXCEPTION
            'open live jobs must be drained or reconciled before migration 198'
            USING ERRCODE = '55000';
    END IF;
END;
$$;

ALTER TABLE agent_jobs
    ADD COLUMN site_status_authority_epoch BIGINT;

ALTER TABLE agent_jobs
    ADD CONSTRAINT agent_jobs_site_status_authority_epoch_positive
    CHECK (
        site_status_authority_epoch IS NULL
        OR site_status_authority_epoch > 0
    );

ALTER TABLE agent_jobs
    ADD CONSTRAINT agent_jobs_open_live_site_fence_required
    CHECK (
        mode NOT IN ('LiveApply', 'LiveDestroy')
        OR status NOT IN ('Pending', 'Leased', 'Running')
        OR site_status_authority_epoch IS NOT NULL
    );

-- The mint-time epoch is execution authority, not mutable queue state.  Extend
-- migration 196's owned-column trigger immediately after adding the column so
-- a runtime UPDATE can never retarget an existing live job to a newer epoch.
DROP TRIGGER trg_agent_jobs_request_resource_version_owned ON agent_jobs;

CREATE TRIGGER trg_agent_jobs_request_resource_version_owned
BEFORE UPDATE OF
    id,
    request_id,
    platform,
    spec,
    mode,
    live_context,
    site_status_authority_epoch,
    origin,
    step_scoped,
    request_resource_version
ON agent_jobs
FOR EACH ROW
EXECUTE FUNCTION reject_agent_job_request_binding_update();

ALTER TABLE agent_jobs
    ENABLE ALWAYS TRIGGER trg_agent_jobs_request_resource_version_owned;

CREATE OR REPLACE FUNCTION ryuki_guard_site_status_authority_epoch()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    observed_now TIMESTAMPTZ := statement_timestamp();
    old_was_fresh BOOLEAN;
    new_is_fresh BOOLEAN;
    authority_changed BOOLEAN;
BEGIN
    IF NEW.last_check > observed_now THEN
        RAISE EXCEPTION 'site status observation cannot be future-dated'
            USING ERRCODE = '23514';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.authority_epoch <= 0 THEN
            RAISE EXCEPTION 'site status authority epoch must be positive'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.state IS DISTINCT FROM 'recovering' THEN
            RAISE EXCEPTION 'new site status authority must begin in recovery'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.site IS DISTINCT FROM OLD.site THEN
        RAISE EXCEPTION 'site status identity is immutable'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.authority_epoch < OLD.authority_epoch
       OR NEW.authority_epoch > OLD.authority_epoch + 1 THEN
        RAISE EXCEPTION 'site status authority epoch must be unchanged or advance by one'
            USING ERRCODE = '23514';
    END IF;

    old_was_fresh :=
        OLD.last_check <= observed_now
        AND OLD.last_check > observed_now - make_interval(
            secs => public.ryuki_live_site_status_max_age_seconds()
        );
    new_is_fresh :=
        NEW.last_check <= observed_now
        AND NEW.last_check > observed_now - make_interval(
            secs => public.ryuki_live_site_status_max_age_seconds()
        );
    authority_changed :=
        ROW(NEW.state, NEW.api_status, NEW.db_status)
        IS DISTINCT FROM
        ROW(OLD.state, OLD.api_status, OLD.db_status);

    -- A timely same-state observation is a lease refresh, not a new authority
    -- epoch.  Every unsafe/recovery transition and every stale-to-fresh
    -- recovery advances the epoch so an older grant can never revive.
    IF NEW.authority_epoch = OLD.authority_epoch
       AND (authority_changed OR (NOT old_was_fresh AND new_is_fresh)) THEN
        NEW.authority_epoch := OLD.authority_epoch + 1;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_site_status_authority_epoch
BEFORE INSERT OR UPDATE ON site_status
FOR EACH ROW
EXECUTE FUNCTION ryuki_guard_site_status_authority_epoch();

ALTER TABLE site_status
    ENABLE ALWAYS TRIGGER trg_site_status_authority_epoch;

CREATE OR REPLACE FUNCTION ryuki_bump_site_epoch_after_registry_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    IF NEW.active IS DISTINCT FROM OLD.active THEN
        UPDATE public.site_status
        SET authority_epoch = authority_epoch + 1,
            updated_at = statement_timestamp()
        WHERE site = NEW.unlocode;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_site_registry_live_execution_epoch
AFTER UPDATE OF active ON site_registry
FOR EACH ROW
EXECUTE FUNCTION ryuki_bump_site_epoch_after_registry_change();

ALTER TABLE site_registry
    ENABLE ALWAYS TRIGGER trg_site_registry_live_execution_epoch;

CREATE OR REPLACE FUNCTION ryuki_guard_component_status_observation()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.last_check > statement_timestamp() THEN
        RAISE EXCEPTION 'component status observation cannot be future-dated'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_component_status_observation
BEFORE INSERT OR UPDATE ON component_status
FOR EACH ROW
EXECUTE FUNCTION ryuki_guard_component_status_observation();

ALTER TABLE component_status
    ENABLE ALWAYS TRIGGER trg_component_status_observation;

CREATE OR REPLACE FUNCTION ryuki_bump_site_epoch_after_component_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    observed_now TIMESTAMPTZ := statement_timestamp();
    old_relevant BOOLEAN := FALSE;
    new_relevant BOOLEAN := FALSE;
    old_was_fresh BOOLEAN := FALSE;
    new_is_fresh BOOLEAN := FALSE;
    old_site TEXT;
    new_site TEXT;
    old_requires_bump BOOLEAN := FALSE;
    new_requires_bump BOOLEAN := FALSE;
    affected_site TEXT;
    bump_epoch BOOLEAN;
BEGIN
    -- Keep INSERT/DELETE operation handling disjoint.  OLD and NEW are
    -- unassigned records for those operations respectively, so correctness
    -- must not depend on boolean-expression evaluation order short-circuiting
    -- an invalid record-field access.
    IF TG_OP = 'DELETE' THEN
        IF OLD.adapter_name = 'vmware' THEN
            UPDATE public.site_status
            SET authority_epoch = authority_epoch + 1,
                updated_at = observed_now
            WHERE site = OLD.site;
        END IF;
        RETURN OLD;
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.adapter_name = 'vmware' THEN
            UPDATE public.site_status
            SET authority_epoch = authority_epoch + 1,
                updated_at = observed_now
            WHERE site = NEW.site;
        END IF;
        RETURN NEW;
    END IF;

    old_relevant := OLD.adapter_name = 'vmware';
    old_site := OLD.site;
    old_was_fresh :=
        OLD.last_check <= observed_now
        AND OLD.last_check > observed_now - make_interval(
            secs => public.ryuki_live_site_status_max_age_seconds()
        );
    new_relevant := NEW.adapter_name = 'vmware';
    new_site := NEW.site;
    new_is_fresh :=
        NEW.last_check <= observed_now
        AND NEW.last_check > observed_now - make_interval(
            secs => public.ryuki_live_site_status_max_age_seconds()
        );

    old_requires_bump := old_relevant AND (
        NOT new_relevant
        OR OLD.site IS DISTINCT FROM NEW.site
        OR OLD.status IS DISTINCT FROM NEW.status
        OR (NOT old_was_fresh AND new_is_fresh)
    );
    new_requires_bump := new_relevant AND (
        NOT old_relevant
        OR OLD.site IS DISTINCT FROM NEW.site
    );

    -- A same-state VMware observation refresh preserves the epoch, but it is
    -- still an authority write and must serialize on the same site-status row
    -- used by fence acquisition.  Multi-site moves lock in canonical site
    -- order so two opposing updates cannot introduce an old-site/new-site
    -- lock inversion.
    FOR affected_site, bump_epoch IN
        SELECT candidate.site, bool_or(candidate.requires_bump)
        FROM (
            VALUES
                (old_site, old_relevant, old_requires_bump),
                (new_site, new_relevant, new_requires_bump)
        ) AS candidate(site, relevant, requires_bump)
        WHERE candidate.relevant
        GROUP BY candidate.site
        ORDER BY candidate.site
    LOOP
        IF bump_epoch THEN
            UPDATE public.site_status
            SET authority_epoch = authority_epoch + 1,
                updated_at = observed_now
            WHERE site = affected_site;
        ELSE
            PERFORM 1
            FROM public.site_status
            WHERE site = affected_site
            FOR NO KEY UPDATE;
        END IF;
    END LOOP;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_component_status_live_execution_epoch
AFTER INSERT OR UPDATE OR DELETE ON component_status
FOR EACH ROW
EXECUTE FUNCTION ryuki_bump_site_epoch_after_component_change();

ALTER TABLE component_status
    ENABLE ALWAYS TRIGGER trg_component_status_live_execution_epoch;

-- TRUNCATE does not fire row DELETE triggers and therefore cannot participate
-- in the per-site mutex protocol.  Reject it; bounded row deletes remain
-- available and advance the affected VMware site's epoch transactionally.
CREATE OR REPLACE FUNCTION ryuki_reject_component_status_truncate()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    RAISE EXCEPTION 'component status authority cannot be truncated; delete rows explicitly'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER trg_component_status_no_truncate
BEFORE TRUNCATE ON component_status
FOR EACH STATEMENT
EXECUTE FUNCTION ryuki_reject_component_status_truncate();

ALTER TABLE component_status
    ENABLE ALWAYS TRIGGER trg_component_status_no_truncate;

CREATE OR REPLACE FUNCTION ryuki_reject_site_status_removal()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    RAISE EXCEPTION 'site status authority rows are durable; deactivate the site instead'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER trg_site_status_no_delete
BEFORE DELETE ON site_status
FOR EACH ROW
EXECUTE FUNCTION ryuki_reject_site_status_removal();

CREATE TRIGGER trg_site_status_no_truncate
BEFORE TRUNCATE ON site_status
FOR EACH STATEMENT
EXECUTE FUNCTION ryuki_reject_site_status_removal();

ALTER TABLE site_status ENABLE ALWAYS TRIGGER trg_site_status_no_delete;
ALTER TABLE site_status ENABLE ALWAYS TRIGGER trg_site_status_no_truncate;

-- Return the exact epoch while taking a share lock on the site's one mutex
-- row.  FOR KEY SHARE is insufficient because it permits non-key UPDATEs to
-- health and epoch columns.  Registry and VMware writers update their base row
-- first and then acquire/bump this same site-status row before commit; reading
-- them through MVCC after locking the mutex therefore serializes the fence
-- before an in-flight writer without waiting on its base-row lock.  Taking
-- locks on all three rows here would invert that writer order and deadlock.
-- NULL is the only projection for missing, inactive, unknown, stale,
-- future-dated, recovering, degraded, or dependency-down state.
CREATE OR REPLACE FUNCTION ryuki_acquire_live_site_execution_epoch(
    requested_site TEXT
)
RETURNS BIGINT
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    registry_active BOOLEAN;
    component_health TEXT;
    component_last_check TIMESTAMPTZ;
    site_health TEXT;
    site_api_health TEXT;
    site_db_health TEXT;
    site_last_check TIMESTAMPTZ;
    selected_epoch BIGINT;
    observed_now TIMESTAMPTZ;
BEGIN
    SELECT status.state,
           status.api_status,
           status.db_status,
           status.last_check,
           status.authority_epoch
    INTO site_health,
         site_api_health,
         site_db_health,
         site_last_check,
         selected_epoch
    FROM public.site_status AS status
    WHERE status.site = requested_site
    FOR SHARE;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT registry.active
    INTO registry_active
    FROM public.site_registry AS registry
    WHERE registry.unlocode = requested_site;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT component.status, component.last_check
    INTO component_health, component_last_check
    FROM public.component_status AS component
    WHERE component.site = requested_site
      AND component.adapter_name = 'vmware';
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    -- Evaluate freshness after every successful-path lock is held.  A fence
    -- that waited behind an authority transition must not reuse the SQL
    -- statement's older start timestamp to accept an observation past its TTL.
    observed_now := clock_timestamp();

    IF registry_active IS DISTINCT FROM TRUE
       OR site_health IS DISTINCT FROM 'healthy'
       OR site_api_health IS DISTINCT FROM 'up'
       OR site_db_health IS DISTINCT FROM 'up'
       OR site_last_check > observed_now
       OR site_last_check <= observed_now - make_interval(
           secs => public.ryuki_live_site_status_max_age_seconds()
       )
       OR component_health IS DISTINCT FROM 'up'
       OR component_last_check > observed_now
       OR component_last_check <= observed_now - make_interval(
           secs => public.ryuki_live_site_status_max_age_seconds()
       ) THEN
        RETURN NULL;
    END IF;

    RETURN selected_epoch;
END;
$$;

-- Persist only the exact epoch supplied by a caller that already acquired the
-- canonical transaction fence.  This is a verifier, never an auto-populator:
-- direct writers and future alternate mint paths cannot create executable
-- live work by omitting or guessing the authority binding.  Terminal history
-- is deliberately outside the admission boundary and may retain NULL.  A
-- terminal live row can accept late evidence but can never be resurrected;
-- retrying a mutation requires a newly reviewed job and a newly minted fence.
CREATE OR REPLACE FUNCTION ryuki_enforce_agent_job_live_site_fence_persistence()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    current_epoch BIGINT;
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.mode IN ('LiveApply', 'LiveDestroy')
       AND OLD.status NOT IN ('Pending', 'Leased', 'Running')
       AND NEW.status IN ('Pending', 'Leased', 'Running') THEN
        RAISE EXCEPTION 'terminal live jobs cannot be reopened; mint a new execution grant'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.mode IN ('LiveApply', 'LiveDestroy')
       AND NEW.status IN ('Pending', 'Leased', 'Running') THEN
        IF NEW.site_status_authority_epoch IS NULL THEN
            RAISE EXCEPTION 'open live job requires a supplied site execution authority epoch'
                USING ERRCODE = '23514';
        END IF;

        current_epoch := public.ryuki_acquire_live_site_execution_epoch(NEW.platform);
        IF current_epoch IS NULL
           OR NEW.site_status_authority_epoch IS DISTINCT FROM current_epoch THEN
            RAISE EXCEPTION 'open live job site execution authority is unavailable or stale'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_agent_jobs_live_site_fence_persistence
BEFORE INSERT OR UPDATE OF status ON agent_jobs
FOR EACH ROW
EXECUTE FUNCTION ryuki_enforce_agent_job_live_site_fence_persistence();

ALTER TABLE agent_jobs
    ENABLE ALWAYS TRIGGER trg_agent_jobs_live_site_fence_persistence;

COMMENT ON FUNCTION ryuki_live_site_status_max_age_seconds() IS
    'Registered security limit limit:live-site-status.maximum-age.';
COMMENT ON FUNCTION ryuki_acquire_live_site_execution_epoch(TEXT) IS
    'Transaction-bound live-mutation fence; returns NULL unless the canonical site and VMware authority are exact-safe and fresh.';
COMMENT ON COLUMN site_status.authority_epoch IS
    'Monotonic live-execution authority epoch; unsafe/recovery transitions invalidate older grants.';
COMMENT ON COLUMN agent_jobs.site_status_authority_epoch IS
    'Exact site-status authority epoch current when a live mutation grant was minted.';

-- Routine EXECUTE defaults to PUBLIC.  The TTL helper and trigger functions
-- are owner-internal; SECURITY DEFINER is limited to the helpers that must
-- invoke private fence primitives or perform the cross-table epoch bump.  The
-- serving role receives exactly the read-and-lock acquisition entry point.
REVOKE ALL ON FUNCTION ryuki_live_site_status_max_age_seconds() FROM PUBLIC;
REVOKE ALL ON FUNCTION ryuki_guard_site_status_authority_epoch() FROM PUBLIC;
REVOKE ALL ON FUNCTION ryuki_bump_site_epoch_after_registry_change() FROM PUBLIC;
REVOKE ALL ON FUNCTION ryuki_guard_component_status_observation() FROM PUBLIC;
REVOKE ALL ON FUNCTION ryuki_bump_site_epoch_after_component_change() FROM PUBLIC;
REVOKE ALL ON FUNCTION ryuki_reject_component_status_truncate() FROM PUBLIC;
REVOKE ALL ON FUNCTION ryuki_reject_site_status_removal() FROM PUBLIC;
REVOKE ALL ON FUNCTION ryuki_acquire_live_site_execution_epoch(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION ryuki_enforce_agent_job_live_site_fence_persistence() FROM PUBLIC;

DO $privileges$
BEGIN
    IF pg_catalog.to_regrole('ryuki_app_runtime') IS NOT NULL THEN
        EXECUTE 'REVOKE ALL ON FUNCTION '
             || 'public.ryuki_live_site_status_max_age_seconds() '
             || 'FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION '
             || 'public.ryuki_guard_site_status_authority_epoch() '
             || 'FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION '
             || 'public.ryuki_bump_site_epoch_after_registry_change() '
             || 'FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION '
             || 'public.ryuki_guard_component_status_observation() '
             || 'FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION '
             || 'public.ryuki_bump_site_epoch_after_component_change() '
             || 'FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION '
             || 'public.ryuki_reject_component_status_truncate() '
             || 'FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION '
             || 'public.ryuki_reject_site_status_removal() '
             || 'FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION '
             || 'public.ryuki_acquire_live_site_execution_epoch(TEXT) '
             || 'FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION '
             || 'public.ryuki_enforce_agent_job_live_site_fence_persistence() '
             || 'FROM ryuki_app_runtime';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
             || 'public.ryuki_acquire_live_site_execution_epoch(TEXT) '
             || 'TO ryuki_app_runtime';
    END IF;
END;
$privileges$;
