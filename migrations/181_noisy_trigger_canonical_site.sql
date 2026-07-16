-- 181_noisy_trigger_canonical_site.sql
--
-- Persist one server-derived site authority for noisy triggers.  A site code
-- matches only as a complete hostname token delimited by '.', '_' or '-'.
-- Zero active matches are quarantined.  If a hostname contains multiple exact
-- site tokens, the longest code wins with a lexical tie-break; there is no
-- implicit site fallback and no partial-substring guess.
--
-- Registry changes do not synchronously rewrite the whole noise table.  They
-- advance a singleton generation in O(1).  Every read requires the current
-- generation, so old classifications fail closed immediately.  A bounded,
-- resumable worker calls reconcile_noisy_trigger_sites() to repair at most 128
-- rows per transaction.  Transaction-scoped advisory locking serializes noisy
-- writes with active-registry changes and closes the insert/activation race.

CREATE TABLE noisy_trigger_site_authority (
    singleton                  BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    generation                 BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0),
    reconciliation_status      TEXT NOT NULL DEFAULT 'queued'
                               CHECK (reconciliation_status IN ('queued', 'running', 'idle')),
    reconciled_rows            BIGINT NOT NULL DEFAULT 0 CHECK (reconciled_rows >= 0),
    last_completed_generation  BIGINT NOT NULL DEFAULT 0
                               CHECK (
                                   last_completed_generation >= 0
                                   AND last_completed_generation <= generation
                               ),
    requested_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO noisy_trigger_site_authority (singleton)
VALUES (TRUE)
ON CONFLICT (singleton) DO NOTHING;

-- This row is the visibility fence for every canonical-site read.  Its
-- identity must never be removed/recreated and its generation must never move
-- backwards or jump: either a queue transition advances it by exactly one, or
-- a bounded reconciliation page updates progress without changing it.  These
-- guards also constrain schema-owner maintenance; the production application
-- role is separately reduced to SELECT-only below.
CREATE OR REPLACE FUNCTION guard_noisy_trigger_site_authority_update()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.singleton IS DISTINCT FROM OLD.singleton THEN
        RAISE EXCEPTION 'noisy-trigger site authority singleton identity is immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.generation > OLD.generation
       AND NEW.generation - OLD.generation = 1 THEN
        -- A legitimate generation advance is nested inside one of the
        -- site_registry statement triggers. A top-level UPDATE, or a direct
        -- call to the internal queue helper, reaches this guard at depth 1 and
        -- cannot mint a new visibility generation.
        IF pg_trigger_depth() < 2
           OR NEW.reconciliation_status <> 'queued'
           OR NEW.reconciled_rows <> 0
           OR NEW.last_completed_generation <> OLD.last_completed_generation THEN
            RAISE EXCEPTION 'noisy-trigger site authority generation advance must queue one exact transition'
                USING ERRCODE = '55000';
        END IF;
    ELSIF NEW.generation = OLD.generation THEN
        IF NEW.requested_at IS DISTINCT FROM OLD.requested_at
           OR NEW.reconciled_rows < OLD.reconciled_rows
           OR NEW.last_completed_generation < OLD.last_completed_generation
           OR NEW.last_completed_generation NOT IN (
               OLD.last_completed_generation,
               OLD.generation
           ) THEN
            RAISE EXCEPTION 'noisy-trigger site authority progress cannot be reset or forged'
                USING ERRCODE = '55000';
        END IF;
    ELSE
        RAISE EXCEPTION 'noisy-trigger site authority generation must be unchanged or advance by exactly one'
            USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_noisy_trigger_site_authority_guard_update
BEFORE UPDATE ON noisy_trigger_site_authority
FOR EACH ROW EXECUTE FUNCTION guard_noisy_trigger_site_authority_update();

CREATE OR REPLACE FUNCTION reject_noisy_trigger_site_authority_removal()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    RAISE EXCEPTION 'noisy-trigger site authority singleton cannot be removed or truncated'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER trg_noisy_trigger_site_authority_no_delete
BEFORE DELETE ON noisy_trigger_site_authority
FOR EACH ROW EXECUTE FUNCTION reject_noisy_trigger_site_authority_removal();

CREATE TRIGGER trg_noisy_trigger_site_authority_no_truncate
BEFORE TRUNCATE ON noisy_trigger_site_authority
FOR EACH STATEMENT EXECUTE FUNCTION reject_noisy_trigger_site_authority_removal();

ALTER TABLE noisy_triggers
    ADD COLUMN site TEXT,
    ADD COLUMN site_resolution TEXT NOT NULL DEFAULT 'quarantined',
    ADD COLUMN site_resolution_generation BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN site_resolved_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Delimiter-aware exact matching.  In particular, a short custom code such as
-- RA does not match "branch" or "application"; it matches only a complete RA
-- token such as srv-ra-app01.  Site codes may themselves contain delimiters,
-- so splitting the code into labels would be ambiguous; compare the literal
-- code and require a delimiter (or string edge) around the whole match.
CREATE OR REPLACE FUNCTION noisy_host_has_site_code(
    candidate_host TEXT,
    candidate_code TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog, public
AS $$
DECLARE
    host_value TEXT := lower(candidate_host);
    code_value TEXT := lower(candidate_code);
    host_length INTEGER := char_length(lower(candidate_host));
    code_length INTEGER := char_length(lower(candidate_code));
    search_from INTEGER := 1;
    relative_position INTEGER;
    match_position INTEGER;
BEGIN
    IF code_length = 0 OR code_length > host_length THEN
        RETURN FALSE;
    END IF;

    LOOP
        relative_position := strpos(substr(host_value, search_from), code_value);
        IF relative_position = 0 THEN
            RETURN FALSE;
        END IF;
        match_position := search_from + relative_position - 1;

        IF (match_position = 1
            OR substr(host_value, match_position - 1, 1) IN ('.', '_', '-'))
           AND (match_position + code_length > host_length
            OR substr(host_value, match_position + code_length, 1) IN ('.', '_', '-'))
        THEN
            RETURN TRUE;
        END IF;

        search_from := match_position + 1;
        IF search_from > host_length THEN
            RETURN FALSE;
        END IF;
    END LOOP;
END;
$$;

-- Multiple complete site tokens are resolved deterministically: longest code,
-- then lexical order.  Unlike the legacy rule, a shorter code embedded inside
-- a longer alphanumeric token is not a match at all.
CREATE OR REPLACE FUNCTION resolve_noisy_trigger_site(candidate_host TEXT)
RETURNS TEXT
LANGUAGE SQL
STABLE
SET search_path = pg_catalog, public
AS $$
    SELECT registry.unlocode
    FROM site_registry AS registry
    WHERE registry.active
      AND noisy_host_has_site_code(candidate_host, registry.unlocode)
    ORDER BY char_length(registry.unlocode) DESC, registry.unlocode ASC
    LIMIT 1
$$;

-- All statements that can change either side of the classification acquire
-- the same transaction lock before touching rows.  The lock is re-entrant for
-- the bounded reconciler and for transactions that create a site and then a
-- noisy row.
CREATE OR REPLACE FUNCTION lock_noisy_trigger_site_authority()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(
        hashtextextended('ryuki.noisy-trigger-site-authority', 0)
    );
    RETURN NULL;
END;
$$;

CREATE TRIGGER trg_noisy_trigger_site_authority_lock
BEFORE INSERT OR UPDATE OR DELETE
ON noisy_triggers
FOR EACH STATEMENT EXECUTE FUNCTION lock_noisy_trigger_site_authority();

CREATE TRIGGER trg_site_registry_noise_authority_lock
BEFORE INSERT OR DELETE OR UPDATE OF active, unlocode
ON site_registry
FOR EACH STATEMENT EXECUTE FUNCTION lock_noisy_trigger_site_authority();

CREATE OR REPLACE FUNCTION maintain_noisy_trigger_site()
RETURNS TRIGGER
LANGUAGE plpgsql
VOLATILE
SET search_path = pg_catalog, public
AS $$
DECLARE
    current_generation BIGINT;
BEGIN
    SELECT generation
    INTO STRICT current_generation
    FROM noisy_trigger_site_authority
    WHERE singleton;

    -- Ignore every caller-supplied authority field.  Host plus the active
    -- durable registry is the only accepted classification source.
    NEW.site := resolve_noisy_trigger_site(NEW.host);
    NEW.site_resolution := CASE
        WHEN NEW.site IS NULL THEN 'quarantined'
        ELSE 'active_registry'
    END;
    NEW.site_resolution_generation := current_generation;
    NEW.site_resolved_at := NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_noisy_trigger_canonical_site
BEFORE INSERT OR UPDATE OF host, site, site_resolution, site_resolution_generation
ON noisy_triggers
FOR EACH ROW EXECUTE FUNCTION maintain_noisy_trigger_site();

-- Advance the visibility generation once per registry statement when (and
-- only when) the set of active codes changes.  Old rows remain physically
-- intact but become invisible because every API query requires this generation.
CREATE OR REPLACE FUNCTION queue_noisy_trigger_site_reconciliation()
RETURNS VOID
LANGUAGE SQL
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    UPDATE noisy_trigger_site_authority
    SET generation = generation + 1,
        reconciliation_status = 'queued',
        reconciled_rows = 0,
        requested_at = NOW(),
        updated_at = NOW()
    WHERE singleton
$$;

CREATE OR REPLACE FUNCTION queue_noise_reconciliation_after_site_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM new_sites WHERE active) THEN
        PERFORM queue_noisy_trigger_site_reconciliation();
    END IF;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION queue_noise_reconciliation_after_site_update()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF EXISTS (
        (SELECT unlocode FROM old_sites WHERE active
         EXCEPT
         SELECT unlocode FROM new_sites WHERE active)
        UNION ALL
        (SELECT unlocode FROM new_sites WHERE active
         EXCEPT
         SELECT unlocode FROM old_sites WHERE active)
    ) THEN
        PERFORM queue_noisy_trigger_site_reconciliation();
    END IF;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION queue_noise_reconciliation_after_site_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM old_sites WHERE active) THEN
        PERFORM queue_noisy_trigger_site_reconciliation();
    END IF;
    RETURN NULL;
END;
$$;

-- TRUNCATE has no transition table and does not fire DELETE triggers. Acquire
-- the same authority lock directly and invalidate the cached classifications
-- before an active registry can be truncated transactionally.
CREATE OR REPLACE FUNCTION queue_noise_reconciliation_before_site_truncate()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(
        hashtextextended('ryuki.noisy-trigger-site-authority', 0)
    );
    IF EXISTS (SELECT 1 FROM site_registry WHERE active) THEN
        PERFORM queue_noisy_trigger_site_reconciliation();
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER trg_site_registry_queue_noise_insert
AFTER INSERT ON site_registry
REFERENCING NEW TABLE AS new_sites
FOR EACH STATEMENT EXECUTE FUNCTION queue_noise_reconciliation_after_site_insert();

CREATE TRIGGER trg_site_registry_queue_noise_update
AFTER UPDATE ON site_registry
REFERENCING OLD TABLE AS old_sites NEW TABLE AS new_sites
FOR EACH STATEMENT EXECUTE FUNCTION queue_noise_reconciliation_after_site_update();

CREATE TRIGGER trg_site_registry_queue_noise_delete
AFTER DELETE ON site_registry
REFERENCING OLD TABLE AS old_sites
FOR EACH STATEMENT EXECUTE FUNCTION queue_noise_reconciliation_after_site_delete();

CREATE TRIGGER trg_site_registry_queue_noise_truncate
BEFORE TRUNCATE ON site_registry
FOR EACH STATEMENT EXECUTE FUNCTION queue_noise_reconciliation_before_site_truncate();

-- Reconcile one hard-bounded page.  Updating `site` to itself deliberately
-- invokes the authoritative BEFORE ROW trigger, which recomputes site,
-- resolution and generation under the shared lock.  Selecting stale rows by
-- generation is itself the durable resume cursor: committed rows disappear
-- from the next page and interrupted pages remain eligible.
CREATE OR REPLACE FUNCTION reconcile_noisy_trigger_sites(batch_size INTEGER DEFAULT 128)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    current_generation BIGINT;
    repaired INTEGER;
    stale_remains BOOLEAN;
BEGIN
    IF batch_size IS NULL OR batch_size < 1 OR batch_size > 256 THEN
        RAISE EXCEPTION 'noise reconciliation batch_size must be between 1 and 256';
    END IF;

    PERFORM pg_advisory_xact_lock(
        hashtextextended('ryuki.noisy-trigger-site-authority', 0)
    );
    SELECT generation
    INTO STRICT current_generation
    FROM noisy_trigger_site_authority
    WHERE singleton
    FOR UPDATE;

    WITH batch AS MATERIALIZED (
        SELECT id
        FROM noisy_triggers
        WHERE site_resolution_generation < current_generation
        ORDER BY site_resolution_generation, id
        LIMIT batch_size
        FOR UPDATE SKIP LOCKED
    )
    UPDATE noisy_triggers AS noisy
    SET site = noisy.site
    FROM batch
    WHERE noisy.id = batch.id;
    GET DIAGNOSTICS repaired = ROW_COUNT;

    SELECT EXISTS (
        SELECT 1
        FROM noisy_triggers
        WHERE site_resolution_generation < current_generation
        LIMIT 1
    )
    INTO stale_remains;

    UPDATE noisy_trigger_site_authority
    SET reconciliation_status = CASE WHEN stale_remains THEN 'running' ELSE 'idle' END,
        reconciled_rows = reconciled_rows + repaired,
        last_completed_generation = CASE
            WHEN stale_remains THEN last_completed_generation
            ELSE current_generation
        END,
        updated_at = NOW()
    WHERE singleton;

    RETURN repaired;
END;
$$;

-- Default function privileges grant EXECUTE to PUBLIC.  Remove that ambient
-- path from every authority writer.  Production runtime receives only the
-- bounded reconciler; registry triggers invoke the queue functions internally.
REVOKE ALL ON FUNCTION queue_noisy_trigger_site_reconciliation() FROM PUBLIC;
REVOKE ALL ON FUNCTION queue_noise_reconciliation_after_site_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION queue_noise_reconciliation_after_site_update() FROM PUBLIC;
REVOKE ALL ON FUNCTION queue_noise_reconciliation_after_site_delete() FROM PUBLIC;
REVOKE ALL ON FUNCTION queue_noise_reconciliation_before_site_truncate() FROM PUBLIC;
REVOKE ALL ON FUNCTION reconcile_noisy_trigger_sites(INTEGER) FROM PUBLIC;

-- Local-development databases do not necessarily provision the stable
-- production role.  When it exists, correct the broad schema default grants
-- immediately; migration postflight independently reasserts the same exact
-- table/function policy for every release.
DO $privileges$
BEGIN
    IF pg_catalog.to_regrole('ryuki_app_runtime') IS NOT NULL THEN
        EXECUTE 'REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN '
             || 'ON TABLE public.noisy_trigger_site_authority FROM ryuki_app_runtime';
        EXECUTE 'GRANT SELECT ON TABLE public.noisy_trigger_site_authority TO ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.queue_noisy_trigger_site_reconciliation() '
             || 'FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.queue_noise_reconciliation_after_site_insert() '
             || 'FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.queue_noise_reconciliation_after_site_update() '
             || 'FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.queue_noise_reconciliation_after_site_delete() '
             || 'FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.queue_noise_reconciliation_before_site_truncate() '
             || 'FROM ryuki_app_runtime';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.reconcile_noisy_trigger_sites(INTEGER) '
             || 'TO ryuki_app_runtime';
    END IF;
END;
$privileges$;

-- NOT VALID avoids a table-validation scan in this transactional migration;
-- PostgreSQL still enforces each constraint for all new/updated rows.  Legacy
-- rows start at generation 0 and remain fail-closed until the bounded worker
-- touches them.
ALTER TABLE noisy_triggers
    ADD CONSTRAINT noisy_triggers_site_resolution_check
        CHECK (site_resolution IN ('active_registry', 'quarantined')) NOT VALID,
    ADD CONSTRAINT noisy_triggers_site_resolution_shape_check
        CHECK (
            (site IS NULL AND site_resolution = 'quarantined')
            OR
            (site IS NOT NULL AND site_resolution = 'active_registry')
        ) NOT VALID,
    ADD CONSTRAINT noisy_triggers_site_resolution_generation_check
        CHECK (site_resolution_generation >= 0) NOT VALID;

-- Deliberately do not add a physical FK from the cached classification to the
-- registry. A registry delete or code rename must be able to commit its O(1)
-- generation fence before the bounded worker rewrites stale cached values. A
-- restrictive FK would either block that authority change or force an
-- unbounded synchronous cascade. Current-generation rows are instead derived
-- exclusively by the trigger from an active registry row; stale generations
-- are invisible to every API query.

-- SQLx runs migrations transactionally, so PostgreSQL cannot use CONCURRENTLY
-- here.  Keep the set minimal and align every read/reconcile key exactly.  The
-- generation prefix lets stale rows be skipped before site/status ordering.
CREATE INDEX idx_noisy_triggers_site_report
    ON noisy_triggers (site_resolution_generation, site)
    WHERE site IS NOT NULL;

CREATE INDEX idx_noisy_triggers_site_event_count
    ON noisy_triggers (
        site_resolution_generation, site, event_count_last_24h DESC, id DESC
    )
    WHERE site IS NOT NULL;

CREATE INDEX idx_noisy_triggers_site_flapping
    ON noisy_triggers (
        site_resolution_generation, site, event_count_last_24h DESC, id DESC
    )
    WHERE flapping AND site IS NOT NULL;

CREATE INDEX idx_noisy_triggers_site_suppressed_page
    ON noisy_triggers (
        site_resolution_generation, site, updated_at DESC, id DESC
    )
    WHERE status = 'Suppressed' AND site IS NOT NULL;

CREATE INDEX idx_noisy_triggers_suppressed_page
    ON noisy_triggers (site_resolution_generation, updated_at DESC, id DESC)
    INCLUDE (site)
    WHERE status = 'Suppressed' AND site IS NOT NULL;

CREATE INDEX idx_noisy_triggers_stale_generation
    ON noisy_triggers (site_resolution_generation, id);
