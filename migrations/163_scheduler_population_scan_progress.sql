-- 163_scheduler_population_scan_progress.sql
--
-- Bound the restore, golden-image, and managed-secret population schedulers.
-- Each population has a database-owned immutable sequence in a compact sidecar
-- table.  A cycle fixes both a high-water sequence and a database-clock cutoff,
-- then commits one raw keyset page plus its queue effects and cursor movement.
-- Rows allocated after the high-water wait for the next cycle.  A lower sequence
-- that commits late is recovered after the cursor resets; it is delayed, not lost.
--
-- Rolling-version fence:
--   * the ACCESS EXCLUSIVE schedules lock drains every pre-migration scheduler
--     transaction before any job kind is rewritten;
--   * physical v2 job kinds are unknown to old binaries, so they cannot execute
--     the legacy population-wide branches after this migration commits;
--   * old names are rejected durably; and
--   * an old binary that tries to record "skipped" and advance a v2 row is
--     rejected by the transaction-local protocol guard, rolling its tick back.
-- Required rollout remains drain -> migration -> v2 binary.  The v2 binary also
-- rejects v1 admission, so an accidental binary-first start fails closed rather
-- than treating old population work as an unsupported job and advancing it.
--
-- DDL/capacity posture:
--   * the transaction keeps a 30-second lock timeout throughout instead of
--     overriding the dedicated runner with an unbounded wait; deployers must
--     drain scheduler jobs/writers and retry in a reviewed window;
--   * the migration emits the exact source-relation footprint before backfill;
--   * sidecars avoid rewriting the three base tables, but their backfill and the
--     compact restore lookup indexes still require measured free-space/WAL headroom.
-- This remains intentionally offline DDL.  Do not treat it as an online rollout.

SET LOCAL lock_timeout = '30s';
LOCK TABLE schedules, restore_requests, golden_images, managed_secrets
    IN ACCESS EXCLUSIVE MODE;

DO $$
DECLARE
    source_bytes BIGINT;
BEGIN
    SELECT COALESCE(SUM(pg_total_relation_size(relid)), 0)
      INTO source_bytes
      FROM unnest(
          ARRAY[
              'restore_requests'::regclass,
              'golden_images'::regclass,
              'managed_secrets'::regclass
          ]
      ) AS source_relations(relid);
    RAISE NOTICE
        'scheduler population migration source footprint: % bytes; verify sidecar/index/WAL headroom before production execution',
        source_bytes;
END;
$$;

-- Version the physical job kinds so a drained old binary sees unknown work and
-- cannot re-enter the vulnerable branches.  Logical operator-facing behavior is
-- unchanged; only the persisted dispatcher protocol is versioned.
CREATE TABLE scheduler_protocol_versions (
    component        TEXT PRIMARY KEY,
    protocol_version SMALLINT NOT NULL CHECK (protocol_version > 0),
    installed_at     TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO scheduler_protocol_versions (component, protocol_version)
VALUES ('population_scan', 2);

UPDATE schedules
   SET job_kind = CASE job_kind
       WHEN 'restore_overdue_scan' THEN 'restore_overdue_scan_v2'
       WHEN 'golden_image_stale_scan' THEN 'golden_image_stale_scan_v2'
       WHEN 'secret_rotation_due_scan' THEN 'secret_rotation_due_scan_v2'
       ELSE job_kind
   END,
       updated_at = clock_timestamp()
 WHERE job_kind IN (
     'restore_overdue_scan',
     'golden_image_stale_scan',
     'secret_rotation_due_scan'
 );

ALTER TABLE schedules
    ADD CONSTRAINT schedules_population_scan_protocol_v2
    CHECK (job_kind NOT IN (
        'restore_overdue_scan',
        'golden_image_stale_scan',
        'secret_rotation_due_scan'
    ));

CREATE FUNCTION enforce_population_schedule_protocol_v2()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF current_setting('ryuki.scheduler_population_protocol', true)
           IS DISTINCT FROM '2' THEN
        RAISE EXCEPTION
            'population scheduler protocol v2 is required to advance schedule %',
            OLD.id
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER schedules_population_protocol_v2_guard
BEFORE UPDATE OF last_run_at, next_run_at ON schedules
FOR EACH ROW
WHEN (OLD.job_kind IN (
          'restore_overdue_scan_v2',
          'golden_image_stale_scan_v2',
          'secret_rotation_due_scan_v2'
      ) OR NEW.job_kind IN (
          'restore_overdue_scan_v2',
          'golden_image_stale_scan_v2',
          'secret_rotation_due_scan_v2'
      ))
EXECUTE FUNCTION enforce_population_schedule_protocol_v2();

-- Golden images and managed secrets already have durable primary keys.  Compact
-- sidecars assign opaque monotonic scheduler cursors without rewriting either
-- base table.  Foreign-key cascades remove/update mappings atomically;
-- AFTER INSERT triggers admit every legacy/direct writer into the population.
CREATE TABLE golden_image_scheduler_population (
    scan_seq BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    image_id UUID NOT NULL UNIQUE
        REFERENCES golden_images (id) ON UPDATE CASCADE ON DELETE CASCADE
);

INSERT INTO golden_image_scheduler_population (image_id)
SELECT id FROM golden_images ORDER BY id;

CREATE FUNCTION sync_golden_image_scheduler_population()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO golden_image_scheduler_population (image_id)
    VALUES (NEW.id)
    ON CONFLICT (image_id) DO NOTHING;
    RETURN NULL;
END;
$$;

CREATE TRIGGER golden_images_scheduler_population_insert
AFTER INSERT ON golden_images
FOR EACH ROW
EXECUTE FUNCTION sync_golden_image_scheduler_population();

CREATE TABLE managed_secret_scheduler_population (
    scan_seq BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    secret_id TEXT NOT NULL UNIQUE
        REFERENCES managed_secrets (id) ON UPDATE CASCADE ON DELETE CASCADE
);

INSERT INTO managed_secret_scheduler_population (secret_id)
SELECT id FROM managed_secrets ORDER BY id;

CREATE FUNCTION sync_managed_secret_scheduler_population()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO managed_secret_scheduler_population (secret_id)
    VALUES (NEW.id)
    ON CONFLICT (secret_id) DO NOTHING;
    RETURN NULL;
END;
$$;

CREATE TRIGGER managed_secrets_scheduler_population_insert
AFTER INSERT ON managed_secrets
FOR EACH ROW
EXECUTE FUNCTION sync_managed_secret_scheduler_population();

-- Restore scheduling needs one row per exact source/site/environment authority
-- tuple, not one row per request.  None of those legacy TEXT values is used as a
-- btree key: an oversized value can exceed PostgreSQL's index-tuple limit.  A
-- compact fingerprint plus a collision slot is unique, while every lookup also
-- compares all original values; even a real fingerprint collision therefore
-- remains two distinct authority tuples.
CREATE TABLE restore_scheduler_system_summary (
    scan_seq             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_ci_key        TEXT NOT NULL,
    target_site          TEXT NOT NULL,
    target_environment   TEXT NOT NULL,
    source_fingerprint   TEXT GENERATED ALWAYS AS (
        md5(source_ci_key) || md5(target_site) || md5(target_environment)
    ) STORED,
    collision_slot       INTEGER NOT NULL CHECK (collision_slot >= 0),
    last_successful_test TIMESTAMPTZ,
    successful_test_count BIGINT NOT NULL CHECK (successful_test_count >= 0),
    total_requests       BIGINT NOT NULL CHECK (total_requests > 0),
    latest_status        TEXT NOT NULL,
    latest_updated_at    TIMESTAMPTZ NOT NULL,
    latest_created_at    TIMESTAMPTZ NOT NULL,
    latest_request_id    UUID NOT NULL,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (source_fingerprint, collision_slot),
    CHECK (successful_test_count <= total_requests)
);

-- Compact exact-key lookup for summary maintenance.  The original text remains
-- an equality recheck, so md5 is an index accelerator rather than an identity.
CREATE INDEX idx_restore_requests_scheduler_source_latest
    ON restore_requests
       ((md5(source_ci_key)), (md5(target_site)), (md5(target_environment)),
        updated_at DESC, created_at DESC, id DESC);

CREATE INDEX idx_restore_requests_scheduler_success_latest
    ON restore_requests
       ((md5(source_ci_key)), (md5(target_site)), (md5(target_environment)),
        updated_at DESC, created_at DESC, id DESC)
    WHERE status IN ('Verified', 'Completed');

WITH stats AS (
    SELECT source_ci_key COLLATE "C" AS source_ci_key,
           target_site COLLATE "C" AS target_site,
           target_environment COLLATE "C" AS target_environment,
           MAX(updated_at) FILTER (
               WHERE status IN ('Verified', 'Completed')
           ) AS last_successful_test,
           COUNT(*) FILTER (
               WHERE status IN ('Verified', 'Completed')
           ) AS successful_test_count,
           COUNT(*) AS total_requests
      FROM restore_requests
     GROUP BY source_ci_key COLLATE "C",
              target_site COLLATE "C",
              target_environment COLLATE "C"
),
latest AS (
    SELECT DISTINCT ON (
               source_ci_key COLLATE "C",
               target_site COLLATE "C",
               target_environment COLLATE "C"
           )
           source_ci_key COLLATE "C" AS source_ci_key,
           target_site COLLATE "C" AS target_site,
           target_environment COLLATE "C" AS target_environment,
           status AS latest_status,
           updated_at AS latest_updated_at,
           created_at AS latest_created_at,
           id AS latest_request_id
      FROM restore_requests
     ORDER BY source_ci_key COLLATE "C",
              target_site COLLATE "C",
              target_environment COLLATE "C",
              updated_at DESC, created_at DESC, id DESC
),
prepared AS (
    SELECT stats.*,
           latest.latest_status,
           latest.latest_updated_at,
           latest.latest_created_at,
           latest.latest_request_id,
           ROW_NUMBER() OVER (
               PARTITION BY md5(stats.source_ci_key) ||
                            md5(stats.target_site) ||
                            md5(stats.target_environment)
               ORDER BY stats.source_ci_key,
                        stats.target_site,
                        stats.target_environment
           ) - 1 AS collision_slot
      FROM stats
      JOIN latest USING (source_ci_key, target_site, target_environment)
)
INSERT INTO restore_scheduler_system_summary (
    source_ci_key,
    target_site,
    target_environment,
    collision_slot,
    last_successful_test,
    successful_test_count,
    total_requests,
    latest_status,
    latest_updated_at,
    latest_created_at,
    latest_request_id
)
SELECT source_ci_key,
       target_site,
       target_environment,
       collision_slot::integer,
       last_successful_test,
       successful_test_count,
       total_requests,
       latest_status,
       latest_updated_at,
       latest_created_at,
       latest_request_id
  FROM prepared;

-- Apply one statement's exact count deltas to one authority summary.  The
-- caller holds the tuple fingerprint's transaction advisory lock.  Counts are
-- maintained incrementally; latest-overall and latest-success facts are two
-- stop-key index probes, never a history COUNT/GROUP BY.  Default-VOLATILE
-- PL/pgSQL queries take READ COMMITTED command snapshots after lock acquisition,
-- so concurrent legacy/direct writers converge instead of overwriting one
-- another.  Higher isolation may abort a conflicting writer for whole-statement
-- retry rather than commit a stale summary.
CREATE FUNCTION apply_restore_scheduler_system_delta(
    p_source_ci_key TEXT,
    p_target_site TEXT,
    p_target_environment TEXT,
    p_total_delta BIGINT,
    p_success_delta BIGINT
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    existing_seq       BIGINT;
    existing_successes BIGINT;
    existing_total     BIGINT;
    next_successes     BIGINT;
    next_total         BIGINT;
    next_collision     INTEGER;
    success_at         TIMESTAMPTZ;
    newest_status      TEXT;
    newest_updated_at  TIMESTAMPTZ;
    newest_created_at  TIMESTAMPTZ;
    newest_request_id  UUID;
BEGIN
    SELECT scan_seq, successful_test_count, total_requests
      INTO existing_seq, existing_successes, existing_total
      FROM restore_scheduler_system_summary
     WHERE source_fingerprint = md5(p_source_ci_key) ||
                                md5(p_target_site) ||
                                md5(p_target_environment)
       AND source_ci_key COLLATE "C" = p_source_ci_key COLLATE "C"
       AND target_site COLLATE "C" = p_target_site COLLATE "C"
       AND target_environment COLLATE "C" = p_target_environment COLLATE "C"
     LIMIT 1
     FOR UPDATE;

    IF existing_seq IS NULL THEN
        IF p_total_delta <= 0
           OR p_success_delta < 0
           OR p_success_delta > p_total_delta THEN
            RAISE EXCEPTION
                'restore scheduler summary missing for non-creating delta (% total, % successful)',
                p_total_delta,
                p_success_delta
                USING ERRCODE = '55000';
        END IF;
        next_total := p_total_delta;
        next_successes := p_success_delta;
    ELSE
        next_total := existing_total + p_total_delta;
        next_successes := existing_successes + p_success_delta;
    END IF;

    IF next_total < 0
       OR next_successes < 0
       OR next_successes > next_total THEN
        RAISE EXCEPTION
            'restore scheduler summary delta violates counts for authority tuple'
            USING ERRCODE = '55000';
    END IF;

    IF next_total = 0 THEN
        PERFORM 1
          FROM restore_requests
         WHERE md5(source_ci_key) = md5(p_source_ci_key)
           AND md5(target_site) = md5(p_target_site)
           AND md5(target_environment) = md5(p_target_environment)
           AND source_ci_key COLLATE "C" = p_source_ci_key COLLATE "C"
           AND target_site COLLATE "C" = p_target_site COLLATE "C"
           AND target_environment COLLATE "C" = p_target_environment COLLATE "C"
         LIMIT 1;
        IF FOUND THEN
            RAISE EXCEPTION
                'restore scheduler summary reached zero while source rows remain'
                USING ERRCODE = '55000';
        END IF;
        DELETE FROM restore_scheduler_system_summary
         WHERE scan_seq = existing_seq;
        RETURN;
    END IF;

    SELECT status, updated_at, created_at, id
      INTO newest_status,
           newest_updated_at,
           newest_created_at,
           newest_request_id
      FROM restore_requests
     WHERE md5(source_ci_key) = md5(p_source_ci_key)
       AND md5(target_site) = md5(p_target_site)
       AND md5(target_environment) = md5(p_target_environment)
       AND source_ci_key COLLATE "C" = p_source_ci_key COLLATE "C"
       AND target_site COLLATE "C" = p_target_site COLLATE "C"
       AND target_environment COLLATE "C" = p_target_environment COLLATE "C"
     ORDER BY updated_at DESC, created_at DESC, id DESC
     LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION
            'restore scheduler summary has positive count without a source row'
            USING ERRCODE = '55000';
    END IF;

    SELECT updated_at
      INTO success_at
      FROM restore_requests
     WHERE md5(source_ci_key) = md5(p_source_ci_key)
       AND md5(target_site) = md5(p_target_site)
       AND md5(target_environment) = md5(p_target_environment)
       AND source_ci_key COLLATE "C" = p_source_ci_key COLLATE "C"
       AND target_site COLLATE "C" = p_target_site COLLATE "C"
       AND target_environment COLLATE "C" = p_target_environment COLLATE "C"
       AND status IN ('Verified', 'Completed')
     ORDER BY updated_at DESC, created_at DESC, id DESC
     LIMIT 1;
    IF (next_successes = 0 AND success_at IS NOT NULL)
       OR (next_successes > 0 AND success_at IS NULL) THEN
        RAISE EXCEPTION
            'restore scheduler summary successful-count delta disagrees with source rows'
            USING ERRCODE = '55000';
    END IF;

    IF existing_seq IS NULL THEN
        SELECT COALESCE(MAX(collision_slot) + 1, 0)
          INTO next_collision
          FROM restore_scheduler_system_summary
         WHERE source_fingerprint = md5(p_source_ci_key) ||
                                    md5(p_target_site) ||
                                    md5(p_target_environment);

        INSERT INTO restore_scheduler_system_summary (
            source_ci_key,
            target_site,
            target_environment,
            collision_slot,
            last_successful_test,
            successful_test_count,
            total_requests,
            latest_status,
            latest_updated_at,
            latest_created_at,
            latest_request_id
        ) VALUES (
            p_source_ci_key,
            p_target_site,
            p_target_environment,
            next_collision,
            success_at,
            next_successes,
            next_total,
            newest_status,
            newest_updated_at,
            newest_created_at,
            newest_request_id
        );
    ELSE
        UPDATE restore_scheduler_system_summary
           SET last_successful_test = success_at,
               successful_test_count = next_successes,
               total_requests = next_total,
               latest_status = newest_status,
               latest_updated_at = newest_updated_at,
               latest_created_at = newest_created_at,
               latest_request_id = newest_request_id,
               updated_at = clock_timestamp()
         WHERE scan_seq = existing_seq;
    END IF;
END;
$$;

-- Transition-table triggers collapse a bulk legacy statement to one refresh
-- per exact affected authority tuple.  The deterministic lock order prevents
-- two multi-tuple writers from acquiring advisory locks in opposite order.
-- This avoids row-trigger B-by-H amplification while keeping writer-independent
-- INSERT/UPDATE/DELETE coverage.
CREATE FUNCTION sync_restore_scheduler_summary_after_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    affected RECORD;
BEGIN
    FOR affected IN
        SELECT
               source_ci_key COLLATE "C" AS source_ci_key,
               target_site COLLATE "C" AS target_site,
               target_environment COLLATE "C" AS target_environment,
               md5(source_ci_key) || md5(target_site) ||
                   md5(target_environment) AS source_fingerprint,
               hashtext(md5(source_ci_key) || md5(target_site) ||
                        md5(target_environment)) AS lock_key,
               COUNT(*) AS total_delta,
               COUNT(*) FILTER (
                   WHERE status IN ('Verified', 'Completed')
               ) AS success_delta
          FROM inserted_restore_requests
         GROUP BY 1, 2, 3, 4, 5
         ORDER BY lock_key, source_fingerprint,
                  source_ci_key, target_site, target_environment
    LOOP
        PERFORM pg_advisory_xact_lock(163, affected.lock_key);
        PERFORM apply_restore_scheduler_system_delta(
            affected.source_ci_key,
            affected.target_site,
            affected.target_environment,
            affected.total_delta,
            affected.success_delta
        );
    END LOOP;
    RETURN NULL;
END;
$$;

CREATE FUNCTION sync_restore_scheduler_summary_after_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    affected RECORD;
BEGIN
    FOR affected IN
        SELECT
               source_ci_key COLLATE "C" AS source_ci_key,
               target_site COLLATE "C" AS target_site,
               target_environment COLLATE "C" AS target_environment,
               md5(source_ci_key) || md5(target_site) ||
                   md5(target_environment) AS source_fingerprint,
               hashtext(md5(source_ci_key) || md5(target_site) ||
                        md5(target_environment)) AS lock_key,
               -COUNT(*) AS total_delta,
               -COUNT(*) FILTER (
                   WHERE status IN ('Verified', 'Completed')
               ) AS success_delta
          FROM deleted_restore_requests
         GROUP BY 1, 2, 3, 4, 5
         ORDER BY lock_key, source_fingerprint,
                  source_ci_key, target_site, target_environment
    LOOP
        PERFORM pg_advisory_xact_lock(163, affected.lock_key);
        PERFORM apply_restore_scheduler_system_delta(
            affected.source_ci_key,
            affected.target_site,
            affected.target_environment,
            affected.total_delta,
            affected.success_delta
        );
    END LOOP;
    RETURN NULL;
END;
$$;

CREATE FUNCTION sync_restore_scheduler_summary_after_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    affected RECORD;
BEGIN
    FOR affected IN
        SELECT
               source_ci_key,
               target_site,
               target_environment,
               md5(source_ci_key) || md5(target_site) ||
                   md5(target_environment) AS source_fingerprint,
               hashtext(md5(source_ci_key) || md5(target_site) ||
                        md5(target_environment)) AS lock_key,
               SUM(total_delta)::BIGINT AS total_delta,
               SUM(success_delta)::BIGINT AS success_delta
          FROM (
              SELECT source_ci_key COLLATE "C" AS source_ci_key,
                     target_site COLLATE "C" AS target_site,
                     target_environment COLLATE "C" AS target_environment,
                     -1::BIGINT AS total_delta,
                     CASE
                         WHEN status IN ('Verified', 'Completed') THEN -1::BIGINT
                         ELSE 0::BIGINT
                     END AS success_delta
                FROM updated_restore_requests_old
              UNION ALL
              SELECT source_ci_key COLLATE "C" AS source_ci_key,
                     target_site COLLATE "C" AS target_site,
                     target_environment COLLATE "C" AS target_environment,
                     1::BIGINT AS total_delta,
                     CASE
                         WHEN status IN ('Verified', 'Completed') THEN 1::BIGINT
                         ELSE 0::BIGINT
                     END AS success_delta
                FROM updated_restore_requests_new
          ) changed_restore_authorities
         GROUP BY 1, 2, 3, 4, 5
         ORDER BY lock_key, source_fingerprint,
                  source_ci_key, target_site, target_environment
    LOOP
        PERFORM pg_advisory_xact_lock(163, affected.lock_key);
        PERFORM apply_restore_scheduler_system_delta(
            affected.source_ci_key,
            affected.target_site,
            affected.target_environment,
            affected.total_delta,
            affected.success_delta
        );
    END LOOP;
    RETURN NULL;
END;
$$;

CREATE FUNCTION sync_restore_scheduler_summary_after_truncate()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    TRUNCATE TABLE restore_scheduler_system_summary;
    RETURN NULL;
END;
$$;

CREATE TRIGGER restore_requests_scheduler_summary_insert
AFTER INSERT ON restore_requests
REFERENCING NEW TABLE AS inserted_restore_requests
FOR EACH STATEMENT
EXECUTE FUNCTION sync_restore_scheduler_summary_after_insert();

CREATE TRIGGER restore_requests_scheduler_summary_delete
AFTER DELETE ON restore_requests
REFERENCING OLD TABLE AS deleted_restore_requests
FOR EACH STATEMENT
EXECUTE FUNCTION sync_restore_scheduler_summary_after_delete();

CREATE TRIGGER restore_requests_scheduler_summary_update
AFTER UPDATE ON restore_requests
REFERENCING OLD TABLE AS updated_restore_requests_old
            NEW TABLE AS updated_restore_requests_new
FOR EACH STATEMENT
EXECUTE FUNCTION sync_restore_scheduler_summary_after_update();

CREATE TRIGGER restore_requests_scheduler_summary_truncate
AFTER TRUNCATE ON restore_requests
FOR EACH STATEMENT
EXECUTE FUNCTION sync_restore_scheduler_summary_after_truncate();

-- Progress is per schedule definition, not merely per job kind.  Queue effects,
-- cursor movement, and schedule continuation commit as one page unit.  Deleting
-- the row on the final short raw page proves cycle exhaustion.  Every classifier
-- uses the same fixed database cutoff for the whole cycle.
CREATE TABLE scheduler_scan_progress (
    schedule_id    TEXT PRIMARY KEY REFERENCES schedules (id) ON DELETE CASCADE,
    job_kind       TEXT NOT NULL CHECK (
        job_kind IN (
            'restore_overdue_scan_v2',
            'golden_image_stale_scan_v2',
            'secret_rotation_due_scan_v2'
        )
    ),
    protocol_version SMALLINT NOT NULL DEFAULT 2 CHECK (protocol_version = 2),
    cursor_seq     BIGINT NOT NULL DEFAULT 0 CHECK (cursor_seq >= 0),
    high_water_seq BIGINT NOT NULL CHECK (high_water_seq >= cursor_seq),
    cycle_cutoff   TIMESTAMPTZ NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
