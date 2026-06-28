-- 122_restore_overdue_scan.sql — route overdue restore tests into the work queue (#52).
--
-- #47 already classifies each protected system's restore-test recency as overdue
-- via the pure `backup_recency::classify_restore_recency`, but the only way an
-- operator learns a system is overdue is by polling the read endpoint. This
-- migration adds a PROACTIVE scan so overdue recoverability surfaces as
-- actionable work without manual polling.
--
-- It reuses the durable-scheduler SAFE-INTERNAL-WRITE recipe (#40/#39/#19): seed
-- one enabled `restore_overdue_scan` schedule. The tick reads restore-test
-- recency across all sites, classifies each system with the pure engine, and
-- enqueues ONE deduped `shift_queue` item per AT-RISK (overdue or never-tested)
-- system. It reads `restore_requests` and writes only our own `shift_queue` — no
-- provider/live call.

-- Seed one enabled scan on a daily (86400s) cadence. Fixed id so a re-run is a
-- no-op; ON CONFLICT DO NOTHING leaves the operator free to disable or retune it
-- without the migration re-asserting it.
INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by)
VALUES (
    '55555555-5555-4555-8555-555555555555',
    'Restore overdue scan (all systems)',
    'restore_overdue_scan',
    86400,
    TRUE,
    NOW(),
    'system'
)
ON CONFLICT (id) DO NOTHING;

-- Make the dedup STRUCTURAL as well as procedural (defense-in-depth + documents
-- the intended key): at most one OPEN restore-test-overdue item per system. The
-- partial predicate constrains only `resolved = false` rows, so it never blocks
-- the post-resolution re-flag. `shift_queue` has no natural key (only a PK on
-- `id`); this is the only unique constraint the enqueue's untargeted
-- `ON CONFLICT DO NOTHING` can hit.
CREATE UNIQUE INDEX IF NOT EXISTS uq_shift_queue_open_restore_overdue
    ON shift_queue (item_type, (metadata->>'source_ci_key'))
    WHERE resolved = false AND item_type = 'restore-test-overdue';
