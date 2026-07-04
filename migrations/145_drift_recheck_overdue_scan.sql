-- 145_drift_recheck_overdue_scan.sql — surface OVERDUE drift re-checks (#31 slice 1).
--
-- A live-applied ("operational") deployment only stays trustworthy if it is re-verified
-- against real infrastructure periodically: configuration can drift out of band between
-- applies (someone hand-edits a resource, a provider mutates state). Nothing today
-- notices when an operational deployment's most recent successful live-apply
-- verification ages past the re-check cadence — an operator only learns it is overdue
-- by polling. This migration adds a PROACTIVE scan so an overdue drift re-check surfaces
-- as actionable work.
--
-- It reuses the durable-scheduler SAFE-INTERNAL-WRITE recipe (#52/#58/#59/#60): seed one
-- enabled `drift_recheck_overdue_scan` schedule. The tick reads 'operational' requests
-- joined to their most recent successful agent_jobs verification (result_status
-- 'applied'/'verified'), flags any whose last verification is older than
-- ryuki_engine::drift_scan::DRIFT_RECHECK_INTERVAL_DAYS, and enqueues ONE deduped
-- `shift_queue` item per overdue deployment. Reads requests + agent_jobs and writes only
-- our own shift_queue — NO provider/live/destructive call.

-- Seed one enabled scan on a daily (86400s) cadence. Fixed id so a re-run is a no-op;
-- ON CONFLICT DO NOTHING leaves the operator free to disable or retune it without the
-- migration re-asserting it.
INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by)
VALUES (
    'd71f7c1c-0031-4d31-8c31-d71f7c1c0031',
    'Drift re-check overdue scan (all sites)',
    'drift_recheck_overdue_scan',
    86400,
    TRUE,
    NOW(),
    'system'
)
ON CONFLICT (id) DO NOTHING;

-- Make the dedup STRUCTURAL as well as procedural (defense-in-depth + documents the
-- intended key): at most one OPEN drift-recheck-overdue item per request. The partial
-- predicate constrains only `resolved = false` rows, so it never blocks the
-- post-resolution re-flag. `shift_queue` has no natural key (only a PK on `id`); this is
-- the only unique constraint the enqueue's untargeted `ON CONFLICT DO NOTHING` can hit.
CREATE UNIQUE INDEX IF NOT EXISTS uq_shift_queue_open_drift_recheck_overdue
    ON shift_queue (item_type, (metadata->>'source_ci_key'))
    WHERE resolved = false AND item_type = 'drift-recheck-overdue';
