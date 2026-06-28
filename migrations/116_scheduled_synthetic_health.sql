-- #40 Scheduled synthetic health checks.
--
-- Wires the existing per-site synthetic health runner into the durable scheduler
-- as the `synthetic_health_run` job kind (a safe-internal-write: it records
-- simulated probe results via the pure engine, no provider/live calls). This
-- migration (a) indexes check_results for the per-check latest-result read the
-- runner and dashboards perform, and (b) seeds one enabled, hourly schedule so the
-- platform begins recording synthetic health automatically.

-- Supports `ORDER BY executed_at DESC` per check (get_latest_result, dashboards,
-- and the scheduled runner's downstream reads) without a full scan as
-- check_results grows.
CREATE INDEX IF NOT EXISTS idx_check_results_check_executed
    ON check_results (check_id, executed_at DESC);

-- Seed one enabled, hourly synthetic-health run. Fixed id so a re-run is a no-op;
-- ON CONFLICT DO NOTHING leaves the operator free to disable or retune it without
-- the migration re-asserting it. Hourly bounds result growth while keeping health
-- signals fresh; the runner processes every ENABLED check across all sites.
INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by)
VALUES (
    '22222222-2222-4222-8222-222222222222',
    'Synthetic health run (all sites)',
    'synthetic_health_run',
    3600,
    TRUE,
    NOW(),
    'system'
)
ON CONFLICT (id) DO NOTHING;
