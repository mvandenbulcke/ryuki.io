-- 120_connection_health_sweep.sql — scheduled connection-health sweep (#19).
--
-- On-demand connection health already exists: POST /api/integrations/{id}/test
-- runs the pure `test_connection_stub` (a DRY-RUN, no live provider call) and
-- records a `connection_health_checks` row. This migration adds a PROACTIVE
-- sweep so the health history stays fresh without an operator manually probing
-- each connection.
--
-- It reuses the #40 durable-scheduler SAFE-INTERNAL-WRITE recipe applied to
-- integration connections: seed one enabled `connection_health_sweep` schedule.
-- The tick lists every connection, runs the pure stub, and appends a
-- connection_health_checks row per connection (a time series — NO dedup).
--
-- No new table, column, or index: migration 102 already created
-- `connection_health_checks` and `idx_connection_health_checks_conn`
-- (connection_id, checked_at DESC), which serves both the history read and the
-- sweep's append pattern.

-- Seed one enabled sweep on a 5-minute cadence. Fixed id so a re-run is a no-op;
-- ON CONFLICT DO NOTHING leaves the operator free to disable or retune it
-- without the migration re-asserting it. 300s keeps connection freshness on a
-- cadence SLOs/dashboards tolerate; the sweep probes every connection.
INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by)
VALUES (
    '44444444-4444-4444-8444-444444444444',
    'Connection health sweep (all connections)',
    'connection_health_sweep',
    300,
    TRUE,
    NOW(),
    'system'
)
ON CONFLICT (id) DO NOTHING;
