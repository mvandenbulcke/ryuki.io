-- 132_connection_health_checks_prune.sql — bound the fastest-growing history table (run-3).
--
-- The seeded connection_health_sweep runs every 300s (5 min) and appends ONE
-- connection_health_checks row PER integration connection PER sweep (~288 rows/day/connection) —
-- the fastest-growing unbounded table (a standing disk-space concern). The FK CASCADE only removes
-- rows when a CONNECTION is deleted (connections persist), so it does not bound a live connection's
-- history.
--
-- This migration seeds an HOURLY connection_health_checks_prune durable-scheduler job. It reuses the
-- generalized newest-N-per-partition prune (keep the newest KEEP_PER_CONNECTION=10000 rows per
-- connection_id, with a per-run cap). It runs HOURLY (not daily, unlike job_executions_prune) so the
-- per-run cap keeps up with per-connection growth (#connections × 12/hour) instead of falling behind
-- a daily #connections × 288. It only DELETEs our own history (no provider/live call);
-- connection_health_checks has no inbound FK and no append-only trigger, so the prune DELETE is
-- allowed.

-- Seed one enabled prune on an HOURLY (3600s) cadence. Fixed id (continues the seed sequence
-- ...cert=9999, job-exec-prune=aaaa -> chc-prune=bbbb) so a re-run is a no-op; ON CONFLICT DO NOTHING
-- leaves the operator free to disable or retune it.
INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by)
VALUES (
    'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    'Connection health-checks history prune (all connections)',
    'connection_health_checks_prune',
    3600,
    TRUE,
    NOW(),
    'system'
)
ON CONFLICT (id) DO NOTHING;

-- Retention index matching the prune's window ORDER BY exactly (codex): the prune ranks rows with
-- ROW_NUMBER() OVER (PARTITION BY connection_id ORDER BY checked_at DESC, id DESC). The existing
-- mig-102 index (connection_id, checked_at DESC) orders the partition but is NOT exact for the
-- `id DESC` tiebreak; this index covers the FULL ordering so the hourly ranking scan is an ordered
-- index scan (no sort) on this fastest-growing table.
-- `checked_at DESC NULLS LAST` (NOT the btree default NULLS FIRST) must match the prune query's
-- `ORDER BY checked_at DESC NULLS LAST, id DESC` EXACTLY, or the planner will not use the index for
-- ordering and falls back to a sort (codex). checked_at is NOT NULL so no NULLs arise, but the
-- ordering must still match for the planner to skip the sort.
CREATE INDEX IF NOT EXISTS idx_connection_health_checks_prune
    ON connection_health_checks (connection_id, checked_at DESC NULLS LAST, id DESC);
