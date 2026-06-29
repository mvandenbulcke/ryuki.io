-- 131_job_executions_prune.sql — bound the unbounded scheduler run-history table (run-3).
--
-- `job_executions` (mig 095) appends a row for EVERY scheduler run. The 5-minute
-- connection_health_sweep alone writes ~288 rows/day, the hourly probes more, plus every daily
-- scan — and NOTHING prunes it, so it grows without bound (a standing disk-space concern). The FK
-- CASCADE only removes rows when a SCHEDULE is deleted (schedules persist), so it does not bound a
-- live schedule's history.
--
-- This migration seeds a daily `job_executions_prune` durable-scheduler job that keeps the newest
-- KEEP_PER_SCHEDULE (=10000, sized for the fastest 5-min cadence ≈ 35 days) rows PER schedule and
-- deletes the rest, with a per-run cap so the first prune of a years-old backlog never does one
-- giant DELETE. It only DELETEs our own run history (no provider/live call); job_executions has no
-- inbound FK and no append-only trigger, so the prune DELETE is allowed.

-- Seed one enabled prune on a daily (86400s) cadence. Fixed id (continues the seed sequence
-- restore=5555, secret=6666, legal-hold=7777, recert=8888, cert=9999 -> prune=aaaa) so a re-run is
-- a no-op; ON CONFLICT DO NOTHING leaves the operator free to disable or retune it.
INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by)
VALUES (
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    'Job-executions history prune (all schedules)',
    'job_executions_prune',
    86400,
    TRUE,
    NOW(),
    'system'
)
ON CONFLICT (id) DO NOTHING;
