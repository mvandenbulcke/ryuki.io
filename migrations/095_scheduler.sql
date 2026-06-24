-- 095_scheduler.sql — durable scheduler / background-job engine (#1).
--
-- The control plane runs recurring background work (self-health probes, and —
-- in later slices — drift scans, recurring reviews, synthetic checks). Until
-- now there was no durable record of WHAT should run, WHEN it last ran, or
-- WHETHER it succeeded; the only background tasks were hard-coded sweeps with no
-- history. This adds the two tables that make recurring work durable and
-- auditable:
--
--   schedules       — the registry of recurring jobs (kind + interval + when
--                     it next/last ran). One row per recurring job.
--   job_executions  — an append-style history of every run: when it started and
--                     finished, its status, and a small detail blob.
--
-- The tick loop (ryuki-api::scheduler) elects a single leader across replicas
-- with a transaction-scoped advisory lock, claims due rows with
-- `FOR UPDATE SKIP LOCKED`, runs ONLY read-only job kinds (the slice-1 safety
-- boundary), records a job_executions row, and advances next_run_at off the DB
-- clock. next_run_at carries no client clock — dueness and advancement are
-- always computed against NOW() server-side.

CREATE TABLE IF NOT EXISTS schedules (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    job_kind      TEXT NOT NULL,
    interval_secs BIGINT NOT NULL,
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    next_run_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_run_at   TIMESTAMPTZ,
    created_by    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Bounds MIRROR ryuki_engine::scheduler MIN/MAX_INTERVAL_SECS (10s .. 1y).
    -- Enforced durably here so a row written outside the validated API path can
    -- never busy-spin the tick (interval too small) or overflow make_interval
    -- (interval too large); the tick also clamps defensively.
    CONSTRAINT schedules_interval_bounded
        CHECK (interval_secs BETWEEN 10 AND 31536000)
);

-- The tick's hot query: enabled schedules whose next run is due, oldest first.
-- Partial index keeps it to the rows the loop actually scans.
CREATE INDEX IF NOT EXISTS idx_schedules_due
    ON schedules (next_run_at)
    WHERE enabled;

CREATE TABLE IF NOT EXISTS job_executions (
    id          TEXT PRIMARY KEY,
    schedule_id TEXT NOT NULL REFERENCES schedules (id) ON DELETE CASCADE,
    job_kind    TEXT NOT NULL,
    status      TEXT NOT NULL,
    detail      TEXT,
    started_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ
);

-- The read view: most-recent executions for a schedule.
CREATE INDEX IF NOT EXISTS idx_job_executions_schedule
    ON job_executions (schedule_id, started_at DESC);

-- Seed one enabled, hourly, read-only platform self-health probe so the engine
-- has real work the moment it comes up. Fixed id so a re-run is a no-op; the
-- probe records a job_executions row each hour proving the scheduler + DB are
-- alive. ON CONFLICT DO NOTHING keeps the operator free to disable/retune it
-- without the migration re-asserting it.
INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by)
VALUES (
    '11111111-1111-4111-8111-111111111111',
    'Platform self-health probe',
    'health_probe',
    3600,
    TRUE,
    NOW(),
    'system'
)
ON CONFLICT (id) DO NOTHING;
