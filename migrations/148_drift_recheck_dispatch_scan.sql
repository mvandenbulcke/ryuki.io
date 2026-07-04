-- 148_drift_recheck_dispatch_scan.sql — DISPATCH the drift re-check (#31 slice 2b-2).
--
-- Slice 1 (migration 145) only FLAGS an overdue drift re-check into shift_queue for a
-- human to act on. This migration adds the scan that actually DISPATCHES the re-check:
-- for every operational deployment overdue per the same `is_drift_recheck_due` gate, it
-- derives a LivePlan JobSpec from the deployment's last successful LiveApply job and
-- inserts ONE deduped `agent_jobs` row (origin = 'drift_recheck'). The agent runs the
-- LivePlan re-check and the CP ingest (already shipped in slice 2/2b-1) classifies drift
-- and resets `requests.last_drift_check_at`.
--
-- This is the FIRST schedule that fans out into `agent_jobs` — every prior scan
-- (#52/#58/#59/#60/#61/#31-slice-1) only enqueues shift_queue items or mutates its own
-- tables. What is dispatched here is still read-only against the target infrastructure
-- (a `LivePlan`, never a `LiveApply`), so no live-execution grant is minted or required —
-- but it IS a real capability escalation from flag-only scans and must be treated as such
-- by anyone extending this pattern to a live-mutating job kind.

-- Seed one enabled scan on a daily (86400s) cadence. Fixed id so a re-run is a no-op;
-- ON CONFLICT DO NOTHING leaves the operator free to disable or retune it without the
-- migration re-asserting it.
INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by)
VALUES (
    'e8d3a2c4-0031-4d31-8c31-e8d3a2c40148',
    'Drift re-check dispatch scan (all sites)',
    'drift_recheck_dispatch_scan',
    86400,
    TRUE,
    NOW(),
    'system'
)
ON CONFLICT (id) DO NOTHING;

-- Speed up the dispatch scan's in-flight dedup check (open_drift_recheck_job_exists):
-- a partial index over only the open, scheduler-created drift-recheck jobs.
CREATE INDEX IF NOT EXISTS idx_agent_jobs_open_drift_recheck
    ON agent_jobs (request_id)
    WHERE origin = 'drift_recheck' AND status IN ('Pending', 'Leased', 'Running');
