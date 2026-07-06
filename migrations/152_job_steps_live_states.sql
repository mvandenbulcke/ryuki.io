-- 152_job_steps_live_states.sql — admit the live-apply-per-step states (#42 slice B1a).
--
-- The forward per-step live path (docs/design/live-apply-per-step.md) adds four new step
-- statuses beyond today's Pending/Running/Succeeded/Failed: 'Planning' (a LivePlan step job
-- is dispatched and in flight), 'AwaitingApproval' (the LivePlan succeeded; the step's real
-- plan is recorded and waiting on an operator's per-step approval — slice B1b), 'Applying'
-- and 'Applied' (reserved for slice B1b's LiveApply dispatch/completion; not yet reachable
-- from any code path in this slice). Dry-run orchestration (#42 2a/2b) is UNCHANGED and never
-- produces these statuses; they are only ever set by the LivePlan-mode dispatch/backlink path.
--
-- live_plan_digest carries the `agent_jobs.evidence_digest` of the step's most recent
-- genuinely-successful LivePlan result forward onto the step row, mirroring exactly what
-- requests_approve_live_apply already does for the single-job live path (it re-derives the
-- same field from agent_jobs at approval time). Recording it directly on job_steps means a
-- future per-step approval endpoint (slice B1b) has the approved plan's digest available
-- without re-querying agent_jobs, and it is what gets SURFACED to approvers reviewing a
-- step's AwaitingApproval state.
--
-- Guarded (DROP IF EXISTS + re-ADD), matching the precedent set by mig 121/136 for widening
-- an auto-named inline CHECK (Postgres names an unnamed column-level CHECK
-- `<table>_<column>_check` — confirmed here via mig 136's `agent_jobs_status_check`). Widening
-- is safe with existing rows (old values are a subset of the new set).
ALTER TABLE job_steps DROP CONSTRAINT IF EXISTS job_steps_status_check;
ALTER TABLE job_steps ADD CONSTRAINT job_steps_status_check
    CHECK (status IN (
        'Pending', 'Running', 'Succeeded', 'Failed',
        'Planning', 'AwaitingApproval', 'Applying', 'Applied'
    ));

ALTER TABLE job_steps ADD COLUMN IF NOT EXISTS live_plan_digest TEXT NULL;
