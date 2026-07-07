-- 155_agent_jobs_mode_live_destroy.sql — admit the LiveDestroy job mode
-- (#42 slice B2-2).
--
-- The mig-054 agent_jobs.mode CHECK mirrored the original three JobMode
-- variants (OfflineDryRun/LivePlan/LiveApply). #42's auto compensating teardown
-- adds JobMode::LiveDestroy (a live-mutating mode that destroys a step's applied
-- resources), and the CP now INSERTs LiveDestroy agent_jobs when a live step
-- fails after earlier steps applied. Widen the CHECK to admit it. Widening is
-- safe with existing rows (old values are a subset), following the mig 151/152/
-- 153/154 drop+re-add precedent. The constraint is auto-named
-- `agent_jobs_mode_check` (Postgres names an unnamed column-level CHECK
-- `<table>_<column>_check`).
ALTER TABLE agent_jobs DROP CONSTRAINT IF EXISTS agent_jobs_mode_check;
ALTER TABLE agent_jobs ADD CONSTRAINT agent_jobs_mode_check
    CHECK (mode IN ('OfflineDryRun', 'LivePlan', 'LiveApply', 'LiveDestroy'));
