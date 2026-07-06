-- 153_agent_jobs_step_scoped_live_apply.sql — per-step LiveApply exemption
-- (#42 live-apply slice B1b).
--
-- The mig-057 index enforced AT MOST ONE LiveApply per request (the single-job
-- no-double-apply invariant). Per-step live apply (#42) legitimately needs one
-- LiveApply job PER STEP of a multi-step request, so a request may now carry
-- several. We add a `step_scoped` flag:
--   * single-job LiveApply jobs keep step_scoped=FALSE and remain
--     unique-per-request — the mig-057 invariant is UNCHANGED for them; and
--   * step-scoped LiveApply jobs (step_scoped=TRUE) are EXEMPT from the
--     request-level uniqueness (one per step, several per request).
--
-- Per-step no-double-apply is instead enforced by the job_steps status gate:
-- the approval endpoint flips a step AwaitingApproval->Applying under a
-- `FOR UPDATE` lock, so each step can be approved (and its LiveApply minted)
-- exactly once. The single-job path's DB-level uniqueness is preserved verbatim
-- below for step_scoped=FALSE rows.
ALTER TABLE agent_jobs ADD COLUMN IF NOT EXISTS step_scoped BOOLEAN NOT NULL DEFAULT FALSE;

-- Redefine the one-per-request live-apply uniqueness to apply ONLY to
-- single-job (non-step-scoped) LiveApply jobs. Existing rows all have
-- step_scoped=FALSE (the column default), so this is a safe, behavior-
-- preserving narrowing for everything that exists today.
DROP INDEX IF EXISTS idx_agent_jobs_unique_live_apply;
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_jobs_unique_live_apply
    ON agent_jobs (request_id)
    WHERE mode = 'LiveApply' AND step_scoped = FALSE;
