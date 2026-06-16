-- At most ONE LiveApply job may ever exist per request — the no-double-apply
-- invariant for live (mutating) execution. Enforcing it in the database makes
-- EVERY grant-minting path concurrency-safe: the request-scoped approval
-- (requests_approve_live_apply) AND the operator endpoint
-- (admin_approve_live_apply_job) both go through create_live_apply_job, whose
-- INSERT uses ON CONFLICT against this index — so two simultaneous approvals
-- can no longer both insert a grant authorising another infrastructure apply.
--
-- The guard spans ALL statuses (not just active): a failed or lease-expired
-- apply must be handled by the operator reconcile flow, never re-minted here.
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_jobs_unique_live_apply
    ON agent_jobs (request_id)
    WHERE mode = 'LiveApply';
