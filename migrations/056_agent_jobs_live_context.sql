-- Adds the control-plane-signed approval grant (VerifiedLiveContext) to
-- agent_jobs. A LiveApply job carries this grant (request_id, approved_plan_digest,
-- approver, expiry, signature). The result verifier enforces that the agent's
-- signed `approved_plan_digest` EQUALS the grant's and that the grant has not
-- expired, so an agent can never apply (or report applying) a plan other than the
-- one an operator reviewed and the control plane granted. NULL for non-live jobs.
ALTER TABLE agent_jobs
    ADD COLUMN IF NOT EXISTS live_context JSONB;

-- Invariant: a LiveApply job MUST carry an approval grant. This is enforced at
-- the APPLICATION layer rather than via a DB CHECK constraint:
--   * job creation (S5a-2) attaches a signed grant when dispatching LiveApply;
--   * the result verifier rejects a LiveApply result whose job has no grant.
-- A DB CHECK was intentionally avoided: adding one to a table that may already
-- hold rows (e.g. an upgraded deployment, or a long-lived dev/test database)
-- fails the migration or later UPDATEs against legacy rows. The app-layer checks
-- give the same guarantee without that brittleness.
