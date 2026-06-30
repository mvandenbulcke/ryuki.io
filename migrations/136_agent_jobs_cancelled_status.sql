-- 136_agent_jobs_cancelled_status.sql — admit a terminal 'Cancelled' agent-job status (run-3).
--
-- An admin can now CANCEL a Pending (not-yet-leased) agent job that was created in error / is no
-- longer wanted, instead of letting an agent pick it up and run it. This widens the inline status
-- CHECK (last set by mig 121, which added 'DeadLettered') to admit 'Cancelled'.
--
-- Like 'DeadLettered', 'Cancelled' is a CP-INTERNAL TERMINAL status: it is NOT added to the
-- ryuki_protocol::JobStatus enum (the agent-facing dispatchable subset), because poll_job only ever
-- leases `WHERE status = 'Pending'`, so a 'Cancelled' job is never dispatched or decoded into
-- JobStatus. Admin reads return status as a String passthrough.
--
-- Guarded (DROP IF EXISTS + re-ADD) so a manual re-run also succeeds; sqlx never re-runs an applied
-- migration. Widening is safe with existing rows (old values are a subset of the new set), and the
-- migration's table lock prevents writes in the drop/add gap.
ALTER TABLE agent_jobs DROP CONSTRAINT IF EXISTS agent_jobs_status_check;
ALTER TABLE agent_jobs ADD CONSTRAINT agent_jobs_status_check
    CHECK (status IN (
        'Pending', 'Leased', 'Running',
        'Succeeded', 'Failed', 'Expired',
        'ReconcileRequired', 'LiveRefused', 'DeadLettered', 'Cancelled'
    ));
