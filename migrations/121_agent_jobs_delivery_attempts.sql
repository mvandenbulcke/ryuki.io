-- #23 CP-side poison-job cap / dead-letter.
-- A non-mutating agent job (OfflineDryRun / LivePlan) whose lease expires is
-- redispatched back to Pending by expire_leases (agents.rs). With no cap a
-- poison job (malformed spec, OOM, partition) re-leases + re-expires forever,
-- silently burning agent capacity. Add a per-job redispatch counter and a
-- terminal DeadLettered status so the cap can fire and surface an alert.
--
-- delivery_attempts: count of lease-expiry REDISPATCHES this job has taken.
-- 0 for a never-expired job; only the non-mutating redispatch path increments
-- it. NOT NULL DEFAULT 0 is safe for existing INSERTs (AGENT_JOB_COLUMNS and the
-- agent lease/fetch/ack paths stay untouched — this is internal CP bookkeeping).
ALTER TABLE agent_jobs ADD COLUMN IF NOT EXISTS delivery_attempts INT NOT NULL DEFAULT 0;

-- Widen the inline status CHECK from mig 054 (agent_jobs_status_check) to admit
-- the new terminal 'DeadLettered' value. Guarded (DROP IF EXISTS + re-ADD) so a
-- manual re-run also succeeds; sqlx never re-runs an applied migration. Widening
-- is safe with existing rows (old values are a subset of the new set) and the
-- migration's table lock prevents writes in the drop/add gap.
ALTER TABLE agent_jobs DROP CONSTRAINT IF EXISTS agent_jobs_status_check;
ALTER TABLE agent_jobs ADD CONSTRAINT agent_jobs_status_check
    CHECK (status IN (
        'Pending', 'Leased', 'Running',
        'Succeeded', 'Failed', 'Expired',
        'ReconcileRequired', 'LiveRefused', 'DeadLettered'
    ));
