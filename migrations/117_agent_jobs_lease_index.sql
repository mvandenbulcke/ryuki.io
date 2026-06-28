-- swarm #33: optimize the agent-job lease query.
--
-- The hot path leases the next job with:
--   SELECT id FROM agent_jobs WHERE platform = $1 AND status = 'Pending'
--   ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1
-- (agents.rs poll_job + the dispatch paths). The existing (platform, status) index
-- covers the equality predicates but not the `ORDER BY created_at`, so Postgres
-- must sort the matching rows on every poll. A composite that appends created_at
-- lets the index satisfy BOTH the predicates and the ordering, so the lease walks
-- the index in created_at order and takes the first unlocked row — no Sort node and
-- fewer rows examined under contention.
CREATE INDEX IF NOT EXISTS idx_agent_jobs_platform_status_created
    ON agent_jobs (platform, status, created_at);

-- The new composite has (platform, status) as a leading prefix, so the prior
-- two-column index is redundant for every query that used it. Drop it to avoid the
-- extra write amplification on this hot, frequently-inserted queue table.
DROP INDEX IF EXISTS idx_agent_jobs_platform_status;
