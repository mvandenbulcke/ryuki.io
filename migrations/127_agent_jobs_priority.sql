-- 127_agent_jobs_priority.sql — priority-weighted agent-job dispatch (#15).
--
-- Agent-job dispatch (poll_job) was strict FIFO by created_at, so a critical job queued
-- behind a backlog waited its turn. Add a `priority` so an operator can bump an urgent job
-- ahead of the queue. Higher = more urgent; 5 is normal. Every existing INSERT INTO
-- agent_jobs omits `priority`, so they all inherit the default — no insert changes needed.

ALTER TABLE agent_jobs
    ADD COLUMN IF NOT EXISTS priority INT NOT NULL DEFAULT 5
    CHECK (priority BETWEEN 0 AND 9);

-- The dispatch index: within the pending set for a platform, order by most-urgent-first,
-- then FIFO, then id as a stable tie-breaker — matching the new poll_job ORDER BY exactly.
-- Plain CREATE INDEX (the migration runner is transactional, so CONCURRENTLY is not
-- available); agent_jobs is a control-plane queue (jobs reach a terminal state), not a hot
-- multi-million-row table, so a brief build lock is acceptable. Mirrors the existing partial
-- indexes (migrations 122/125).
CREATE INDEX IF NOT EXISTS idx_agent_jobs_dispatch
    ON agent_jobs (platform, priority DESC, created_at, id)
    WHERE status = 'Pending';
