-- S3b: result columns on agent_jobs + idempotency constraint.
--
-- Schema decision: add result columns directly to agent_jobs (no companion
-- table) because:
--   1. There is exactly one result per job attempt (1:1 relationship).
--   2. A companion table forces a JOIN on every status poll and complicates
--      the atomic terminal UPDATE that must be a single statement.
--   3. The signed_envelope JSONB column is the only "large" addition; at
--      ~512–2 KB per result it does not meaningfully bloat hot rows that are
--      still in Pending/Leased/Running.
--
-- Idempotency key: (id, attempt_id, result_id) — the agent's idempotency
-- triple from the protocol spec. A UNIQUE constraint on these three columns
-- lets the handler detect "already recorded" by catching the unique violation
-- (or by checking rows_affected == 0 on the conditional UPDATE and then
-- reading back the stored result_id). Both paths are implemented in the handler.
--
-- All columns are nullable: they are NULL for jobs that have not yet reached
-- a terminal state.

ALTER TABLE agent_jobs
    ADD COLUMN IF NOT EXISTS result_id        UUID,
    ADD COLUMN IF NOT EXISTS result_status    TEXT
                                              CHECK (result_status IS NULL OR result_status IN (
                                                  'check_ok', 'planned', 'applied',
                                                  'verified', 'failed', 'live_refused'
                                              )),
    ADD COLUMN IF NOT EXISTS evidence_digest  TEXT,
    ADD COLUMN IF NOT EXISTS evidence_json    JSONB,
    ADD COLUMN IF NOT EXISTS signed_envelope  JSONB,
    ADD COLUMN IF NOT EXISTS completed_at     TIMESTAMPTZ;

-- Idempotency constraint: a given (job_id, attempt_id, result_id) triple may
-- only be recorded once. Because the terminal UPDATE is conditioned on
-- attempt_id AND lease_generation, a stale result for a superseded attempt
-- will produce rows_affected == 0 before it ever hits this constraint — but
-- the constraint is the hard backstop.
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_jobs_result_idempotency
    ON agent_jobs (id, attempt_id, result_id)
    WHERE result_id IS NOT NULL;
