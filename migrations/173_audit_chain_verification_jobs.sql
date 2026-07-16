-- 173_audit_chain_verification_jobs.sql — durable bounded audit-chain scans.
--
-- POST /api/audit/log/verify enqueues or joins a singleton job. A background
-- worker captures one immutable-by-id tail and advances a bounded hash-chain
-- checkpoint in short transactions. The HTTP request never fetches audit rows.

CREATE TABLE IF NOT EXISTS audit_chain_verification_jobs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status              TEXT NOT NULL DEFAULT 'queued'
                        CHECK (status IN ('queued', 'running', 'verified',
                                          'divergent', 'failed')),
    requested_by        TEXT NOT NULL,
    requested_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at          TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at        TIMESTAMPTZ,
    snapshot_tail_id    BIGINT,
    snapshot_tail_hash  TEXT,
    cursor_id           BIGINT NOT NULL DEFAULT 0 CHECK (cursor_id >= 0),
    expected_prev_hash  TEXT NOT NULL DEFAULT 'GENESIS',
    checked             BIGINT NOT NULL DEFAULT 0 CHECK (checked >= 0),
    first_divergent_id  BIGINT,
    reason_code         TEXT,
    CONSTRAINT audit_chain_verification_tail_pair
        CHECK ((snapshot_tail_id IS NULL) = (snapshot_tail_hash IS NULL)),
    CONSTRAINT audit_chain_verification_terminal_shape
        CHECK (
            (status IN ('queued', 'running') AND completed_at IS NULL)
            OR
            (status IN ('verified', 'divergent', 'failed') AND completed_at IS NOT NULL)
        )
);

-- One active job across every API replica. A constant expression is used
-- because the singleton is global rather than partitioned by tenant/site.
CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_chain_verification_active
    ON audit_chain_verification_jobs ((1))
    WHERE status IN ('queued', 'running');

CREATE INDEX IF NOT EXISTS idx_audit_chain_verification_completed
    ON audit_chain_verification_jobs (completed_at DESC, id DESC)
    WHERE status IN ('verified', 'divergent', 'failed');
