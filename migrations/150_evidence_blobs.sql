-- 150_evidence_blobs.sql — content-addressed store for large execution evidence (#60 slice 2).
-- Large evidence (esp. the untruncated terraform show -json plan) bloats the frequently-updated
-- agent_jobs row. On ingest, evidence over the inline threshold is stored here keyed by its
-- verified sha256 digest (== agent_jobs.evidence_digest); the row keeps only a small reference.
-- Content-addressed: identical evidence across jobs dedups by digest (ON CONFLICT DO NOTHING).
-- No FK to agent_jobs (shared/deduped across jobs, same rationale as integration_secrets).
CREATE TABLE IF NOT EXISTS evidence_blobs (
    digest      TEXT PRIMARY KEY,
    bytes       BYTEA NOT NULL,
    size_bytes  BIGINT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
