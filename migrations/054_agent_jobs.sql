-- Agent job queue: one row per dispatchable unit of work.
-- request_id references the upstream change-request (not FK-constrained here
-- so the queue is usable before requests table exists in every deploy config).
-- Fencing fields (attempt_id, lease_generation, fencing_token, cp_nonce) are
-- set atomically by the SKIP LOCKED lease query; cp_nonce is a per-lease
-- one-time nonce the agent must echo verbatim in its signed result.
-- mode CHECK mirrors JobMode variants; status CHECK mirrors JobStatus variants.
-- LiveApply lease expiry → ReconcileRequired (never auto-redispatched).
-- Non-mutating (OfflineDryRun / LivePlan) lease expiry → back to Pending with
-- a new attempt_id / lease_generation.
CREATE TABLE agent_jobs (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id       UUID        NOT NULL,
    platform         TEXT        NOT NULL,
    spec             JSONB       NOT NULL,
    mode             TEXT        NOT NULL
                                 CHECK (mode IN ('OfflineDryRun', 'LivePlan', 'LiveApply')),
    status           TEXT        NOT NULL DEFAULT 'Pending'
                                 CHECK (status IN (
                                     'Pending', 'Leased', 'Running',
                                     'Succeeded', 'Failed', 'Expired',
                                     'ReconcileRequired', 'LiveRefused'
                                 )),
    agent_id         TEXT,
    attempt_id       UUID,
    lease_generation BIGINT      NOT NULL DEFAULT 0,
    fencing_token    TEXT,
    cp_nonce         TEXT,
    lease_deadline   TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agent_jobs_platform_status ON agent_jobs (platform, status);
CREATE INDEX idx_agent_jobs_request_id      ON agent_jobs (request_id);

-- Seed: a couple of OfflineDryRun rows for test harness convenience.
-- These are NOT wired to a real request (request_id is a stable fixture UUID).
INSERT INTO agent_jobs (request_id, platform, spec, mode) VALUES
(
    '00000000-0000-0000-0000-000000000001'::uuid,
    'ci-test',
    '{"request_id":"00000000-0000-0000-0000-000000000001","offering_id":"00000000-0000-0000-0000-000000000002","iac_ref":"linux-server-deployment@v1","iac_digest":"0000000000000000000000000000000000000000000000000000000000000000","vars":{},"mode":"offline_dry_run"}'::jsonb,
    'OfflineDryRun'
),
(
    '00000000-0000-0000-0000-000000000003'::uuid,
    'ci-test',
    '{"request_id":"00000000-0000-0000-0000-000000000003","offering_id":"00000000-0000-0000-0000-000000000004","iac_ref":"patch-maintenance@v2","iac_digest":"0000000000000000000000000000000000000000000000000000000000000000","vars":{},"mode":"offline_dry_run"}'::jsonb,
    'OfflineDryRun'
);
