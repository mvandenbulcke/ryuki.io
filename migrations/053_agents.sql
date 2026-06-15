-- Agent registry: one row per enrolled execution agent.
-- Status lifecycle: pending → approved (admin action) | revoked (admin action).
-- A pending agent cannot pull jobs; only approved agents may poll.
-- token_hash: lowercase-hex SHA-256 of the full plaintext bearer token (same
-- hashing as api_tokens). Public_key: base64-encoded Ed25519 verifying key.
-- capabilities: self-declared at registration; reconciled by admin against
-- trusted inventory before approval (see §5 / S3b).
CREATE TABLE agents (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id         TEXT        NOT NULL UNIQUE,
    platform         TEXT        NOT NULL,
    capabilities     JSONB       NOT NULL DEFAULT '{}',
    public_key       TEXT        NOT NULL,
    token_hash       TEXT        NOT NULL UNIQUE,
    status           TEXT        NOT NULL DEFAULT 'pending'
                                 CHECK (status IN ('pending', 'approved', 'revoked')),
    last_seen_at     TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agents_platform_status ON agents (platform, status);
