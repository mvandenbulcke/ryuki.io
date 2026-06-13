-- API tokens / service-account credentials (design doc feature 3).
-- Machine credentials that resolve through the existing RBAC path. Only the
-- SHA-256 hash (lowercase hex of the full `ryk_...` plaintext) is persisted;
-- plaintext is returned exactly once at creation and never stored or logged.
-- Revocation is a soft-delete (revoked_at) — never a hard DELETE — so the row
-- survives as evidence. site_scope/environment_scope are persisted and shown
-- but NOT yet enforced (scoped enforcement is a later feature). token_valid
-- durably records the dry-run/non-privileged mint semantics: tokens minted in
-- a dry-run mode are FALSE forever and can never satisfy the verified-admin
-- gate even after the mode later changes.
CREATE TABLE api_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    owner_principal TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    roles TEXT[] NOT NULL DEFAULT '{}',
    site_scope TEXT,
    environment_scope TEXT,
    token_valid BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX idx_api_tokens_token_hash ON api_tokens (token_hash);
CREATE INDEX idx_api_tokens_active ON api_tokens (revoked_at, expires_at);
