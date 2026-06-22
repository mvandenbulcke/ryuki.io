-- OIDC browser sign-in: single-use login state store.
-- state: opaque CSPRNG value; single-use (take() deletes it).
-- nonce: forwarded to IdP, returned in ID token for replay defense.
-- pkce_verifier: raw PKCE code verifier (S256 method); never leaves the server.
-- expires_at: 10-minute window; rows past this are dead and ignored by take().
CREATE TABLE IF NOT EXISTS oidc_login_states (
    state           TEXT        PRIMARY KEY,
    nonce           TEXT        NOT NULL,
    pkce_verifier   TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '10 minutes'
);

-- Keeps the TTL sweep (cleanup_expired) and take()'s `expires_at > NOW()` guard
-- index-backed, so an unauthenticated flood on the auth-exempt login endpoint
-- cannot turn cleanup into a sequential scan.
CREATE INDEX IF NOT EXISTS idx_oidc_login_states_expires_at
    ON oidc_login_states (expires_at);
