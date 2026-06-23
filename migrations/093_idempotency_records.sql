-- 093_idempotency_records.sql — HTTP idempotency-key dedup for create endpoints.
--
-- A client that wants at-most-once create semantics sends an `Idempotency-Key`
-- header (an unguessable UUID). The idempotency middleware claims the key here
-- atomically (INSERT ... ON CONFLICT), runs the handler once, stores the
-- response, and replays it on a retry instead of creating a duplicate.
--
-- Scoped per principal: the PRIMARY KEY is (user_scope, key), so one tenant's
-- key never collides with — or replays — another tenant's response, even if the
-- key value is reused or leaked. The middleware runs INSIDE auth, so user_scope
-- is the authenticated session's user_id.
--
-- response_status / response_body are NULL between the claim and the handler
-- completing — that in-flight window is what a concurrent retry sees (→ 409).
-- A claim whose handler never finished (crash/cancel) is reclaimed once it is
-- older than the in-flight TTL, so a key can never lock out permanently — but
-- only by an IDENTICAL request (same fingerprint); a different request on a
-- dead key is still a 422 conflict.
-- claim_id is a per-claim fence token: every finalizing UPDATE/DELETE is scoped
-- to it, so a slow handler whose claim was reclaimed after the TTL cannot clobber
-- the newer owner's record.
-- fingerprint = sha256(method ++ path-and-query ++ body) detects a key reused
-- with a DIFFERENT request (→ 422). created_at bounds the table and drives both
-- the in-flight reclaim and a TTL sweep.

CREATE TABLE IF NOT EXISTS idempotency_records (
    user_scope      TEXT NOT NULL,
    key             TEXT NOT NULL,
    fingerprint     TEXT NOT NULL,
    claim_id        TEXT NOT NULL,
    response_status INTEGER,
    response_body   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_scope, key)
);

CREATE INDEX IF NOT EXISTS idx_idempotency_records_created_at
    ON idempotency_records (created_at);
