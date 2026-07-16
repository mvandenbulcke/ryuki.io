-- Bind every persisted interactive session to one monotonic identity-authority
-- generation. Account/password/role/provider lifecycle changes advance the
-- generation, so an older session cannot become valid again if configuration
-- is rolled back to an earlier value.
--
-- This is an intentionally session-invalidating cutover. Pre-165 rows have no
-- provider/issuer/subject authority binding, so preserving them would turn the
-- new join into an unsafe legacy fallback. Interactive sessions are ephemeral;
-- all users must sign in again after this migration.

CREATE TABLE identity_authorities (
    provider TEXT NOT NULL,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    authority_epoch BIGINT NOT NULL DEFAULT 1
        CHECK (authority_epoch > 0),
    authority_digest BYTEA NOT NULL
        CHECK (octet_length(authority_digest) = 32),
    authority_status TEXT NOT NULL DEFAULT 'active'
        CHECK (authority_status IN ('active', 'revoked')),
    source_watermark BIGINT NOT NULL DEFAULT 0
        CHECK (source_watermark >= 0),
    last_asserted_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (provider, issuer, subject),
    CHECK (length(provider) BETWEEN 1 AND 64),
    CHECK (provider ~ '^[A-Za-z0-9][A-Za-z0-9._-]*$'),
    CHECK (length(issuer) BETWEEN 1 AND 2048),
    CHECK (length(subject) BETWEEN 1 AND 512)
);

LOCK TABLE sessions IN ACCESS EXCLUSIVE MODE;
DELETE FROM sessions;

ALTER TABLE sessions
    ADD COLUMN identity_issuer TEXT NOT NULL,
    ADD COLUMN identity_subject TEXT NOT NULL,
    ADD COLUMN identity_authority_epoch BIGINT NOT NULL
        CHECK (identity_authority_epoch > 0),
    ADD CONSTRAINT sessions_identity_authority_fk
        FOREIGN KEY (provider, identity_issuer, identity_subject)
        REFERENCES identity_authorities (provider, issuer, subject)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT;

CREATE INDEX sessions_identity_authority_idx
    ON sessions (provider, identity_issuer, identity_subject, identity_authority_epoch);

COMMENT ON TABLE identity_authorities IS
    'Provider-neutral, monotonic authorization projection for interactive sessions';
COMMENT ON COLUMN identity_authorities.authority_digest IS
    'Keyed digest of the current credential/role authority; never return or log';
COMMENT ON COLUMN identity_authorities.source_watermark IS
    'Monotonic normalized lifecycle-event watermark; zero means callback/config assertions only';
COMMENT ON COLUMN sessions.identity_authority_epoch IS
    'Authority generation captured atomically when the session was minted';
