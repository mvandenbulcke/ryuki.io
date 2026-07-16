-- Separate the non-authenticating administrative session identifier from the
-- high-entropy bearer credential.
--
-- This is an intentionally session-invalidating security migration:
-- * every pre-159 row used sessions.id itself as the live bearer, so all
--   existing rows are deleted rather than guessing whether they are safe;
-- * renaming id makes pre-159 readers and writers fail closed after cutover
--   instead of accepting the new administrative UUID as a credential;
-- * new rows must carry exactly one 32-byte keyed verifier, with no default,
--   so an old writer cannot create a legacy credential row.
--
-- The migration takes an exclusive table lock. Deploy it as a non-overlapping
-- control-plane cutover; all users must sign in again afterward.
LOCK TABLE sessions IN ACCESS EXCLUSIVE MODE;

DELETE FROM sessions;

ALTER TABLE sessions RENAME COLUMN id TO session_record_id;

ALTER TABLE sessions
    ADD COLUMN bearer_verifier BYTEA NOT NULL,
    ADD CONSTRAINT sessions_bearer_verifier_length
        CHECK (octet_length(bearer_verifier) = 32);

CREATE UNIQUE INDEX sessions_bearer_verifier_uidx
    ON sessions (bearer_verifier);

COMMENT ON COLUMN sessions.session_record_id IS
    'Non-authenticating UUID for administrative list/get/revoke and audit references';
COMMENT ON COLUMN sessions.bearer_verifier IS
    'HMAC-SHA256 verifier of the one-time rys_ bearer; never return or log';
