-- 052_integration_connections.sql — generic vendor integration framework (Slice 1).
--
-- Two tables:
--   integration_connections — vendor connection metadata; NEVER stores plaintext
--     secret material. credential_ref is: a Vault path (vault source), a
--     comma-separated list of env KEY NAMES (env-var source), or the FK id into
--     integration_secrets (db-encrypted source, pointing at the ciphertext row).
--   integration_secrets — ciphertext-only storage for db-encrypted credentials.
--     Isolated from the connections table so connections rows can be freely
--     serialized/returned without exposing ciphertext.
--
-- Enum values mirror Rust serde kebab-case strings exactly so rows round-trip
-- byte-for-byte through the engine structs (same pattern as 051_secrets_rotation).
--
-- Timestamps are stored as TEXT in RFC3339 format (engine convention).

CREATE TABLE IF NOT EXISTS integration_connections (
    id               TEXT PRIMARY KEY,
    vendor_type      TEXT NOT NULL,
    name             TEXT NOT NULL,
    endpoint_url     TEXT NOT NULL,
    site_scope       TEXT,
    credential_source TEXT NOT NULL
                     CHECK (credential_source IN ('vault', 'db-encrypted', 'env-var')),
    credential_ref   TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL DEFAULT 'configured',
    readiness        TEXT NOT NULL DEFAULT 'configured',
    execution_mode   TEXT NOT NULL DEFAULT 'static-dry-run',
    last_test_at     TEXT,
    last_test_result TEXT,
    created_by       TEXT NOT NULL DEFAULT 'system',
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_integration_connections_vendor
    ON integration_connections (vendor_type);

CREATE INDEX IF NOT EXISTS idx_integration_connections_site
    ON integration_connections (site_scope);

-- Separate table: ciphertext ONLY.  The encryption KEY never appears here.
-- connection_id FK cascades on delete so removing a connection removes its secret.
CREATE TABLE IF NOT EXISTS integration_secrets (
    id            TEXT PRIMARY KEY,
    connection_id TEXT NOT NULL
                  REFERENCES integration_connections (id) ON DELETE CASCADE,
    ciphertext    BYTEA NOT NULL,
    nonce         BYTEA NOT NULL,
    key_id        TEXT NOT NULL DEFAULT 'env:RYUKI_INTEGRATION__ENCRYPTION_KEY',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_integration_secrets_connection
    ON integration_secrets (connection_id);

-- set_updated_at trigger for integration_connections.
-- CREATE OR REPLACE avoids a collision if the function already exists from a
-- prior migration (e.g., maintenance_windows).
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW()::text;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Only create the trigger if it does not already exist on this table.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'trg_integration_connections_updated_at'
          AND tgrelid = 'integration_connections'::regclass
    ) THEN
        CREATE TRIGGER trg_integration_connections_updated_at
            BEFORE UPDATE ON integration_connections
            FOR EACH ROW EXECUTE FUNCTION set_updated_at();
    END IF;
END $$;
