-- 105_credential_expiry.sql — integration credential rotation / expiry (#41).
--
-- integration_connections (052) tracked WHERE a credential lives but not WHEN it
-- expires, so nothing surfaced a credential about to lapse. Add an optional
-- expiry instant; POST /api/integrations/{id}/credential-expiry sets it and
-- GET /api/integrations/credentials/expiring lists credentials due within N days
-- (including already-expired) so operators can rotate before an outage.

ALTER TABLE integration_connections
    ADD COLUMN IF NOT EXISTS credential_expires_at TIMESTAMPTZ;

-- The expiring-soon scan: connections ordered by how soon their credential
-- lapses (NULLs — no tracked expiry — sort last and are excluded by the filter).
CREATE INDEX IF NOT EXISTS idx_integration_connections_cred_expiry
    ON integration_connections (credential_expires_at)
    WHERE credential_expires_at IS NOT NULL;
