-- 149_integration_webhook_secret.sql — dedicated inbound-webhook signing secret (#18 slice 2).
-- webhook_secret_ref mirrors credential_ref: it is the integration_secrets.id of the DEDICATED
-- webhook signing secret, distinct from the outbound credential_ref. NULL = no webhook secret
-- configured -> the (later) receiver handler fails closed (401). Nullable, no default, so every
-- existing INSERT INTO integration_connections still works. No DB-level FK (mirrors credential_ref,
-- a bare TEXT pointer); the secret row is looked up defensively scoped to (id, connection_id).
ALTER TABLE integration_connections ADD COLUMN IF NOT EXISTS webhook_secret_ref TEXT;
