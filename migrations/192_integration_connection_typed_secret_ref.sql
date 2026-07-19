-- Typed SecretRef storage and source discriminator for integration credentials.
--
-- Legacy rows remain readable with both new columns NULL, but the new
-- `secret-provider-ref` enum is NOT compatible with a same-release old reader.
-- This is therefore an offline Recreate cutover: drain every pre-192 API
-- replica and database session, run this migration under the bounded lock
-- below, then start only the matching image. Do not use RollingUpdate. The
-- generation column fences typed row replacement; it is not a mixed-binary
-- rollout fence and must never be described as one.
--
-- Current binaries parse a present JSON document strictly and may never fall
-- back to credential_ref when that document is malformed or mismatched. This
-- migration does not infer provider/deployment/trust/fingerprint authority from
-- legacy Vault paths or environment-variable names.

SET LOCAL lock_timeout = '30s';
LOCK TABLE integration_connections IN ACCESS EXCLUSIVE MODE;

ALTER TABLE integration_connections
    ADD COLUMN IF NOT EXISTS credential_secret_ref JSONB;

ALTER TABLE integration_connections
    ADD COLUMN IF NOT EXISTS credential_secret_ref_generation BIGINT;

ALTER TABLE integration_connections
    DROP CONSTRAINT IF EXISTS integration_connections_credential_source_check;

ALTER TABLE integration_connections
    ADD CONSTRAINT integration_connections_credential_source_check
    CHECK (credential_source IN (
        'vault',
        'db-encrypted',
        'env-var',
        'secret-provider-ref'
    ));

ALTER TABLE integration_connections
    DROP CONSTRAINT IF EXISTS integration_connections_typed_secret_ref_shape_check;

ALTER TABLE integration_connections
    ADD CONSTRAINT integration_connections_typed_secret_ref_shape_check
    CHECK (
        (
            credential_source IN ('vault', 'db-encrypted', 'env-var')
            AND credential_secret_ref IS NULL
            AND credential_secret_ref_generation IS NULL
        )
        OR
        (
            credential_source = 'secret-provider-ref'
            AND credential_ref = ''
            AND credential_secret_ref IS NOT NULL
            AND jsonb_typeof(credential_secret_ref) = 'object'
            AND credential_secret_ref_generation IS NOT NULL
            AND credential_secret_ref_generation > 0
        )
    );

COMMENT ON COLUMN integration_connections.credential_secret_ref IS
    'Closed, value-free runtime SecretRef JSON. Application code performs strict schema and authority validation; never secret material.';

COMMENT ON COLUMN integration_connections.credential_secret_ref_generation IS
    'Positive expand/migrate/cutover generation for a present typed SecretRef; NULL identifies an untouched legacy row.';
