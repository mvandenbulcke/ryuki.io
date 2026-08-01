-- 207_inbound_webhook_authority_generation.sql
--
-- Bind every accepted inbound webhook to one immutable credential generation
-- and one authoritative connection context.  The receiver holds a row lock on
-- that context from secret resolution through receipt/event commit; rotations
-- and deletion take the incompatible connection-row lock and therefore
-- serialize on the same boundary.

SET LOCAL lock_timeout = '30s';

LOCK TABLE
    integration_connections,
    integration_secrets,
    inbound_webhook_receipts,
    domain_events
IN ACCESS EXCLUSIVE MODE;

ALTER TABLE integration_connections
    ADD COLUMN webhook_secret_generation BIGINT;

ALTER TABLE integration_secrets
    ADD COLUMN webhook_secret_generation BIGINT,
    ADD CONSTRAINT integration_secrets_webhook_generation_positive
        CHECK (
            webhook_secret_generation IS NULL
            OR webhook_secret_generation > 0
        );

-- Preserve every previously active credential as generation-one history before
-- revoking its unbound authority. The API needs this encrypted history to
-- reject accidental reuse of secret material held by an old sender.
UPDATE integration_secrets AS secret
SET webhook_secret_generation = 1
FROM integration_connections AS connection
WHERE connection.webhook_secret_ref = secret.id
  AND connection.id = secret.connection_id;

CREATE UNIQUE INDEX integration_secrets_webhook_generation_uidx
    ON integration_secrets (connection_id, webhook_secret_generation)
    WHERE webhook_secret_generation IS NOT NULL;

COMMENT ON COLUMN integration_secrets.webhook_secret_generation IS
    'Immutable inbound-webhook credential history generation; NULL for non-webhook credentials';

-- Legacy references have no trustworthy record of which vendor/site context
-- existed when their holders received the secret. Revoke them at the cutover;
-- an administrator must provision a fresh v2 generation before delivery can
-- resume. The ciphertext rows remain connection-scoped as immutable reuse
-- history and are removed only by the existing connection cascade.
UPDATE integration_connections
SET webhook_secret_ref = NULL,
    webhook_secret_generation = CASE
        WHEN webhook_secret_ref IS NULL THEN 0
        ELSE 1
    END;

ALTER TABLE integration_connections
    ALTER COLUMN webhook_secret_generation SET DEFAULT 0,
    ALTER COLUMN webhook_secret_generation SET NOT NULL,
    ADD CONSTRAINT integration_connections_webhook_secret_generation_shape
        CHECK (
            (webhook_secret_ref IS NULL AND webhook_secret_generation >= 0)
            OR
            (webhook_secret_ref IS NOT NULL AND webhook_secret_generation > 0)
        );

COMMENT ON COLUMN integration_connections.webhook_secret_generation IS
    'Monotonic inbound-webhook credential generation; zero means never configured and NULL ref means inactive';

-- Once a sender has been authorized for a configured connection, changing the
-- vendor or site while retaining that credential would transfer its authority
-- into the new context. Metadata reassignment must atomically revoke the active
-- credential; a later provisioning call creates a fresh generation.
CREATE OR REPLACE FUNCTION enforce_integration_webhook_authority_generation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.webhook_secret_ref IS NOT NULL
       AND (
           NEW.vendor_type IS DISTINCT FROM OLD.vendor_type
           OR NEW.site_scope IS DISTINCT FROM OLD.site_scope
       )
       AND NOT (
           NEW.webhook_secret_ref IS NULL
           AND NEW.webhook_secret_generation = OLD.webhook_secret_generation
       ) THEN
        RAISE EXCEPTION
            'webhook authority changes must revoke the active credential'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'integration_connections_webhook_authority_immutable';
    END IF;

    IF NEW.webhook_secret_ref IS DISTINCT FROM OLD.webhook_secret_ref THEN
        IF NEW.webhook_secret_ref IS NULL THEN
            IF NEW.webhook_secret_generation <> OLD.webhook_secret_generation THEN
                RAISE EXCEPTION
                    'webhook credential revocation must preserve its generation'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'integration_connections_webhook_generation_transition';
            END IF;
        ELSIF NEW.webhook_secret_generation <> OLD.webhook_secret_generation + 1 THEN
            RAISE EXCEPTION
                'webhook credential replacement must advance exactly one generation'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'integration_connections_webhook_generation_transition';
        ELSE
            IF NOT EXISTS (
                SELECT 1
                FROM integration_secrets AS secret
                WHERE secret.id = NEW.webhook_secret_ref
                  AND secret.connection_id = NEW.id
                  AND secret.webhook_secret_generation =
                      NEW.webhook_secret_generation
            ) THEN
                RAISE EXCEPTION
                    'webhook credential reference must resolve inside its connection'
                    USING ERRCODE = '23503',
                          CONSTRAINT = 'integration_connections_webhook_secret_reference';
            END IF;
        END IF;
    ELSIF NEW.webhook_secret_generation <> OLD.webhook_secret_generation THEN
        RAISE EXCEPTION
            'webhook credential generation cannot change without a new reference'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'integration_connections_webhook_generation_transition';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS integration_connections_webhook_authority_generation
    ON integration_connections;
CREATE TRIGGER integration_connections_webhook_authority_generation
    BEFORE UPDATE OF vendor_type, site_scope, webhook_secret_ref,
        webhook_secret_generation
    ON integration_connections
    FOR EACH ROW
    EXECUTE FUNCTION enforce_integration_webhook_authority_generation();

-- Webhook credential history is immutable while its connection exists. Rotation
-- appends a fresh row and retains every retired generation so plaintext reuse
-- can be rejected. A connection cascade may remove all of its history only
-- after the parent row has ceased to be visible.
CREATE OR REPLACE FUNCTION enforce_webhook_secret_history_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF OLD.webhook_secret_generation IS NOT NULL
           OR NEW.webhook_secret_generation IS NOT NULL THEN
            RAISE EXCEPTION 'webhook credential history rows are immutable'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'integration_secrets_webhook_history_immutable';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.webhook_secret_generation IS NOT NULL
       AND EXISTS (
           SELECT 1
           FROM integration_connections AS connection
           WHERE connection.id = OLD.connection_id
       ) THEN
        RAISE EXCEPTION 'webhook credential history is retained until connection deletion'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'integration_secrets_webhook_history_immutable';
    END IF;
    RETURN OLD;
END;
$$;

DROP TRIGGER IF EXISTS integration_secrets_webhook_history_immutable
    ON integration_secrets;
CREATE TRIGGER integration_secrets_webhook_history_immutable
    BEFORE UPDATE OR DELETE
    ON integration_secrets
    FOR EACH ROW
    EXECUTE FUNCTION enforce_webhook_secret_history_immutable();

ALTER TABLE inbound_webhook_receipts
    ADD COLUMN webhook_secret_ref TEXT,
    ADD COLUMN webhook_secret_generation BIGINT,
    ADD COLUMN authority_context_sha256 TEXT,
    ADD COLUMN webhook_vendor_type TEXT,
    ADD COLUMN webhook_site_scope TEXT;

ALTER TABLE inbound_webhook_receipts
    DROP CONSTRAINT inbound_webhook_receipts_signature_version,
    ADD CONSTRAINT inbound_webhook_receipts_signature_authority_shape
        CHECK (
            (
                signature_version = 1
                AND webhook_secret_ref IS NULL
                AND webhook_secret_generation IS NULL
                AND authority_context_sha256 IS NULL
                AND webhook_vendor_type IS NULL
                AND webhook_site_scope IS NULL
            )
            OR
            (
                signature_version = 2
                AND webhook_secret_ref IS NOT NULL
                AND octet_length(webhook_secret_ref) BETWEEN 1 AND 128
                AND webhook_secret_generation IS NOT NULL
                AND webhook_secret_generation > 0
                AND authority_context_sha256 IS NOT NULL
                AND authority_context_sha256 ~ '^[0-9a-f]{64}$'
                AND webhook_vendor_type IS NOT NULL
                AND octet_length(webhook_vendor_type) BETWEEN 1 AND 128
            )
        );

COMMENT ON COLUMN inbound_webhook_receipts.webhook_secret_ref IS
    'Internal immutable credential id selected by the accepted v2 request; never projected to callers';
COMMENT ON COLUMN inbound_webhook_receipts.webhook_secret_generation IS
    'Credential generation selected by the accepted v2 request';
COMMENT ON COLUMN inbound_webhook_receipts.authority_context_sha256 IS
    'Digest of connection/credential/generation/vendor/site authority authenticated by the v2 message';
COMMENT ON COLUMN inbound_webhook_receipts.webhook_vendor_type IS
    'Vendor authority selected by the accepted v2 request';
COMMENT ON COLUMN inbound_webhook_receipts.webhook_site_scope IS
    'Nullable site authority selected by the accepted v2 request';
COMMENT ON COLUMN inbound_webhook_receipts.delivery_id IS
    'External delivery identifier authenticated by the v2 canonical message';

CREATE OR REPLACE FUNCTION enforce_inbound_webhook_receipt_authority_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.connection_id IS DISTINCT FROM OLD.connection_id
       OR NEW.delivery_id IS DISTINCT FROM OLD.delivery_id
       OR NEW.signature_version IS DISTINCT FROM OLD.signature_version
       OR NEW.webhook_secret_ref IS DISTINCT FROM OLD.webhook_secret_ref
       OR NEW.webhook_secret_generation IS DISTINCT FROM OLD.webhook_secret_generation
       OR NEW.authority_context_sha256 IS DISTINCT FROM OLD.authority_context_sha256
       OR NEW.webhook_vendor_type IS DISTINCT FROM OLD.webhook_vendor_type
       OR NEW.webhook_site_scope IS DISTINCT FROM OLD.webhook_site_scope
       OR NEW.signed_at IS DISTINCT FROM OLD.signed_at
       OR NEW.body_sha256 IS DISTINCT FROM OLD.body_sha256
       OR NEW.advisory_lock_key IS DISTINCT FROM OLD.advisory_lock_key
       OR NEW.accepted_at IS DISTINCT FROM OLD.accepted_at
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR OLD.event_id IS NOT NULL
       OR NEW.event_id IS NULL THEN
        RAISE EXCEPTION 'inbound webhook receipt authority is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'inbound_webhook_receipts_authority_immutable';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS inbound_webhook_receipts_authority_immutable
    ON inbound_webhook_receipts;
CREATE TRIGGER inbound_webhook_receipts_authority_immutable
    BEFORE UPDATE ON inbound_webhook_receipts
    FOR EACH ROW
    EXECUTE FUNCTION enforce_inbound_webhook_receipt_authority_immutable();

CREATE OR REPLACE FUNCTION enforce_inbound_webhook_receipt_v2_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.signature_version <> 2 THEN
        RAISE EXCEPTION 'new inbound webhook receipts require signature contract v2'
            USING ERRCODE = '55000',
                  CONSTRAINT = 'inbound_webhook_receipts_v2_insert';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS inbound_webhook_receipts_v2_insert
    ON inbound_webhook_receipts;
CREATE TRIGGER inbound_webhook_receipts_v2_insert
    BEFORE INSERT ON inbound_webhook_receipts
    FOR EACH ROW
    EXECUTE FUNCTION enforce_inbound_webhook_receipt_v2_insert();

-- Replace the rolling-deployment marker before new binaries write v2 events.
-- Old v1 binaries fail closed at the event boundary; their unbound receipt then
-- also fails the existing deferred receipt invariant.
CREATE OR REPLACE FUNCTION enforce_inbound_webhook_contract_v2()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF current_setting('ryuki.inbound_webhook_contract', TRUE) IS DISTINCT FROM '2' THEN
        RAISE EXCEPTION 'inbound webhook contract v2 is required'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS domain_events_inbound_webhook_contract_v1 ON domain_events;
DROP TRIGGER IF EXISTS domain_events_inbound_webhook_contract_v2 ON domain_events;
CREATE TRIGGER domain_events_inbound_webhook_contract_v2
    BEFORE INSERT ON domain_events
    FOR EACH ROW
    WHEN (NEW.event_type = 'integration.webhook-received')
    EXECUTE FUNCTION enforce_inbound_webhook_contract_v2();

DROP FUNCTION IF EXISTS enforce_inbound_webhook_contract_v1();

-- Upgrade migration 160's deferred event/receipt existence check to exact v2
-- authority equality. The raw credential reference remains receipt-local; its
-- generation and authority digest are the non-secret event projection.
CREATE OR REPLACE FUNCTION enforce_inbound_webhook_event_receipted()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM inbound_webhook_receipts AS receipt
        WHERE receipt.event_id = NEW.id
          AND receipt.connection_id = NEW.aggregate_id
          AND NEW.aggregate_type = 'integration_connection'
          AND receipt.signature_version = 2
          AND NEW.payload->>'connection_id' = receipt.connection_id
          AND NEW.payload->>'signature_version' = receipt.signature_version::TEXT
          AND NEW.payload->>'webhook_secret_generation' =
              receipt.webhook_secret_generation::TEXT
          AND NEW.payload->>'authority_context_sha256' =
              receipt.authority_context_sha256
          AND NEW.payload->>'vendor_type' = receipt.webhook_vendor_type
          AND NEW.payload->>'delivery_id' = receipt.delivery_id
          AND NEW.payload->>'body_sha256' = receipt.body_sha256
          AND (NEW.payload->>'signed_at')::TIMESTAMPTZ = receipt.signed_at
          AND NEW.site IS NOT DISTINCT FROM receipt.webhook_site_scope
          AND NEW.actor = 'webhook:' || receipt.webhook_vendor_type
    ) THEN
        RAISE EXCEPTION
            'inbound webhook event must match its receipt authority before commit'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'domain_events_inbound_webhook_receipt_authority';
    END IF;
    RETURN NEW;
END;
$$;
