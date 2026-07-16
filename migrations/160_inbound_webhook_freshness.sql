-- 160_inbound_webhook_freshness.sql — authenticated freshness and replay receipts.
--
-- A webhook signature now covers a versioned canonical message containing the
-- fixed method/path, connection id, Unix timestamp, delivery id, and SHA-256
-- digest of the exact body. Freshness is checked before secret resolution. This
-- table supplies the durable concurrency boundary: one authenticated delivery
-- can bind to only one domain event, even across processes and restarts.

CREATE TABLE IF NOT EXISTS inbound_webhook_receipts (
    -- Intentionally no integration_connections FK: a connection can disappear
    -- after its secret was resolved, and deleting it must not erase replay state
    -- while the authenticated timestamp can still pass the freshness window.
    connection_id    TEXT NOT NULL,
    delivery_id      TEXT NOT NULL,
    signature_version SMALLINT NOT NULL,
    signed_at        TIMESTAMPTZ NOT NULL,
    body_sha256      TEXT NOT NULL,
    -- Domain-separated SHA-256 prefix computed by the API. Delivery handling
    -- takes this transaction-scoped advisory lock before its final clock check;
    -- cleanup uses the same key non-blockingly so it cannot erase an in-flight
    -- replay boundary.
    advisory_lock_key BIGINT NOT NULL,
    event_id         BIGINT
                     REFERENCES domain_events (id) ON DELETE RESTRICT,
    accepted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at       TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (connection_id, delivery_id),
    CONSTRAINT inbound_webhook_receipts_connection_id_size
        CHECK (octet_length(connection_id) BETWEEN 1 AND 128),
    CONSTRAINT inbound_webhook_receipts_delivery_id_size
        CHECK (octet_length(delivery_id) BETWEEN 1 AND 128),
    CONSTRAINT inbound_webhook_receipts_signature_version
        CHECK (signature_version = 1),
    CONSTRAINT inbound_webhook_receipts_body_sha256
        CHECK (body_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT inbound_webhook_receipts_expiry
        CHECK (expires_at >= signed_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS inbound_webhook_receipts_event_id_uidx
    ON inbound_webhook_receipts (event_id)
    WHERE event_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_inbound_webhook_receipts_expiry
    ON inbound_webhook_receipts (expires_at, connection_id, delivery_id);

COMMENT ON TABLE inbound_webhook_receipts IS
    'Atomic single-use receipts for authenticated inbound webhook deliveries';
COMMENT ON COLUMN inbound_webhook_receipts.delivery_id IS
    'External delivery identifier authenticated by the v1 canonical message';
COMMENT ON COLUMN inbound_webhook_receipts.advisory_lock_key IS
    'Stable transaction advisory-lock key for this connection/delivery pair';

-- A claim is intentionally nullable only while its event is appended in the
-- same transaction. Make that application ordering a deferred database
-- invariant as well: no transaction may commit a live unbound receipt.
CREATE OR REPLACE FUNCTION enforce_inbound_webhook_receipt_bound()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM inbound_webhook_receipts
        WHERE connection_id = NEW.connection_id
          AND delivery_id = NEW.delivery_id
          AND event_id IS NULL
    ) THEN
        RAISE EXCEPTION 'inbound webhook receipt must bind an event before commit'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS inbound_webhook_receipt_bound ON inbound_webhook_receipts;
CREATE CONSTRAINT TRIGGER inbound_webhook_receipt_bound
    AFTER INSERT OR UPDATE ON inbound_webhook_receipts
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION enforce_inbound_webhook_receipt_bound();

-- Fail closed during a rolling or rollback overlap. A pre-160 API binary signs
-- only the body and appends events without a receipt. New code sets this marker
-- transaction-locally before inserting the event and receipt together.
CREATE OR REPLACE FUNCTION enforce_inbound_webhook_contract_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF current_setting('ryuki.inbound_webhook_contract', TRUE) IS DISTINCT FROM '1' THEN
        RAISE EXCEPTION 'inbound webhook contract v1 is required'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS domain_events_inbound_webhook_contract_v1 ON domain_events;
CREATE TRIGGER domain_events_inbound_webhook_contract_v1
    BEFORE INSERT ON domain_events
    FOR EACH ROW
    WHEN (NEW.event_type = 'integration.webhook-received')
    EXECUTE FUNCTION enforce_inbound_webhook_contract_v1();

-- The GUC above is an early rolling-deployment fence, not the relational
-- proof. At commit, every newly appended webhook event must be referenced by
-- exactly one receipt (the partial unique index enforces the "one"). Expired
-- receipts may be deleted later without deleting the historical event.
CREATE OR REPLACE FUNCTION enforce_inbound_webhook_event_receipted()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM inbound_webhook_receipts
        WHERE event_id = NEW.id
    ) THEN
        RAISE EXCEPTION 'inbound webhook event must be receipt-bound before commit'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS domain_events_inbound_webhook_receipted ON domain_events;
CREATE CONSTRAINT TRIGGER domain_events_inbound_webhook_receipted
    AFTER INSERT ON domain_events
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    WHEN (NEW.event_type = 'integration.webhook-received')
    EXECUTE FUNCTION enforce_inbound_webhook_event_receipted();
