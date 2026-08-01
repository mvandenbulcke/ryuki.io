-- Replace per-row TEXT casts in the snapshot stale-claim path with one typed,
-- indexed expiry. Existing text is retained as request evidence, but
-- only a strictly shaped, length-bounded RFC3339 value is promoted into the
-- authoritative TIMESTAMPTZ column. Invalid legacy rows remain present with a
-- NULL typed expiry and are therefore quarantined from every application read
-- and lifecycle transition.
--
-- This is an offline migration: drain pre-204 API writers before applying it.
-- A stale writer that omits requested_expiry_at fails closed into quarantine;
-- it cannot enter the stale work index or become visible to the new binary.

SET LOCAL lock_timeout = '30s';
SET LOCAL TIME ZONE 'UTC';
LOCK TABLE snapshots IN ACCESS EXCLUSIVE MODE;

ALTER TABLE snapshots
    ADD COLUMN IF NOT EXISTS requested_expiry_at TIMESTAMPTZ;

-- RFC3339 has a four-digit year. The explicit shape rejects PostgreSQL's
-- broader date grammar, while pg_input_is_valid verifies calendar and offset
-- ranges without allowing a malformed cast to abort the migration. CASE keeps
-- the cast behind that validation boundary. The 64-byte ceiling matches the
-- domain/HTTP boundary.
UPDATE snapshots
SET requested_expiry_at = CASE
    WHEN OCTET_LENGTH(requested_expiry) BETWEEN 20 AND 64
     AND SUBSTRING(requested_expiry FROM 1 FOR 4) <> '0000'
     AND requested_expiry ~
         '^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]([.][0-9]+)?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$'
     AND CASE
         WHEN pg_input_is_valid(requested_expiry, 'timestamptz')
         THEN EXTRACT(YEAR FROM requested_expiry::TIMESTAMPTZ AT TIME ZONE 'UTC')
                  BETWEEN 1 AND 9999
         ELSE FALSE
     END
    THEN requested_expiry::TIMESTAMPTZ
    ELSE NULL
END;

ALTER TABLE snapshots
    DROP CONSTRAINT IF EXISTS snapshots_requested_expiry_typed_check;

ALTER TABLE snapshots
    ADD CONSTRAINT snapshots_requested_expiry_typed_check
    CHECK (
        requested_expiry_at IS NULL
        OR (
            OCTET_LENGTH(requested_expiry) BETWEEN 20 AND 64
            AND SUBSTRING(requested_expiry FROM 1 FOR 4) <> '0000'
            AND requested_expiry ~
                '^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]([.][0-9]+)?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$'
            AND CASE
                WHEN pg_input_is_valid(requested_expiry, 'timestamptz')
                THEN EXTRACT(YEAR FROM requested_expiry::TIMESTAMPTZ AT TIME ZONE 'UTC')
                         BETWEEN 1 AND 9999
                     AND requested_expiry::TIMESTAMPTZ = requested_expiry_at
                ELSE FALSE
            END
        )
    );

COMMENT ON COLUMN snapshots.requested_expiry_at IS
    'Authoritative typed snapshot expiry. NULL quarantines an invalid or unvalidated legacy writer row from reads and lifecycle work.';

-- The typed range predicate and ordering exactly match the bounded claim
-- query. requested_expiry_at leads the key so PostgreSQL can stop at NOW(),
-- then created_at/id provide a stable order among equal expiries before LIMIT.
DROP INDEX IF EXISTS idx_snapshots_stale_claim;
CREATE INDEX idx_snapshots_stale_claim
    ON snapshots(requested_expiry_at ASC, created_at ASC, id ASC)
    WHERE configuration_item_id IS NOT NULL
      AND requested_expiry_at IS NOT NULL
      AND status IN ('Draft', 'ReviewRequested', 'ExpiryApproved');
