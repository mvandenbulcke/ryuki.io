-- Migration 066: one log forwarder per (hostname, source_type).
--
-- The onboard handler now treats an existing (hostname, source_type) pair as
-- already-onboarded (idempotent) and serializes onboard/disable per hostname
-- with a transaction-scoped advisory lock. This UNIQUE constraint is the hard
-- backstop: even if two writers somehow raced past the advisory lock, the DB
-- refuses a duplicate forwarding row for the same host + source type.

-- 1. Defensively collapse any pre-existing duplicate (hostname, source_type)
--    rows so the UNIQUE constraint below can be added cleanly. When duplicates
--    exist we keep the row in the BEST state (status precedence
--    Active < Configured < Failed < NotConfigured), tie-broken by smallest id —
--    never silently dropping an actively-forwarding row in favour of a disabled
--    one. Seed rows (migration 022) are already distinct, so this is a no-op on
--    clean data.
DELETE FROM log_forwarders a
USING log_forwarders b
WHERE a.hostname = b.hostname
  AND a.source_type = b.source_type
  AND a.id <> b.id
  AND (
        CASE b.status
            WHEN 'Active' THEN 0
            WHEN 'Configured' THEN 1
            WHEN 'Failed' THEN 2
            ELSE 3
        END,
        b.id
      ) < (
        CASE a.status
            WHEN 'Active' THEN 0
            WHEN 'Configured' THEN 1
            WHEN 'Failed' THEN 2
            ELSE 3
        END,
        a.id
      );

-- 2. Enforce one forwarder per (hostname, source_type).
ALTER TABLE log_forwarders
    ADD CONSTRAINT log_forwarders_hostname_source_type_key UNIQUE (hostname, source_type);
