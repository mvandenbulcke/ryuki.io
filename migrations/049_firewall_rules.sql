-- 049_firewall_rules.sql — durable firewall rules (P1 persistence sweep).
--
-- Firewall rules created via POST /api/network/firewall/rules lived only in a
-- process-local OnceLock<Mutex> engine static and reset on restart. This adds
-- the durable table; the engine stays pure (the static becomes the no-DB
-- fallback) and ryuki-api persists/reads here via sqlx.
--
-- The id is the engine-generated "fw-<site>-<hex>" string (TEXT PK). The enum
-- columns (protocol/action/direction/status) store their canonical KEBAB-CASE
-- serde strings ("tcp", "allow", "inbound", "pending-review") so a DB row
-- serializes byte-for-byte like the engine FirewallRule. created_at is the
-- engine's ISO string (kept as TEXT to round-trip exactly).

CREATE TABLE IF NOT EXISTS firewall_rules (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    source_ip   TEXT NOT NULL,
    source_port TEXT NOT NULL DEFAULT 'any',
    dest_ip     TEXT NOT NULL,
    dest_port   TEXT NOT NULL DEFAULT 'any',
    protocol    TEXT NOT NULL,
    action      TEXT NOT NULL,
    direction   TEXT NOT NULL,
    priority    INTEGER NOT NULL,
    site        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending-review',
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_firewall_rules_site ON firewall_rules (site);
CREATE INDEX IF NOT EXISTS idx_firewall_rules_direction ON firewall_rules (direction);
