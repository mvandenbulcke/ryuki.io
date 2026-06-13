-- 050_ipam.sql — durable IPAM subnets + IP reservations (P1 persistence sweep).
--
-- IP reservations created via POST /api/network/ipam/reserve (and freed via
-- POST /api/network/ipam/release/{id}) lived only in a process-local
-- OnceLock<Mutex> engine static and reset on restart — so did the mutated
-- subnet counters (used_ips / available_ips / status). This adds the durable
-- tables; the engine stays pure (its static becomes the no-DB fallback) and
-- ryuki-api persists/reads here via sqlx.
--
-- Unlike the DNS/firewall tables (which start empty because a reservation is
-- self-contained), IPAM is a two-entity domain: you reserve an IP *into* a
-- subnet, and a reserve mutates that subnet's live counters. So the subnets are
-- reference data that MUST exist for the feature to work — this migration seeds
-- the four demo subnets and five demo reservations with the exact values from
-- the engine's seed_data(), so DB mode renders identically to the static demo.
--
-- The id columns are the engine-generated string ids (TEXT PK). The subnet
-- status column stores the canonical CAPITALIZED serde string
-- ("Available"/"Exhausted"/"Reserved") so a row serializes byte-for-byte like
-- the engine IpamSubnet. reserved_at/expiry are the engine's ISO strings (kept
-- as TEXT to round-trip exactly).

CREATE TABLE IF NOT EXISTS ipam_subnets (
    id            TEXT PRIMARY KEY,
    cidr          TEXT NOT NULL,
    gateway       TEXT NOT NULL,
    vlan_id       INTEGER NOT NULL,
    site          TEXT NOT NULL,
    total_ips     INTEGER NOT NULL,
    used_ips      INTEGER NOT NULL,
    available_ips INTEGER NOT NULL,
    status        TEXT NOT NULL DEFAULT 'Available'
);

CREATE TABLE IF NOT EXISTS ip_reservations (
    id          TEXT PRIMARY KEY,
    ip_address  TEXT NOT NULL,
    subnet_id   TEXT NOT NULL REFERENCES ipam_subnets (id) ON DELETE CASCADE,
    hostname    TEXT NOT NULL,
    purpose     TEXT NOT NULL,
    reserved_by TEXT NOT NULL,
    reserved_at TEXT NOT NULL,
    expiry      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ipam_subnets_site ON ipam_subnets (site);
CREATE INDEX IF NOT EXISTS idx_ip_reservations_subnet ON ip_reservations (subnet_id);

-- Seed reference subnets (exact values from engine seed_data()).
INSERT INTO ipam_subnets (id, cidr, gateway, vlan_id, site, total_ips, used_ips, available_ips, status) VALUES
    ('subnet-defra-001', '10.42.10.0/24', '10.42.10.1', 110, 'DEFRA', 254, 60,  194, 'Available'),
    ('subnet-defra-002', '10.42.11.0/24', '10.42.11.1', 111, 'DEFRA', 254, 254, 0,   'Exhausted'),
    ('subnet-gblon-001', '10.42.20.0/24', '10.42.20.1', 210, 'GBLON', 254, 80,  174, 'Available'),
    ('subnet-nlams-001', '10.42.30.0/24', '10.42.30.1', 310, 'NLAMS', 254, 120, 134, 'Reserved')
ON CONFLICT (id) DO NOTHING;

-- Seed reservations (timestamps fixed; the static path keeps its dynamic ones).
INSERT INTO ip_reservations (id, ip_address, subnet_id, hostname, purpose, reserved_by, reserved_at, expiry) VALUES
    ('res-defra-001', '10.42.10.21', 'subnet-defra-001', 'portal-defra-01', 'Portal frontend', 'netops',   '2026-06-03T00:00:00+00:00', '2026-08-22T00:00:00+00:00'),
    ('res-defra-002', '10.42.10.22', 'subnet-defra-001', 'api-defra-01',    'API node',        'platform', '2026-06-05T00:00:00+00:00', '2026-09-03T00:00:00+00:00'),
    ('res-gblon-001', '10.42.20.21', 'subnet-gblon-001', 'portal-gblon-01', 'Portal frontend', 'netops',   '2026-06-04T00:00:00+00:00', '2026-09-02T00:00:00+00:00'),
    ('res-gblon-002', '10.42.20.45', 'subnet-gblon-001', 'legacy-gblon-01', 'Legacy service',  'ops',      '2026-05-14T00:00:00+00:00', '2026-06-28T00:00:00+00:00'),
    ('res-nlams-001', '10.42.30.21', 'subnet-nlams-001', 'portal-nlams-01', 'Portal frontend', 'netops',   '2026-06-06T00:00:00+00:00', '2026-09-04T00:00:00+00:00')
ON CONFLICT (id) DO NOTHING;
