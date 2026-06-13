-- 048_dns_records.sql — durable DNS records (P1 persistence sweep, slice 1).
--
-- BEFORE this wave the DNS/IPAM domain kept its records in a process-local
-- `OnceLock<Mutex<DnsIpamStore>>` engine static, re-seeded with demo fixtures
-- on every restart — so a record created through POST /api/network/dns/records
-- vanished when the API restarted. This is the first concrete slice of the
-- broader "engines reset on restart" gap (the same shape as the durable request
-- / audit work in migrations 046-047): the engine stays pure (the static is now
-- only the no-DB fallback), and ryuki-api persists/reads here via sqlx.
--
-- The id is the engine-generated "dns-<site>-<hex>" string, so it is the TEXT
-- primary key (not a uuid). record_type / status are stored as their canonical
-- serde strings ("A".."SRV" / "Pending"|"Active"|"Deprecated") so a DB row
-- serializes byte-for-byte like the engine's DnsRecord on read.

CREATE TABLE IF NOT EXISTS dns_records (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    record_type TEXT NOT NULL,
    value       TEXT NOT NULL,
    zone        TEXT NOT NULL,
    ttl         INTEGER NOT NULL,
    site        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'Pending',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The list endpoint filters by site and/or record_type.
CREATE INDEX IF NOT EXISTS idx_dns_records_site ON dns_records (site);
CREATE INDEX IF NOT EXISTS idx_dns_records_record_type ON dns_records (record_type);
