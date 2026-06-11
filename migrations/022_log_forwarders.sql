CREATE TABLE log_forwarders (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    source_type TEXT NOT NULL CHECK (source_type IN ('windows-event-log', 'syslog', 'auditd', 'iis', 'apache')),
    site TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'not-configured' CHECK (status IN ('not-configured', 'configured', 'active', 'failed')),
    log_volume_per_day_mb INTEGER NOT NULL DEFAULT 0,
    retention_days INTEGER NOT NULL DEFAULT 90,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_log_forwarders_hostname ON log_forwarders(hostname);
CREATE INDEX idx_log_forwarders_site ON log_forwarders(site);
CREATE INDEX idx_log_forwarders_status ON log_forwarders(status);
CREATE INDEX idx_log_forwarders_source_type ON log_forwarders(source_type);

INSERT INTO log_forwarders (id, hostname, source_type, site, status, log_volume_per_day_mb, retention_days) VALUES
    ('ls-00000000-0000-0000-0000-000000000001', 'srv-love-01.ryuki.local', 'windows-event-log', 'LOVE', 'active', 450, 90),
    ('ls-00000000-0000-0000-0000-000000000002', 'srv-love-02.ryuki.local', 'syslog', 'LOVE', 'active', 120, 90),
    ('ls-00000000-0000-0000-0000-000000000003', 'srv-bur1-01.ryuki.local', 'windows-event-log', 'BUR1', 'configured', 380, 60),
    ('ls-00000000-0000-0000-0000-000000000004', 'srv-ccss-web.ryuki.local', 'iis', 'CCSS', 'failed', 2100, 30),
    ('ls-00000000-0000-0000-0000-000000000005', 'srv-tor1-lnx.ryuki.local', 'auditd', 'TOR1', 'not-configured', 85, 90),
    ('ls-00000000-0000-0000-0000-000000000006', 'srv-love-web.ryuki.local', 'iis', 'LOVE', 'active', 3200, 90),
    ('ls-00000000-0000-0000-0000-000000000007', 'srv-bur1-lnx.ryuki.local', 'syslog', 'BUR1', 'active', 90, 90);
