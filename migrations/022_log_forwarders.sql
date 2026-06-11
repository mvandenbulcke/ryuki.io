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
    ('ls-00000000-0000-0000-0000-000000000001', 'srv-defra-01.example.local', 'windows-event-log', 'DEFRA', 'active', 450, 90),
    ('ls-00000000-0000-0000-0000-000000000002', 'srv-defra-02.example.local', 'syslog', 'DEFRA', 'active', 120, 90),
    ('ls-00000000-0000-0000-0000-000000000003', 'srv-gblon-01.example.local', 'windows-event-log', 'GBLON', 'configured', 380, 60),
    ('ls-00000000-0000-0000-0000-000000000004', 'srv-frpar-web.example.local', 'iis', 'FRPAR', 'failed', 2100, 30),
    ('ls-00000000-0000-0000-0000-000000000005', 'srv-nlams-lnx.example.local', 'auditd', 'NLAMS', 'not-configured', 85, 90),
    ('ls-00000000-0000-0000-0000-000000000006', 'srv-defra-web.example.local', 'iis', 'DEFRA', 'active', 3200, 90),
    ('ls-00000000-0000-0000-0000-000000000007', 'srv-gblon-lnx.example.local', 'syslog', 'GBLON', 'active', 90, 90);
