CREATE TABLE noisy_triggers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    trigger_name TEXT NOT NULL,
    host TEXT NOT NULL,
    severity TEXT NOT NULL,
    event_count_last_24h INTEGER NOT NULL DEFAULT 0,
    avg_interval_minutes DOUBLE PRECISION NOT NULL DEFAULT 0,
    flapping BOOLEAN NOT NULL DEFAULT false,
    suggested_action TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'UnderReview', 'Suppressed', 'Resolved')),
    suppress_until TIMESTAMPTZ,
    suppress_reason TEXT,
    resolution TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_noisy_triggers_host ON noisy_triggers(host);
CREATE INDEX idx_noisy_triggers_status ON noisy_triggers(status);
CREATE INDEX idx_noisy_triggers_flapping ON noisy_triggers(flapping);

INSERT INTO noisy_triggers (id, trigger_name, host, severity, event_count_last_24h, avg_interval_minutes, flapping, suggested_action, status, suppress_until, suppress_reason, resolution, created_at) VALUES
    ('e0000100-1000-1000-1000-000000000001', 'High CPU utilization', 'srv-defra-app01.corp.local', 'warning', 47, 30.6, false, 'Adjust threshold from 80% to 90% for this host class', 'Active', NULL, NULL, NULL, NOW() - INTERVAL '24 hours'),
    ('e0000100-1000-1000-1000-000000000002', 'ICMP ping loss', 'srv-gblon-net01.corp.local', 'disaster', 183, 7.8, true, 'Correlate with known network maintenance window GBLON-SW-UPGRADE', 'Active', NULL, NULL, NULL, NOW() - INTERVAL '6 hours'),
    ('e0000100-1000-1000-1000-000000000003', 'Disk space low', 'srv-nlams-fs01.corp.local', 'average', 12, 120.0, false, 'Add maintenance window for scheduled log rotation', 'UnderReview', NULL, NULL, NULL, NOW() - INTERVAL '12 hours'),
    ('e0000100-1000-1000-1000-000000000004', 'Service port flapping', 'srv-frpar-web01.corp.local', 'high', 89, 4.2, true, 'Adjust threshold sensitivity for port availability check', 'Suppressed', NOW() + INTERVAL '24 hours', 'Known intermittent issue during LB migration; suppressed for 48h', NULL, NOW() - INTERVAL '48 hours'),
    ('e0000100-1000-1000-1000-000000000005', 'SSL certificate expiry warning', 'srv-defra-lb01.corp.local', 'warning', 1, 1440.0, false, 'Correlate with certificate lifecycle management — cert renewed, trigger auto-resolved', 'Resolved', NULL, NULL, 'Certificate renewed on 2026-06-10; trigger cleared after next Zabbix discovery cycle', NOW() - INTERVAL '5 days');
