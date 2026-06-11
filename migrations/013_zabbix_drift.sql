CREATE TABLE drift_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    site TEXT NOT NULL,
    expected_group TEXT NOT NULL,
    actual_group TEXT NOT NULL,
    expected_template TEXT NOT NULL,
    actual_template TEXT NOT NULL,
    expected_proxy TEXT NOT NULL,
    actual_proxy TEXT NOT NULL,
    drift_severity TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'detected',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO drift_reports (id, host_id, hostname, site, expected_group, actual_group, expected_template, actual_template, expected_proxy, actual_proxy, drift_severity, status) VALUES
    ('b0000000-0000-0000-0000-000000000001', 'host-love-srv-01', 'love-srv-01.contoso.com', 'LOVE', 'LOVE-Production-Servers', 'LOVE-Discovered-Hosts', 'Template-OS-Windows-Server-2022', 'Template-OS-Windows-Server-2019', 'zabbix-proxy-love', 'zabbix-proxy-love', 'high', 'detected'),
    ('b0000000-0000-0000-0000-000000000002', 'host-bur1-srv-02', 'bur1-srv-02.contoso.com', 'BUR1', 'BUR1-Production-Servers', 'BUR1-Production-Servers', 'Template-OS-Linux-RHEL-9', 'Template-OS-Linux-RHEL-8', 'zabbix-proxy-bur1', 'zabbix-proxy-bur1', 'medium', 'detected'),
    ('b0000000-0000-0000-0000-000000000003', 'host-ccss-srv-03', 'ccss-srv-03.contoso.com', 'CCSS', 'CCSS-DMZ-Servers', 'CCSS-Production-Servers', 'Template-OS-Windows-Server-2022', 'Template-OS-Windows-Server-2022', 'zabbix-proxy-ccss', 'zabbix-proxy-default', 'critical', 'detected'),
    ('b0000000-0000-0000-0000-000000000004', 'host-tor1-srv-04', 'tor1-srv-04.contoso.com', 'TOR1', 'TOR1-Production-Servers', 'TOR1-Production-Servers', 'Template-OS-Windows-Server-2022', 'Template-OS-Windows-Server-2022', 'zabbix-proxy-tor1', 'zabbix-proxy-tor1', 'medium', 'detected');
