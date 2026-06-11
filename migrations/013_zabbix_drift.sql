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
    ('b0000000-0000-0000-0000-000000000001', 'host-defra-srv-01', 'defra-srv-01.contoso.com', 'DEFRA', 'DEFRA-Production-Servers', 'DEFRA-Discovered-Hosts', 'Template-OS-Windows-Server-2022', 'Template-OS-Windows-Server-2019', 'zabbix-proxy-defra', 'zabbix-proxy-defra', 'high', 'detected'),
    ('b0000000-0000-0000-0000-000000000002', 'host-gblon-srv-02', 'gblon-srv-02.contoso.com', 'GBLON', 'GBLON-Production-Servers', 'GBLON-Production-Servers', 'Template-OS-Linux-RHEL-9', 'Template-OS-Linux-RHEL-8', 'zabbix-proxy-gblon', 'zabbix-proxy-gblon', 'medium', 'detected'),
    ('b0000000-0000-0000-0000-000000000003', 'host-frpar-srv-03', 'frpar-srv-03.contoso.com', 'FRPAR', 'FRPAR-DMZ-Servers', 'FRPAR-Production-Servers', 'Template-OS-Windows-Server-2022', 'Template-OS-Windows-Server-2022', 'zabbix-proxy-frpar', 'zabbix-proxy-default', 'critical', 'detected'),
    ('b0000000-0000-0000-0000-000000000004', 'host-nlams-srv-04', 'nlams-srv-04.contoso.com', 'NLAMS', 'NLAMS-Production-Servers', 'NLAMS-Production-Servers', 'Template-OS-Windows-Server-2022', 'Template-OS-Windows-Server-2022', 'zabbix-proxy-nlams', 'zabbix-proxy-nlams', 'medium', 'detected');
