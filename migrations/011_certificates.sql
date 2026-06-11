CREATE TABLE certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    common_name TEXT NOT NULL,
    subject TEXT,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_to TIMESTAMPTZ NOT NULL,
    service_type TEXT NOT NULL,
    hostname TEXT NOT NULL,
    site TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO certificates (common_name, subject, valid_from, valid_to, service_type, hostname, site, status) VALUES
    ('*.corp.local', 'CN=*.corp.local', NOW() - INTERVAL '30 days', NOW() + INTERVAL '60 days', 'IIS', 'web01.corp.local', 'BUR1', 'Expiring'),
    ('vcenter.corp.local', 'CN=vcenter.corp.local', NOW() - INTERVAL '180 days', NOW() + INTERVAL '185 days', 'VMware', 'vcenter.corp.local', 'BUR1', 'Active'),
    ('esxi01.corp.local', 'CN=esxi01.corp.local', NOW() - INTERVAL '400 days', NOW() - INTERVAL '30 days', 'ESXi', 'esxi01.corp.local', 'ALBI', 'Expired');
