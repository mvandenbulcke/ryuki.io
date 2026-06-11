CREATE TABLE ad_computers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    site TEXT NOT NULL,
    ou_path TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Disabled', 'Quarantined', 'Deleted')),
    last_logon TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    os TEXT NOT NULL DEFAULT 'Windows Server 2022',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX idx_ad_computers_site ON ad_computers(site);
CREATE INDEX idx_ad_computers_status ON ad_computers(status);
CREATE INDEX idx_ad_computers_name ON ad_computers(name);

INSERT INTO ad_computers (name, site, ou_path, status, last_logon, os, metadata) VALUES
    ('LOVE-SRV-01', 'LOVE', 'OU=Servers,OU=LOVE,DC=corp,DC=local', 'Active', NOW(), 'Windows Server 2022', '{"role": "web-server"}'),
    ('LOVE-DC-01', 'LOVE', 'OU=Domain Controllers,DC=corp,DC=local', 'Active', NOW(), 'Windows Server 2022', '{"role": "domain-controller"}'),
    ('BUR1-SRV-01', 'BUR1', 'OU=Servers,OU=BUR1,DC=corp,DC=local', 'Active', NOW(), 'Windows Server 2019', '{"role": "app-server"}'),
    ('BUR1-SRV-02', 'BUR1', 'OU=Servers,OU=BUR1,DC=corp,DC=local', 'Disabled', NOW() - INTERVAL '150 days', 'Windows Server 2016', '{"role": "legacy-app", "disabled_reason": "Decommission pending review"}'),
    ('TOR1-TEST-01', 'TOR1', 'OU=Testing,OU=TOR1,DC=corp,DC=local', 'Quarantined', NOW() - INTERVAL '30 days', 'Windows Server 2022', '{"role": "test-server", "quarantine_reason": "Security incident investigation"}');
