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
    ('DEFRA-SRV-01', 'DEFRA', 'OU=Servers,OU=DEFRA,DC=corp,DC=local', 'Active', NOW(), 'Windows Server 2022', '{"role": "web-server"}'),
    ('DEFRA-DC-01', 'DEFRA', 'OU=Domain Controllers,DC=corp,DC=local', 'Active', NOW(), 'Windows Server 2022', '{"role": "domain-controller"}'),
    ('GBLON-SRV-01', 'GBLON', 'OU=Servers,OU=GBLON,DC=corp,DC=local', 'Active', NOW(), 'Windows Server 2019', '{"role": "app-server"}'),
    ('GBLON-SRV-02', 'GBLON', 'OU=Servers,OU=GBLON,DC=corp,DC=local', 'Disabled', NOW() - INTERVAL '150 days', 'Windows Server 2016', '{"role": "legacy-app", "disabled_reason": "Decommission pending review"}'),
    ('NLAMS-TEST-01', 'NLAMS', 'OU=Testing,OU=NLAMS,DC=corp,DC=local', 'Quarantined', NOW() - INTERVAL '30 days', 'Windows Server 2022', '{"role": "test-server", "quarantine_reason": "Security incident investigation"}');
