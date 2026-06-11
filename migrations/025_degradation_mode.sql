CREATE TABLE site_status (
    site TEXT PRIMARY KEY,
    state TEXT NOT NULL DEFAULT 'healthy' CHECK (state IN ('healthy', 'degraded', 'unreachable', 'recovering')),
    api_status TEXT NOT NULL DEFAULT 'up' CHECK (api_status IN ('up', 'degraded', 'down')),
    db_status TEXT NOT NULL DEFAULT 'up' CHECK (db_status IN ('up', 'degraded', 'down')),
    degradation_reason TEXT,
    last_check TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE component_status (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site TEXT NOT NULL REFERENCES site_status(site) ON DELETE CASCADE,
    adapter_name TEXT NOT NULL CHECK (adapter_name IN ('vmware', 'hyperv', 'proxmox', 'nutanix', 'xen', 'kvm', 'veeam', 'zabbix', 'servicenow', 'commvault', 'rubrik', 'cohesity', 'netbackup')),
    status TEXT NOT NULL DEFAULT 'up' CHECK (status IN ('up', 'degraded', 'down')),
    last_check TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_site_status_state ON site_status(state);
CREATE INDEX idx_component_status_site ON component_status(site);
CREATE INDEX idx_component_status_adapter ON component_status(adapter_name);

INSERT INTO site_status (site, state, api_status, db_status, degradation_reason) VALUES
    ('DEFRA', 'healthy', 'up', 'up', NULL),
    ('GBLON', 'degraded', 'degraded', 'up', 'Hyper-V and Veeam adapters reporting degraded connectivity'),
    ('NLAMS', 'unreachable', 'down', 'down', 'Site NLAMS network unreachable, all components down');

INSERT INTO component_status (site, adapter_name, status) VALUES
    ('DEFRA', 'vmware', 'up'),
    ('DEFRA', 'hyperv', 'up'),
    ('DEFRA', 'proxmox', 'up'),
    ('DEFRA', 'nutanix', 'up'),
    ('DEFRA', 'xen', 'up'),
    ('DEFRA', 'kvm', 'up'),
    ('DEFRA', 'veeam', 'up'),
    ('DEFRA', 'zabbix', 'up'),
    ('DEFRA', 'servicenow', 'up'),
    ('DEFRA', 'commvault', 'up'),
    ('DEFRA', 'rubrik', 'up'),
    ('DEFRA', 'cohesity', 'up'),
    ('DEFRA', 'netbackup', 'up'),
    ('GBLON', 'vmware', 'up'),
    ('GBLON', 'hyperv', 'degraded'),
    ('GBLON', 'proxmox', 'up'),
    ('GBLON', 'nutanix', 'up'),
    ('GBLON', 'xen', 'up'),
    ('GBLON', 'kvm', 'up'),
    ('GBLON', 'veeam', 'degraded'),
    ('GBLON', 'zabbix', 'up'),
    ('GBLON', 'servicenow', 'up'),
    ('GBLON', 'commvault', 'up'),
    ('GBLON', 'rubrik', 'up'),
    ('GBLON', 'cohesity', 'up'),
    ('GBLON', 'netbackup', 'up'),
    ('NLAMS', 'vmware', 'down'),
    ('NLAMS', 'hyperv', 'down'),
    ('NLAMS', 'proxmox', 'down'),
    ('NLAMS', 'nutanix', 'down'),
    ('NLAMS', 'xen', 'down'),
    ('NLAMS', 'kvm', 'down'),
    ('NLAMS', 'veeam', 'down'),
    ('NLAMS', 'zabbix', 'down'),
    ('NLAMS', 'servicenow', 'down'),
    ('NLAMS', 'commvault', 'down'),
    ('NLAMS', 'rubrik', 'down'),
    ('NLAMS', 'cohesity', 'down'),
    ('NLAMS', 'netbackup', 'down');
