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
    adapter_name TEXT NOT NULL CHECK (adapter_name IN ('vmware', 'hyperv', 'proxmox', 'veeam', 'zabbix')),
    status TEXT NOT NULL DEFAULT 'up' CHECK (status IN ('up', 'degraded', 'down')),
    last_check TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_site_status_state ON site_status(state);
CREATE INDEX idx_component_status_site ON component_status(site);
CREATE INDEX idx_component_status_adapter ON component_status(adapter_name);

INSERT INTO site_status (site, state, api_status, db_status, degradation_reason) VALUES
    ('LOVE', 'healthy', 'up', 'up', NULL),
    ('BUR1', 'degraded', 'degraded', 'up', 'Hyper-V and Veeam adapters reporting degraded connectivity'),
    ('TOR1', 'unreachable', 'down', 'down', 'Site TOR1 network unreachable, all components down');

INSERT INTO component_status (site, adapter_name, status) VALUES
    ('LOVE', 'vmware', 'up'),
    ('LOVE', 'hyperv', 'up'),
    ('LOVE', 'proxmox', 'up'),
    ('LOVE', 'veeam', 'up'),
    ('LOVE', 'zabbix', 'up'),
    ('BUR1', 'vmware', 'up'),
    ('BUR1', 'hyperv', 'degraded'),
    ('BUR1', 'proxmox', 'up'),
    ('BUR1', 'veeam', 'degraded'),
    ('BUR1', 'zabbix', 'up'),
    ('TOR1', 'vmware', 'down'),
    ('TOR1', 'hyperv', 'down'),
    ('TOR1', 'proxmox', 'down'),
    ('TOR1', 'veeam', 'down'),
    ('TOR1', 'zabbix', 'down');
