CREATE TABLE approved_packages (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    vendor TEXT NOT NULL,
    package_type TEXT NOT NULL CHECK (package_type IN ('msi', 'exe', 'apt', 'rpm', 'script')),
    approved_by TEXT NOT NULL,
    approved_date DATE NOT NULL,
    site_scope TEXT NOT NULL DEFAULT 'all' CHECK (site_scope IN ('all', 'specific')),
    site_scope_list TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE software_deployments (
    id TEXT PRIMARY KEY,
    server_name TEXT NOT NULL,
    package_id TEXT NOT NULL REFERENCES approved_packages(id),
    package_name TEXT NOT NULL,
    target_version TEXT NOT NULL,
    scheduled_time TIMESTAMPTZ,
    requester TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Draft' CHECK (status IN ('Draft', 'Validated', 'Planned', 'Approved', 'Executing', 'Executed', 'Verified', 'Completed', 'Failed', 'Rejected')),
    approved_by TEXT,
    plan_json JSONB,
    executed_at TIMESTAMPTZ,
    verified_at TIMESTAMPTZ,
    evidence_json JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_software_deployments_server ON software_deployments(server_name);
CREATE INDEX idx_software_deployments_package ON software_deployments(package_id);
CREATE INDEX idx_software_deployments_status ON software_deployments(status);

INSERT INTO approved_packages (id, name, version, vendor, package_type, approved_by, approved_date, site_scope, site_scope_list) VALUES
    ('pkg-zabbix-agent', 'Zabbix Agent 7.0', '7.0.4', 'Zabbix LLC', 'msi', 'security-team', '2026-05-15', 'all', '{}'),
    ('pkg-crowdstrike-sensor', 'CrowdStrike Falcon Sensor', '7.11.0', 'CrowdStrike', 'exe', 'security-team', '2026-05-20', 'all', '{}'),
    ('pkg-veeam-agent', 'Veeam Agent for Windows', '6.1.2', 'Veeam Software', 'msi', 'backup-team', '2026-04-10', 'specific', '{"LOVE","BUR1","TOR1"}'),
    ('pkg-qualys-agent', 'Qualys Cloud Agent', '5.2.0', 'Qualys Inc.', 'rpm', 'compliance-team', '2026-06-01', 'all', '{}'),
    ('pkg-ms-teams', 'Microsoft Teams', '24091.214.2846.4154', 'Microsoft', 'exe', 'workplace-team', '2026-05-28', 'all', '{}');

INSERT INTO software_deployments (id, server_name, package_id, package_name, target_version, scheduled_time, requester, status, approved_by, executed_at, verified_at) VALUES
    ('dep-001', 'w-love-srv-01', 'pkg-zabbix-agent', 'Zabbix Agent 7.0', '7.0.4', '2026-06-15 22:00:00Z', 'ops-team', 'Completed', 'admin', '2026-06-14 22:05:00Z', '2026-06-14 22:12:00Z'),
    ('dep-002', 'l-bur1-srv-03', 'pkg-crowdstrike-sensor', 'CrowdStrike Falcon Sensor', '7.11.0', '2026-06-18 23:00:00Z', 'security-team', 'Draft', NULL, NULL, NULL),
    ('dep-003', 'w-tor1-srv-02', 'pkg-qualys-agent', 'Qualys Cloud Agent', '5.2.0', '2026-06-20 01:00:00Z', 'compliance-team', 'Draft', NULL, NULL, NULL);
