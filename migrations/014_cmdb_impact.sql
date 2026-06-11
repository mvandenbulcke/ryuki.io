CREATE TABLE configuration_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ci_name TEXT NOT NULL UNIQUE,
    ci_type TEXT NOT NULL CHECK (ci_type IN ('Server', 'Application', 'Database', 'Network', 'Storage')),
    criticality TEXT NOT NULL CHECK (criticality IN ('Low', 'Medium', 'High', 'Critical')),
    site TEXT NOT NULL,
    owner TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE ci_relationships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_ci TEXT NOT NULL REFERENCES configuration_items(ci_name) ON DELETE CASCADE,
    target_ci TEXT NOT NULL REFERENCES configuration_items(ci_name) ON DELETE CASCADE,
    relationship_type TEXT NOT NULL CHECK (relationship_type IN ('DependsOn', 'Hosts', 'ConnectsTo')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (source_ci, target_ci, relationship_type)
);

CREATE INDEX idx_configuration_items_ci_type ON configuration_items(ci_type);
CREATE INDEX idx_configuration_items_site ON configuration_items(site);
CREATE INDEX idx_ci_relationships_source ON ci_relationships(source_ci);
CREATE INDEX idx_ci_relationships_target ON ci_relationships(target_ci);

INSERT INTO configuration_items (ci_name, ci_type, criticality, site, owner) VALUES
    ('app-portal', 'Application', 'Critical', 'DEFRA', 'app-team-portal'),
    ('app-billing', 'Application', 'High', 'DEFRA', 'app-team-billing'),
    ('env-prod-defra', 'Server', 'Critical', 'DEFRA', 'infra-team'),
    ('db-portal', 'Database', 'Critical', 'DEFRA', 'dba-team'),
    ('db-billing', 'Database', 'High', 'DEFRA', 'dba-team'),
    ('vm-defra-web01', 'Server', 'High', 'DEFRA', 'infra-team'),
    ('vm-defra-web02', 'Server', 'High', 'DEFRA', 'infra-team'),
    ('vm-defra-db01', 'Server', 'Critical', 'DEFRA', 'infra-team'),
    ('vm-defra-db02', 'Server', 'High', 'DEFRA', 'infra-team'),
    ('san-defra-tier1', 'Storage', 'Critical', 'DEFRA', 'storage-team'),
    ('san-defra-tier2', 'Storage', 'High', 'DEFRA', 'storage-team'),
    ('net-defra-vlan100', 'Network', 'High', 'DEFRA', 'network-team'),
    ('net-defra-vlan200', 'Network', 'High', 'DEFRA', 'network-team');

INSERT INTO ci_relationships (source_ci, target_ci, relationship_type) VALUES
    ('app-portal', 'env-prod-defra', 'DependsOn'),
    ('app-portal', 'db-portal', 'DependsOn'),
    ('app-billing', 'env-prod-defra', 'DependsOn'),
    ('app-billing', 'db-billing', 'DependsOn'),
    ('env-prod-defra', 'vm-defra-web01', 'Hosts'),
    ('env-prod-defra', 'vm-defra-web02', 'Hosts'),
    ('env-prod-defra', 'san-defra-tier1', 'DependsOn'),
    ('db-portal', 'vm-defra-db01', 'DependsOn'),
    ('db-portal', 'san-defra-tier1', 'DependsOn'),
    ('db-billing', 'vm-defra-db02', 'DependsOn'),
    ('db-billing', 'san-defra-tier2', 'DependsOn'),
    ('vm-defra-web01', 'san-defra-tier1', 'DependsOn'),
    ('vm-defra-web01', 'net-defra-vlan100', 'ConnectsTo'),
    ('vm-defra-web02', 'san-defra-tier1', 'DependsOn'),
    ('vm-defra-web02', 'net-defra-vlan100', 'ConnectsTo'),
    ('vm-defra-db01', 'san-defra-tier1', 'DependsOn'),
    ('vm-defra-db01', 'net-defra-vlan200', 'ConnectsTo'),
    ('vm-defra-db02', 'san-defra-tier2', 'DependsOn'),
    ('vm-defra-db02', 'net-defra-vlan200', 'ConnectsTo');
