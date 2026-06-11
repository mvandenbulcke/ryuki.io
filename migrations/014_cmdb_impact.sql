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
    ('app-portal', 'Application', 'Critical', 'LOVE', 'app-team-portal'),
    ('app-billing', 'Application', 'High', 'LOVE', 'app-team-billing'),
    ('env-prod-love', 'Server', 'Critical', 'LOVE', 'infra-team'),
    ('db-portal', 'Database', 'Critical', 'LOVE', 'dba-team'),
    ('db-billing', 'Database', 'High', 'LOVE', 'dba-team'),
    ('vm-love-web01', 'Server', 'High', 'LOVE', 'infra-team'),
    ('vm-love-web02', 'Server', 'High', 'LOVE', 'infra-team'),
    ('vm-love-db01', 'Server', 'Critical', 'LOVE', 'infra-team'),
    ('vm-love-db02', 'Server', 'High', 'LOVE', 'infra-team'),
    ('san-love-tier1', 'Storage', 'Critical', 'LOVE', 'storage-team'),
    ('san-love-tier2', 'Storage', 'High', 'LOVE', 'storage-team'),
    ('net-love-vlan100', 'Network', 'High', 'LOVE', 'network-team'),
    ('net-love-vlan200', 'Network', 'High', 'LOVE', 'network-team');

INSERT INTO ci_relationships (source_ci, target_ci, relationship_type) VALUES
    ('app-portal', 'env-prod-love', 'DependsOn'),
    ('app-portal', 'db-portal', 'DependsOn'),
    ('app-billing', 'env-prod-love', 'DependsOn'),
    ('app-billing', 'db-billing', 'DependsOn'),
    ('env-prod-love', 'vm-love-web01', 'Hosts'),
    ('env-prod-love', 'vm-love-web02', 'Hosts'),
    ('env-prod-love', 'san-love-tier1', 'DependsOn'),
    ('db-portal', 'vm-love-db01', 'DependsOn'),
    ('db-portal', 'san-love-tier1', 'DependsOn'),
    ('db-billing', 'vm-love-db02', 'DependsOn'),
    ('db-billing', 'san-love-tier2', 'DependsOn'),
    ('vm-love-web01', 'san-love-tier1', 'DependsOn'),
    ('vm-love-web01', 'net-love-vlan100', 'ConnectsTo'),
    ('vm-love-web02', 'san-love-tier1', 'DependsOn'),
    ('vm-love-web02', 'net-love-vlan100', 'ConnectsTo'),
    ('vm-love-db01', 'san-love-tier1', 'DependsOn'),
    ('vm-love-db01', 'net-love-vlan200', 'ConnectsTo'),
    ('vm-love-db02', 'san-love-tier2', 'DependsOn'),
    ('vm-love-db02', 'net-love-vlan200', 'ConnectsTo');
