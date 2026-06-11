CREATE TABLE immutability_checks (
    id TEXT PRIMARY KEY,
    repository_name TEXT NOT NULL,
    repository_type TEXT NOT NULL CHECK (repository_type IN ('StoreOnce', 'HardenedLinux', 'ObjectStorage')),
    site TEXT NOT NULL,
    immutability_enabled BOOLEAN NOT NULL DEFAULT false,
    retention_lock_set BOOLEAN NOT NULL DEFAULT false,
    min_retention_days INTEGER NOT NULL DEFAULT 0,
    last_verified TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL DEFAULT 'AtRisk' CHECK (status IN ('Compliant', 'AtRisk', 'NonCompliant')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_immutability_site ON immutability_checks(site);
CREATE INDEX idx_immutability_status ON immutability_checks(status);
CREATE INDEX idx_immutability_repository_type ON immutability_checks(repository_type);

INSERT INTO immutability_checks (id, repository_name, repository_type, site, immutability_enabled, retention_lock_set, min_retention_days, last_verified, status) VALUES
    ('imm-00000000-0000-0000-0000-000000000001', 'repo-love-storeonce-01', 'StoreOnce', 'LOVE', true, true, 90, NOW() - INTERVAL '2 days', 'Compliant'),
    ('imm-00000000-0000-0000-0000-000000000002', 'repo-bur1-hlr-01', 'HardenedLinux', 'BUR1', true, false, 30, NOW() - INTERVAL '7 days', 'AtRisk'),
    ('imm-00000000-0000-0000-0000-000000000003', 'repo-ccss-objstore-01', 'ObjectStorage', 'CCSS', false, false, 0, NOW() - INTERVAL '14 days', 'NonCompliant'),
    ('imm-00000000-0000-0000-0000-000000000004', 'repo-tor1-storeonce-02', 'StoreOnce', 'TOR1', true, true, 60, NOW() - INTERVAL '1 day', 'Compliant');
