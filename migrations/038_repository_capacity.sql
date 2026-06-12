CREATE TABLE backup_repositories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    repository_type TEXT NOT NULL CHECK (repository_type IN ('store-once', 'data-domain', 'object-storage', 'hardened-linux')),
    site TEXT NOT NULL,
    total_capacity_tb NUMERIC(10, 2) NOT NULL,
    used_capacity_tb NUMERIC(10, 2) NOT NULL,
    growth_rate_gb_per_day NUMERIC(8, 2) NOT NULL DEFAULT 0,
    days_until_full NUMERIC(8, 1),
    last_forecast TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL DEFAULT 'healthy' CHECK (status IN ('healthy', 'warning', 'critical')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (site, name)
);

CREATE TABLE capacity_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES backup_repositories(id) ON DELETE CASCADE,
    used_capacity_tb NUMERIC(10, 2) NOT NULL,
    utilization_pct NUMERIC(5, 1) NOT NULL,
    days_until_full NUMERIC(8, 1),
    status TEXT NOT NULL DEFAULT 'healthy' CHECK (status IN ('healthy', 'warning', 'critical')),
    snapshot_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_backup_repositories_site ON backup_repositories(site);
CREATE INDEX idx_backup_repositories_type ON backup_repositories(repository_type);
CREATE INDEX idx_backup_repositories_status ON backup_repositories(site, status);
CREATE INDEX idx_capacity_history_repo ON capacity_history(repository_id);
CREATE INDEX idx_capacity_history_snapshot ON capacity_history(repository_id, snapshot_at DESC);

INSERT INTO backup_repositories (id, name, repository_type, site, total_capacity_tb, used_capacity_tb, growth_rate_gb_per_day, days_until_full, last_forecast, status)
VALUES
    ('e0000380-3800-3800-3800-000000000001', 'defra-storeonce-01', 'store-once', 'DEFRA', 200.00, 178.00, 3.50, 6.3, '2026-06-11 08:00:00+00', 'critical'),
    ('e0000380-3800-3800-3800-000000000002', 'defra-datadomain-01', 'data-domain', 'DEFRA', 150.00, 120.00, 2.10, 14.3, '2026-06-11 08:00:00+00', 'warning'),
    ('e0000380-3800-3800-3800-000000000003', 'gblon-storeonce-01', 'store-once', 'GBLON', 250.00, 190.00, 1.80, 33.3, '2026-06-11 08:00:00+00', 'healthy'),
    ('e0000380-3800-3800-3800-000000000004', 'gblon-hardened-01', 'hardened-linux', 'GBLON', 500.00, 120.00, 4.20, 90.5, '2026-06-11 08:00:00+00', 'healthy');

INSERT INTO capacity_history (id, repository_id, used_capacity_tb, utilization_pct, days_until_full, status, snapshot_at)
VALUES
    ('a0000380-3800-3800-3800-000000000001', 'e0000380-3800-3800-3800-000000000001', 170.00, 85.0, 8.6, 'warning', '2026-05-11 08:00:00+00'),
    ('a0000380-3800-3800-3800-000000000002', 'e0000380-3800-3800-3800-000000000001', 174.00, 87.0, 7.4, 'warning', '2026-05-25 08:00:00+00'),
    ('a0000380-3800-3800-3800-000000000003', 'e0000380-3800-3800-3800-000000000001', 178.00, 89.0, 6.3, 'critical', '2026-06-11 08:00:00+00'),
    ('a0000380-3800-3800-3800-000000000004', 'e0000380-3800-3800-3800-000000000002', 115.00, 76.7, 16.7, 'warning', '2026-05-11 08:00:00+00'),
    ('a0000380-3800-3800-3800-000000000005', 'e0000380-3800-3800-3800-000000000002', 118.00, 78.7, 15.2, 'warning', '2026-05-25 08:00:00+00'),
    ('a0000380-3800-3800-3800-000000000006', 'e0000380-3800-3800-3800-000000000002', 120.00, 80.0, 14.3, 'warning', '2026-06-11 08:00:00+00'),
    ('a0000380-3800-3800-3800-000000000007', 'e0000380-3800-3800-3800-000000000003', 180.00, 72.0, 38.9, 'healthy', '2026-05-11 08:00:00+00'),
    ('a0000380-3800-3800-3800-000000000008', 'e0000380-3800-3800-3800-000000000003', 185.00, 74.0, 36.1, 'healthy', '2026-05-25 08:00:00+00'),
    ('a0000380-3800-3800-3800-000000000009', 'e0000380-3800-3800-3800-000000000003', 190.00, 76.0, 33.3, 'healthy', '2026-06-11 08:00:00+00'),
    ('a0000380-3800-3800-3800-00000000000a', 'e0000380-3800-3800-3800-000000000004', 110.00, 22.0, 92.9, 'healthy', '2026-05-11 08:00:00+00'),
    ('a0000380-3800-3800-3800-00000000000b', 'e0000380-3800-3800-3800-000000000004', 115.00, 23.0, 91.7, 'healthy', '2026-05-25 08:00:00+00'),
    ('a0000380-3800-3800-3800-00000000000c', 'e0000380-3800-3800-3800-000000000004', 120.00, 24.0, 90.5, 'healthy', '2026-06-11 08:00:00+00');
