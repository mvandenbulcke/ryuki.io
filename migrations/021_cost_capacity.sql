CREATE TABLE site_capacity (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site TEXT NOT NULL UNIQUE,
    total_cpu_cores INTEGER NOT NULL,
    used_cpu_cores INTEGER NOT NULL,
    total_memory_gb INTEGER NOT NULL,
    used_memory_gb INTEGER NOT NULL,
    total_storage_gb INTEGER NOT NULL,
    used_storage_gb INTEGER NOT NULL,
    vm_count INTEGER NOT NULL DEFAULT 0,
    cpu_utilization_pct NUMERIC(5,1) NOT NULL,
    memory_utilization_pct NUMERIC(5,1) NOT NULL,
    monthly_cost NUMERIC(10,2) NOT NULL DEFAULT 0,
    forecast_cpu_6m_pct NUMERIC(5,1),
    forecast_memory_6m_pct NUMERIC(5,1),
    forecast_storage_6m_pct NUMERIC(5,1),
    snapshot_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE vm_utilization (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vm_name TEXT NOT NULL,
    site TEXT NOT NULL,
    cluster_name TEXT NOT NULL,
    cpu_cores INTEGER NOT NULL,
    memory_gb INTEGER NOT NULL,
    storage_gb INTEGER NOT NULL,
    cpu_usage_pct NUMERIC(5,1) NOT NULL,
    memory_usage_pct NUMERIC(5,1) NOT NULL,
    monthly_cost NUMERIC(10,2) NOT NULL,
    idle BOOLEAN NOT NULL DEFAULT false,
    oversized BOOLEAN NOT NULL DEFAULT false,
    orphaned_disk_gb INTEGER NOT NULL DEFAULT 0,
    snapshot_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (site, vm_name)
);

CREATE INDEX idx_vm_utilization_site ON vm_utilization(site);
CREATE INDEX idx_vm_utilization_cluster ON vm_utilization(site, cluster_name);
CREATE INDEX idx_vm_utilization_idle ON vm_utilization(site) WHERE idle = true;
CREATE INDEX idx_vm_utilization_oversized ON vm_utilization(site) WHERE oversized = true;

INSERT INTO site_capacity (id, site, total_cpu_cores, used_cpu_cores, total_memory_gb, used_memory_gb, total_storage_gb, used_storage_gb, vm_count, cpu_utilization_pct, memory_utilization_pct, monthly_cost, forecast_cpu_6m_pct, forecast_memory_6m_pct, forecast_storage_6m_pct) VALUES
    ('c0000300-3000-3000-3000-000000000001', 'LOVE', 56, 24, 228, 100, 1640, 1640, 10, 51.5, 48.6, 3245.00, 62.3, 57.6, 62.4),
    ('c0000300-3000-3000-3000-000000000002', 'BUR1', 62, 24, 248, 107, 1860, 1860, 8, 42.8, 40.5, 2980.00, 54.6, 49.5, 55.1);

INSERT INTO vm_utilization (id, vm_name, site, cluster_name, cpu_cores, memory_gb, storage_gb, cpu_usage_pct, memory_usage_pct, monthly_cost, idle, oversized, orphaned_disk_gb) VALUES
    ('d0000300-3000-3000-3000-000000000001', 'love-srv-01', 'LOVE', 'love-general-cluster', 8, 32, 200, 72.5, 65.0, 291.40, false, false, 0),
    ('d0000300-3000-3000-3000-000000000002', 'love-srv-02', 'LOVE', 'love-general-cluster', 4, 16, 100, 18.2, 22.1, 153.20, false, false, 0),
    ('d0000300-3000-3000-3000-000000000003', 'love-srv-03', 'LOVE', 'love-general-cluster', 16, 64, 500, 85.3, 78.0, 524.80, false, false, 0),
    ('d0000300-3000-3000-3000-000000000004', 'love-db-01', 'LOVE', 'love-db-cluster', 12, 48, 400, 91.2, 88.5, 429.60, false, false, 0),
    ('d0000300-3000-3000-3000-000000000005', 'love-web-01', 'LOVE', 'love-web-cluster', 2, 8, 80, 12.0, 35.0, 117.00, false, true, 0),
    ('d0000300-3000-3000-3000-000000000006', 'love-web-02', 'LOVE', 'love-web-cluster', 2, 8, 80, 14.0, 31.0, 117.00, false, true, 0),
    ('d0000300-3000-3000-3000-000000000007', 'love-dev-01', 'LOVE', 'love-general-cluster', 4, 16, 100, 2.1, 5.3, 153.20, true, false, 0),
    ('d0000300-3000-3000-3000-000000000008', 'love-dev-02', 'LOVE', 'love-general-cluster', 4, 16, 120, 3.5, 6.2, 154.80, true, false, 50),
    ('d0000300-3000-3000-3000-000000000009', 'love-legacy-01', 'LOVE', 'love-general-cluster', 2, 4, 60, 95.0, 92.0, 88.60, false, false, 0),
    ('d0000300-3000-3000-3000-00000000000a', 'love-dc-01', 'LOVE', 'love-general-cluster', 4, 16, 100, 45.0, 48.0, 153.20, false, false, 0),
    ('d0000300-3000-3000-3000-00000000000b', 'bur1-srv-01', 'BUR1', 'bur1-general-cluster', 8, 32, 200, 68.0, 60.0, 291.40, false, false, 0),
    ('d0000300-3000-3000-3000-00000000000c', 'bur1-srv-02', 'BUR1', 'bur1-general-cluster', 4, 16, 100, 22.0, 28.0, 153.20, false, false, 0),
    ('d0000300-3000-3000-3000-00000000000d', 'bur1-srv-03', 'BUR1', 'bur1-general-cluster', 16, 64, 500, 80.0, 75.0, 524.80, false, false, 0),
    ('d0000300-3000-3000-3000-00000000000e', 'bur1-db-01', 'BUR1', 'bur1-db-cluster', 12, 48, 400, 88.0, 82.0, 429.60, false, false, 0),
    ('d0000300-3000-3000-3000-00000000000f', 'bur1-dr-01', 'BUR1', 'bur1-dr-cluster', 8, 32, 300, 3.0, 4.5, 299.40, true, false, 0),
    ('d0000300-3000-3000-3000-000000000010', 'bur1-web-01', 'BUR1', 'bur1-web-cluster', 2, 8, 60, 18.0, 42.0, 115.40, false, true, 0),
    ('d0000300-3000-3000-3000-000000000011', 'bur1-qa-01', 'BUR1', 'bur1-general-cluster', 4, 16, 100, 4.0, 7.0, 153.20, true, false, 0),
    ('d0000300-3000-3000-3000-000000000012', 'bur1-qa-02', 'BUR1', 'bur1-general-cluster', 8, 32, 200, 5.0, 8.5, 299.40, true, true, 100);
