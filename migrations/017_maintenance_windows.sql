CREATE TABLE maintenance_windows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site TEXT NOT NULL,
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ NOT NULL,
    reason TEXT NOT NULL,
    affected_cis TEXT[] NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'Planned',
    created_by TEXT NOT NULL DEFAULT 'system',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_maintenance_windows_site ON maintenance_windows(site);
CREATE INDEX idx_maintenance_windows_times ON maintenance_windows(start_time, end_time);
CREATE INDEX idx_maintenance_windows_status ON maintenance_windows(status);

INSERT INTO maintenance_windows (id, site, start_time, end_time, reason, affected_cis, status, created_by) VALUES
    ('c0000000-0000-0000-0000-000000000001', 'LOVE', '2026-06-15 22:00:00+00', '2026-06-16 06:00:00+00', 'Scheduled SQL Server patching', ARRAY['sql-love-01', 'sql-love-02'], 'Planned', 'patch-team'),
    ('c0000000-0000-0000-0000-000000000002', 'BUR1', '2026-06-17 00:00:00+00', '2026-06-17 04:00:00+00', 'Hypervisor firmware upgrade', ARRAY['esx-bur1-01', 'esx-bur1-02', 'esx-bur1-03'], 'Planned', 'infra-team'),
    ('c0000000-0000-0000-0000-000000000003', 'CCSS', '2026-06-20 01:00:00+00', '2026-06-20 07:00:00+00', 'Network switch firmware upgrade', ARRAY['sw-ccss-core-01', 'sw-ccss-core-02'], 'Planned', 'network-team'),
    ('c0000000-0000-0000-0000-000000000004', 'LOVE', '2026-06-28 02:00:00+00', '2026-06-28 04:00:00+00', 'Load balancer certificate rotation', ARRAY['lb-love-01'], 'Planned', 'sec-team');
