CREATE TABLE sql_deployments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_name TEXT NOT NULL,
    sql_version TEXT NOT NULL CHECK (sql_version IN ('2019', '2022')),
    edition TEXT NOT NULL CHECK (edition IN ('Standard', 'Enterprise', 'Developer')),
    cpu INTEGER NOT NULL CHECK (cpu >= 1),
    memory_gb INTEGER NOT NULL CHECK (memory_gb >= 2),
    data_disk_gb INTEGER NOT NULL CHECK (data_disk_gb >= 10),
    log_disk_gb INTEGER NOT NULL CHECK (log_disk_gb >= 10),
    tempdb_disk_gb INTEGER NOT NULL CHECK (tempdb_disk_gb >= 10),
    collation TEXT NOT NULL DEFAULT 'SQL_Latin1_General_CP1_CI_AS',
    service_account TEXT NOT NULL,
    site TEXT NOT NULL,
    cluster_mode TEXT NOT NULL CHECK (cluster_mode IN ('Standalone', 'FCI', 'AG')),
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN (
        'draft', 'validated', 'planned', 'installing', 'configuring',
        'verified', 'backed-up', 'monitored', 'completed', 'failed'
    )),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (site, instance_name)
);

CREATE TABLE sql_deployment_operations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    deployment_id UUID NOT NULL REFERENCES sql_deployments(id) ON DELETE CASCADE,
    operation_type TEXT NOT NULL CHECK (operation_type IN (
        'plan', 'validate', 'install', 'configure', 'verify',
        'backup', 'monitoring'
    )),
    status TEXT NOT NULL DEFAULT 'completed' CHECK (status IN ('running', 'completed', 'failed')),
    payload JSONB,
    result JSONB,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX idx_sql_deployments_site ON sql_deployments(site);
CREATE INDEX idx_sql_deployments_status ON sql_deployments(status);
CREATE INDEX idx_sql_deployments_cluster_mode ON sql_deployments(site, cluster_mode);
CREATE INDEX idx_sql_deployment_operations_deployment ON sql_deployment_operations(deployment_id);
CREATE INDEX idx_sql_deployment_operations_type ON sql_deployment_operations(deployment_id, operation_type);

INSERT INTO sql_deployments (id, instance_name, sql_version, edition, cpu, memory_gb, data_disk_gb, log_disk_gb, tempdb_disk_gb, collation, service_account, site, cluster_mode, status)
VALUES
    ('e0000400-4000-4000-4000-000000000001', 'LOVE-SQL-PROD-01', '2022', 'Enterprise', 8, 64, 500, 200, 100, 'Latin1_General_CI_AS', 'svc-sql-love-prod@ryuki.local', 'LOVE', 'AG', 'draft'),
    ('e0000400-4000-4000-4000-000000000002', 'BUR1-SQL-PROD-01', '2019', 'Standard', 4, 32, 250, 100, 50, 'SQL_Latin1_General_CP1_CI_AS', 'svc-sql-bur1-prod@ryuki.local', 'BUR1', 'Standalone', 'draft');
