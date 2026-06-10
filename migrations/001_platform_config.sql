CREATE TABLE platform_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO platform_config (key, value) VALUES
    ('entra_tenant_id', ''),
    ('entra_client_id', ''),
    ('entra_authority', 'https://login.microsoftonline.com/common'),
    ('auth_mode', 'mock-dry-run'),
    ('database_provider', 'cloudnativepg'),
    ('secret_provider', 'hashicorp-vault'),
    ('kubernetes_runtime', 'vsphere-vks'),
    ('monitoring_provider', 'zabbix'),
    ('backup_provider', 'veeam');
