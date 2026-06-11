CREATE TABLE app_environments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_name TEXT NOT NULL,
    environment TEXT NOT NULL,
    tier TEXT NOT NULL,
    vm_count INTEGER NOT NULL DEFAULT 0,
    cpu_per_vm INTEGER NOT NULL DEFAULT 0,
    memory_per_vm INTEGER NOT NULL DEFAULT 0,
    disk_gb INTEGER NOT NULL DEFAULT 0,
    network_zone TEXT NOT NULL DEFAULT '',
    requires_sql BOOLEAN NOT NULL DEFAULT false,
    requires_redis BOOLEAN NOT NULL DEFAULT false,
    site TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    networking_plan TEXT NOT NULL DEFAULT '',
    dns_plan TEXT NOT NULL DEFAULT '',
    certs_plan TEXT NOT NULL DEFAULT '',
    monitoring_plan TEXT NOT NULL DEFAULT '',
    backup_plan TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

CREATE TABLE environment_tiers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id UUID NOT NULL REFERENCES app_environments(id),
    tier TEXT NOT NULL,
    vm_count INTEGER NOT NULL DEFAULT 0,
    cpu_per_vm INTEGER NOT NULL DEFAULT 0,
    memory_per_vm INTEGER NOT NULL DEFAULT 0,
    disk_gb INTEGER NOT NULL DEFAULT 0,
    network_zone TEXT NOT NULL DEFAULT '',
    requires_sql BOOLEAN NOT NULL DEFAULT false,
    requires_redis BOOLEAN NOT NULL DEFAULT false,
    status TEXT NOT NULL DEFAULT 'draft'
);

INSERT INTO app_environments (app_name, environment, tier, vm_count, cpu_per_vm, memory_per_vm, disk_gb, network_zone, requires_sql, requires_redis, site, status, networking_plan, dns_plan, certs_plan, monitoring_plan, backup_plan) VALUES
    ('payment-service', 'prod', 'front', 2, 4, 8, 50, 'dmz', false, false, 'DEFRA', 'planned', 'DRY-RUN: Networking plan for dmz at DEFRA', 'DRY-RUN: DNS plan for payment-service-prod', 'DRY-RUN: TLS cert for payment-service-prod', 'DRY-RUN: Monitoring for payment-service-prod-front', 'DRY-RUN: Backup plan for payment-service-prod'),
    ('payment-service', 'prod', 'mid', 3, 8, 16, 100, 'app', false, true, 'DEFRA', 'planned', 'DRY-RUN: Networking plan for app at DEFRA', 'DRY-RUN: DNS plan for payment-service-prod', 'DRY-RUN: TLS cert for payment-service-prod', 'DRY-RUN: Monitoring for payment-service-prod-mid', 'DRY-RUN: Backup plan for payment-service-prod'),
    ('payment-service', 'prod', 'back', 2, 4, 32, 200, 'data', true, false, 'DEFRA', 'planned', 'DRY-RUN: Networking plan for data at DEFRA', 'DRY-RUN: DNS plan for payment-service-prod', 'DRY-RUN: TLS cert for payment-service-prod', 'DRY-RUN: Monitoring for payment-service-prod-back', 'DRY-RUN: Backup plan for payment-service-prod'),
    ('inventory-api', 'staging', 'front', 2, 4, 8, 50, 'dmz', false, false, 'GBLON', 'planned', 'DRY-RUN: Networking plan for dmz at GBLON', 'DRY-RUN: DNS plan for inventory-api-staging', 'DRY-RUN: TLS cert for inventory-api-staging', 'DRY-RUN: Monitoring for inventory-api-staging-front', 'DRY-RUN: Backup plan for inventory-api-staging'),
    ('inventory-api', 'staging', 'mid', 3, 8, 16, 100, 'app', false, true, 'GBLON', 'planned', 'DRY-RUN: Networking plan for app at GBLON', 'DRY-RUN: DNS plan for inventory-api-staging', 'DRY-RUN: TLS cert for inventory-api-staging', 'DRY-RUN: Monitoring for inventory-api-staging-mid', 'DRY-RUN: Backup plan for inventory-api-staging'),
    ('inventory-api', 'staging', 'back', 2, 4, 32, 200, 'data', true, false, 'GBLON', 'planned', 'DRY-RUN: Networking plan for data at GBLON', 'DRY-RUN: DNS plan for inventory-api-staging', 'DRY-RUN: TLS cert for inventory-api-staging', 'DRY-RUN: Monitoring for inventory-api-staging-back', 'DRY-RUN: Backup plan for inventory-api-staging');
