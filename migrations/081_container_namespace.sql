-- Migration 081: durable persistence for container_namespace domain
-- Tables: k8s_namespaces, container_requests
-- ResourceQuota is a value object flattened into k8s_namespaces columns.
-- Enum values are stored in PascalCase (serde default == variant name == Display).

CREATE TABLE k8s_namespaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    cluster TEXT NOT NULL,
    site TEXT NOT NULL,
    cpu_limit INTEGER NOT NULL CHECK (cpu_limit >= 0),
    cpu_request INTEGER NOT NULL CHECK (cpu_request >= 0),
    memory_limit_gb INTEGER NOT NULL CHECK (memory_limit_gb >= 0),
    memory_request_gb INTEGER NOT NULL CHECK (memory_request_gb >= 0),
    storage_gb INTEGER NOT NULL CHECK (storage_gb >= 0),
    max_pods INTEGER NOT NULL CHECK (max_pods >= 0),
    network_policy TEXT NOT NULL,
    service_accounts TEXT[] NOT NULL DEFAULT '{}',
    status TEXT NOT NULL CHECK (status IN ('Active','Creating','Terminating','Suspended')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE container_requests (
    id TEXT PRIMARY KEY,
    requester TEXT NOT NULL,
    namespace_name TEXT NOT NULL,
    cluster TEXT NOT NULL,
    site TEXT NOT NULL,
    cpu_request INTEGER NOT NULL CHECK (cpu_request >= 0),
    memory_gb INTEGER NOT NULL CHECK (memory_gb >= 0),
    storage_gb INTEGER NOT NULL CHECK (storage_gb >= 0),
    environment TEXT NOT NULL CHECK (environment IN ('Dev','Test','Staging','Prod')),
    purpose TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('Draft','Validated','Approved','Provisioned')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_k8s_namespaces_site ON k8s_namespaces(site);
CREATE INDEX idx_container_requests_site ON container_requests(site);
-- A (cluster, name) is unique only among NON-Terminating namespaces, matching the
-- engine's duplicate-name check (status != Terminating) and validate-name: a name
-- becomes reusable once its namespace is Terminating. A plain UNIQUE(cluster,name)
-- would block re-provisioning over a Terminating namespace (a behavior regression)
-- and disagree with validate-name (which reports the name available).
CREATE UNIQUE INDEX idx_k8s_namespaces_cluster_name_active
    ON k8s_namespaces(cluster, name) WHERE status <> 'Terminating';

-- Seed namespaces (6 rows from seed_namespaces())
-- quota(cpu, memory_gb, storage_gb) => cpu_limit=cpu*2, cpu_request=cpu,
--   memory_limit_gb=memory_gb*2, memory_request_gb=memory_gb, storage_gb=storage_gb,
--   max_pods=max(cpu*8, 16)

INSERT INTO k8s_namespaces
    (id, name, cluster, site, cpu_limit, cpu_request, memory_limit_gb, memory_request_gb, storage_gb, max_pods, network_policy, service_accounts, status)
VALUES
    -- quota(8,16,200): cpu_limit=16,cpu_request=8,mem_limit=32,mem_req=16,storage=200,max_pods=64
    ('k8s-defra-app-001', 'defra-apps-dev', 'defra-aks-01', 'DEFRA',
     16, 8, 32, 16, 200, 64, 'deny-by-default',
     ARRAY['defra-app-deployer','defra-app-reader'], 'Active'),

    -- quota(24,96,800): cpu_limit=48,cpu_request=24,mem_limit=192,mem_req=96,storage=800,max_pods=192
    ('k8s-defra-data-001', 'defra-data-prod', 'defra-aks-02', 'DEFRA',
     48, 24, 192, 96, 800, 192, 'restricted-egress',
     ARRAY['defra-data-runner'], 'Active'),

    -- quota(16,64,500): cpu_limit=32,cpu_request=16,mem_limit=128,mem_req=64,storage=500,max_pods=128
    ('k8s-gblon-obs-001', 'gblon-observability', 'gblon-k8s-01', 'GBLON',
     32, 16, 128, 64, 500, 128, 'monitoring-ingress',
     ARRAY['gblon-prometheus','gblon-grafana'], 'Active'),

    -- quota(12,32,300): cpu_limit=24,cpu_request=12,mem_limit=64,mem_req=32,storage=300,max_pods=96
    ('k8s-gblon-build-001', 'gblon-build-test', 'gblon-k8s-02', 'GBLON',
     24, 12, 64, 32, 300, 96, 'ci-egress',
     ARRAY['gblon-build-runner'], 'Suspended'),

    -- quota(10,24,250): cpu_limit=20,cpu_request=10,mem_limit=48,mem_req=24,storage=250,max_pods=80
    ('k8s-frpar-api-001', 'frpar-api-staging', 'frpar-k8s-01', 'FRPAR',
     20, 10, 48, 24, 250, 80, 'staging-shared',
     ARRAY['frpar-api-deployer'], 'Creating'),

    -- quota(20,48,400): cpu_limit=40,cpu_request=20,mem_limit=96,mem_req=48,storage=400,max_pods=160
    -- NOTE: frpar-edge-prod is on frpar-k8s-01, same cluster as frpar-api-staging but
    -- different name — satisfies UNIQUE(cluster, name)
    ('k8s-frpar-edge-001', 'frpar-edge-prod', 'frpar-k8s-01', 'FRPAR',
     40, 20, 96, 48, 400, 160, 'edge-restricted',
     ARRAY['frpar-edge-runtime'], 'Active');

-- Seed requests (4 rows from seed_requests())
INSERT INTO container_requests
    (id, requester, namespace_name, cluster, site, cpu_request, memory_gb, storage_gb, environment, purpose, status)
VALUES
    ('cr-defra-001', 'alice.platform', 'defra-risk-dev', 'defra-aks-01', 'DEFRA',
     4, 12, 100, 'Dev', 'Risk model development', 'Validated'),

    ('cr-gblon-001', 'bob.sre', 'gblon-chaos-test', 'gblon-k8s-02', 'GBLON',
     6, 16, 120, 'Test', 'Chaos testing sandbox', 'Draft'),

    ('cr-frpar-001', 'carla.apps', 'frpar-payments-staging', 'frpar-k8s-01', 'FRPAR',
     8, 24, 200, 'Staging', 'Payments pre-prod validation', 'Approved'),

    ('cr-defra-002', 'diego.data', 'defra-analytics-prod', 'defra-aks-02', 'DEFRA',
     16, 64, 500, 'Prod', 'Analytics production workloads', 'Approved');
