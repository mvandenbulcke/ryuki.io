-- Migration 072: Load Balancer durable persistence
-- 4 tables: lb_pools, lb_virtual_servers, lb_pool_members, lb_requests
-- Enum values are kebab-case serde forms (matching engine #[serde(rename_all="kebab-case")])

CREATE TABLE lb_pools (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    site TEXT NOT NULL,
    algorithm TEXT NOT NULL CHECK (algorithm IN ('round-robin', 'least-connections', 'weighted')),
    health_monitor TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE lb_virtual_servers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    vip TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port >= 1 AND port <= 65535),
    protocol TEXT NOT NULL CHECK (protocol IN ('http', 'https', 'tcp')),
    pool_id TEXT NOT NULL REFERENCES lb_pools(id) ON DELETE CASCADE,
    site TEXT NOT NULL,
    ssl_profile TEXT,
    persistence_method TEXT NOT NULL CHECK (persistence_method IN ('cookie', 'source-ip', 'none')),
    status TEXT NOT NULL CHECK (status IN ('online', 'offline', 'draining', 'creating')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE lb_pool_members (
    pool_id TEXT NOT NULL REFERENCES lb_pools(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port >= 1 AND port <= 65535),
    weight INTEGER NOT NULL DEFAULT 1 CHECK (weight >= 0),
    status TEXT NOT NULL CHECK (status IN ('up', 'down', 'disabled', 'draining')),
    PRIMARY KEY (pool_id, hostname)
);

CREATE TABLE lb_requests (
    id TEXT PRIMARY KEY,
    requester TEXT NOT NULL,
    virtual_server_name TEXT NOT NULL,
    vip TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port >= 1 AND port <= 65535),
    protocol TEXT NOT NULL CHECK (protocol IN ('http', 'https', 'tcp')),
    site TEXT NOT NULL,
    pool_members TEXT[] NOT NULL DEFAULT '{}',
    status TEXT NOT NULL CHECK (status IN ('draft', 'validated', 'provisioned', 'verified')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_lb_virtual_servers_site ON lb_virtual_servers(site);
-- Enforce VIP uniqueness per site at the DB layer: the provision handler's
-- find_vip_conflict pre-check is advisory (a TOCTOU race could let two concurrent
-- provisions of the same vip+site both pass it), so this constraint is what
-- actually prevents duplicate VIPs. The provision handler maps the resulting
-- unique-violation to 409.
CREATE UNIQUE INDEX idx_lb_virtual_servers_vip_site ON lb_virtual_servers(vip, site);
CREATE INDEX idx_lb_pools_site ON lb_pools(site);
CREATE INDEX idx_lb_pool_members_pool ON lb_pool_members(pool_id);
CREATE INDEX idx_lb_requests_site ON lb_requests(site);

-- Seed: pools first (FK parent), then pool members, then virtual servers (FK to pools), then requests
-- Pool 1: DEFRA web pool
INSERT INTO lb_pools (id, name, site, algorithm, health_monitor) VALUES
    ('pool-defra-web', 'defra-web-pool', 'DEFRA', 'round-robin', 'http-200');

-- Pool 2: GBLON api pool
INSERT INTO lb_pools (id, name, site, algorithm, health_monitor) VALUES
    ('pool-gblon-api', 'gblon-api-pool', 'GBLON', 'weighted', 'https-api');

-- Pool 3: FRPAR tcp pool (no health monitor)
INSERT INTO lb_pools (id, name, site, algorithm, health_monitor) VALUES
    ('pool-frpar-tcp', 'frpar-tcp-pool', 'FRPAR', 'least-connections', NULL);

-- Pool members (pool_id, hostname, ip, port, weight, status)
INSERT INTO lb_pool_members (pool_id, hostname, ip, port, weight, status) VALUES
    ('pool-defra-web', 'defra-web-01', '10.10.20.11', 8080, 1, 'up'),
    ('pool-defra-web', 'defra-web-02', '10.10.20.12', 8080, 1, 'up'),
    ('pool-gblon-api', 'gblon-api-01', '10.20.30.21', 8443, 2, 'up'),
    ('pool-gblon-api', 'gblon-api-02', '10.20.30.22', 8443, 1, 'down'),
    ('pool-frpar-tcp', 'frpar-tcp-01', '10.30.40.31', 9000, 1, 'disabled');

-- Virtual servers (FK: pool_id -> lb_pools)
INSERT INTO lb_virtual_servers (id, name, vip, port, protocol, pool_id, site, ssl_profile, persistence_method, status) VALUES
    ('vs-defra-web',   'defra-web-vs',   '10.10.10.50', 443,  'https', 'pool-defra-web', 'DEFRA', 'standard-tls', 'cookie',    'online'),
    ('vs-defra-admin', 'defra-admin-vs', '10.10.10.51', 80,   'http',  'pool-defra-web', 'DEFRA', NULL,           'source-ip', 'draining'),
    ('vs-gblon-api',   'gblon-api-vs',   '10.20.10.50', 443,  'https', 'pool-gblon-api', 'GBLON', 'api-tls',      'none',      'online'),
    ('vs-frpar-tcp',   'frpar-tcp-vs',   '10.30.10.50', 9000, 'tcp',   'pool-frpar-tcp', 'FRPAR', NULL,           'none',      'offline');

-- Requests (pool_members is TEXT[])
INSERT INTO lb_requests (id, requester, virtual_server_name, vip, port, protocol, site, pool_members, status) VALUES
    ('lbr-defra-001', 'alice.operator', 'defra-web-vs',   '10.10.10.50', 443,  'https', 'DEFRA', ARRAY['defra-web-01', 'defra-web-02'], 'provisioned'),
    ('lbr-gblon-001', 'bob.engineer',   'gblon-api-vs',   '10.20.10.50', 443,  'https', 'GBLON', ARRAY['gblon-api-01', 'gblon-api-02'], 'verified'),
    ('lbr-frpar-001', 'carol.admin',    'frpar-tcp-vs',   '10.30.10.50', 9000, 'tcp',   'FRPAR', ARRAY['frpar-tcp-01'],                 'validated');
