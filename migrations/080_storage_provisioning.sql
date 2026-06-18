-- Migration 080: Storage Provisioning durable persistence
-- 3 tables: storage_arrays, storage_volumes, storage_requests
-- Enum values are kebab-case serde forms (matching engine #[serde(rename_all="kebab-case")])
-- u64 size/capacity fields stored as BIGINT (i64 in Rust)
-- storage_array field on volumes/requests is a plain TEXT name string (not an FK)

CREATE TABLE storage_arrays (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    vendor TEXT NOT NULL CHECK (vendor IN ('pure-storage', 'dell-emc', 'net-app', 'hpe')),
    model TEXT NOT NULL,
    site TEXT NOT NULL,
    total_capacity_gb BIGINT NOT NULL CHECK (total_capacity_gb >= 0),
    used_capacity_gb BIGINT NOT NULL CHECK (used_capacity_gb >= 0),
    pool_count INTEGER NOT NULL CHECK (pool_count >= 0),
    status TEXT NOT NULL CHECK (status IN ('healthy', 'degraded', 'critical')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Core capacity invariant: used can never exceed total. The guarded
    -- provision/extend UPDATEs already enforce this; the durable schema must too
    -- (defense against any out-of-band write).
    CONSTRAINT storage_arrays_used_le_total CHECK (used_capacity_gb <= total_capacity_gb)
);

CREATE TABLE storage_volumes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    volume_type TEXT NOT NULL CHECK (volume_type IN ('lun', 'nfs', 'cifs', 'object')),
    size_gb BIGINT NOT NULL CHECK (size_gb > 0),
    storage_array TEXT NOT NULL,   -- array ID string, not FK-enforced
    pool TEXT NOT NULL,
    site TEXT NOT NULL,
    host_mappings TEXT[] NOT NULL DEFAULT '{}',
    protection TEXT NOT NULL CHECK (protection IN ('raid', 'none', 'replicated')),
    status TEXT NOT NULL CHECK (status IN ('creating', 'available', 'mounted', 'expanding', 'retiring')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Unique volume name per site (engine used mutex-guard check; DB enforces at constraint level)
CREATE UNIQUE INDEX idx_storage_volumes_name_site ON storage_volumes(name, site);

CREATE TABLE storage_requests (
    id TEXT PRIMARY KEY,
    requester TEXT NOT NULL,
    hostname TEXT NOT NULL,
    size_gb BIGINT NOT NULL CHECK (size_gb > 0),
    volume_type TEXT NOT NULL CHECK (volume_type IN ('lun', 'nfs', 'cifs', 'object')),
    storage_array TEXT NOT NULL,   -- array ID string, not FK-enforced
    site TEXT NOT NULL,
    purpose TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('draft', 'validated', 'provisioned', 'mounted', 'completed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_storage_arrays_site ON storage_arrays(site);
CREATE INDEX idx_storage_volumes_site ON storage_volumes(site);
CREATE INDEX idx_storage_requests_site ON storage_requests(site);

-- Seed: arrays first (no FK deps), then volumes and requests
-- Arrays: 3 rows
INSERT INTO storage_arrays (id, name, vendor, model, site, total_capacity_gb, used_capacity_gb, pool_count, status) VALUES
    ('arr-defra-001', 'defra-pure-fa-01',       'pure-storage', 'FlashArray//X70', 'DEFRA', 20480, 3072,  2, 'healthy'),
    ('arr-gblon-001', 'gblon-dellemc-pmax-01',   'dell-emc',     'PowerMax 2500',   'GBLON', 32768, 12288, 3, 'degraded'),
    ('arr-frpar-001', 'frpar-netapp-a400-01',    'net-app',      'AFF A400',        'FRPAR', 24576, 7680,  2, 'healthy');

-- Volumes: 6 rows (storage_array is the array ID string)
INSERT INTO storage_volumes (id, name, volume_type, size_gb, storage_array, pool, site, host_mappings, protection, status) VALUES
    ('vol-defra-001', 'defra-db-lun-01',       'lun',    2048, 'arr-defra-001', 'gold',    'DEFRA', ARRAY['defra-db-01', 'defra-db-02'], 'raid',       'mounted'),
    ('vol-defra-002', 'defra-app-nfs-01',      'nfs',    1024, 'arr-defra-001', 'silver',  'DEFRA', ARRAY['defra-app-01'],               'replicated', 'mounted'),
    ('vol-gblon-001', 'gblon-vm-cifs-01',      'cifs',   4096, 'arr-gblon-001', 'shared',  'GBLON', ARRAY['gblon-fs-01'],                'raid',       'mounted'),
    ('vol-gblon-002', 'gblon-logs-obj-01',     'object', 8192, 'arr-gblon-001', 'archive', 'GBLON', '{}',                                'none',       'available'),
    ('vol-frpar-001', 'frpar-sql-lun-01',      'lun',    1536, 'arr-frpar-001', 'gold',    'FRPAR', ARRAY['frpar-sql-01'],               'raid',       'mounted'),
    ('vol-frpar-002', 'frpar-backup-nfs-01',   'nfs',    6144, 'arr-frpar-001', 'backup',  'FRPAR', '{}',                                'replicated', 'available');

-- Requests: 4 rows
INSERT INTO storage_requests (id, requester, hostname, size_gb, volume_type, storage_array, site, purpose, status) VALUES
    ('sr-defra-001', 'alice.engineer', 'defra-web-03',  512,  'nfs',    'arr-defra-001', 'DEFRA', 'application content', 'validated'),
    ('sr-gblon-001', 'bob.engineer',   'gblon-db-03',   2048, 'lun',    'arr-gblon-001', 'GBLON', 'database expansion',  'draft'),
    ('sr-frpar-001', 'carol.engineer', 'frpar-ana-01',  1024, 'cifs',   'arr-frpar-001', 'FRPAR', 'analytics share',     'provisioned'),
    ('sr-defra-002', 'dave.engineer',  'defra-obj-01',  4096, 'object', 'arr-defra-001', 'DEFRA', 'audit archive',       'completed');
