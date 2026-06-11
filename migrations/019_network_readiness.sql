CREATE TABLE switch_ports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    switch_name TEXT NOT NULL,
    port_number INTEGER NOT NULL,
    vlan_id INTEGER NOT NULL DEFAULT 1,
    vlan_name TEXT NOT NULL DEFAULT 'default',
    status TEXT NOT NULL DEFAULT 'Available',
    connected_device TEXT,
    site TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (switch_name, port_number)
);

CREATE TABLE vlans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vlan_id INTEGER NOT NULL,
    vlan_name TEXT NOT NULL,
    subnet TEXT NOT NULL,
    gateway TEXT NOT NULL,
    site TEXT NOT NULL,
    purpose TEXT NOT NULL,
    available_ips INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (site, vlan_id)
);

CREATE TABLE port_reservations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reservation_id TEXT NOT NULL UNIQUE,
    site TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    vlan_id INTEGER,
    port_ids TEXT[] NOT NULL DEFAULT '{}',
    ip_count INTEGER NOT NULL DEFAULT 0,
    purpose TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'reserved',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO switch_ports (id, switch_name, port_number, vlan_id, vlan_name, status, connected_device, site) VALUES
    ('a0000100-1000-1000-1000-000000000001', 'love-sw-01', 1, 100, 'love-mgmt', 'InUse', 'love-srv-01', 'LOVE'),
    ('a0000100-1000-1000-1000-000000000002', 'love-sw-01', 2, 100, 'love-mgmt', 'InUse', 'love-srv-02', 'LOVE'),
    ('a0000100-1000-1000-1000-000000000003', 'love-sw-01', 3, 200, 'love-prod', 'Available', NULL, 'LOVE'),
    ('a0000100-1000-1000-1000-000000000004', 'love-sw-01', 4, 200, 'love-prod', 'Available', NULL, 'LOVE'),
    ('a0000100-1000-1000-1000-000000000005', 'love-sw-01', 5, 100, 'love-mgmt', 'Available', NULL, 'LOVE'),
    ('a0000100-1000-1000-1000-000000000006', 'love-sw-01', 6, 100, 'love-mgmt', 'Available', NULL, 'LOVE'),
    ('a0000100-1000-1000-1000-000000000007', 'love-sw-01', 7, 100, 'love-mgmt', 'Available', NULL, 'LOVE'),
    ('a0000100-1000-1000-1000-000000000008', 'love-sw-01', 8, 100, 'love-mgmt', 'Available', NULL, 'LOVE'),

    ('a0000100-1000-1000-1000-000000000009', 'love-sw-02', 1, 300, 'love-dmz', 'Available', NULL, 'LOVE'),
    ('a0000100-1000-1000-1000-00000000000a', 'love-sw-02', 2, 300, 'love-dmz', 'Available', NULL, 'LOVE'),
    ('a0000100-1000-1000-1000-00000000000b', 'love-sw-02', 3, 300, 'love-dmz', 'Available', NULL, 'LOVE'),
    ('a0000100-1000-1000-1000-00000000000c', 'love-sw-02', 4, 300, 'love-dmz', 'Available', NULL, 'LOVE'),
    ('a0000100-1000-1000-1000-00000000000d', 'love-sw-02', 5, 300, 'love-dmz', 'Available', NULL, 'LOVE'),
    ('a0000100-1000-1000-1000-00000000000e', 'love-sw-02', 6, 300, 'love-dmz', 'Available', NULL, 'LOVE'),
    ('a0000100-1000-1000-1000-00000000000f', 'love-sw-02', 7, 300, 'love-dmz', 'Available', NULL, 'LOVE'),
    ('a0000100-1000-1000-1000-000000000010', 'love-sw-02', 8, 300, 'love-dmz', 'Available', NULL, 'LOVE'),

    ('a0000100-1000-1000-1000-000000000011', 'love-sw-03', 1, 100, 'love-mgmt', 'Available', NULL, 'LOVE'),
    ('a0000100-1000-1000-1000-000000000012', 'love-sw-03', 2, 100, 'love-mgmt', 'Available', NULL, 'LOVE'),
    ('a0000100-1000-1000-1000-000000000013', 'love-sw-03', 3, 100, 'love-mgmt', 'Available', NULL, 'LOVE'),
    ('a0000100-1000-1000-1000-000000000014', 'love-sw-03', 4, 100, 'love-mgmt', 'Available', NULL, 'LOVE'),
    ('a0000100-1000-1000-1000-000000000015', 'love-sw-03', 5, 100, 'love-mgmt', 'Available', NULL, 'LOVE'),
    ('a0000100-1000-1000-1000-000000000016', 'love-sw-03', 6, 100, 'love-mgmt', 'Available', NULL, 'LOVE'),
    ('a0000100-1000-1000-1000-000000000017', 'love-sw-03', 7, 1, 'default', 'Disabled', NULL, 'LOVE'),
    ('a0000100-1000-1000-1000-000000000018', 'love-sw-03', 8, 1, 'default', 'Disabled', NULL, 'LOVE'),

    ('a0000100-1000-1000-1000-000000000019', 'bur1-sw-01', 1, 110, 'bur1-mgmt', 'InUse', 'bur1-srv-01', 'BUR1'),
    ('a0000100-1000-1000-1000-00000000001a', 'bur1-sw-01', 2, 110, 'bur1-mgmt', 'InUse', 'bur1-srv-02', 'BUR1'),
    ('a0000100-1000-1000-1000-00000000001b', 'bur1-sw-01', 3, 210, 'bur1-prod', 'Available', NULL, 'BUR1'),
    ('a0000100-1000-1000-1000-00000000001c', 'bur1-sw-01', 4, 210, 'bur1-prod', 'Available', NULL, 'BUR1'),
    ('a0000100-1000-1000-1000-00000000001d', 'bur1-sw-01', 5, 110, 'bur1-mgmt', 'Available', NULL, 'BUR1'),
    ('a0000100-1000-1000-1000-00000000001e', 'bur1-sw-01', 6, 110, 'bur1-mgmt', 'Available', NULL, 'BUR1'),
    ('a0000100-1000-1000-1000-00000000001f', 'bur1-sw-01', 7, 110, 'bur1-mgmt', 'Available', NULL, 'BUR1'),
    ('a0000100-1000-1000-1000-000000000020', 'bur1-sw-01', 8, 110, 'bur1-mgmt', 'Available', NULL, 'BUR1'),

    ('a0000100-1000-1000-1000-000000000021', 'bur1-sw-02', 1, 310, 'bur1-dmz', 'Available', NULL, 'BUR1'),
    ('a0000100-1000-1000-1000-000000000022', 'bur1-sw-02', 2, 310, 'bur1-dmz', 'Available', NULL, 'BUR1'),
    ('a0000100-1000-1000-1000-000000000023', 'bur1-sw-02', 3, 310, 'bur1-dmz', 'Available', NULL, 'BUR1'),
    ('a0000100-1000-1000-1000-000000000024', 'bur1-sw-02', 4, 310, 'bur1-dmz', 'Available', NULL, 'BUR1'),
    ('a0000100-1000-1000-1000-000000000025', 'bur1-sw-02', 5, 310, 'bur1-dmz', 'Available', NULL, 'BUR1'),
    ('a0000100-1000-1000-1000-000000000026', 'bur1-sw-02', 6, 310, 'bur1-dmz', 'Available', NULL, 'BUR1'),
    ('a0000100-1000-1000-1000-000000000027', 'bur1-sw-02', 7, 310, 'bur1-dmz', 'Available', NULL, 'BUR1'),
    ('a0000100-1000-1000-1000-000000000028', 'bur1-sw-02', 8, 310, 'bur1-dmz', 'Available', NULL, 'BUR1'),

    ('a0000100-1000-1000-1000-000000000029', 'bur1-sw-03', 1, 110, 'bur1-mgmt', 'Available', NULL, 'BUR1'),
    ('a0000100-1000-1000-1000-00000000002a', 'bur1-sw-03', 2, 110, 'bur1-mgmt', 'Available', NULL, 'BUR1'),
    ('a0000100-1000-1000-1000-00000000002b', 'bur1-sw-03', 3, 110, 'bur1-mgmt', 'Available', NULL, 'BUR1'),
    ('a0000100-1000-1000-1000-00000000002c', 'bur1-sw-03', 4, 110, 'bur1-mgmt', 'Available', NULL, 'BUR1'),
    ('a0000100-1000-1000-1000-00000000002d', 'bur1-sw-03', 5, 110, 'bur1-mgmt', 'Available', NULL, 'BUR1'),
    ('a0000100-1000-1000-1000-00000000002e', 'bur1-sw-03', 6, 110, 'bur1-mgmt', 'Available', NULL, 'BUR1'),
    ('a0000100-1000-1000-1000-00000000002f', 'bur1-sw-03', 7, 1, 'default', 'Disabled', NULL, 'BUR1'),
    ('a0000100-1000-1000-1000-000000000030', 'bur1-sw-03', 8, 1, 'default', 'Disabled', NULL, 'BUR1');

INSERT INTO vlans (id, vlan_id, vlan_name, subnet, gateway, site, purpose, available_ips) VALUES
    ('b0000200-2000-2000-2000-000000000001', 100, 'love-mgmt', '10.1.1.0/24', '10.1.1.1', 'LOVE', 'Management', 200),
    ('b0000200-2000-2000-2000-000000000002', 200, 'love-prod', '10.1.2.0/24', '10.1.2.1', 'LOVE', 'Production', 180),
    ('b0000200-2000-2000-2000-000000000003', 300, 'love-dmz', '10.1.3.0/24', '10.1.3.1', 'LOVE', 'DMZ', 50),
    ('b0000200-2000-2000-2000-000000000004', 110, 'bur1-mgmt', '10.2.1.0/24', '10.2.1.1', 'BUR1', 'Management', 200),
    ('b0000200-2000-2000-2000-000000000005', 210, 'bur1-prod', '10.2.2.0/24', '10.2.2.1', 'BUR1', 'Production', 180),
    ('b0000200-2000-2000-2000-000000000006', 310, 'bur1-dmz', '10.2.3.0/24', '10.2.3.1', 'BUR1', 'DMZ', 50);
