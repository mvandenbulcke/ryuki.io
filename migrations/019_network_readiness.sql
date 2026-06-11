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
    ('a0000100-1000-1000-1000-000000000001', 'defra-sw-01', 1, 100, 'defra-mgmt', 'InUse', 'defra-srv-01', 'DEFRA'),
    ('a0000100-1000-1000-1000-000000000002', 'defra-sw-01', 2, 100, 'defra-mgmt', 'InUse', 'defra-srv-02', 'DEFRA'),
    ('a0000100-1000-1000-1000-000000000003', 'defra-sw-01', 3, 200, 'defra-prod', 'Available', NULL, 'DEFRA'),
    ('a0000100-1000-1000-1000-000000000004', 'defra-sw-01', 4, 200, 'defra-prod', 'Available', NULL, 'DEFRA'),
    ('a0000100-1000-1000-1000-000000000005', 'defra-sw-01', 5, 100, 'defra-mgmt', 'Available', NULL, 'DEFRA'),
    ('a0000100-1000-1000-1000-000000000006', 'defra-sw-01', 6, 100, 'defra-mgmt', 'Available', NULL, 'DEFRA'),
    ('a0000100-1000-1000-1000-000000000007', 'defra-sw-01', 7, 100, 'defra-mgmt', 'Available', NULL, 'DEFRA'),
    ('a0000100-1000-1000-1000-000000000008', 'defra-sw-01', 8, 100, 'defra-mgmt', 'Available', NULL, 'DEFRA'),

    ('a0000100-1000-1000-1000-000000000009', 'defra-sw-02', 1, 300, 'defra-dmz', 'Available', NULL, 'DEFRA'),
    ('a0000100-1000-1000-1000-00000000000a', 'defra-sw-02', 2, 300, 'defra-dmz', 'Available', NULL, 'DEFRA'),
    ('a0000100-1000-1000-1000-00000000000b', 'defra-sw-02', 3, 300, 'defra-dmz', 'Available', NULL, 'DEFRA'),
    ('a0000100-1000-1000-1000-00000000000c', 'defra-sw-02', 4, 300, 'defra-dmz', 'Available', NULL, 'DEFRA'),
    ('a0000100-1000-1000-1000-00000000000d', 'defra-sw-02', 5, 300, 'defra-dmz', 'Available', NULL, 'DEFRA'),
    ('a0000100-1000-1000-1000-00000000000e', 'defra-sw-02', 6, 300, 'defra-dmz', 'Available', NULL, 'DEFRA'),
    ('a0000100-1000-1000-1000-00000000000f', 'defra-sw-02', 7, 300, 'defra-dmz', 'Available', NULL, 'DEFRA'),
    ('a0000100-1000-1000-1000-000000000010', 'defra-sw-02', 8, 300, 'defra-dmz', 'Available', NULL, 'DEFRA'),

    ('a0000100-1000-1000-1000-000000000011', 'defra-sw-03', 1, 100, 'defra-mgmt', 'Available', NULL, 'DEFRA'),
    ('a0000100-1000-1000-1000-000000000012', 'defra-sw-03', 2, 100, 'defra-mgmt', 'Available', NULL, 'DEFRA'),
    ('a0000100-1000-1000-1000-000000000013', 'defra-sw-03', 3, 100, 'defra-mgmt', 'Available', NULL, 'DEFRA'),
    ('a0000100-1000-1000-1000-000000000014', 'defra-sw-03', 4, 100, 'defra-mgmt', 'Available', NULL, 'DEFRA'),
    ('a0000100-1000-1000-1000-000000000015', 'defra-sw-03', 5, 100, 'defra-mgmt', 'Available', NULL, 'DEFRA'),
    ('a0000100-1000-1000-1000-000000000016', 'defra-sw-03', 6, 100, 'defra-mgmt', 'Available', NULL, 'DEFRA'),
    ('a0000100-1000-1000-1000-000000000017', 'defra-sw-03', 7, 1, 'default', 'Disabled', NULL, 'DEFRA'),
    ('a0000100-1000-1000-1000-000000000018', 'defra-sw-03', 8, 1, 'default', 'Disabled', NULL, 'DEFRA'),

    ('a0000100-1000-1000-1000-000000000019', 'gblon-sw-01', 1, 110, 'gblon-mgmt', 'InUse', 'gblon-srv-01', 'GBLON'),
    ('a0000100-1000-1000-1000-00000000001a', 'gblon-sw-01', 2, 110, 'gblon-mgmt', 'InUse', 'gblon-srv-02', 'GBLON'),
    ('a0000100-1000-1000-1000-00000000001b', 'gblon-sw-01', 3, 210, 'gblon-prod', 'Available', NULL, 'GBLON'),
    ('a0000100-1000-1000-1000-00000000001c', 'gblon-sw-01', 4, 210, 'gblon-prod', 'Available', NULL, 'GBLON'),
    ('a0000100-1000-1000-1000-00000000001d', 'gblon-sw-01', 5, 110, 'gblon-mgmt', 'Available', NULL, 'GBLON'),
    ('a0000100-1000-1000-1000-00000000001e', 'gblon-sw-01', 6, 110, 'gblon-mgmt', 'Available', NULL, 'GBLON'),
    ('a0000100-1000-1000-1000-00000000001f', 'gblon-sw-01', 7, 110, 'gblon-mgmt', 'Available', NULL, 'GBLON'),
    ('a0000100-1000-1000-1000-000000000020', 'gblon-sw-01', 8, 110, 'gblon-mgmt', 'Available', NULL, 'GBLON'),

    ('a0000100-1000-1000-1000-000000000021', 'gblon-sw-02', 1, 310, 'gblon-dmz', 'Available', NULL, 'GBLON'),
    ('a0000100-1000-1000-1000-000000000022', 'gblon-sw-02', 2, 310, 'gblon-dmz', 'Available', NULL, 'GBLON'),
    ('a0000100-1000-1000-1000-000000000023', 'gblon-sw-02', 3, 310, 'gblon-dmz', 'Available', NULL, 'GBLON'),
    ('a0000100-1000-1000-1000-000000000024', 'gblon-sw-02', 4, 310, 'gblon-dmz', 'Available', NULL, 'GBLON'),
    ('a0000100-1000-1000-1000-000000000025', 'gblon-sw-02', 5, 310, 'gblon-dmz', 'Available', NULL, 'GBLON'),
    ('a0000100-1000-1000-1000-000000000026', 'gblon-sw-02', 6, 310, 'gblon-dmz', 'Available', NULL, 'GBLON'),
    ('a0000100-1000-1000-1000-000000000027', 'gblon-sw-02', 7, 310, 'gblon-dmz', 'Available', NULL, 'GBLON'),
    ('a0000100-1000-1000-1000-000000000028', 'gblon-sw-02', 8, 310, 'gblon-dmz', 'Available', NULL, 'GBLON'),

    ('a0000100-1000-1000-1000-000000000029', 'gblon-sw-03', 1, 110, 'gblon-mgmt', 'Available', NULL, 'GBLON'),
    ('a0000100-1000-1000-1000-00000000002a', 'gblon-sw-03', 2, 110, 'gblon-mgmt', 'Available', NULL, 'GBLON'),
    ('a0000100-1000-1000-1000-00000000002b', 'gblon-sw-03', 3, 110, 'gblon-mgmt', 'Available', NULL, 'GBLON'),
    ('a0000100-1000-1000-1000-00000000002c', 'gblon-sw-03', 4, 110, 'gblon-mgmt', 'Available', NULL, 'GBLON'),
    ('a0000100-1000-1000-1000-00000000002d', 'gblon-sw-03', 5, 110, 'gblon-mgmt', 'Available', NULL, 'GBLON'),
    ('a0000100-1000-1000-1000-00000000002e', 'gblon-sw-03', 6, 110, 'gblon-mgmt', 'Available', NULL, 'GBLON'),
    ('a0000100-1000-1000-1000-00000000002f', 'gblon-sw-03', 7, 1, 'default', 'Disabled', NULL, 'GBLON'),
    ('a0000100-1000-1000-1000-000000000030', 'gblon-sw-03', 8, 1, 'default', 'Disabled', NULL, 'GBLON');

INSERT INTO vlans (id, vlan_id, vlan_name, subnet, gateway, site, purpose, available_ips) VALUES
    ('b0000200-2000-2000-2000-000000000001', 100, 'defra-mgmt', '10.1.1.0/24', '10.1.1.1', 'DEFRA', 'Management', 200),
    ('b0000200-2000-2000-2000-000000000002', 200, 'defra-prod', '10.1.2.0/24', '10.1.2.1', 'DEFRA', 'Production', 180),
    ('b0000200-2000-2000-2000-000000000003', 300, 'defra-dmz', '10.1.3.0/24', '10.1.3.1', 'DEFRA', 'DMZ', 50),
    ('b0000200-2000-2000-2000-000000000004', 110, 'gblon-mgmt', '10.2.1.0/24', '10.2.1.1', 'GBLON', 'Management', 200),
    ('b0000200-2000-2000-2000-000000000005', 210, 'gblon-prod', '10.2.2.0/24', '10.2.2.1', 'GBLON', 'Production', 180),
    ('b0000200-2000-2000-2000-000000000006', 310, 'gblon-dmz', '10.2.3.0/24', '10.2.3.1', 'GBLON', 'DMZ', 50);
