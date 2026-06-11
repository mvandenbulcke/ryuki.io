CREATE TABLE datacenter_readiness_checks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site TEXT NOT NULL,
    check_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'not-checked',
    last_checked TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    details TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (site, check_type)
);

INSERT INTO datacenter_readiness_checks (id, site, check_type, status, last_checked, details) VALUES
    ('d0000100-1000-1000-1000-000000000001', 'LOVE', 'power', 'passed', '2026-06-11T10:00:00Z', 'PDU A+B redundant, UPS load 62% with 28 min runtime'),
    ('d0000100-1000-1000-1000-000000000002', 'LOVE', 'cooling', 'passed', '2026-06-11T10:00:00Z', 'CRAC units nominal, return air 22 C, supply 16 C'),
    ('d0000100-1000-1000-1000-000000000003', 'LOVE', 'rack-space', 'warning', '2026-06-11T10:00:00Z', '12 rack units free across 3 racks (limited headroom)'),
    ('d0000100-1000-1000-1000-000000000004', 'LOVE', 'switchport', 'passed', '2026-06-11T10:00:00Z', '18 switchports available across prod/dmz/mgmt VLANs'),
    ('d0000100-1000-1000-1000-000000000005', 'LOVE', 'firmware', 'warning', '2026-06-11T10:00:00Z', '2 PDUs on firmware v2.8 (current v3.1), SFP modules current'),
    ('d0000100-1000-1000-1000-000000000006', 'LOVE', 'capacity', 'passed', '2026-06-11T10:00:00Z', 'Compute 78% allocated, storage 64%, network fabric 42%'),

    ('d0000100-1000-1000-1000-000000000007', 'BUR1', 'power', 'failed', '2026-06-11T09:30:00Z', 'UPS-B in bypass mode, PDU-3 overload alarm at 91%'),
    ('d0000100-1000-1000-1000-000000000008', 'BUR1', 'cooling', 'warning', '2026-06-11T09:30:00Z', 'CRAC-2 compressor cycling, return air 26 C (threshold 24 C)'),
    ('d0000100-1000-1000-1000-000000000009', 'BUR1', 'rack-space', 'failed', '2026-06-11T09:30:00Z', 'Zero rack units free, 2 racks over-populated (48U in 42U)'),
    ('d0000100-1000-1000-1000-00000000000a', 'BUR1', 'switchport', 'passed', '2026-06-11T09:30:00Z', '22 switchports available, fabric links healthy'),
    ('d0000100-1000-1000-1000-00000000000b', 'BUR1', 'firmware', 'failed', '2026-06-11T09:30:00Z', 'Core switch firmware EOL 2025-Q3, CRAC controller behind 3 revs'),
    ('d0000100-1000-1000-1000-00000000000c', 'BUR1', 'capacity', 'warning', '2026-06-11T09:30:00Z', 'Compute 94% allocated (critical), storage 88%, network 71%'),

    ('d0000100-1000-1000-1000-00000000000d', 'CCSS', 'power', 'passed', '2026-06-11T08:00:00Z', 'PDU A+B nominal, UPS load 45%, generator tested 2026-06-09'),
    ('d0000100-1000-1000-1000-00000000000e', 'CCSS', 'cooling', 'passed', '2026-06-11T08:00:00Z', 'All CRAC units healthy, supply temp 15 C per ASHRAE A1'),
    ('d0000100-1000-1000-1000-00000000000f', 'CCSS', 'rack-space', 'passed', '2026-06-11T08:00:00Z', '42 rack units free across 7 empty racks (new buildout)'),
    ('d0000100-1000-1000-1000-000000000010', 'CCSS', 'switchport', 'not-checked', '2026-06-11T08:00:00Z', 'Switch fabric not yet provisioned, awaiting L2 install'),
    ('d0000100-1000-1000-1000-000000000011', 'CCSS', 'firmware', 'not-checked', '2026-06-11T08:00:00Z', 'Hardware not yet racked, firmware baseline pending'),
    ('d0000100-1000-1000-1000-000000000012', 'CCSS', 'capacity', 'passed', '2026-06-11T08:00:00Z', 'Greenfield site, 100% free across compute/storage/network');
