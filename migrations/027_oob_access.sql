CREATE TABLE oob_endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_type TEXT NOT NULL,
    hostname TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    site TEXT NOT NULL,
    firmware_version TEXT NOT NULL,
    certificate_valid BOOLEAN NOT NULL DEFAULT false,
    cert_expiry TIMESTAMPTZ NOT NULL,
    last_tested TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reachable BOOLEAN NOT NULL DEFAULT false,
    default_credentials_changed BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (site, hostname)
);

INSERT INTO oob_endpoints (id, endpoint_type, hostname, ip_address, site, firmware_version, certificate_valid, cert_expiry, last_tested, reachable, default_credentials_changed) VALUES
    ('c0000100-1000-1000-1000-000000000001', 'iLO', 'ilove01.corp.local', '10.1.100.11', 'LOVE', '2.78', true, NOW() + INTERVAL '180 days', NOW(), true, true),
    ('c0000100-1000-1000-1000-000000000002', 'iDRAC', 'idrac02.corp.local', '10.1.100.12', 'LOVE', '6.10.30.00', false, NOW() - INTERVAL '15 days', NOW() - INTERVAL '4 hours', false, false),
    ('c0000100-1000-1000-1000-000000000003', 'IPMI', 'ipmi03.corp.local', '10.1.100.13', 'LOVE', '1.94', true, NOW() + INTERVAL '20 days', NOW(), true, true),
    ('c0000100-1000-1000-1000-000000000004', 'iLO', 'ilocur101.corp.local', '10.2.100.11', 'BUR1', '2.80', true, NOW() + INTERVAL '365 days', NOW() - INTERVAL '2 days', true, true),
    ('c0000100-1000-1000-1000-000000000005', 'XCC', 'xccbur102.corp.local', '10.2.100.12', 'BUR1', '4.20', true, NOW() + INTERVAL '10 days', NOW() - INTERVAL '1 day', false, false),
    ('c0000100-1000-1000-1000-000000000006', 'iDRAC', 'idracbur103.corp.local', '10.2.100.13', 'BUR1', '6.00.00.00', false, NOW() - INTERVAL '45 days', NOW() - INTERVAL '12 hours', true, true);
