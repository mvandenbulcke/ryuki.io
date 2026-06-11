CREATE TABLE hardware_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor TEXT NOT NULL,
    model TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    site TEXT NOT NULL,
    cluster TEXT NOT NULL,
    warranty_expiry TIMESTAMPTZ NOT NULL,
    firmware_baseline TEXT NOT NULL,
    firmware_installed TEXT NOT NULL,
    support_status TEXT NOT NULL DEFAULT 'Supported',
    lifecycle_status TEXT NOT NULL DEFAULT 'Production',
    last_health_check TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE firmware_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES hardware_assets(id),
    version TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO hardware_assets (vendor, model, serial_number, site, cluster, warranty_expiry, firmware_baseline, firmware_installed, support_status, lifecycle_status) VALUES
    ('HPE', 'DL360 Gen10', 'HPE-DL360-001', 'BUR1', 'bur1-prod-cluster-a', NOW() + INTERVAL '45 days', '2.94', '2.92', 'Expiring', 'Production'),
    ('HPE', 'DL380 Gen10', 'HPE-DL380-001', 'BUR1', 'bur1-prod-cluster-a', NOW() + INTERVAL '730 days', '2.94', '2.94', 'Supported', 'Production'),
    ('Lenovo', 'SR635', 'LNV-SR635-001', 'BUR1', 'bur1-storage-cluster-b', NOW() - INTERVAL '120 days', '3.20', '3.10', 'Expired', 'Extended'),
    ('HPE', 'DL360 Gen10', 'HPE-DL360-002', 'ALBI', 'albi-prod-cluster-a', NOW() + INTERVAL '60 days', '2.94', '2.94', 'Expiring', 'Production'),
    ('Lenovo', 'SR635', 'LNV-SR635-002', 'ALBI', 'albi-storage-cluster-b', NOW() + INTERVAL '1095 days', '3.20', '3.20', 'Supported', 'Production'),
    ('HPE', 'DL380 Gen9', 'HPE-DL380-002', 'ALBI', 'albi-test-cluster-c', NOW() - INTERVAL '500 days', '2.94', '2.80', 'Expired', 'Retiring');
