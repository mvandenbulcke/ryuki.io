CREATE TABLE firmware_records (
    id TEXT PRIMARY KEY,
    device_type TEXT NOT NULL CHECK (device_type IN ('Server','Switch','PDU','CRAC','Firewall')),
    vendor TEXT NOT NULL,
    model TEXT NOT NULL,
    current_version TEXT NOT NULL,
    minimum_version TEXT NOT NULL,
    latest_version TEXT NOT NULL,
    eol_date TEXT NOT NULL,
    site TEXT NOT NULL,
    compliance_status TEXT NOT NULL CHECK (compliance_status IN ('Compliant','NonCompliant','EOL','Exception')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE firmware_exceptions (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES firmware_records(id) ON DELETE CASCADE,
    reason TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    expiry_date TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_firmware_records_site ON firmware_records(site);
CREATE INDEX idx_firmware_records_compliance ON firmware_records(compliance_status);
CREATE INDEX idx_firmware_exceptions_device ON firmware_exceptions(device_id);

INSERT INTO firmware_records (id, device_type, vendor, model, current_version, minimum_version, latest_version, eol_date, site, compliance_status) VALUES
('fw-defra-srv-001', 'Server', 'HPE', 'DL360 Gen10', '2.94', '2.90', '2.96', '2028-12-31', 'DEFRA', 'Compliant'),
('fw-defra-sw-001', 'Switch', 'Cisco', 'Nexus 93180YC-FX', '10.2.1', '10.2.5', '10.4.3', '2027-09-30', 'DEFRA', 'NonCompliant'),
('fw-defra-pdu-001', 'PDU', 'APC', 'AP8941', '6.9.4', '6.8.0', '7.1.2', '2029-03-31', 'DEFRA', 'Compliant'),
('fw-gblon-srv-001', 'Server', 'Lenovo', 'SR635', '3.10', '3.20', '3.24', '2028-06-30', 'GBLON', 'NonCompliant'),
('fw-gblon-sw-001', 'Switch', 'Arista', '7050SX3', '4.25.7', '4.29.1', '4.31.2', '2025-09-30', 'GBLON', 'EOL'),
('fw-gblon-crac-001', 'CRAC', 'Vertiv', 'Liebert iCOM', '8.1', '8.0', '8.4', '2027-12-31', 'GBLON', 'Exception'),
('fw-deber-fw-001', 'Firewall', 'Palo Alto', 'PA-3220', '10.1.11', '10.2.8', '11.1.4', '2026-12-31', 'DEBER', 'NonCompliant'),
('fw-deber-srv-001', 'Server', 'Dell', 'PowerEdge R750', '6.10', '6.8', '7.1', '2030-01-31', 'DEBER', 'Compliant'),
('fw-deber-pdu-001', 'PDU', 'Eaton', 'ePDU G3', '2.5.0', '2.8.0', '3.0.1', '2024-12-31', 'DEBER', 'EOL');

INSERT INTO firmware_exceptions (id, device_id, reason, approved_by, expiry_date) VALUES
('fwex-gblon-crac-001', 'fw-gblon-crac-001', 'Awaiting maintenance window for CRAC controller upgrade', 'facilities.lead', to_char(CURRENT_DATE + INTERVAL '21 days', 'YYYY-MM-DD'));
