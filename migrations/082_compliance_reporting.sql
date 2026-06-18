-- migration 082: compliance_reporting durable persistence
-- Tables: compliance_frameworks, compliance_controls, compliance_reports, compliance_findings

CREATE TABLE IF NOT EXISTS compliance_frameworks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    last_assessed TEXT NOT NULL,
    next_assessment_due TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS compliance_controls (
    id TEXT PRIMARY KEY,
    framework_id TEXT NOT NULL REFERENCES compliance_frameworks(id),
    control_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('Compliant','NonCompliant','NotApplicable')),
    evidence_ref TEXT,
    assessed_by TEXT,
    assessed_at TEXT,
    site TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS compliance_reports (
    id TEXT PRIMARY KEY,
    framework_id TEXT NOT NULL REFERENCES compliance_frameworks(id),
    site TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    overall_status TEXT NOT NULL CHECK (overall_status IN ('Compliant','NonCompliant','AtRisk')),
    compliant_controls INTEGER NOT NULL CHECK (compliant_controls >= 0),
    total_controls INTEGER NOT NULL CHECK (total_controls >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS compliance_findings (
    id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL REFERENCES compliance_reports(id) ON DELETE CASCADE,
    control_id TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('Critical','High','Medium','Low')),
    description TEXT NOT NULL,
    remediation TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('Open','InProgress','Resolved','Waived')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Seed: frameworks ──────────────────────────────────────────────────────────

INSERT INTO compliance_frameworks (id, name, version, last_assessed, next_assessment_due)
VALUES
    ('cf-pci-dss',   'PCI-DSS',   '4.0',  (NOW() - INTERVAL '60 days')::TEXT, (NOW() + INTERVAL '305 days')::TEXT),
    ('cf-soc2',      'SOC2',      '2022', (NOW() - INTERVAL '35 days')::TEXT, (NOW() + INTERVAL '330 days')::TEXT),
    ('cf-iso27001',  'ISO27001',  '2022', (NOW() - INTERVAL '90 days')::TEXT, (NOW() + INTERVAL '275 days')::TEXT)
ON CONFLICT (id) DO NOTHING;

-- ─── Seed: controls ───────────────────────────────────────────────────────────

INSERT INTO compliance_controls (id, framework_id, control_id, title, description, status, evidence_ref, assessed_by, assessed_at, site)
VALUES
    -- PCI-DSS controls
    ('cc-pci-001', 'cf-pci-dss', 'PCI-1.1',  'Firewall configuration standards',
        'Maintain documented firewall and router configuration standards.',
        'Compliant', 'ev-cc-pci-001', 'static.auditor', (NOW() - INTERVAL '30 days')::TEXT, 'DEFRA'),

    ('cc-pci-002', 'cf-pci-dss', 'PCI-3.4',  'Protect stored cardholder data',
        'Render sensitive data unreadable wherever stored.',
        'NonCompliant', 'ev-cc-pci-002', 'static.auditor', (NOW() - INTERVAL '28 days')::TEXT, 'DEFRA'),

    ('cc-pci-003', 'cf-pci-dss', 'PCI-6.3',  'Secure software development',
        'Develop software using secure coding practices.',
        'Compliant', 'ev-cc-pci-003', 'static.auditor', (NOW() - INTERVAL '27 days')::TEXT, 'DEFRA'),

    ('cc-pci-004', 'cf-pci-dss', 'PCI-8.2',  'User identification',
        'Assign unique IDs before allowing access to system components.',
        'Compliant', 'ev-cc-pci-004', 'static.auditor', (NOW() - INTERVAL '26 days')::TEXT, 'GBLON'),

    ('cc-pci-005', 'cf-pci-dss', 'PCI-10.2', 'Audit logging',
        'Implement automated audit trails for all system components.',
        'NonCompliant', 'ev-cc-pci-005', 'static.auditor', (NOW() - INTERVAL '25 days')::TEXT, 'GBLON'),

    -- SOC2 controls
    ('cc-soc2-001', 'cf-soc2', 'CC1.1', 'Integrity and ethical values',
        'Demonstrate commitment to integrity and ethical values.',
        'Compliant', 'ev-cc-soc2-001', 'static.auditor', (NOW() - INTERVAL '20 days')::TEXT, 'DEFRA'),

    ('cc-soc2-002', 'cf-soc2', 'CC2.1', 'Communication of objectives',
        'Communicate quality information to support internal controls.',
        'Compliant', 'ev-cc-soc2-002', 'static.auditor', (NOW() - INTERVAL '19 days')::TEXT, 'DEFRA'),

    ('cc-soc2-003', 'cf-soc2', 'CC6.1', 'Logical access controls',
        'Implement logical access security software and infrastructure.',
        'NonCompliant', 'ev-cc-soc2-003', 'static.auditor', (NOW() - INTERVAL '18 days')::TEXT, 'GBLON'),

    ('cc-soc2-004', 'cf-soc2', 'CC7.2', 'Security monitoring',
        'Monitor system components for anomalies and events.',
        'Compliant', 'ev-cc-soc2-004', 'static.auditor', (NOW() - INTERVAL '17 days')::TEXT, 'GBLON'),

    -- NotApplicable: evidence_ref, assessed_by, assessed_at all NULL
    ('cc-soc2-005', 'cf-soc2', 'CC8.1', 'Change management',
        'Authorize, design, develop, and implement changes.',
        'NotApplicable', NULL, NULL, NULL, 'FRPAR'),

    -- ISO27001 controls
    ('cc-iso-001', 'cf-iso27001', 'A.5.1',  'Information security policies',
        'Define, approve, publish, and review security policies.',
        'Compliant', 'ev-cc-iso-001', 'static.auditor', (NOW() - INTERVAL '15 days')::TEXT, 'DEFRA'),

    ('cc-iso-002', 'cf-iso27001', 'A.8.9',  'Configuration management',
        'Establish and maintain secure configurations.',
        'NonCompliant', 'ev-cc-iso-002', 'static.auditor', (NOW() - INTERVAL '14 days')::TEXT, 'FRPAR'),

    ('cc-iso-003', 'cf-iso27001', 'A.8.15', 'Logging',
        'Produce, store, protect, and analyze logs.',
        'Compliant', 'ev-cc-iso-003', 'static.auditor', (NOW() - INTERVAL '13 days')::TEXT, 'GBLON'),

    ('cc-iso-004', 'cf-iso27001', 'A.8.16', 'Monitoring activities',
        'Monitor networks, systems, and applications for anomalous behavior.',
        'Compliant', 'ev-cc-iso-004', 'static.auditor', (NOW() - INTERVAL '12 days')::TEXT, 'GBLON'),

    ('cc-iso-005', 'cf-iso27001', 'A.8.24', 'Use of cryptography',
        'Define and implement rules for cryptography and key management.',
        'Compliant', 'ev-cc-iso-005', 'static.auditor', (NOW() - INTERVAL '11 days')::TEXT, 'DEFRA')

ON CONFLICT (id) DO NOTHING;

-- ─── Seed: reports ────────────────────────────────────────────────────────────

INSERT INTO compliance_reports (id, framework_id, site, generated_at, overall_status, compliant_controls, total_controls)
VALUES
    ('cr-defra-pci-001', 'cf-pci-dss', 'DEFRA', (NOW() - INTERVAL '7 days')::TEXT, 'NonCompliant', 2, 3),
    ('cr-gblon-soc2-001', 'cf-soc2',   'GBLON', (NOW() - INTERVAL '4 days')::TEXT, 'NonCompliant', 1, 2)
ON CONFLICT (id) DO NOTHING;

-- ─── Seed: findings ───────────────────────────────────────────────────────────

INSERT INTO compliance_findings (id, report_id, control_id, severity, description, remediation, status)
VALUES
    -- findings for cr-defra-pci-001
    ('cr-find-001', 'cr-defra-pci-001', 'cc-pci-002', 'High',
        'Stored sensitive data evidence is incomplete for DEFRA.',
        'Attach encrypted-storage evidence and key-management review.',
        'Open'),

    ('cr-find-002', 'cr-defra-pci-001', 'cc-pci-002', 'Medium',
        'Data retention exception lacks current owner sign-off.',
        'Renew owner approval and add expiry to the retention exception.',
        'InProgress'),

    -- findings for cr-gblon-soc2-001
    ('cr-find-003', 'cr-gblon-soc2-001', 'cc-soc2-003', 'Critical',
        'Privileged access review evidence is missing.',
        'Complete privileged access recertification and attach evidence.',
        'Open'),

    ('cr-find-004', 'cr-gblon-soc2-001', 'cc-soc2-003', 'Low',
        'Access control procedure references an old support group.',
        'Update procedure owner and support group reference.',
        'Open')

ON CONFLICT (id) DO NOTHING;
