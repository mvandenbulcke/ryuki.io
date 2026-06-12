CREATE TABLE legal_holds (
    id TEXT PRIMARY KEY,
    server_or_app_name TEXT NOT NULL,
    hold_type TEXT NOT NULL CHECK (hold_type IN ('Investigation', 'Litigation', 'Compliance', 'Retention')),
    reason TEXT NOT NULL,
    initiated_by TEXT NOT NULL,
    initiated_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expiry_date TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Released', 'Expired')),
    affected_backups JSONB NOT NULL DEFAULT '[]',
    site TEXT NOT NULL,
    released_by TEXT,
    released_date TIMESTAMPTZ,
    audit_trail JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_legal_holds_server ON legal_holds(server_or_app_name);
CREATE INDEX idx_legal_holds_site ON legal_holds(site);
CREATE INDEX idx_legal_holds_status ON legal_holds(status);
CREATE INDEX idx_legal_holds_hold_type ON legal_holds(hold_type);
CREATE INDEX idx_legal_holds_expiry ON legal_holds(expiry_date);

INSERT INTO legal_holds (id, server_or_app_name, hold_type, reason, initiated_by, initiated_date, expiry_date, status, affected_backups, site, audit_trail) VALUES
    ('lh-00000000-0000-0000-0000-000000000001', 'srv-defra-finance.example.local', 'Litigation', 'DRY-RUN: Regulatory investigation Q2-2026 — financial audit trail preservation required', 'compliance-team', NOW() - INTERVAL '45 days', NOW() + INTERVAL '135 days', 'Active', '["backup-srv-defra-finance-20260601", "backup-srv-defra-finance-20260515", "backup-srv-defra-finance-20260501"]', 'DEFRA', ('[{"timestamp":"' || (NOW() - INTERVAL '45 days')::text || '","action":"hold_placed","by":"compliance-team","detail":"DRY-RUN: Hold placed for Q2 regulatory investigation"}]')::jsonb),
    ('lh-00000000-0000-0000-0000-000000000002', 'srv-gblon-erp.example.local', 'Compliance', 'DRY-RUN: SOX compliance extended retention — 7-year archive mandate', 'audit-team', NOW() - INTERVAL '365 days', NOW() + INTERVAL '2190 days', 'Active', '["backup-srv-gblon-erp-20260301", "backup-srv-gblon-erp-20251201", "backup-srv-gblon-erp-20250901", "backup-srv-gblon-erp-20250601"]', 'GBLON', ('[{"timestamp":"' || (NOW() - INTERVAL '365 days')::text || '","action":"hold_placed","by":"audit-team","detail":"DRY-RUN: SOX compliance retention hold activated"}]')::jsonb),
    ('lh-00000000-0000-0000-0000-000000000003', 'srv-frpar-hr.example.local', 'Investigation', 'DRY-RUN: HR data integrity investigation — access logs and backup retention', 'security-team', NOW() - INTERVAL '15 days', NOW() + INTERVAL '15 days', 'Active', '["backup-srv-frpar-hr-20260605", "backup-srv-frpar-hr-20260525"]', 'FRPAR', ('[{"timestamp":"' || (NOW() - INTERVAL '15 days')::text || '","action":"hold_placed","by":"security-team","detail":"DRY-RUN: HR investigation hold activated, backup scope defined"}]')::jsonb);
