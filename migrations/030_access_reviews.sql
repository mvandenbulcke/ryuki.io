CREATE TABLE access_reviews (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_type TEXT NOT NULL,
    target_name TEXT NOT NULL,
    owner TEXT NOT NULL,
    last_reviewed TIMESTAMPTZ,
    next_review_due TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'Current',
    risk_level TEXT NOT NULL DEFAULT 'Low',
    site TEXT NOT NULL,
    reviewer TEXT,
    decision TEXT,
    review_history JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_access_reviews_site ON access_reviews (site);
CREATE INDEX idx_access_reviews_status ON access_reviews (status);
CREATE INDEX idx_access_reviews_next_due ON access_reviews (next_review_due);
CREATE INDEX idx_access_reviews_type ON access_reviews (target_type);

INSERT INTO access_reviews (id, target_type, target_name, owner, last_reviewed, next_review_due, status, risk_level, site, reviewer, decision, review_history) VALUES
    ('c0000200-1000-1000-1000-000000000001', 'Role', 'Domain Admins', 'alice.smith', NOW() - INTERVAL '120 days', NOW() - INTERVAL '30 days', 'Overdue', 'High', 'DEFRA', NULL, NULL, '[]'),
    ('c0000200-1000-1000-1000-000000000002', 'Group', 'Backup Operators', 'bob.jones', NOW() - INTERVAL '100 days', NOW() - INTERVAL '10 days', 'Overdue', 'Med', 'DEFRA', NULL, NULL, '[]'),
    ('c0000200-1000-1000-1000-000000000003', 'ServiceAccount', 'svc_scom_sa', 'carol.wong', NULL, NOW() + INTERVAL '45 days', 'Current', 'Low', 'GBLON', NULL, NULL, '[]'),
    ('c0000200-1000-1000-1000-000000000004', 'FileShare', '\\\\fs01\\finance', 'dave.kim', NOW() - INTERVAL '60 days', NOW() + INTERVAL '5 days', 'UnderReview', 'High', 'GBLON', 'auditor.lee', NULL, '[{"timestamp": "' || NOW() - INTERVAL '3 days' || '", "action": "initiated", "reviewer": "auditor.lee", "detail": "Review initiated for finance share recertification"}]'),
    ('c0000200-1000-1000-1000-000000000005', 'ServiceAccount', 'svc_backup_sa', 'eve.taylor', NOW() - INTERVAL '150 days', NOW() - INTERVAL '5 days', 'Overdue', 'Med', 'DEFRA', NULL, NULL, '[]');
