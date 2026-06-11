CREATE TABLE monitoring_review_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_or_service_name TEXT NOT NULL,
    review_type TEXT NOT NULL CHECK (review_type IN ('NewOnboarding', 'TemplateMismatch', 'GroupChange', 'ProxyReassignment', 'DriftDetected')),
    site TEXT NOT NULL,
    assigned_to TEXT,
    sla_deadline TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending', 'Assigned', 'InProgress', 'Resolved', 'Overdue')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_monitoring_queue_site ON monitoring_review_queue(site);
CREATE INDEX idx_monitoring_queue_status ON monitoring_review_queue(status);
CREATE INDEX idx_monitoring_queue_assigned ON monitoring_review_queue(assigned_to);
CREATE INDEX idx_monitoring_queue_sla ON monitoring_review_queue(sla_deadline);

INSERT INTO monitoring_review_queue (id, host_or_service_name, review_type, site, assigned_to, sla_deadline, status, created_at) VALUES
    ('d0000100-1000-1000-1000-000000000001', 'srv-defra-web01.example.local', 'NewOnboarding', 'DEFRA', NULL, NOW() + INTERVAL '48 hours', 'Pending', NOW() - INTERVAL '2 hours'),
    ('d0000100-1000-1000-1000-000000000002', 'srv-gblon-db01.example.local', 'TemplateMismatch', 'GBLON', 'alice', NOW() - INTERVAL '4 hours', 'Overdue', NOW() - INTERVAL '3 days'),
    ('d0000100-1000-1000-1000-000000000003', 'srv-defra-app02.example.local', 'GroupChange', 'DEFRA', 'bob', NOW() + INTERVAL '24 hours', 'Assigned', NOW() - INTERVAL '6 hours'),
    ('d0000100-1000-1000-1000-000000000004', 'srv-gblon-fs01.example.local', 'ProxyReassignment', 'GBLON', 'carol', NOW() + INTERVAL '12 hours', 'InProgress', NOW() - INTERVAL '12 hours'),
    ('d0000100-1000-1000-1000-000000000005', 'srv-nlams-mon01.example.local', 'DriftDetected', 'NLAMS', NULL, NOW() + INTERVAL '72 hours', 'Pending', NOW() - INTERVAL '1 hour');
