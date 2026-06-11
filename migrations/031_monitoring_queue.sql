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
    ('d0000100-1000-1000-1000-000000000001', 'srv-love-web01.corp.local', 'NewOnboarding', 'LOVE', NULL, NOW() + INTERVAL '48 hours', 'Pending', NOW() - INTERVAL '2 hours'),
    ('d0000100-1000-1000-1000-000000000002', 'srv-bur1-db01.corp.local', 'TemplateMismatch', 'BUR1', 'alice', NOW() - INTERVAL '4 hours', 'Overdue', NOW() - INTERVAL '3 days'),
    ('d0000100-1000-1000-1000-000000000003', 'srv-love-app02.corp.local', 'GroupChange', 'LOVE', 'bob', NOW() + INTERVAL '24 hours', 'Assigned', NOW() - INTERVAL '6 hours'),
    ('d0000100-1000-1000-1000-000000000004', 'srv-bur1-fs01.corp.local', 'ProxyReassignment', 'BUR1', 'carol', NOW() + INTERVAL '12 hours', 'InProgress', NOW() - INTERVAL '12 hours'),
    ('d0000100-1000-1000-1000-000000000005', 'srv-tor1-mon01.corp.local', 'DriftDetected', 'TOR1', NULL, NOW() + INTERVAL '72 hours', 'Pending', NOW() - INTERVAL '1 hour');
