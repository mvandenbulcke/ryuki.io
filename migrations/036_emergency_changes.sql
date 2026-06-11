CREATE TABLE emergency_changes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    change_description TEXT NOT NULL,
    affected_systems TEXT[] NOT NULL DEFAULT '{}',
    initiated_by TEXT NOT NULL,
    reason_override TEXT NOT NULL,
    approved_by TEXT,
    executed_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'Initiated',
    audit_evidence TEXT[] NOT NULL DEFAULT '{}',
    site TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    post_review_notes TEXT
);

INSERT INTO emergency_changes (id, change_description, affected_systems, initiated_by, reason_override, approved_by, executed_at, status, audit_evidence, site, created_at, updated_at, post_review_notes) VALUES
    ('d0000100-1000-1000-1000-000000000001', 'Urgent firewall rule change for DB replication recovery', ARRAY['defra-db-cluster', 'defra-fw-edge'], 'alice.operator', 'Incident INC-2025-0042 — replication lag exceeds SLA', 'EMERGENCY — auto-approved per break-glass policy', NOW() - INTERVAL '3 hours', 'Verified', ARRAY['FW rule diff applied to defra-fw-edge-01', 'DB replication caught up within 12min of change', 'Post-change verification: all replicas in sync'], 'DEFRA', NOW() - INTERVAL '4 hours', NOW() - INTERVAL '2 hours', 'Reviewed by SOC lead. Emergency justified. No process gap.'),
    ('d0000100-1000-1000-1000-000000000002', 'Emergency storage capacity expansion — datastore at 97%', ARRAY['gblon-vsan-cluster', 'gblon-datastore-prod'], 'bob.engineer', 'Capacity alert GBLON-DS-PROD-001 — risk of VM outage', 'EMERGENCY — auto-approved per break-glass policy', NOW() - INTERVAL '1 hour', 'Executed', ARRAY['Added 2TB to gblon-datastore-prod', 'No VM disruption observed', 'Post-expand usage: 72%'], 'GBLON', NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour', NULL),
    ('d0000100-1000-1000-1000-000000000003', 'Emergency certificate renewal — wildcard expired on defra-lb-01', ARRAY['defra-lb-01', 'defra-ingress'], 'carol.security', 'TLS cert expiry causing user-facing errors on portal', 'EMERGENCY — auto-approved per break-glass policy', NULL, 'Approved', ARRAY[]::text[], 'DEFRA', NOW() - INTERVAL '30 minutes', NOW() - INTERVAL '15 minutes', NULL);
