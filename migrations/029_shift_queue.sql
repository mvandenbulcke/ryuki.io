CREATE TABLE shift_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    item_type TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    priority TEXT NOT NULL DEFAULT 'P3',
    assigned_to TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged BOOLEAN NOT NULL DEFAULT false,
    acknowledged_by TEXT,
    acknowledged_at TIMESTAMPTZ,
    resolved BOOLEAN NOT NULL DEFAULT false,
    resolution TEXT,
    resolved_at TIMESTAMPTZ,
    escalated BOOLEAN NOT NULL DEFAULT false,
    escalation_reason TEXT,
    escalated_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO shift_queue (id, item_type, title, description, priority, assigned_to, created_at, acknowledged, acknowledged_by, acknowledged_at, resolved, escalated, escalation_reason, escalated_at, metadata) VALUES
    ('d0000100-1000-1000-1000-000000000001', 'failed-operation', 'SQL patching wave failed on sql-love-01', 'Patch wave wave-sql-001 failed during execution step with exit code 3. Rollback completed, server is operational but unpatched.', 'P2', 'ops-lead', NOW() - INTERVAL '1 hour', true, 'ops-lead', NOW() - INTERVAL '30 minutes', false, false, NULL, NULL, '{"site":"LOVE","wave_id":"wave-sql-001"}'),
    ('d0000100-1000-1000-1000-000000000002', 'blocked-request', 'Linux deployment request blocked awaiting VLAN approval', 'Request req-lnx-042 for RHEL deployment at BUR1 is blocked. VLAN 210 approval from network team is pending for 6 hours.', 'P3', NULL, NOW() - INTERVAL '6 hours', false, NULL, NULL, false, false, NULL, NULL, '{"site":"BUR1","request_id":"req-lnx-042","vlan":"210"}'),
    ('d0000100-1000-1000-1000-000000000003', 'pending-approval', 'Decommission request awaiting final approval', 'Server srv-legacy-19 at CCSS is ready for decommission. Quarantine period of 7 days completed. Awaiting infra manager approval.', 'P3', 'infra-lead', NOW() - INTERVAL '12 hours', true, 'infra-lead', NOW() - INTERVAL '10 hours', false, false, NULL, NULL, '{"site":"CCSS","decommission_id":"dec-019"}'),
    ('d0000100-1000-1000-1000-000000000004', 'active-incident', 'Storage latency spike on esx-bur1-02 datastore', 'Active incident: datastore ds-bur1-prod-03 showing 45ms latency (threshold 20ms). 6 VMs affected. Storage team investigating.', 'P1', 'storage-lead', NOW() - INTERVAL '45 minutes', true, 'ops-lead', NOW() - INTERVAL '40 minutes', false, true, 'P1 incident affecting production storage', NOW() - INTERVAL '30 minutes', '{"site":"BUR1","datastore":"ds-bur1-prod-03","incident_id":"INC-2026-0042"}'),
    ('d0000100-1000-1000-1000-000000000005', 'veeam-failure', 'Veeam backup job failed for file server fs-tor1-01', 'Last night backup job Backup-FS-TOR1 failed with VSS writer error. No successful backup in 36 hours. Retry attempted 3 times.', 'P2', 'backup-eng', NOW() - INTERVAL '3 hours', false, NULL, NULL, false, false, NULL, NULL, '{"site":"TOR1","job_name":"Backup-FS-TOR1","server":"fs-tor1-01"}'),
    ('d0000100-1000-1000-1000-000000000006', 'expiring-cert', 'SSL certificate for portal.ryuki.io expiring in 7 days', 'Wildcard certificate *.ryuki.io expires on 2026-06-18. Auto-renewal job cert-renew-portal failed 2 consecutive runs. Manual intervention required.', 'P2', 'sec-team', NOW() - INTERVAL '24 hours', true, 'sec-team', NOW() - INTERVAL '20 hours', false, false, NULL, NULL, '{"cert_name":"*.ryuki.io","expiry_date":"2026-06-18"}');
