CREATE TABLE failure_patterns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    error_type TEXT NOT NULL,
    error_message_fragment TEXT NOT NULL,
    occurrence_count INT NOT NULL DEFAULT 1,
    affected_workflow TEXT NOT NULL,
    affected_components TEXT[] NOT NULL DEFAULT '{}',
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    suggested_article_title TEXT NOT NULL DEFAULT '',
    suggested_article_body TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'New',
    rejection_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (error_type, affected_workflow)
);

INSERT INTO failure_patterns (id, error_type, error_message_fragment, occurrence_count, affected_workflow, affected_components, first_seen, last_seen, suggested_article_title, suggested_article_body, status) VALUES
    ('c0000200-1000-1000-1000-000000000001', 'VmNicTeamingMismatch', 'NIC teaming policy does not match vSwitch configuration', 12, 'windows-server-deployment', ARRAY['vCenter', 'ESXi host', 'vDS switch'], NOW() - INTERVAL '30 days', NOW() - INTERVAL '2 hours', 'Runbook: VM NIC teaming mismatch — Windows Server deployment fails at customisation stage', '### Symptom\nWindows Server deployment fails during VM customisation with NIC teaming policy mismatch.\n\n### Root Cause\nThe vDS teaming policy does not match the expected configuration in the customisation spec.\n\n### Resolution\n1. Verify vDS teaming policy for port group\n2. Align customisation spec with vDS switch configuration\n3. Retry VM customisation\n\n### Affected Components\nvCenter, ESXi host, vDS switch\n\n### Source\nStatic-dry-run pattern analysis. No live provider call performed.', 'New'),
    ('c0000200-1000-1000-1000-000000000002', 'CertificateAutoEnrollmentStalled', 'Auto-enrollment service stopped responding after domain controller reboot', 8, 'certificate-lifecycle', ARRAY['AD CS', 'Domain Controller', 'Certificate template'], NOW() - INTERVAL '45 days', NOW() - INTERVAL '1 day', 'Runbook: Certificate auto-enrollment stalled after domain controller maintenance', '### Symptom\nCertificate auto-enrollment stops processing requests after a domain controller restart.\n\n### Root Cause\nThe AD CS enrollment service requires a manual restart after domain controller maintenance.\n\n### Resolution\n1. Restart AD CS enrollment service on the issuing CA\n2. Verify CRL distribution point reachability\n3. Trigger gpupdate on affected hosts\n\n### Source\nStatic-dry-run pattern analysis. No live provider call performed.', 'New'),
    ('c0000200-1000-1000-1000-000000000003', 'BackupSnapshotTimeout', 'Veeam backup job timed out waiting for VMware snapshot removal', 15, 'backup-coverage', ARRAY['Veeam', 'vCenter', 'SAN storage'], NOW() - INTERVAL '60 days', NOW() - INTERVAL '6 hours', 'Runbook: Veeam backup timeout — VMware snapshot consolidation delay during high I/O', '### Symptom\nVeeam backup jobs time out during snapshot removal on VMs with high disk I/O.\n\n### Root Cause\nSnapshot consolidation takes longer than the Veeam timeout threshold during peak I/O periods.\n\n### Resolution\n1. Check datastore latency during backup window\n2. Increase Veeam snapshot removal timeout to 30 minutes\n3. Schedule backups outside peak I/O windows\n4. Consider storage-level snapshot offload for high-churn VMs\n\n### Source\nStatic-dry-run pattern analysis. No live provider call performed.', 'UnderReview'),
    ('c0000200-1000-1000-1000-000000000004', 'ZabbixAgentVersionDrift', 'Zabbix agent autoregistration failed due to version mismatch with server', 6, 'zabbix-onboarding', ARRAY['Zabbix server', 'Zabbix agent', 'Package repository'], NOW() - INTERVAL '20 days', NOW() - INTERVAL '12 hours', 'Runbook: Zabbix agent version drift preventing autoregistration', '### Symptom\nNew hosts fail Zabbix autoregistration with agent version mismatch error.\n\n### Root Cause\nThe Linux package repository has a newer agent version than the Zabbix server allows.\n\n### Resolution\n1. Verify agent and server version compatibility matrix\n2. Pin agent package version in deployment template\n3. Update Zabbix server to support newer agent versions\n4. Re-trigger autoregistration on affected hosts\n\n### Source\nStatic-dry-run pattern analysis. No live provider call performed.', 'New');
