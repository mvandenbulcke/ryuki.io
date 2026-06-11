CREATE TABLE servicenow_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_type TEXT NOT NULL CHECK (request_type IN ('incident', 'change', 'request', 'knowledge')),
    external_ref TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'Draft' CHECK (status IN ('Draft', 'Ready', 'Pending', 'Submitted', 'Failed')),
    ci_name TEXT NOT NULL,
    payload_summary TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    submitted_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_snow_queue_status ON servicenow_queue(status);
CREATE INDEX idx_snow_queue_ci_name ON servicenow_queue(ci_name);
CREATE INDEX idx_snow_queue_request_type ON servicenow_queue(request_type);

INSERT INTO servicenow_queue (id, request_type, external_ref, status, ci_name, payload_summary, created_at, submitted_at, metadata) VALUES
    ('d0000100-1000-1000-1000-000000000201', 'incident', 'INC-2026-0042', 'Submitted', 'srv-defra-web01.corp.local', 'High CPU alert — incident created, ops-lead assigned', NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour', '{"urgency":"2","assignment_group":"Wintel-Operations","site":"DEFRA"}'),
    ('d0000100-1000-1000-1000-000000000202', 'change', 'CHG-2026-0127', 'Ready', 'srv-gblon-db01.corp.local', 'Planned memory upgrade from 64 GB to 128 GB — maintenance window 2026-06-15 02:00-04:00 UTC', NOW() - INTERVAL '4 hours', NULL, '{"change_type":"Standard","risk":"Low","planned_start":"2026-06-15T02:00:00Z","planned_end":"2026-06-15T04:00:00Z","site":"GBLON"}'),
    ('d0000100-1000-1000-1000-000000000203', 'request', '', 'Draft', 'srv-nlams-mon01.corp.local', 'Request for Zabbix agent upgrade on monitoring server — pending validation', NOW() - INTERVAL '6 hours', NULL, '{"request_type":"software-upgrade","site":"NLAMS"}'),
    ('d0000100-1000-1000-1000-000000000204', 'knowledge', 'KB-2026-0182', 'Pending', 'srv-gblon-fs01.corp.local', 'VSS writer recovery procedure for file server backup failures — draft KB article', NOW() - INTERVAL '1 hour', NULL, '{"knowledge_base":"Operations","site":"GBLON"}');
