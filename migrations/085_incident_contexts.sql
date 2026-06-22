CREATE TABLE IF NOT EXISTS incident_contexts (
    incident_id TEXT PRIMARY KEY,
    title       TEXT        NOT NULL,
    severity    TEXT        NOT NULL,
    status      TEXT        NOT NULL,
    incident_json JSONB     NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incident_contexts_status ON incident_contexts(status);

INSERT INTO incident_contexts (incident_id, title, severity, status, incident_json, created_at, updated_at)
VALUES (
    'inc-defra-001',
    'DEFRA database latency spike',
    'sev2',
    'active',
    '{"incident_id":"inc-defra-001","title":"DEFRA database latency spike","severity":"sev2","affected_ci":[{"ci_name":"defra-db-cluster","ci_type":"database","site":"DEFRA","status":"degraded"}],"upstream_deps":[{"ci_name":"defra-core-network","relationship":"network-connectivity","direction":"upstream"},{"ci_name":"defra-identity-services","relationship":"authentication","direction":"upstream"}],"downstream_deps":[{"ci_name":"defra-portal-ui","relationship":"user-facing-service","direction":"downstream"},{"ci_name":"defra-batch-workers","relationship":"processing-dependency","direction":"downstream"}],"recent_changes":[{"change_id":"CHG-DEFRA-net-001","description":"DEFRA spine switch policy update","changed_by":"alex.netops","timestamp":"2026-06-11T08:45:00Z","risk_level":"medium"},{"change_id":"CHG-DEFRA-app-002","description":"DEFRA workload placement rebalance","changed_by":"sam.platform","timestamp":"2026-06-11T07:15:00Z","risk_level":"low"}],"on_call":{"primary":"morgan.platform","secondary":"jamie.sre","escalation":"defra-incident-commander","group":"platform-operations"},"related_tickets":["INC-DEFRA-7421","CHG-DEFRA-219"],"assembled_at":"2026-06-11T10:00:00Z","status":"active","resolution":null}',
    '2026-06-11T10:00:00Z',
    '2026-06-11T10:00:00Z'
)
ON CONFLICT (incident_id) DO NOTHING;

INSERT INTO incident_contexts (incident_id, title, severity, status, incident_json, created_at, updated_at)
VALUES (
    'inc-gblon-001',
    'GBLON storage fabric errors',
    'sev1',
    'active',
    '{"incident_id":"inc-gblon-001","title":"GBLON storage fabric errors","severity":"sev1","affected_ci":[{"ci_name":"gblon-vsan-cluster","ci_type":"storage","site":"GBLON","status":"critical"}],"upstream_deps":[{"ci_name":"gblon-core-network","relationship":"network-connectivity","direction":"upstream"},{"ci_name":"gblon-identity-services","relationship":"authentication","direction":"upstream"}],"downstream_deps":[{"ci_name":"gblon-portal-ui","relationship":"user-facing-service","direction":"downstream"},{"ci_name":"gblon-batch-workers","relationship":"processing-dependency","direction":"downstream"}],"recent_changes":[{"change_id":"CHG-GBLON-net-001","description":"GBLON spine switch policy update","changed_by":"alex.netops","timestamp":"2026-06-11T08:45:00Z","risk_level":"medium"},{"change_id":"CHG-GBLON-app-002","description":"GBLON workload placement rebalance","changed_by":"sam.platform","timestamp":"2026-06-11T07:15:00Z","risk_level":"low"}],"on_call":{"primary":"casey.storage","secondary":"riley.datacenter","escalation":"gblon-incident-commander","group":"storage-operations"},"related_tickets":["INC-GBLON-8844","CHG-GBLON-118"],"assembled_at":"2026-06-11T09:30:00Z","status":"active","resolution":null}',
    '2026-06-11T09:30:00Z',
    '2026-06-11T09:30:00Z'
)
ON CONFLICT (incident_id) DO NOTHING;
