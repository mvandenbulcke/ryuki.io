CREATE TABLE IF NOT EXISTS runbook_executions (
    id TEXT PRIMARY KEY,
    runbook_id TEXT NOT NULL,
    status TEXT NOT NULL,
    site TEXT NOT NULL,
    started_by TEXT NOT NULL,
    execution_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_runbook_executions_site ON runbook_executions(site);

INSERT INTO runbook_executions (id, runbook_id, status, site, started_by, execution_json, created_at, updated_at)
VALUES
    (
        'rbx-defra-001',
        'patch-windows-server',
        'draft',
        'DEFRA',
        'alice.engineer',
        '{"id":"rbx-defra-001","runbook_id":"patch-windows-server","status":"draft","site":"DEFRA","started_by":"alice.engineer","steps_results":[{"step_order":1,"status":"pending","output":"Pending dry-run execution","started_at":null,"completed_at":null},{"step_order":2,"status":"pending","output":"Pending dry-run execution","started_at":null,"completed_at":null},{"step_order":3,"status":"pending","output":"Pending dry-run execution","started_at":null,"completed_at":null}]}'::jsonb,
        '2026-01-01T00:00:00Z',
        '2026-01-01T00:00:00Z'
    ),
    (
        'rbx-gblon-001',
        'restart-service',
        'approved',
        'GBLON',
        'bob.engineer',
        '{"id":"rbx-gblon-001","runbook_id":"restart-service","status":"approved","site":"GBLON","started_by":"bob.engineer","steps_results":[{"step_order":1,"status":"pending","output":"Pending dry-run execution","started_at":null,"completed_at":null},{"step_order":2,"status":"pending","output":"Pending dry-run execution","started_at":null,"completed_at":null},{"step_order":3,"status":"pending","output":"Pending dry-run execution","started_at":null,"completed_at":null}]}'::jsonb,
        '2026-01-01T00:00:00Z',
        '2026-01-01T00:00:00Z'
    ),
    (
        'rbx-deber-001',
        'certificate-renewal',
        'completed',
        'DEBER',
        'carla.engineer',
        '{"id":"rbx-deber-001","runbook_id":"certificate-renewal","status":"completed","site":"DEBER","started_by":"carla.engineer","steps_results":[{"step_order":1,"status":"completed","output":"Step 1 completed in dry-run mode","started_at":"2026-01-01T00:00:00Z","completed_at":"2026-01-01T00:00:00Z"},{"step_order":2,"status":"completed","output":"Step 2 completed in dry-run mode","started_at":"2026-01-01T00:00:00Z","completed_at":"2026-01-01T00:00:00Z"},{"step_order":3,"status":"completed","output":"Step 3 completed in dry-run mode","started_at":"2026-01-01T00:00:00Z","completed_at":"2026-01-01T00:00:00Z"}]}'::jsonb,
        '2026-01-01T00:00:00Z',
        '2026-01-01T00:00:00Z'
    )
ON CONFLICT (id) DO NOTHING;
