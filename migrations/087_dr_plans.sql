CREATE TABLE IF NOT EXISTS dr_plans (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    site        TEXT NOT NULL,
    status      TEXT NOT NULL,
    plan_json   JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dr_plans_site ON dr_plans(site);

INSERT INTO dr_plans (id, name, site, status, plan_json, created_at, updated_at)
VALUES (
    'drp-defra-001',
    'DEFRA production full-site failover',
    'DEFRA',
    'active',
    '{"id":"drp-defra-001","name":"DEFRA production full-site failover","site":"DEFRA","target_site":"GBLON","systems":["defra-app-01","defra-db-01"],"rpo_minutes":15,"rto_minutes":120,"last_tested":"2026-05-13T00:00:00Z","next_test_due":"2026-06-12T00:00:00Z","status":"active"}',
    '2026-05-13T00:00:00Z',
    '2026-05-13T00:00:00Z'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO dr_plans (id, name, site, status, plan_json, created_at, updated_at)
VALUES (
    'drp-gblon-001',
    'GBLON storage partial failover',
    'GBLON',
    'approved',
    '{"id":"drp-gblon-001","name":"GBLON storage partial failover","site":"GBLON","target_site":"FRPAR","systems":["gblon-vsan-01","gblon-vsan-02"],"rpo_minutes":30,"rto_minutes":180,"last_tested":"2026-06-10T00:00:00Z","next_test_due":"2026-07-10T00:00:00Z","status":"approved"}',
    '2026-06-10T00:00:00Z',
    '2026-06-10T00:00:00Z'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO dr_plans (id, name, site, status, plan_json, created_at, updated_at)
VALUES (
    'drp-frpar-001',
    'FRPAR communications tabletop',
    'FRPAR',
    'draft',
    '{"id":"drp-frpar-001","name":"FRPAR communications tabletop","site":"FRPAR","target_site":"DEFRA","systems":["frpar-core-01","frpar-fw-01"],"rpo_minutes":60,"rto_minutes":240,"last_tested":null,"next_test_due":"2026-06-20T00:00:00Z","status":"draft"}',
    '2026-04-01T00:00:00Z',
    '2026-04-01T00:00:00Z'
) ON CONFLICT (id) DO NOTHING;
