CREATE TABLE IF NOT EXISTS dr_test_runs (
    id          TEXT PRIMARY KEY,
    plan_id     TEXT NOT NULL,
    site        TEXT NOT NULL,
    completed   BOOLEAN NOT NULL DEFAULT false,
    run_json    JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dr_test_runs_plan_id ON dr_test_runs(plan_id);

-- Seed the 4 engine demo test runs with static timestamps
INSERT INTO dr_test_runs (id, plan_id, site, completed, run_json, created_at, updated_at)
VALUES (
    'drt-defra-001',
    'drp-defra-001',
    'DEFRA',
    true,
    '{"id":"drt-defra-001","plan_id":"drp-defra-001","site":"DEFRA","started_at":"2026-05-13T21:00:00Z","completed_at":"2026-05-13T23:00:00Z","result":"passed","systems_tested":["defra-app-01","defra-db-01"],"systems_failed":[],"tester":"dr.coordinator","evidence_pack_id":"evp-dr-defra-001"}',
    '2026-05-13T21:00:00Z',
    '2026-05-13T23:00:00Z'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO dr_test_runs (id, plan_id, site, completed, run_json, created_at, updated_at)
VALUES (
    'drt-defra-002',
    'drp-defra-001',
    'DEFRA',
    true,
    '{"id":"drt-defra-002","plan_id":"drp-defra-001","site":"DEFRA","started_at":"2026-03-17T20:00:00Z","completed_at":"2026-03-17T22:00:00Z","result":"partial","systems_tested":["defra-app-01","defra-db-01"],"systems_failed":["defra-db-01"],"tester":"platform.ops","evidence_pack_id":"evp-dr-defra-002"}',
    '2026-03-17T20:00:00Z',
    '2026-03-17T22:00:00Z'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO dr_test_runs (id, plan_id, site, completed, run_json, created_at, updated_at)
VALUES (
    'drt-gblon-001',
    'drp-gblon-001',
    'GBLON',
    true,
    '{"id":"drt-gblon-001","plan_id":"drp-gblon-001","site":"GBLON","started_at":"2026-06-10T22:00:00Z","completed_at":"2026-06-10T23:00:00Z","result":"passed","systems_tested":["gblon-vsan-01","gblon-vsan-02"],"systems_failed":[],"tester":"storage.ops","evidence_pack_id":"evp-dr-gblon-001"}',
    '2026-06-10T22:00:00Z',
    '2026-06-10T23:00:00Z'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO dr_test_runs (id, plan_id, site, completed, run_json, created_at, updated_at)
VALUES (
    'drt-frpar-001',
    'drp-frpar-001',
    'FRPAR',
    true,
    '{"id":"drt-frpar-001","plan_id":"drp-frpar-001","site":"FRPAR","started_at":"2025-12-22T22:00:00Z","completed_at":"2025-12-22T23:00:00Z","result":"failed","systems_tested":["frpar-core-01","frpar-fw-01"],"systems_failed":["frpar-fw-01"],"tester":"network.ops","evidence_pack_id":"evp-dr-frpar-001"}',
    '2025-12-22T22:00:00Z',
    '2025-12-22T23:00:00Z'
) ON CONFLICT (id) DO NOTHING;
