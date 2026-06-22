-- 089_firewall_rule_sets.sql — durable firewall rule-sets (last in-memory store).
--
-- FirewallRuleSet instances created via POST /api/network/firewall/rule-sets lived
-- only in a process-local OnceLock<Mutex> engine static and reset on restart. This
-- adds the durable table; the engine static becomes the no-DB fallback.
--
-- The id is the engine-generated "fws-<site>-<hex>" string (TEXT PK). The status
-- column stores the kebab-case serde form ("draft", "applied", "revoked").
-- rule_set_json round-trips the full FirewallRuleSet struct for faithful reconstruction.

CREATE TABLE IF NOT EXISTS firewall_rule_sets (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    site            TEXT NOT NULL,
    status          TEXT NOT NULL,
    rule_set_json   JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_firewall_rule_sets_site ON firewall_rule_sets(site);

-- Seed the 3 engine rule-sets verbatim from seed_data()
INSERT INTO firewall_rule_sets (id, name, site, status, rule_set_json) VALUES
    (
        'fws-defra-001',
        'DEFRA web edge policy',
        'DEFRA',
        'draft',
        '{"id":"fws-defra-001","name":"DEFRA web edge policy","rules":["fw-defra-001","fw-defra-002"],"site":"DEFRA","applied_to":"defra-edge-fw-01","status":"draft"}'
    ),
    (
        'fws-gblon-001',
        'GBLON core protection',
        'GBLON',
        'applied',
        '{"id":"fws-gblon-001","name":"GBLON core protection","rules":["fw-gblon-001","fw-gblon-002"],"site":"GBLON","applied_to":"10.20.0.0/16","status":"applied"}'
    ),
    (
        'fws-nlams-001',
        'NLAMS diagnostics policy',
        'NLAMS',
        'revoked',
        '{"id":"fws-nlams-001","name":"NLAMS diagnostics policy","rules":["fw-nlams-001","fw-nlams-002"],"site":"NLAMS","applied_to":"nlams-core-fw-01","status":"revoked"}'
    )
ON CONFLICT (id) DO NOTHING;
