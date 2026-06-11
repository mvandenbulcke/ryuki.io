CREATE TABLE baseline_checks (
    id TEXT PRIMARY KEY,
    check_name TEXT NOT NULL,
    category TEXT NOT NULL,
    expected_value TEXT NOT NULL,
    severity TEXT NOT NULL
);

CREATE TABLE baseline_results (
    server_name TEXT NOT NULL,
    check_id TEXT NOT NULL REFERENCES baseline_checks(id),
    compliant BOOLEAN NOT NULL DEFAULT true,
    actual_value TEXT NOT NULL,
    last_checked TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (server_name, check_id)
);

CREATE INDEX idx_baseline_results_server ON baseline_results(server_name);
CREATE INDEX idx_baseline_results_check ON baseline_results(check_id);

INSERT INTO baseline_checks (id, check_name, category, expected_value, severity) VALUES
    ('bc-001', 'CrowdStrike Falcon Agent', 'Security', 'running', 'Critical'),
    ('bc-002', 'VMware Tools', 'Tools', 'running, current', 'High'),
    ('bc-003', 'Zabbix Agent', 'Monitoring', 'running, v6.4+', 'High'),
    ('bc-004', 'Windows Firewall', 'Configuration', 'enabled, domain profile', 'Critical');

INSERT INTO baseline_results (server_name, check_id, compliant, actual_value) VALUES
    ('srv-defra-dc01', 'bc-001', true, 'running'),
    ('srv-defra-dc01', 'bc-002', true, 'running, current'),
    ('srv-defra-dc01', 'bc-003', true, 'running, v6.4+'),
    ('srv-defra-dc01', 'bc-004', true, 'enabled, domain profile'),
    ('srv-defra-web01', 'bc-001', true, 'running'),
    ('srv-defra-web01', 'bc-002', true, 'running, current'),
    ('srv-defra-web01', 'bc-003', true, 'running, v6.4+'),
    ('srv-defra-web01', 'bc-004', true, 'enabled, domain profile'),
    ('srv-gblon-db01', 'bc-001', true, 'running'),
    ('srv-gblon-db01', 'bc-002', true, 'running, current'),
    ('srv-gblon-db01', 'bc-003', true, 'running, v6.4+'),
    ('srv-gblon-db01', 'bc-004', false, 'disabled'),
    ('srv-frpar-app01', 'bc-001', false, 'not installed'),
    ('srv-frpar-app01', 'bc-002', true, 'running, current'),
    ('srv-frpar-app01', 'bc-003', true, 'running, v6.4+'),
    ('srv-frpar-app01', 'bc-004', true, 'enabled, domain profile'),
    ('srv-nlams-fs01', 'bc-001', true, 'running'),
    ('srv-nlams-fs01', 'bc-002', true, 'running, current'),
    ('srv-nlams-fs01', 'bc-003', false, 'stopped'),
    ('srv-nlams-fs01', 'bc-004', true, 'enabled, domain profile');
