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
    ('srv-love-dc01', 'bc-001', true, 'running'),
    ('srv-love-dc01', 'bc-002', true, 'running, current'),
    ('srv-love-dc01', 'bc-003', true, 'running, v6.4+'),
    ('srv-love-dc01', 'bc-004', true, 'enabled, domain profile'),
    ('srv-love-web01', 'bc-001', true, 'running'),
    ('srv-love-web01', 'bc-002', true, 'running, current'),
    ('srv-love-web01', 'bc-003', true, 'running, v6.4+'),
    ('srv-love-web01', 'bc-004', true, 'enabled, domain profile'),
    ('srv-bur1-db01', 'bc-001', true, 'running'),
    ('srv-bur1-db01', 'bc-002', true, 'running, current'),
    ('srv-bur1-db01', 'bc-003', true, 'running, v6.4+'),
    ('srv-bur1-db01', 'bc-004', false, 'disabled'),
    ('srv-ccss-app01', 'bc-001', false, 'not installed'),
    ('srv-ccss-app01', 'bc-002', true, 'running, current'),
    ('srv-ccss-app01', 'bc-003', true, 'running, v6.4+'),
    ('srv-ccss-app01', 'bc-004', true, 'enabled, domain profile'),
    ('srv-tor1-fs01', 'bc-001', true, 'running'),
    ('srv-tor1-fs01', 'bc-002', true, 'running, current'),
    ('srv-tor1-fs01', 'bc-003', false, 'stopped'),
    ('srv-tor1-fs01', 'bc-004', true, 'enabled, domain profile');
