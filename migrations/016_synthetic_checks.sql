CREATE TABLE health_checks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    check_type TEXT NOT NULL CHECK (check_type IN ('http', 'tcp', 'dns', 'certificate')),
    endpoint TEXT NOT NULL,
    expected_status INTEGER NOT NULL DEFAULT 200,
    expected_body_contains TEXT,
    interval_seconds INTEGER NOT NULL DEFAULT 60,
    site TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE check_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    check_id UUID NOT NULL REFERENCES health_checks(id),
    status TEXT NOT NULL CHECK (status IN ('pass', 'fail')),
    latency_ms INTEGER NOT NULL DEFAULT 0,
    message TEXT NOT NULL DEFAULT '',
    executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO health_checks (name, check_type, endpoint, expected_status, expected_body_contains, interval_seconds, site, enabled) VALUES
    ('portal-web-endpoint', 'http', 'portal.ryuki.io', 200, 'Ryuki Infrastructure Platform', 60, 'DEFRA', true),
    ('api-health-endpoint', 'http', 'api.ryuki.io', 200, NULL, 30, 'DEFRA', true),
    ('payment-dns-resolution', 'dns', 'payment-service.ryuki.io', 0, NULL, 120, 'DEFRA', true),
    ('db-tcp-connectivity', 'tcp', 'db.ryuki.io:5432', 0, NULL, 30, 'GBLON', true),
    ('api-cert-expiry', 'certificate', 'api.ryuki.io:443', 0, NULL, 3600, 'GBLON', true);
