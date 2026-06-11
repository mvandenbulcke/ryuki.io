CREATE TABLE gmsa_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    sam_account_name TEXT NOT NULL,
    dns_host_name TEXT NOT NULL,
    service_principal_names TEXT[] NOT NULL DEFAULT '{}',
    site TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Expiring', 'Expired', 'Revoked')),
    managed_password_interval_days INTEGER NOT NULL DEFAULT 30,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_rotation_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE gmsa_host_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gmsa_account_id UUID NOT NULL REFERENCES gmsa_accounts(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (gmsa_account_id, host)
);

CREATE INDEX idx_gmsa_accounts_site ON gmsa_accounts(site);
CREATE INDEX idx_gmsa_accounts_status ON gmsa_accounts(status);
CREATE INDEX idx_gmsa_accounts_name ON gmsa_accounts(name);
CREATE INDEX idx_gmsa_host_assignments_host ON gmsa_host_assignments(host);
CREATE INDEX idx_gmsa_host_assignments_gmsa ON gmsa_host_assignments(gmsa_account_id);

INSERT INTO gmsa_accounts (name, sam_account_name, dns_host_name, service_principal_names, site, status, managed_password_interval_days, created_at, last_rotation_at) VALUES
    ('svc-webappool-gblon', 'svc-webappool-gblon$', 'svc-webappool-gblon.corp.local', ARRAY['HTTP/webapp01.corp.local', 'HTTP/webapp02.corp.local'], 'GBLON', 'Active', 30, NOW() - INTERVAL '45 days', NOW() - INTERVAL '15 days'),
    ('svc-sqlagent-defra', 'svc-sqlagent-defra$', 'svc-sqlagent-defra.corp.local', ARRAY['MSSQLSvc/sql01.corp.local:1433'], 'DEFRA', 'Expiring', 60, NOW() - INTERVAL '180 days', NOW() - INTERVAL '55 days'),
    ('svc-iisworker-frpar', 'svc-iisworker-frpar$', 'svc-iisworker-frpar.corp.local', ARRAY['HTTP/iis-frpar.corp.local'], 'FRPAR', 'Expired', 30, NOW() - INTERVAL '400 days', NOW() - INTERVAL '35 days');

INSERT INTO gmsa_host_assignments (gmsa_account_id, host)
    SELECT id, unnest(ARRAY['webapp01.corp.local', 'webapp02.corp.local'])
    FROM gmsa_accounts WHERE name = 'svc-webappool-gblon';

INSERT INTO gmsa_host_assignments (gmsa_account_id, host)
    SELECT id, 'sql01.corp.local'
    FROM gmsa_accounts WHERE name = 'svc-sqlagent-defra';

INSERT INTO gmsa_host_assignments (gmsa_account_id, host)
    SELECT id, 'iis-frpar.corp.local'
    FROM gmsa_accounts WHERE name = 'svc-iisworker-frpar';
