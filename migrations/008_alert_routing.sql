CREATE TABLE alert_routes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    trigger_name TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'warning',
    host_group TEXT NOT NULL,
    support_group TEXT NOT NULL,
    priority TEXT NOT NULL DEFAULT 'P3',
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE route_decisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id TEXT NOT NULL,
    route_id UUID REFERENCES alert_routes(id),
    support_group TEXT NOT NULL,
    escalated BOOLEAN NOT NULL DEFAULT false,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    evidence TEXT
);

INSERT INTO alert_routes (trigger_name, severity, host_group, support_group, priority) VALUES
    ('High CPU utilization', 'high', 'Windows Servers', 'Wintel Operations', 'P2'),
    ('Disk space low', 'warning', 'Linux Servers', 'Linux Operations', 'P3'),
    ('Service unavailable', 'disaster', 'Critical Infrastructure', 'Datacenter Operations', 'P1'),
    ('Backup job failed', 'high', 'Veeam Infrastructure', 'Backup Operations', 'P2');
