CREATE TABLE outage_notices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site TEXT NOT NULL,
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ NOT NULL,
    impact_level TEXT NOT NULL DEFAULT 'None' CHECK (impact_level IN ('None', 'Low', 'Med', 'High', 'Critical')),
    message_template TEXT NOT NULL DEFAULT 'Maintenance on {{site}}. Systems affected: {{systems}}. Impact: {{impact}}. Window: {{start}} to {{end}} UTC.',
    status TEXT NOT NULL DEFAULT 'Draft' CHECK (status IN ('Draft', 'Sent', 'Acknowledged', 'Completed', 'Cancelled')),
    sent_at TIMESTAMPTZ,
    acknowledged_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE outage_notice_systems (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    notice_id UUID NOT NULL REFERENCES outage_notices(id) ON DELETE CASCADE,
    system_name TEXT NOT NULL
);

CREATE TABLE outage_notice_acknowledgments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    notice_id UUID NOT NULL REFERENCES outage_notices(id) ON DELETE CASCADE,
    acknowledged_by TEXT NOT NULL,
    acknowledged_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_outage_notices_site ON outage_notices(site);
CREATE INDEX idx_outage_notices_status ON outage_notices(site, status);
CREATE INDEX idx_outage_notices_start ON outage_notices(site, start_time);
CREATE INDEX idx_outage_notice_systems_notice ON outage_notice_systems(notice_id);

INSERT INTO outage_notices (id, site, start_time, end_time, impact_level, message_template, status, sent_at, acknowledged_by, created_at, updated_at)
VALUES
    ('e0000420-4200-4200-4200-000000000001', 'LOVE', NOW() + INTERVAL '2 days', NOW() + INTERVAL '2 days 4 hours', 'High', 'Scheduled database maintenance on {{site}}. Systems affected: {{systems}}. Expected impact: {{impact}}. Window: {{start}} to {{end}} UTC.', 'Draft', NULL, NULL, NOW() - INTERVAL '12 hours', NOW() - INTERVAL '12 hours'),
    ('e0000420-4200-4200-4200-000000000002', 'BUR1', NOW() - INTERVAL '6 hours', NOW() - INTERVAL '1 hour', 'Critical', 'Emergency storage expansion on {{site}}. Systems affected: {{systems}}. Expected impact: {{impact}}. Window: {{start}} to {{end}} UTC.', 'Sent', NOW() - INTERVAL '5 hours 30 minutes', 'bob.engineer', NOW() - INTERVAL '7 hours', NOW() - INTERVAL '5 hours'),
    ('e0000420-4200-4200-4200-000000000003', 'CCSS', NOW() + INTERVAL '5 days', NOW() + INTERVAL '5 days 3 hours', 'Med', 'Network firmware upgrade on {{site}}. Systems affected: {{systems}}. Expected impact: {{impact}}. Window: {{start}} to {{end}} UTC.', 'Draft', NULL, NULL, NOW() - INTERVAL '1 hour', NOW() - INTERVAL '1 hour');

INSERT INTO outage_notice_systems (notice_id, system_name) VALUES
    ('e0000420-4200-4200-4200-000000000001', 'love-db-cluster'),
    ('e0000420-4200-4200-4200-000000000001', 'love-app-servers'),
    ('e0000420-4200-4200-4200-000000000002', 'bur1-vsan-cluster'),
    ('e0000420-4200-4200-4200-000000000002', 'bur1-esx-hosts'),
    ('e0000420-4200-4200-4200-000000000003', 'ccss-core-switch'),
    ('e0000420-4200-4200-4200-000000000003', 'ccss-edge-firewall');
