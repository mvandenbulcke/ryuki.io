CREATE TABLE aiops_suggestions (
    id TEXT PRIMARY KEY,
    suggestion_type TEXT NOT NULL CHECK (suggestion_type IN ('RightSizing', 'Migration', 'Consolidation', 'RiskReduction', 'CostOptimization', 'PerformanceImprovement')),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    affected_components TEXT[] NOT NULL DEFAULT '{}',
    estimated_savings DOUBLE PRECISION,
    confidence_score DOUBLE PRECISION NOT NULL CHECK (confidence_score >= 0.0 AND confidence_score <= 1.0),
    status TEXT NOT NULL DEFAULT 'New' CHECK (status IN ('New', 'Reviewed', 'Accepted', 'Rejected', 'Implemented')),
    reviewer TEXT,
    rejection_reason TEXT,
    implementation_plan TEXT,
    site TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_aiops_suggestions_site ON aiops_suggestions(site);
CREATE INDEX idx_aiops_suggestions_status ON aiops_suggestions(status);
CREATE INDEX idx_aiops_suggestions_type ON aiops_suggestions(suggestion_type);

INSERT INTO aiops_suggestions (id, suggestion_type, title, description, affected_components, estimated_savings, confidence_score, status, site, created_at, updated_at) VALUES
    ('aiops-0001', 'RightSizing', 'Downsize love-web-01 from 8 GB to 4 GB memory', 'love-web-01 averages 31% memory utilization over 90 days. Reducing from 8 GB to 4 GB aligns allocation with observed demand while maintaining a 2x headroom.', ARRAY['love-web-01', 'love-web-cluster'], 192.00, 0.89, 'New', 'LOVE', NOW() - INTERVAL '10 days', NOW() - INTERVAL '10 days'),
    ('aiops-0002', 'CostOptimization', 'Shutdown idle dev VMs during non-business hours', 'love-dev-01 and love-dev-02 show < 4% CPU utilization outside 08:00-18:00. Automated power schedule could save ~65% of their monthly cost.', ARRAY['love-dev-01', 'love-dev-02', 'love-general-cluster'], 348.40, 0.95, 'New', 'LOVE', NOW() - INTERVAL '8 days', NOW() - INTERVAL '8 days'),
    ('aiops-0003', 'Migration', 'Migrate love-legacy-01 from VMware to newer cluster', 'love-legacy-01 runs at 95% CPU / 92% memory on aging hardware with no vMotion compatibility. Migrate to love-general-cluster to reduce contention and improve availability.', ARRAY['love-legacy-01', 'vCenter', 'love-general-cluster'], NULL, 0.82, 'New', 'LOVE', NOW() - INTERVAL '6 days', NOW() - INTERVAL '6 days'),
    ('aiops-0004', 'Consolidation', 'Consolidate bur1-web-01 and bur1-qa-01 onto shared host', 'Both VMs run on separate hosts with combined utilization under 25%. Consolidating frees one hypervisor license and reduces power draw.', ARRAY['bur1-web-01', 'bur1-qa-01', 'bur1-web-cluster'], 1280.00, 0.78, 'New', 'BUR1', NOW() - INTERVAL '4 days', NOW() - INTERVAL '4 days'),
    ('aiops-0005', 'RiskReduction', 'Update backup policy for bur1-dr-01 — last verified 90+ days ago', 'bur1-dr-01 backup verification is 90+ days stale. A failed restore test would leave DR site unrecoverable. Schedule immediate verification and increase frequency to weekly.', ARRAY['bur1-dr-01', 'Veeam', 'bur1-dr-cluster'], NULL, 0.97, 'New', 'BUR1', NOW() - INTERVAL '2 days', NOW() - INTERVAL '2 days');
