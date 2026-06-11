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
    ('aiops-0001', 'RightSizing', 'Downsize defra-web-01 from 8 GB to 4 GB memory', 'defra-web-01 averages 31% memory utilization over 90 days. Reducing from 8 GB to 4 GB aligns allocation with observed demand while maintaining a 2x headroom.', ARRAY['defra-web-01', 'defra-web-cluster'], 192.00, 0.89, 'New', 'DEFRA', NOW() - INTERVAL '10 days', NOW() - INTERVAL '10 days'),
    ('aiops-0002', 'CostOptimization', 'Shutdown idle dev VMs during non-business hours', 'defra-dev-01 and defra-dev-02 show < 4% CPU utilization outside 08:00-18:00. Automated power schedule could save ~65% of their monthly cost.', ARRAY['defra-dev-01', 'defra-dev-02', 'defra-general-cluster'], 348.40, 0.95, 'New', 'DEFRA', NOW() - INTERVAL '8 days', NOW() - INTERVAL '8 days'),
    ('aiops-0003', 'Migration', 'Migrate defra-legacy-01 from VMware to newer cluster', 'defra-legacy-01 runs at 95% CPU / 92% memory on aging hardware with no vMotion compatibility. Migrate to defra-general-cluster to reduce contention and improve availability.', ARRAY['defra-legacy-01', 'vCenter', 'defra-general-cluster'], NULL, 0.82, 'New', 'DEFRA', NOW() - INTERVAL '6 days', NOW() - INTERVAL '6 days'),
    ('aiops-0004', 'Consolidation', 'Consolidate gblon-web-01 and gblon-qa-01 onto shared host', 'Both VMs run on separate hosts with combined utilization under 25%. Consolidating frees one hypervisor license and reduces power draw.', ARRAY['gblon-web-01', 'gblon-qa-01', 'gblon-web-cluster'], 1280.00, 0.78, 'New', 'GBLON', NOW() - INTERVAL '4 days', NOW() - INTERVAL '4 days'),
    ('aiops-0005', 'RiskReduction', 'Update backup policy for gblon-dr-01 — last verified 90+ days ago', 'gblon-dr-01 backup verification is 90+ days stale. A failed restore test would leave DR site unrecoverable. Schedule immediate verification and increase frequency to weekly.', ARRAY['gblon-dr-01', 'Veeam', 'gblon-dr-cluster'], NULL, 0.97, 'New', 'GBLON', NOW() - INTERVAL '2 days', NOW() - INTERVAL '2 days');
