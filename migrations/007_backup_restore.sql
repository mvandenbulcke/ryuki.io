CREATE TABLE backup_coverage_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site_scope JSONB NOT NULL DEFAULT '[]',
    environment_scope JSONB NOT NULL DEFAULT '[]',
    generation_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    total_assets INTEGER NOT NULL DEFAULT 0,
    covered_assets INTEGER NOT NULL DEFAULT 0,
    missing_backup INTEGER NOT NULL DEFAULT 0,
    missing_dr_replica INTEGER NOT NULL DEFAULT 0,
    stale_policy INTEGER NOT NULL DEFAULT 0,
    critical_gaps JSONB NOT NULL DEFAULT '[]',
    coverage_percentage DOUBLE PRECISION NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'generated',
    recommendations JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE restore_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_ci_key TEXT NOT NULL,
    restore_type TEXT NOT NULL,
    restore_point TEXT NOT NULL,
    target_site TEXT NOT NULL,
    target_environment TEXT NOT NULL,
    verification_plan TEXT NOT NULL DEFAULT '',
    retention_need TEXT NOT NULL DEFAULT '',
    owner TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    dry_run_plan TEXT,
    approver TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
