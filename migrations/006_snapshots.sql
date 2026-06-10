CREATE TABLE snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_ci_key TEXT NOT NULL,
    snapshot_purpose TEXT NOT NULL,
    requested_expiry TEXT NOT NULL,
    owner TEXT NOT NULL,
    support_group TEXT NOT NULL DEFAULT '',
    change_context TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'draft',
    policy_decision TEXT,
    backup_impact TEXT,
    remediation_plan TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
