CREATE TABLE decommission_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_name TEXT NOT NULL,
    site TEXT NOT NULL,
    os_family TEXT NOT NULL,
    server_type TEXT NOT NULL DEFAULT 'VM',
    reason TEXT NOT NULL,
    final_backup_required BOOLEAN NOT NULL DEFAULT false,
    quarantine_days INTEGER NOT NULL DEFAULT 30,
    status TEXT NOT NULL DEFAULT 'draft',
    dependencies_identified JSONB DEFAULT '[]',
    backup_confirmed BOOLEAN NOT NULL DEFAULT false,
    approvals_collected JSONB DEFAULT '[]',
    quarantine_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

CREATE TABLE quarantine_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_name TEXT NOT NULL,
    action TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
