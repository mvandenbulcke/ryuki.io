CREATE TABLE vm_day2_operations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_ci_key TEXT NOT NULL,
    change_type TEXT NOT NULL,
    target_value INTEGER NOT NULL DEFAULT 0,
    site TEXT NOT NULL,
    environment TEXT NOT NULL,
    owner TEXT NOT NULL,
    maintenance_window TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    plan_json JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
