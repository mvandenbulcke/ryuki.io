CREATE TABLE requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'intake',
    stage TEXT NOT NULL DEFAULT 'intake',
    site TEXT NOT NULL,
    environment TEXT NOT NULL,
    name TEXT NOT NULL,
    cpu INTEGER NOT NULL DEFAULT 0,
    memory_gb INTEGER NOT NULL DEFAULT 0,
    justification TEXT,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
