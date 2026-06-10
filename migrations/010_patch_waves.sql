CREATE TABLE patch_waves (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site TEXT NOT NULL,
    os_family TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE patch_wave_servers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wave_id UUID NOT NULL REFERENCES patch_waves(id) ON DELETE CASCADE,
    server_name TEXT NOT NULL,
    patch_status TEXT NOT NULL DEFAULT 'pending',
    reboot_required BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO patch_waves (id, site, os_family, status) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'LOVE', 'windows', 'draft'),
    ('a0000000-0000-0000-0000-000000000002', 'BUR1', 'linux', 'validated'),
    ('a0000000-0000-0000-0000-000000000003', 'CCSS', 'windows', 'approved');

INSERT INTO patch_wave_servers (wave_id, server_name, patch_status, reboot_required) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'w-love-srv-01', 'pending', false),
    ('a0000000-0000-0000-0000-000000000001', 'w-love-srv-02', 'pending', false),
    ('a0000000-0000-0000-0000-000000000001', 'w-love-srv-03', 'pending', true),
    ('a0000000-0000-0000-0000-000000000002', 'l-bur1-srv-01', 'patched', true),
    ('a0000000-0000-0000-0000-000000000002', 'l-bur1-srv-02', 'pending', false),
    ('a0000000-0000-0000-0000-000000000003', 'w-ccss-srv-01', 'patched', false),
    ('a0000000-0000-0000-0000-000000000003', 'w-ccss-srv-02', 'patched', true);
