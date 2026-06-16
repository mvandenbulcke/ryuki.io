-- Extend patch_waves to hold the full PatchWave model.
--
-- The existing table (id, site, os_family, status, created_at, updated_at)
-- cannot round-trip the rich engine model. We add the missing columns with
-- safe defaults so the ALTER is non-destructive on existing rows, then
-- backfill the seed rows to produce valid model instances.
--
-- patch_wave_servers remains as-is: reserved for future per-server tracking
-- (patch_status, reboot_required etc.). The model's server list lives in the
-- new servers JSONB column below.

ALTER TABLE patch_waves ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT '';
ALTER TABLE patch_waves ADD COLUMN IF NOT EXISTS servers JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE patch_waves ADD COLUMN IF NOT EXISTS site_scope JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE patch_waves ADD COLUMN IF NOT EXISTS environment_scope JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE patch_waves ADD COLUMN IF NOT EXISTS schedule JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE patch_waves ADD COLUMN IF NOT EXISTS reboot_policy TEXT NOT NULL DEFAULT 'RebootIfRequired';
ALTER TABLE patch_waves ADD COLUMN IF NOT EXISTS blackout_dates JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE patch_waves ADD COLUMN IF NOT EXISTS validation_errors JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE patch_waves ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Migration 010 defaulted status to lowercase 'draft', but the repo layer
-- round-trips serde PascalCase variant names. Align the column DEFAULT so a
-- defaulted insert can never be CAS-incompatible (it would read back as 'Draft'
-- yet the optimistic-lock WHERE status = 'Draft' would miss the stored 'draft').
ALTER TABLE patch_waves ALTER COLUMN status SET DEFAULT 'Draft';

-- Legacy denormalized columns: the authoritative values live in site_scope
-- (JSONB) and metadata.os_family. Allow NULL so an incomplete model is recorded
-- honestly as "unknown" rather than as an empty string in a NOT NULL column.
ALTER TABLE patch_waves ALTER COLUMN site DROP NOT NULL;
ALTER TABLE patch_waves ALTER COLUMN os_family DROP NOT NULL;

-- Normalize the migration-010 seed rows from lowercase to the PascalCase serde
-- variant names the repo expects. Must run BEFORE the CHECK constraint below.
UPDATE patch_waves SET status = 'Draft'     WHERE status = 'draft';
UPDATE patch_waves SET status = 'Validated' WHERE status = 'validated';
UPDATE patch_waves SET status = 'Approved'  WHERE status = 'approved';

-- Pin the legal enum sets at the database boundary so a bad write (or a future
-- migration typo) cannot persist a status/policy the repo can't decode.
ALTER TABLE patch_waves ADD CONSTRAINT patch_waves_status_check
    CHECK (status IN ('Draft', 'Validated', 'Approved', 'Scheduled', 'InProgress', 'Completed', 'Failed'));
ALTER TABLE patch_waves ADD CONSTRAINT patch_waves_reboot_policy_check
    CHECK (reboot_policy IN ('RebootIfRequired', 'RebootAlways', 'NoReboot', 'ScheduleOnly'));

-- Backfill the three known migration-010 seed rows so they are valid model
-- instances. Targeted by their fixed seed ids — a durable discriminator, unlike
-- "name = ''" which could later match a legitimately empty-named row on a
-- manual re-apply. The server list is aggregated from patch_wave_servers.
UPDATE patch_waves pw SET
    name = 'Patch Wave - ' || pw.site || ' - ' || pw.os_family,
    site_scope = jsonb_build_array(pw.site),
    environment_scope = '["production"]'::jsonb,
    schedule = jsonb_build_object(
        'start',              '2026-06-15T22:00:00Z',
        'end',                '2026-06-16T06:00:00Z',
        'maintenance_window', 'EU-Overnight',
        'patch_group',        'Group-A'
    ),
    servers = COALESCE(
        (SELECT jsonb_agg(s.server_name)
         FROM patch_wave_servers s
         WHERE s.wave_id = pw.id),
        '[]'::jsonb
    )
WHERE pw.id IN (
    'a0000000-0000-0000-0000-000000000001',
    'a0000000-0000-0000-0000-000000000002',
    'a0000000-0000-0000-0000-000000000003'
);
