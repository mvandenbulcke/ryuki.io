-- 141_golden_image_stale_scan.sql — surface STALE golden images (missed monthly refresh).
--
-- Golden base images are expected to be rebuilt on a monthly cadence so they carry recent
-- OS patches, but `image_factory::schedule_monthly_build` only ever fires on the HTTP
-- endpoint — nothing notices when a promoted image ages past its refresh window. An
-- operator only learns an image is stale (and its deployments are missing a month of
-- patches) by polling. This migration adds a PROACTIVE scan so a stale base image surfaces
-- as actionable work.
--
-- It reuses the durable-scheduler SAFE-INTERNAL-WRITE recipe (#52/#58/#59): seed one
-- enabled `golden_image_stale_scan` schedule. The tick reads golden_images in status
-- 'promoted' (the live image), flags any whose build_date is older than the refresh
-- window, and enqueues ONE deduped `shift_queue` item per stale image. Reads golden_images
-- and writes only our own shift_queue — NO provider/live/destructive call.

-- Seed one enabled scan on a daily (86400s) cadence. Fixed id so a re-run is a no-op;
-- ON CONFLICT DO NOTHING leaves the operator free to disable or retune it without the
-- migration re-asserting it.
INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by)
VALUES (
    'c0c0c0c0-c0c0-4c0c-8c0c-c0c0c0c0c0c0',
    'Golden image stale scan (all sites)',
    'golden_image_stale_scan',
    86400,
    TRUE,
    NOW(),
    'system'
)
ON CONFLICT (id) DO NOTHING;

-- Make the dedup STRUCTURAL as well as procedural (defense-in-depth + documents the
-- intended key): at most one OPEN golden-image-stale item per image. The partial
-- predicate constrains only `resolved = false` rows, so it never blocks the
-- post-resolution re-flag. `shift_queue` has no natural key (only a PK on `id`); this is
-- the only unique constraint the enqueue's untargeted `ON CONFLICT DO NOTHING` can hit.
CREATE UNIQUE INDEX IF NOT EXISTS uq_shift_queue_open_golden_image_stale
    ON shift_queue (item_type, (metadata->>'source_ci_key'))
    WHERE resolved = false AND item_type = 'golden-image-stale';
