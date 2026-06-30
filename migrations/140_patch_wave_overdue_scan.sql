-- 140_patch_wave_overdue_scan.sql — proactively surface MISSED patch windows as work items.
--
-- A patch wave carries its committed maintenance-window start in `schedule->>'start'`.
-- Once a wave is 'Scheduled' it is committed to start at that time, but nothing in the
-- platform notices when that window passes without the wave moving to 'InProgress' —
-- the only way an operator learns a patch wave missed its window is by polling. This
-- migration adds a PROACTIVE scan so a missed patch window surfaces as actionable work.
--
-- It reuses the durable-scheduler SAFE-INTERNAL-WRITE recipe (#52/#58): seed one enabled
-- `patch_wave_overdue_scan` schedule. The tick reads patch_waves in status 'Scheduled',
-- flags any whose `schedule->>'start'` is in the past, and enqueues ONE deduped
-- `shift_queue` item per missed wave. Reads patch_waves and writes only our own
-- shift_queue — NO provider/live/destructive call.

-- Seed one enabled scan on a daily (86400s) cadence. Fixed id so a re-run is a no-op;
-- ON CONFLICT DO NOTHING leaves the operator free to disable or retune it without the
-- migration re-asserting it.
INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by)
VALUES (
    'b0b0b0b0-b0b0-4b0b-8b0b-b0b0b0b0b0b0',
    'Patch wave overdue scan (all sites)',
    'patch_wave_overdue_scan',
    86400,
    TRUE,
    NOW(),
    'system'
)
ON CONFLICT (id) DO NOTHING;

-- Make the dedup STRUCTURAL as well as procedural (defense-in-depth + documents the
-- intended key): at most one OPEN patch-wave-overdue item per wave. The partial
-- predicate constrains only `resolved = false` rows, so it never blocks the
-- post-resolution re-flag. `shift_queue` has no natural key (only a PK on `id`); this is
-- the only unique constraint the enqueue's untargeted `ON CONFLICT DO NOTHING` can hit.
CREATE UNIQUE INDEX IF NOT EXISTS uq_shift_queue_open_patch_wave_overdue
    ON shift_queue (item_type, (metadata->>'source_ci_key'))
    WHERE resolved = false AND item_type = 'patch-wave-overdue';
