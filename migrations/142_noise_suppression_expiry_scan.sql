-- 142_noise_suppression_expiry_scan.sql — auto-revert EXPIRED noise suppressions.
--
-- Suppressing a noisy trigger is a TIME-BOXED mute: `suppress_trigger` stamps a
-- `suppress_until` deadline and sets status='Suppressed'. But nothing ever compared that
-- deadline against NOW() to flip the trigger back, so a trigger past its window stayed
-- status='Suppressed' forever — stale in `noise_suppressed_list`, in the `noise_report`
-- suppressed/active counts, and in every status-summary surface. (It was never hidden from
-- detection: noise detect filters only on event volume, not status — so this is a stale
-- STATUS LABEL, a LOW data-accuracy issue, not a missed-detection bug.)
--
-- This migration adds a PROACTIVE scan so an expired suppression returns to the active
-- board on its own, the same daily durable-correction model the rest of the scan family
-- uses (#52/#17/#12/#58/#59/#60). It reuses the SAFE-INTERNAL-WRITE recipe, but as an
-- IN-PLACE flip rather than a shift_queue enqueue: the tick reads `noisy_triggers` in
-- status 'Suppressed' whose `suppress_until` is in the past and flips them to 'Active',
-- clearing `suppress_until`. Mutates only our own `noisy_triggers` table — NO
-- provider/live/destructive call.

-- Seed one enabled scan on a daily (86400s) cadence. Fixed id so a re-run is a no-op;
-- ON CONFLICT DO NOTHING leaves the operator free to disable or retune it without the
-- migration re-asserting it.
INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by)
VALUES (
    'd0d0d0d0-d0d0-4d0d-8d0d-d0d0d0d0d0d0',
    'Noise suppression expiry scan (all sites)',
    'noise_suppression_expiry_scan',
    86400,
    TRUE,
    NOW(),
    'system'
)
ON CONFLICT (id) DO NOTHING;

-- Lookup index for the scan's daily probe. The existing idx_noisy_triggers_status is a
-- plain index on `status`; this partial index is tighter for the exact predicate the scan
-- runs (`status='Suppressed' AND suppress_until <= NOW()`), and excludes indefinite
-- suppressions (suppress_until IS NULL) that can never expire and so never concern the
-- scan. NOT a uniqueness constraint — the scan is a bulk UPDATE, not a deduped enqueue.
CREATE INDEX IF NOT EXISTS idx_noisy_triggers_suppress_expiry
    ON noisy_triggers (suppress_until)
    WHERE status = 'Suppressed' AND suppress_until IS NOT NULL;
