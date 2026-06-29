-- 129_recertification_overdue_scan.sql — route overdue access-review campaigns into the work queue (#12).
--
-- `recertification_campaigns` carries an `end_date`, but the only way an operator learns a
-- campaign blew its deadline while still `Active` is by manually inspecting it. This migration
-- adds a PROACTIVE scan so overdue campaigns surface as actionable work without manual polling.
--
-- It reuses the durable-scheduler SAFE-INTERNAL-WRITE recipe (#7/#17/#52/#40/#39/#19): seed one
-- enabled `recertification_overdue_scan` schedule. The tick reads Active campaigns past their
-- `end_date`, classifies each with the pure `access_recertification::classify_recertification_overdue`,
-- and enqueues ONE deduped `shift_queue` item per overdue campaign. It reads
-- `recertification_campaigns` and writes only our own `shift_queue` — NO state change to the
-- campaign and NO access revocation / provider change (the recertification system is deliberately
-- review-only: "no-live-access-changes"). recertification_campaigns has NO sensitive free-text
-- column, so the surfaced governance metadata is safe.

-- Seed one enabled scan on a daily (86400s) cadence. Fixed id (continues the seed sequence
-- restore=5555, secret=6666, legal-hold=7777 -> recert=8888) so a re-run is a no-op;
-- ON CONFLICT DO NOTHING leaves the operator free to disable or retune it.
INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by)
VALUES (
    '88888888-8888-4888-8888-888888888888',
    'Recertification overdue scan (all campaigns)',
    'recertification_overdue_scan',
    86400,
    TRUE,
    NOW(),
    'system'
)
ON CONFLICT (id) DO NOTHING;

-- Make the dedup STRUCTURAL as well as procedural (defense-in-depth + documents the intended
-- key): at most one OPEN recertification-overdue item per campaign INSTANCE. The dedup key is the
-- composite `{id}@{start_date_ms}` (in metadata->>'source_ci_key'), so a reused campaign id with a
-- new start_date never collides with a stale item, and a deadline EXTENSION (which moves end_date,
-- not start_date) does not create a duplicate. The partial predicate constrains only
-- `resolved = false` rows, so it never blocks a future re-flag once an item is resolved.
CREATE UNIQUE INDEX IF NOT EXISTS uq_shift_queue_open_recertification_overdue
    ON shift_queue (item_type, (metadata->>'source_ci_key'))
    WHERE resolved = false AND item_type = 'recertification-overdue';
