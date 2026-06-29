-- 126_legal_hold_expiry_scan.sql — route expiring legal holds into the work queue (#17).
--
-- `legal_holds` carries an `expiry_date`, but the only way an operator learns a hold is
-- expiring (or already past expiry while still Active) is by polling
-- GET /api/protect/legal-hold/expiring. This migration adds a PROACTIVE scan so
-- expiring legal holds surface as actionable work without manual polling.
--
-- It reuses the durable-scheduler SAFE-INTERNAL-WRITE recipe (#7/#52/#40/#39/#19): seed
-- one enabled `legal_hold_expiry_scan` schedule. The tick reads Active holds within 30
-- days of (or past) their expiry — the SAME predicate as the on-demand endpoint —
-- classifies each with the pure `legal_hold::classify_legal_hold_expiry`, and enqueues
-- ONE deduped `shift_queue` item per hold. It reads `legal_holds` and writes only our own
-- `shift_queue` — NO state change to the hold (releasing/expiring a legal hold is a
-- deliberate, audited human action), and NEVER reads or surfaces the sensitive
-- `reason`/`audit_trail` columns.

-- Seed one enabled scan on a daily (86400s) cadence. Fixed id so a re-run is a no-op;
-- ON CONFLICT DO NOTHING leaves the operator free to disable or retune it.
INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by)
VALUES (
    '77777777-7777-4777-8777-777777777777',
    'Legal hold expiry scan (all holds)',
    'legal_hold_expiry_scan',
    86400,
    TRUE,
    NOW(),
    'system'
)
ON CONFLICT (id) DO NOTHING;

-- Make the dedup STRUCTURAL as well as procedural (defense-in-depth + documents the
-- intended key): at most one OPEN legal-hold-expiring item per hold. The partial
-- predicate constrains only `resolved = false` rows, so it never blocks a future re-flag
-- once an item is resolved. `shift_queue` has no natural key (only a PK on `id`); this is
-- the unique constraint the enqueue's untargeted `ON CONFLICT DO NOTHING` can hit.
CREATE UNIQUE INDEX IF NOT EXISTS uq_shift_queue_open_legal_hold_expiring
    ON shift_queue (item_type, (metadata->>'source_ci_key'))
    WHERE resolved = false AND item_type = 'legal-hold-expiring';
