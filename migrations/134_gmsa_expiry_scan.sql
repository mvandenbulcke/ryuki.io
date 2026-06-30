-- 134_gmsa_expiry_scan.sql — route gMSA accounts with an overdue/due-soon managed-password
-- rotation into the work queue (run-3).
--
-- `gmsa_accounts` carries `last_rotation_at` + `managed_password_interval_days`, so a gMSA's
-- managed password is due to rotate at `last_rotation_at + managed_password_interval_days`. The
-- only way an operator learns a rotation is overdue (or due soon) is by polling the on-demand
-- `gmsa_lifecycle::get_expiring` surface — there is no PROACTIVE scan. An overdue rotation is a
-- security-hygiene signal (stale CP telemetry, or AD-side auto-rotation isn't happening), so this
-- adds a proactive scan.
--
-- It reuses the durable-scheduler SAFE-INTERNAL-WRITE recipe (the 5th expiry scan, after
-- secret-rotation / legal-hold / recertification / certificate): seed one enabled
-- `gmsa_expiry_scan`. The tick reads gmsa_accounts whose computed next-rotation deadline is within
-- (or past) a 7-day window (excluding Revoked, guarding managed_password_interval_days > 0),
-- classifies each with the pure `gmsa_lifecycle::classify_gmsa_expiry`, and enqueues ONE deduped
-- `shift_queue` item per account — REFRESHING an open item to the current state (due-soon →
-- overdue, P3 → P2). It reads `gmsa_accounts` and writes only `shift_queue` — NO gMSA mutation
-- (rotation/verification stays a deliberate action), and the gMSA managed password is never in
-- this table, so nothing sensitive is surfaced.

-- Seed one enabled scan on a daily (86400s) cadence. Fixed id (continues the seed sequence
-- cert=9999, job-exec-prune=aaaa, chc-prune=bbbb, check-results-prune=cccc -> gmsa=dddd; valid v4:
-- version nibble 4, variant nibble 8) so a re-run is a no-op; ON CONFLICT DO NOTHING leaves the
-- operator free to disable or retune it.
INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by)
VALUES (
    'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    'gMSA rotation expiry scan (all accounts)',
    'gmsa_expiry_scan',
    86400,
    TRUE,
    NOW(),
    'system'
)
ON CONFLICT (id) DO NOTHING;

-- Structural dedup (defense-in-depth + documents the key): at most one OPEN gmsa-expiring item per
-- account. source_ci_key = the bare gMSA id (a UUID, never reused). The partial predicate
-- constrains only `resolved = false`, so a resolved item never blocks a future re-flag.
CREATE UNIQUE INDEX IF NOT EXISTS uq_shift_queue_open_gmsa_expiring
    ON shift_queue (item_type, (metadata->>'source_ci_key'))
    WHERE resolved = false AND item_type = 'gmsa-expiring';
