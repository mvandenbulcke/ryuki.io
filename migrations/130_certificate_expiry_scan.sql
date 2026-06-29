-- 130_certificate_expiry_scan.sql — route expiring/expired TLS certs into the work queue (run-3).
--
-- `certificates` carries `valid_to`, but the only way an operator learns a cert is expiring (or
-- already past expiry) is by polling GET /api/maintain/certificates/expiring. An expired TLS cert
-- is a user-facing outage, so this migration adds a PROACTIVE scan.
--
-- It reuses the durable-scheduler SAFE-INTERNAL-WRITE recipe (#7/#17/#12): seed one enabled
-- `certificate_expiry_scan` schedule. The tick reads certs with `valid_to` within (or past) a
-- 30-day window, classifies each with the pure `certificate_lifecycle::classify_certificate_expiry`,
-- and enqueues ONE deduped `shift_queue` item per cert — REFRESHING an open item to the current
-- state (expiring-soon → expired, P2 → P1). It reads `certificates` and writes only `shift_queue`
-- — NO cert mutation (renewal/revoke is a deliberate action), and `certificates` holds only cert
-- metadata (no private key), so nothing sensitive is surfaced.

-- Seed one enabled scan on a daily (86400s) cadence. Fixed id (continues the seed sequence
-- restore=5555, secret=6666, legal-hold=7777, recert=8888 -> cert=9999) so a re-run is a no-op;
-- ON CONFLICT DO NOTHING leaves the operator free to disable or retune it.
INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by)
VALUES (
    '99999999-9999-4999-8999-999999999999',
    'Certificate expiry scan (all certs)',
    'certificate_expiry_scan',
    86400,
    TRUE,
    NOW(),
    'system'
)
ON CONFLICT (id) DO NOTHING;

-- Structural dedup (defense-in-depth + documents the key): at most one OPEN certificate-expiring
-- item per cert. source_ci_key = the bare cert id (a UUID, never reused; renewal updates the same
-- row's valid_to). The partial predicate constrains only `resolved = false`, so a resolved item
-- never blocks a future re-flag.
CREATE UNIQUE INDEX IF NOT EXISTS uq_shift_queue_open_certificate_expiring
    ON shift_queue (item_type, (metadata->>'source_ci_key'))
    WHERE resolved = false AND item_type = 'certificate-expiring';
