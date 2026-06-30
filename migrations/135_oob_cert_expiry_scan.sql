-- 135_oob_cert_expiry_scan.sql — route out-of-band (iLO/iDRAC/IPMI) management endpoints with an
-- expiring/expired TLS cert into the work queue (run-3).
--
-- `oob_endpoints` (mig 027) carries `cert_expiry`, but the only way an operator learns an OOB
-- management cert is expiring (or already past) is ad-hoc inspection. An expired OOB cert degrades
-- secure management access to the box (and is a security-hygiene failure), so this adds a PROACTIVE
-- scan — the 6th (and final) instance of the durable-scheduler SAFE-INTERNAL-WRITE expiry-scan
-- recipe (after secret-rotation / legal-hold / recertification / certificate / gMSA).
--
-- The tick reads oob_endpoints whose `cert_expiry` is within (or past) a 30-day window, classifies
-- each with the SAME pure `certificate_lifecycle::classify_certificate_expiry` the cert scan uses
-- (an OOB cert is the same TLS-cert-expiry shape), and enqueues ONE deduped `shift_queue` item per
-- endpoint — REFRESHING an open item to the current state (expiring-soon → expired, P3 → P2). It
-- reads `oob_endpoints` and writes only `shift_queue` — NO OOB mutation, and the surfaced fields
-- (endpoint_type, hostname, site, cert_expiry) are operational identity (no IPMI/credential).

-- Seed one enabled scan on a daily (86400s) cadence. Fixed id (continues the seed sequence
-- gmsa=dddd -> oob=eeee; valid v4: version nibble 4, variant nibble 8) so a re-run is a no-op;
-- ON CONFLICT DO NOTHING leaves the operator free to disable or retune it.
INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by)
VALUES (
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
    'OOB management cert expiry scan (all endpoints)',
    'oob_cert_expiry_scan',
    86400,
    TRUE,
    NOW(),
    'system'
)
ON CONFLICT (id) DO NOTHING;

-- Structural dedup (defense-in-depth + documents the key): at most one OPEN oob-cert-expiring item
-- per endpoint. source_ci_key = the bare OOB endpoint id (a UUID, never reused). The partial
-- predicate constrains only `resolved = false`, so a resolved item never blocks a future re-flag.
CREATE UNIQUE INDEX IF NOT EXISTS uq_shift_queue_open_oob_cert_expiring
    ON shift_queue (item_type, (metadata->>'source_ci_key'))
    WHERE resolved = false AND item_type = 'oob-cert-expiring';
