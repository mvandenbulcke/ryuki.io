# OOB-management cert-endpoint expiry scan (run-3)

## Problem

`oob_endpoints` (mig 027 — iLO/iDRAC/IPMI-style out-of-band management endpoints) carries
`cert_expiry TIMESTAMPTZ NOT NULL`: the OOB management interface's TLS certificate expiry. An expired
OOB cert degrades secure management access to the box (and is a security-hygiene failure), but the
only way an operator learns it is expiring/expired is ad-hoc inspection — there is NO proactive scan.
This adds one, the 6th (and final) instance of the durable-scheduler SAFE-INTERNAL-WRITE expiry-scan
recipe (after secret-rotation / legal-hold / recertification / certificate / gMSA), COMPLETING the
scheduled-automation theme.

## Approach (mirrors `certificate_expiry_scan`, commit 592942c)

**Reuse the cert classifier** — `oob_endpoints.cert_expiry` is the same TLS-cert-expiry shape as
`certificates.valid_to`, so the scan REUSES the pure
`certificate_lifecycle::classify_certificate_expiry(cert_expiry_ms, now_ms, soon_window_ms)` →
`{Expired, ExpiringSoon, Valid}`. No new engine classifier (DRY).

**Scheduler arm** (`ryuki-api/src/scheduler.rs`, `oob_cert_expiry_scan`): on the tick tx,
```
SELECT id::text, endpoint_type, hostname, site, cert_expiry
FROM oob_endpoints
WHERE cert_expiry <= NOW() + INTERVAL '31 days'
ORDER BY cert_expiry
```
The SQL predicate (DB `NOW()`, 31-day window) is a COARSE PREFILTER that is a strict SUPERSET of the
30-day classifier window — so even a ~1h DST drift can't push a 30-day-actionable row outside the
prefilter (the gMSA-scan lesson); the pure classifier (CP clock, 30-day window) is the AUTHORITATIVE
guard. Predicate on `cert_expiry` (NOT the possibly-stale `certificate_valid` boolean — the cert-scan
lesson). For each row: classify (CP-clock `now_ms`, 30-day soon window); skip if `!is_actionable`
(clock-skew guard); enqueue ONE deduped `shift_queue` item (`enqueue_if_absent`, item_type
`oob-cert-expiring`, `source_ci_key` = the OOB endpoint id (a UUID, never reused)); then REFRESH the
open item to the current state/priority (so expiring-soon → expired upgrades in place, mirroring the
cert scan). Priority: Expired → **P2**, ExpiringSoon → **P3** — an OOB cert covers INTERNAL
management access, a security/access degradation, NOT a user-facing outage like a public TLS cert
(so P2, not the cert scan's P1). Reads `oob_endpoints`, writes only `shift_queue` — NO OOB mutation;
the surfaced fields (endpoint_type, hostname, site, cert_expiry) are non-secret identity (no
credential / IPMI password).

**Engine schedulability** (`ryuki-engine/src/scheduler.rs`): add `oob_cert_expiry_scan` to the
`job_is_schedulable` allowlist + matrix and `_live`-negative tests.

**Migration** `135_oob_cert_expiry_scan.sql`: seed one enabled DAILY (86400s) `oob_cert_expiry_scan`
schedule (fixed id `eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee` — continues the seed sequence
…gmsa=dddd → oob=eeee; valid v4; ON CONFLICT (id) DO NOTHING) + the partial unique dedup index
`uq_shift_queue_open_oob_cert_expiring ON shift_queue (item_type, (metadata->>'source_ci_key'))
WHERE resolved = false AND item_type = 'oob-cert-expiring'`.

**shift_queue const**: `OOB_CERT_EXPIRY_ITEM_TYPE = "oob-cert-expiring"`.

## Tests
- API DB test (mirrors `certificate_scan_enqueues_by_state_and_refreshes`): seed three OOB endpoints
  — expired (cert_expiry past) → P2/"expired", expiring-soon (within 30d) → P3/"expiring-soon",
  far-future → not enqueued; second run is a no-op (dedup); then move the expiring-soon endpoint's
  cert_expiry into the past, re-scan → the SAME open item upgrades to P2/"expired" (refresh, no dup).
- Migration idempotency + index dedup (self-contained `CREATE INDEX IF NOT EXISTS` for the
  behind-migrations local DB, mirroring the gMSA/cert tests).

## Risk / rollback
Additive: one scheduler arm (reusing the cert classifier), one allowlist entry, one seed migration +
index, one shift_queue const. No OOB mutation, no secret surfaced. Rollback = revert + disable the
seeded schedule.
