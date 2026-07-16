# Certificate expiry scan — surface expiring/expired TLS certs as work

Status: SHIPPED (run-3 discovery swarm, CONFIRMED M/S). Plan review NEEDS-CHANGES → APPROVE (MAJOR 1
confirmed by verifying renewal updates the same row; MAJOR 2 = the refresh-open-item-each-scan; MINOR
= priority-by-state), implementation review APPROVE (no findings).
Reuses the proven durable-scheduler SAFE-INTERNAL-WRITE recipe (#7 secret-rotation, #17 legal-hold,
#12 recertification — all review-approved). Additive: ONE engine classifier, ONE scheduler job-kind
arm, ONE seed migration, ONE shift_queue item-type. NO hot-path, NO HTTP surface. Highest-stakes of
the expiring-scan family (an expired TLS cert = a user-facing outage).

## Row-lifecycle contract (plan-review MAJOR 1, CONFIRMED)
`certificates.id` IS the currently-deployed cert binding, and renewal UPDATES THE SAME ROW:
`renew_certificate` (certificate_lifecycle.rs:95) clones the record keeping its `id` and moves
`valid_to` forward; the API persists it via `repos::certificates::transition` on that row
(contracts.rs:24627) — NOT a new INSERT. So (a) the bare cert `id` is a correct, stable dedup key
(a UUID, never reused), and (b) a renewed cert's `valid_to` moves to the future → it drops out of
the scan predicate → it is not re-enqueued. No instance key needed.

## The gap (verified)
`certificates` (mig 011: id UUID, common_name, subject, valid_from, valid_to TIMESTAMPTZ,
service_type, hostname, site, status) is readable on-demand via
`GET /api/maintain/certificates/expiring` (contracts.rs:24697, `days` window), but there is NO
PROACTIVE scan — an operator only learns a cert is expiring by polling. Every parallel
time-sensitive signal already has a scan (secret-rotation/legal-hold/recertification); certs do not.

## Design — mirror legal_hold_expiry_scan
A daily scan that reads `certificates`, classifies each within the actionable window, and enqueues
ONE deduped `shift_queue` item per expiring/expired cert. Reads certs, writes only `shift_queue` —
NO mutation of the cert row (renewal/revoke stays a separate deliberate action).

### Engine classifier (ryuki-engine/src/certificate_lifecycle.rs) — pure
```
pub enum CertificateExpiry { Expired, ExpiringSoon, Valid }
  is_actionable() = Expired | ExpiringSoon
  as_str() = "expired" | "expiring-soon" | "valid"
pub fn classify_certificate_expiry(valid_to_ms, now_ms, soon_window_ms) -> CertificateExpiry
  = now >= valid_to        -> Expired
  | valid_to <= now+soon   -> ExpiringSoon
  | else                   -> Valid
```
Identical shape to `legal_hold::classify_legal_hold_expiry`. The api scan re-checks
`is_actionable()` with the CP clock AFTER the SQL filter (a near-edge row the DB clock selected but
the CP clock says is still Valid is skipped — a queue item never carries a non-actionable verdict).

### Scheduler arm (ryuki-api/src/scheduler.rs run_job)
`"certificate_expiry_scan" =>` (all on `tx`):
```
SELECT id::text, common_name, hostname, service_type, site, valid_to, status
FROM certificates WHERE valid_to <= NOW() + INTERVAL '30 days' ORDER BY valid_to
```
(Predicate on `valid_to`, NOT `status` — the status column has no sync trigger so `valid_to` is the
truth; an `Expired`-status cert that is genuinely past IS surfaced; a stale `Active`-status cert with
a past `valid_to` is still surfaced.) For each: classify with the CP-clock `now_ms` + a 30-day soon
window; skip `!is_actionable()`; then enqueue AND REFRESH:
- source_ci_key = the cert `id` (bare UUID — see the row-lifecycle contract above).
- `priority` BY STATE (review MINOR): `Expired` → `P1` (it is an outage NOW), `ExpiringSoon` → `P2`.
- title: `Certificate {state}: {common_name}` (state = expired / expiring-soon)
- description: `{service_type} certificate '{common_name}' on {hostname} ({site}) — valid_to
  {valid_to}. Renew or replace it.`
- metadata: `{ source_ci_key: id, common_name, hostname, service_type, site, valid_to,
  cert_status: status, expiry_state: state }`
- `enqueue_if_absent(tx, CERTIFICATE_EXPIRY_ITEM_TYPE, &id, title, description, priority, metadata)`
- **REFRESH the OPEN item to the current state (review MAJOR 2):** `enqueue_if_absent` is INSERT … ON
  CONFLICT DO NOTHING, so an item first seen as `expiring-soon` would keep a STALE title /
  `expiry_state` / `P2` priority after the cert crosses into `expired` — unacceptable for a
  high-impact TLS cert. So, right after the enqueue, run one `UPDATE shift_queue SET title=$,
  description=$, priority=$, metadata=$::jsonb, updated_at=NOW() WHERE item_type='certificate-expiring'
  AND resolved=false AND metadata->>'source_ci_key'=$id`. This converges the OPEN item (just-inserted
  OR pre-existing) to the CURRENT state every scan — so `expiring-soon`→`expired` upgrades the label
  AND bumps `P2`→`P1`. Idempotent (a no-state-change scan rewrites the same values). (This is a
  deliberate enhancement over the first-seen legal-hold/secret/recert scans, justified by cert
  outage impact.)

SECRET HYGIENE: `certificates` holds only cert METADATA (common_name/hostname/service_type/site/
dates) — the PRIVATE KEY is NOT in this table. Every surfaced field is safe for the execute-tier
shift_queue. (`expiry_state` is a distinct metadata key from `cert_status` to avoid confusing the
verdict with the row's stored status — same hygiene pattern as legal-hold's `expiry_state`.)

### job_is_schedulable (ryuki-engine/src/scheduler.rs)
Add `"certificate_expiry_scan"` to the safe-internal-write allowlist (it writes shift_queue).

### shift_queue const (ryuki-api/src/repos/shift_queue.rs)
`pub const CERTIFICATE_EXPIRY_ITEM_TYPE: &str = "certificate-expiring";`

### Migration 130 (next free; highest is 129)
- Seed ONE enabled `certificate_expiry_scan` schedule. Fixed UUID
  `99999999-9999-4999-8999-999999999999` (continues the seed sequence restore=5/secret=6/
  legal-hold=7/recert=8 → cert=9; collides with none). Daily 86400s, next_run_at NOW(),
  created_by 'system', `ON CONFLICT (id) DO NOTHING`.
- Partial unique index (idempotent): `uq_shift_queue_open_certificate_expiring ON shift_queue
  (item_type, (metadata->>'source_ci_key')) WHERE resolved = false AND item_type =
  'certificate-expiring'`.

## Tests
- Engine: `classify_certificate_expiry` boundaries (now > valid_to → Expired; within window →
  ExpiringSoon; far future → Valid; exact now==valid_to → Expired); `is_actionable`/`as_str`.
- Engine: `job_is_schedulable("certificate_expiry_scan")` true + the matrix/`_live` negatives.
- Scheduler (DB): `migration_130_is_idempotent_and_index_dedups` (mirror 126/129).
- Scheduler (DB): seed an expired cert (→ P1, expiry_state "expired") + an expiring-soon cert (→ P2,
  "expiring-soon") + a far-future cert → run the scan → expired + soon each enqueue ONE item with the
  right `expiry_state`/priority; the far-future cert enqueues nothing; re-running is idempotent
  (dedup). NO private-key/secret in any surfaced field.
- Scheduler (DB) — REFRESH (review MAJOR 2): an open item first created for an `expiring-soon` cert,
  whose `valid_to` is then moved into the past → the next scan UPGRADES the same open item to
  `expiry_state` "expired" + priority "P1" (no duplicate row).
- Scheduler (DB) — stale-status: a cert with `status='Active'` but a PAST `valid_to` is still
  surfaced (the predicate is on `valid_to`, not the stale status).

## Out of scope (the sibling run-3 scans)
- OOB-management cert-endpoint expiry scan (`oob_endpoints.cert_expiry`) and gMSA service-account
  expiry scan (`gmsa_lifecycle`) — same pattern, their own changes.
- Any cert renewal/auto-rotation or status auto-transition (surface-only, like the other scans).
