# gMSA password-rotation expiry scan (run-3)

## Problem

`gmsa_accounts` (mig 020) carries `last_rotation_at` + `managed_password_interval_days`, so a gMSA's
managed password is due to rotate at `last_rotation_at + managed_password_interval_days`. The ONLY
way an operator learns a rotation is overdue (or due soon) is by polling the on-demand
`gmsa_lifecycle::get_expiring` surface — there is NO proactive scan. An overdue gMSA password
rotation is a real security-hygiene signal (either our record is stale, or AD-side auto-rotation
isn't happening and the account needs verification). This adds a PROACTIVE scan, the 5th instance
of the durable-scheduler SAFE-INTERNAL-WRITE recipe (secret-rotation / legal-hold / recertification
/ certificate already shipped).

## Approach (mirrors `certificate_expiry_scan`, commit 592942c)

**Pure engine classifier** (`gmsa_lifecycle.rs`): add `classify_gmsa_expiry(next_rotation_unix_ms,
now_unix_ms, soon_window_ms) -> GmsaExpiry { Overdue, DueSoon, Current }` + `as_str()`
("overdue"/"due-soon"/"current") + `is_actionable()` (Overdue | DueSoon) — a direct mirror of
`CertificateExpiry` / `classify_certificate_expiry`. The existing impure `get_expiring`
(uses `Utc::now()`, for the on-demand endpoint) stays; the scan uses the new PURE classifier so the
decision is deterministic and the CP clock is the single source of "now" (post-SQL clock-skew guard).

**Scheduler arm** (`ryuki-api/src/scheduler.rs`, `gmsa_expiry_scan`): on the tick tx,
```
SELECT id::text, name, sam_account_name, site, status, managed_password_interval_days,
       last_rotation_at,
       (last_rotation_at + managed_password_interval_days * INTERVAL '1 day') AS next_rotation
FROM gmsa_accounts
WHERE status <> 'Revoked'
  AND managed_password_interval_days > 0
  AND last_rotation_at + managed_password_interval_days * INTERVAL '1 day'
        <= NOW() + INTERVAL '8 days'
ORDER BY next_rotation
```
The prefilter window is **8 days** while the classifier window is **7** — the prefilter is a strict
SUPERSET of the actionable set, so even a ~1h DST calendar-day-vs-86.4M-ms drift (if the DB ran off
UTC) can't push a 7-day-actionable row outside the prefilter; the classifier discards the 7–8 day
rows as `Current` (codex).
(a Revoked account is decommissioned — not rotation-relevant; `managed_password_interval_days > 0`
guards against bad source data turning a 0/negative interval into permanent overdue noise — codex;
integer-times-interval avoids text interval parsing; predicate on the COMPUTED next_rotation, NOT the
possibly-stale `status` column — the cert-scan lesson). The SQL predicate (DB `NOW()`) is a COARSE
PREFILTER; the pure classifier (CP-clock `now_ms`) is the AUTHORITATIVE actionability guard — a row
passing the prefilter but classifying `Current` under the CP clock is skipped (this is the proven
cert-scan dual-clock split, NOT a "single clock" claim). For each row: classify (CP-clock `now_ms`,
7-day soon window); skip if `!is_actionable`; enqueue ONE deduped `shift_queue` item
(`enqueue_if_absent`, item_type `gmsa-expiring`, `source_ci_key` = the gMSA id (a UUID, never
reused)); then REFRESH the open item to the current state/priority (so due-soon → overdue upgrades in
place, mirroring the cert scan's ON-CONFLICT-DO-NOTHING refresh). Priority: Overdue → P2
(security-hygiene degradation, not an outage like an expired cert), DueSoon → P3. The queue item is
framed as **"verify AD-side rotation / refresh the control-plane record"**, NOT "rotate the password
manually" — AD auto-rotates the managed password, so an overdue `last_rotation_at` means stale CP
telemetry or broken AD-side rotation, both of which call for VERIFICATION (codex). Reads
`gmsa_accounts`, writes only `shift_queue` — NO gMSA mutation. Surfaced fields (name,
sam_account_name, site, status, next_rotation) are non-secret identity — the gMSA password is never
in this table.

**Engine schedulability** (`ryuki-engine/src/scheduler.rs`): add `gmsa_expiry_scan` to the
`job_is_schedulable` allowlist (safe-internal-write branch) + the matrix and `_live`-negative tests.

**Migration** `134_gmsa_expiry_scan.sql`: seed one enabled DAILY (86400s) `gmsa_expiry_scan` schedule
(fixed id `dddddddd-dddd-4ddd-8ddd-dddddddddddd` — continues the seed sequence
…cert=9999, job-exec-prune=aaaa, chc-prune=bbbb, check-results-prune=cccc → gmsa=dddd; valid v4;
ON CONFLICT (id) DO NOTHING) + the partial unique dedup index
`uq_shift_queue_open_gmsa_expiring ON shift_queue (item_type, (metadata->>'source_ci_key'))
WHERE resolved = false AND item_type = 'gmsa-expiring'`.

**shift_queue const**: `GMSA_EXPIRY_ITEM_TYPE = "gmsa-expiring"`.

## Tests
- Engine: `classify_gmsa_expiry` boundaries — overdue (next_rotation in past), due-soon (within
  window), current (beyond window); is_actionable / as_str.
- Engine scheduler: `gmsa_expiry_scan` is schedulable + NOT read-only; `gmsa_expiry_scan_live` refused.
- API DB test (mirrors `certificate_scan_enqueues_by_state_and_refreshes`): seed three gMSA accounts
  — overdue (next_rotation past) → P2/"overdue", due-soon (within 7d) → P3/"due-soon", and far-future
  → not enqueued; a second run is a no-op (dedup); then move the due-soon account's `last_rotation_at`
  into the past, re-scan → the SAME open item upgrades to P2/"overdue" (refresh, no duplicate).
  (global_pool per the scheduler test convention.)
- Migration idempotency test (seed re-applies as a no-op).

## Risk / rollback
Additive: new engine classifier, one scheduler arm, one allowlist entry, one seed migration + index,
one shift_queue const. No gMSA mutation, no secret surfaced. Rollback = revert + disable the seeded
schedule. The scan only ever writes deduped `shift_queue` rows.
