# Scheduled legal-hold expiry scan — durable-scheduler job kind

Status: SHIPPED (plan review NEEDS-CHANGES → 1 MAJOR + 2 MINOR folded in; implementation review
APPROVE, no findings. A review note prompted the addition of a pure regression test
`execute_holders_also_hold_audit` (ryuki-engine/auth.rs) pinning the `execute ⊆ audit`
RBAC invariant that the cross-tier hygiene argument relies on — if a future role got
execute without audit, it fails loudly). See "## Plan-review fixes" at the end.
Verify-first swarm 2026-06-29 finding #17.
VERIFIED: `job_is_schedulable` (ryuki-engine/scheduler.rs) now lists 5 write kinds (incl.
the just-shipped `secret_rotation_due_scan`) — NO legal-hold scan. `GET /api/protect/
legal-hold/expiring` (contracts.rs:10176) is on-demand only, using `WHERE status='Active'
AND expiry_date <= NOW() + INTERVAL '30 days'`. A near-clone of the shipped
`secret_rotation_due_scan` (see secret-rotation-due-scan.md), but SIMPLER. Additive: ONE
migration, engine + api.

## Why simpler than the secret-rotation scan
`legal_holds.expiry_date` is a real `TIMESTAMPTZ NOT NULL` (mig 026), NOT a TEXT string
like `managed_secrets.next_rotation_due`. So there is NO parse/malformed-date concern and
NO second `invalid` signal — a single deduped item type suffices, and the SQL `expiry_date
<= NOW() + INTERVAL '30 days'` comparison is safe (no cast on a string).

## Secret hygiene (the analog of secret-rotation's vault_path)
`legal_holds` has a `reason TEXT` free-text column that can contain SENSITIVE
litigation/investigation details, plus `initiated_by`, `released_by`, `audit_trail`. The
scan must NEVER select or surface the hold `reason`/`audit_trail` in the shift_queue item
or the scheduler `detail`. The work item carries only operator-triage identity:
`id`, `server_or_app_name` (the asset under hold), `hold_type` (Investigation/Litigation/
Compliance/Retention — a category, not details), `site`, `expiry_date`. (The metadata
`reason` KEY is the classifier VERDICT "expired"/"expiring_soon", NOT the hold's reason
column — same convention as restore/secret scans.)

## Engine (ryuki-engine)
1. `scheduler.rs` — add `"legal_hold_expiry_scan"` to `job_is_schedulable` (NOT read-only).
2. `legal_hold.rs` — a PURE classifier:
   ```rust
   #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
   #[serde(rename_all = "snake_case")]
   pub enum LegalHoldExpiry { Active, ExpiringSoon, Expired }
   impl LegalHoldExpiry {
       pub fn as_str(&self) -> &'static str { Active→"active", ExpiringSoon→"expiring_soon", Expired→"expired" }
       pub fn is_actionable(&self) -> bool { matches!(self, ExpiringSoon | Expired) }
   }
   /// MILLIS. Expired if now>=expiry; ExpiringSoon if expiry within [now, now+soon_window);
   /// else Active (not actionable). Pure.
   pub fn classify_legal_hold_expiry(expiry_ms, now_ms, soon_window_ms) -> LegalHoldExpiry { ... }
   ```
   (soon_window = 30 days, matching the on-demand endpoint.)

## API run_job arm (ryuki-api/scheduler.rs)
`"legal_hold_expiry_scan" =>` mirroring `secret_rotation_due_scan`:
- SQL-filter to the actionable window (matches the on-demand predicate), selecting ONLY
  non-sensitive columns into a local `#[derive(sqlx::FromRow)]` struct:
  ```sql
  SELECT id, server_or_app_name, hold_type, expiry_date, site FROM legal_holds
   WHERE status = 'Active' AND expiry_date <= NOW() + INTERVAL '30 days' ORDER BY id
  ```
  (`expiry_date` read as `chrono::DateTime<Utc>` — a real TIMESTAMPTZ, no parse.)
- Per row: skip blank id; `classify_legal_hold_expiry(expiry.timestamp_millis(), now_ms,
  30d_ms)` → reason verdict; `enqueue_if_absent(LEGAL_HOLD_EXPIRY_ITEM_TYPE, dedup key = id,
  title = format!("Legal hold {verdict}: {server_or_app_name}"), description (asset/type/
  site/expiry — NO hold reason), metadata { source_ci_key:id, name:server_or_app_name,
  hold_type, site, expiry_date, reason:verdict })`.
- Return `("succeeded", Some(format!("enqueued {n} expiring legal hold(s)")))` — aggregate
  count only (`detail` is surfaced via /api/ops/scheduler/executions).

## shift_queue item type (ryuki-api/repos/shift_queue.rs)
`pub const LEGAL_HOLD_EXPIRY_ITEM_TYPE: &str = "legal-hold-expiring";`

## Migration 126 (migrations/126_legal_hold_expiry_scan.sql)
Latest migration is 125 → 126 is next. Mirror 125:
```sql
INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by)
VALUES ('77777777-7777-4777-8777-777777777777', 'Legal hold expiry scan (all holds)',
        'legal_hold_expiry_scan', 86400, TRUE, NOW(), 'system')
ON CONFLICT (id) DO NOTHING;

CREATE UNIQUE INDEX IF NOT EXISTS uq_shift_queue_open_legal_hold_expiring
    ON shift_queue (item_type, (metadata->>'source_ci_key'))
    WHERE resolved = false AND item_type = 'legal-hold-expiring';
```

## Tests
PURE (legal_hold.rs): `classify_legal_hold_expiry` — now>expiry→Expired, expiry in 10 days
(<30d)→ExpiringSoon, expiry in 60 days (>30d)→Active; boundary now==expiry→Expired;
is_actionable / as_str.
PURE (scheduler.rs): `job_is_schedulable("legal_hold_expiry_scan")` true AND not read-only.
DB (ryuki-api scheduler.rs tests, mirror secret_rotation_scan): seed Active holds — (a)
EXPIRED (expiry 2 days ago), (b) EXPIRING-SOON (expiry in 10 days), (c) FAR-FUTURE (expiry
in 60 days), (d) a RELEASED expired hold — with fresh ids; disable the migration-126
schedule; seed a due `legal_hold_expiry_scan` schedule; `tick_once`. Assert: (a) enqueued
once with reason "expired"; (b) enqueued once with reason "expiring_soon"; (c)/(d) NOT
enqueued; the item metadata has NO `reason`-COLUMN leak (assert no litigation text — the
metadata `reason` is the verdict only) and NO `audit_trail`; dedup on a re-planted 2nd
tick; aggregate `detail` format. Per-id assertions (shared DB).

## Files
- sources/ryuki-engine/src/scheduler.rs (allowlist), legal_hold.rs (classifier + tests)
- sources/ryuki-api/src/scheduler.rs (run_job arm + DB tests), repos/shift_queue.rs (const)
- migrations/126_legal_hold_expiry_scan.sql

## Out of scope
- Auto-releasing/auto-expiring a hold (this is enumeration → work queue only, no state
  change to the hold — releasing a legal hold is a deliberate, audited human action).
- A portal view of the legal-hold queue.
- Auto-RESOLVING an already-open queue item when a hold is later Released/Expired
  (MINOR): the `status='Active'` filter + the partial unique index prevent NEW/duplicate
  items, but do NOT resolve an existing open item on a later state transition — same as
  the restore/secret scans (resolution is operator action). A "resolve on release"
  follow-up is separate.

## Plan-review fixes (SUPERSEDE the body where they conflict)
- **MAJOR — boundary/clock alignment.** SQL filters `expiry_date <= NOW() + INTERVAL
  '30 days'` (inclusive), but DB `NOW()` and the Rust `now_ms` are DIFFERENT clocks, so a
  hold near the 30-day edge could be SELECTed yet classify `Active`. Fix BOTH ends: (1) the
  classifier's ExpiringSoon upper bound is INCLUSIVE — `now_ms < expiry_ms <= now_ms +
  window_ms` → ExpiringSoon (matches the SQL `<=`); (2) the arm adds `if
  !verdict.is_actionable() { continue; }` after classifying, so even a clock-skew `Active`
  row that slips through SQL is SKIPPED — a queue item NEVER carries an `active` verdict.
- **MINOR — metadata key `expiry_state`, not `reason`.** `legal_holds` HAS a sensitive
  `reason` column, so the verdict is keyed `expiry_state` ("expired"/"expiring_soon") to
  avoid any confusion with the hold's reason in UI/export/debug paths. (Diverges from the
  restore/secret scans' `reason` key — justified by the column-name collision.)
- **MINOR — stale items** documented above (Out of scope).

## Cross-tier hygiene analysis — asset name + hold_type are SAFE
The shift queue reads at the `execute` tier (`is_execute_read_path`, main.rs:715 — operator
working data). Legal-hold reads (`/api/protect/legal-hold/...`) are `audit`-tier (not a
sensitive-read prefix). In the RBAC map EVERY `execute`-holder also holds `audit` (all
`*Operator` = [execute, audit]), so shift-queue readers are a SUBSET of legal-hold readers
— surfacing `server_or_app_name` + `hold_type` in the work item is NOT a cross-tier leak
(any operator who can read the queue can already read the hold). The free-text `reason`
(litigation/investigation detail) and `audit_trail` are STILL excluded as defense-in-depth
(work-queue items may propagate to dashboards/exports/logs more liberally than the
access-controlled endpoint).
