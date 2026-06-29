# Notification dispatch outbox — the dry-run seam for outbound delivery

Status: SHIPPED (run-2 swarm #9, CONFIRMED H). codex plan review NEEDS-CHANGES → APPROVE (the
fail-open BLOCKER fixed with a SAVEPOINT design); codex impl review NEEDS-CHANGES (minor only,
"the savepoint/atomicity crux is sound") → both minors fixed (DispatchChannel serde
`rename_all="lowercase"` to match `as_db()`; a fail-open regression test that forces the outbox
insert to fail and proves the in-app notification still commits). The SMALLEST additive,
FAIL-OPEN slice toward outbound (email/webhook) notification delivery: it stands up the dispatch
DECISION + a durable outbox, with NO network I/O. A later slice flips the outbox from dry-run to
real sending (re-planning at send time, never promoting these telemetry rows).

## The gap (verified)
Notifications today are in-app read-receipts only (`portal_notifications`, mig 083; bell endpoints
in contracts.rs). `SmtpConfig` (ryuki-core/src/config.rs:722) is DEAD — referenced only by its
own definition + config plumbing + tests; nothing opens an SMTP connection. There is NO
send/deliver/webhook/email code anywhere. ~10 contract contexts declare
`"...-notification-dispatch-disabled"` blocked reasons. So a Critical alert can be raised but
never leaves the portal.

## Design — a dry-run outbox recorded at emit time (no I/O)
Three additive pieces; no existing behavior changes except two emit paths gaining one extra
in-tx insert each.

### 1. Pure engine routing policy (ryuki-engine/src/notifications.rs)
```
pub enum DispatchChannel { Email, Webhook }   // serializes lowercase: 'email' / 'webhook'

/// Pure, total, deterministic: which OUTBOUND channels a notification warrants.
/// In-app delivery already happened (the portal_notifications row); this decides
/// what ELSE. Policy by severity (the only routing input that does not require
/// per-recipient target config, which is a deliberate follow-up):
pub fn plan_dispatch(draft: &NotificationDraft) -> Vec<DispatchChannel>:
    Critical          => [Email, Webhook]   // page operators
    Warning           => [Webhook]          // ops channel
    Info | Success    => []                  // in-app only
```
No target/address resolution here — that (who gets emailed at what address) is the follow-up
that wires real config. Slice 1 records the channel DECISION only.

### 2. Migration 128 — notification_dispatch_outbox (next free number; highest is 127)
```
CREATE TABLE notification_dispatch_outbox (
  id              TEXT PRIMARY KEY,                 -- "ndo-{uuid}"
  notification_id TEXT NOT NULL REFERENCES portal_notifications(id) ON DELETE CASCADE,
  channel         TEXT NOT NULL CHECK (channel IN ('email','webhook')),
  status          TEXT NOT NULL DEFAULT 'dry_run_logged'
                    CHECK (status IN ('pending','dry_run_logged','sent','failed','skipped')),
  planned_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  dispatched_at   TIMESTAMPTZ,
  UNIQUE (notification_id, channel)                 -- dedup: one row per (notification, channel)
);
-- Default admin listing is ORDER BY planned_at DESC (no status filter), so it needs a
-- planned_at index; the (status, planned_at DESC) index serves status-filtered reads (codex).
CREATE INDEX ... ON notification_dispatch_outbox (planned_at DESC);
CREATE INDEX ... ON notification_dispatch_outbox (status, planned_at DESC);
```
FK + ON DELETE CASCADE mirrors `portal_notification_reads` (mig 083): the outbox row is a
queryable record FOR THE LIFETIME of its notification — a dispatch plan for a deleted
notification is meaningless, so it is intentionally tied to notification retention (NOT a
long-lived independent audit ledger; the durable audit of lifecycle actions lives in the audit
log). The status enum is forward-compatible (pending/sent/failed reserved for the real-dispatch
follow-up); slice 1 only ever writes `dry_run_logged`.

### 3. Record the plan at emit time — BEST-EFFORT via SAVEPOINT (ryuki-api/src/repos/notifications.rs)
The dry-run outbox is STRICTLY SUBORDINATE to the in-app notification and to the operational
alert: recording a dispatch plan must NEVER fail or roll back the notification/alert it
describes. In Postgres a single failed statement aborts the ENTIRE surrounding transaction, so
the outbox write CANNOT simply share the caller's tx (codex BLOCKER) — an outbox-specific
failure (rollout-window missing migration, lock timeout, PK collision, future constraint drift)
would abort the alert/notification. So the helper wraps its inserts in a SAVEPOINT (sqlx nested
tx) and swallows+logs any failure, rolling back ONLY the outbox work:
```
async fn record_dispatch_plan_best_effort(conn: &mut PgConnection, notification_id, channels):
    if channels.is_empty() { return; }                 // common Info/Success path: no savepoint
    let sp = conn.begin().await    // SAVEPOINT (nested tx); on Err → warn + return
    for ch in channels:
        INSERT INTO notification_dispatch_outbox (id, notification_id, channel, status)
        VALUES ('ndo-{uuid}', $1, $2, 'dry_run_logged')
        ON CONFLICT (notification_id, channel) DO NOTHING   -- idempotent
        // on Err → warn, sp.rollback() (ROLLBACK TO SAVEPOINT), return (notification survives)
    sp.commit()                    // RELEASE SAVEPOINT
```
Wired into BOTH emitters, computing `plan_dispatch(draft)` per draft, passing the existing
`&mut *tx` / `&mut *conn`:
- `emit_for_transition` (best-effort, own tx): the savepoint guarantees an outbox failure does
  NOT roll back the in-app notification row (codex MAJOR — the notification outranks the outbox).
- `insert_draft_tx` (the atomic operational-alert path): the savepoint guarantees an outbox
  failure does NOT abort the caller's alert+event tx (codex BLOCKER). The alert always commits;
  its dispatch plan is recorded when it can be, skipped (logged) when it can't.

Most lifecycle notifications are Info/Success → `plan_dispatch` returns `[]` → no savepoint, no
outbox rows (the common path is byte-for-byte untouched). Only reject/cancel (Warning) +
operational alerts (Warning/Critical) produce outbox rows.

### 4. Operator visibility — GET /api/admin/notifications/dispatch-outbox (admin)
Read-only admin endpoint listing outbox rows (newest first, optional `?status=` + `?limit=`),
so operators can SEE what the system WOULD dispatch — queryable dry-run telemetry while the
notification is retained (NOT a long-lived audit ledger; lifecycle audit lives in the audit log).
Mirrors the admin GET conventions (AuthExtractor, `get_db()` → 503/empty on no-DB,
`json!({source, dispatches})`). Admin-tier (operator-facing, not self-service).

## Tests
- Engine (notifications.rs): `plan_dispatch` for all 4 severities → exact channel sets;
  serialization of DispatchChannel ↔ 'email'/'webhook'.
- Repo (DB): `record_dispatch_plan_tx` inserts the rows; the (notification_id, channel) UNIQUE
  dedups a second identical plan (idempotent ON CONFLICT). `emit_for_transition` for a Warning
  (reject) writes a webhook outbox row; for a Success (approve) writes NONE.
- Migration idempotency: `migration_128_is_idempotent` (re-run seed/DDL is a clean no-op).
- Endpoint: admin lists rows (DB) + no-DB degrades; non-admin → 403 at the gate.

## Routing policy is DRY-RUN TELEMETRY, not a send-ready queue (codex MAJOR)
`plan_dispatch` is severity-only — a deliberately simple baseline that records "what a naive
severity policy would dispatch." It is NOT a send-ready queue, and the real-dispatch follow-up
MUST NOT blindly promote historical `dry_run_logged` rows to real sends: severity conflates
lifecycle user-notifications (reject/cancel = Warning, which probably should NOT page an ops
webhook) with operational alerts (the genuine paging case). The real policy must key on
event/recipient/role + per-recipient target config, and RE-PLAN from the notification at send
time. Slice 1's rows exist to prove the seam + give operators visibility, not to be sent.

## Out of scope (explicit follow-ups)
- REAL sending (SMTP via SmtpConfig / webhook via reqwest), the `pending`→`sent`/`failed`
  dispatcher loop (likely a durable-scheduler job kind), and retry/backoff. Slice 1 is dry-run
  only — no network egress; CI cannot (and should not) validate actual delivery. The real-send
  policy RE-PLANS at send time (it does not promote slice-1 telemetry rows — see above).
- Per-recipient target/address resolution + the address-vs-PII redaction boundary (the deferred
  product decision: where channel targets come from — role config vs user prefs vs on-call).
- Flipping the `"notification-dispatch-disabled"` contract blocked reasons (done one contract at
  a time once real dispatch lands).
