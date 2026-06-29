# Recertification overdue scan — surface overdue access-review campaigns as work

Status: SHIPPED (run-1 #12 / run-2 backlog). codex plan review NEEDS-CHANGES → APPROVE (instance-
specific source_ci_key + `<= NOW()` + the hygiene/index refinements folded in); codex impl review
APPROVE (2 non-blocking MINORs applied: `timestamp_micros()` for exact TIMESTAMPTZ precision in the
instance key; a stale-item-suppression test + the engine schedulability-matrix assertion). Reuses
the proven durable-scheduler SAFE-INTERNAL-WRITE recipe (#7 secret-rotation, #17 legal-hold — both
codex-approved). Additive: ONE engine classifier, ONE scheduler job-kind arm, ONE seed migration,
ONE shift_queue item-type const. NO hot-path, NO HTTP surface. NO access revocation / provider
change (the recertification system is review-only — "no-live-access-changes").

## The gap (verified) + the hard constraint
`recertification_campaigns` (mig 070: id, name, start_date, end_date, review_type, reviewer_group,
reviews_count, completed_count, status ∈ {Active, Completed}) persists access-review campaigns,
but the ONLY way an operator learns a campaign blew its `end_date` while still `Active` is by
manually inspecting it — there is no proactive surfacing, and the status never transitions on its
own.

HARD CONSTRAINT (verified): the access-recertification system is DELIBERATELY review-only —
contracts.rs:4140 `"no-live-access-changes"`: it "never changes Entra groups, AD groups,
ServiceNow records, local memberships, or provider state." So the run-2 framing of "scheduled
REVOCATION" is OUT OF CONTRACT and explicitly excluded. This slice SURFACES overdue campaigns as
operator work (exactly like legal-hold-expiry-scan surfaces expiring holds for a human decision);
it does NOT revoke access, does NOT change provider state, and does NOT mutate the campaign.

## Design — mirror legal_hold_expiry_scan exactly
A daily durable-scheduler scan that reads `recertification_campaigns`, classifies overdue, and
enqueues ONE deduped `shift_queue` item per overdue campaign. Reads campaigns, writes only our own
`shift_queue` — NO state change to the campaign.

### Engine classifier (ryuki-engine/src/access_recertification.rs) — pure
```
pub enum RecertificationDueState { Overdue, NotYetDue }
  is_actionable() = matches!(Overdue)        // only Overdue becomes queue work
  as_str() = "overdue" | "not-yet-due"
pub fn classify_recertification_overdue(end_date_ms: i64, now_ms: i64) -> RecertificationDueState
  = if now_ms >= end_date_ms { Overdue } else { NotYetDue }
```
Mirrors `legal_hold::classify_legal_hold_expiry` (simpler — overdue is binary, no "soon" window
in slice 1). The api scan double-checks `is_actionable()` with Rust's clock AFTER the SQL filter,
so a near-edge row the DB clock selected but Rust's clock says is not-yet-due is SKIPPED — the same
clock-skew hardening codex required for legal-hold (a queue item never carries a non-actionable
verdict).

### Scheduler arm (ryuki-api/src/scheduler.rs run_job)
`"recertification_overdue_scan" =>` (all on `tx`):
```
SELECT id, name, start_date, end_date, review_type, reviewer_group, reviews_count, completed_count
FROM recertification_campaigns WHERE status = 'Active' AND end_date <= NOW() ORDER BY id
```
(`end_date <= NOW()` so the SQL filter is a SUPERSET consistent with the `>=` classifier and the
post-SQL clock-skew guard stays authoritative — an exactly-at-deadline campaign is not delayed a
day; codex MINOR.) For each row: `classify_recertification_overdue(end_date_ms, now_ms)`; skip if
`!is_actionable()`; build a title/description from the GOVERNANCE metadata and `enqueue_if_absent`.
A campaign is enqueued even when `completed_count == reviews_count` — if it is still `Active` past
its deadline it is unclosed operator work (codex).
- title: `Recertification overdue: {name}`
- description: `{review_type} campaign '{name}' (reviewer group {reviewer_group}) blew its
  recertification deadline {end_date} — {completed_count}/{reviews_count} reviews complete. Review
  and close it.`
- **source_ci_key = `{id}@{start_date_ms}`** — INSTANCE-specific, NOT the bare campaign id (codex
  MAJOR). Campaign ids are `arcamp-{8hex}` (created) or fixed seed slugs (`arcamp-ad-q2`), so id
  REUSE — though unlikely — is not guaranteed; keying the bare id would let a stale unresolved item
  suppress a genuinely-new overdue campaign that reused the id. `start_date` is the immutable
  instance birth marker, so `{id}@{start_date_ms}` distinguishes instances AND stays stable across
  a deadline EXTENSION (which moves `end_date`, not `start_date`) — no duplicate item on extend.
- metadata: `{ source_ci_key: "{id}@{start_date_ms}", campaign_id: id, name, review_type,
  reviewer_group, start_date, end_date, reviews_count, completed_count, due_state: "overdue" }`
- `enqueue_if_absent(tx, RECERTIFICATION_OVERDUE_ITEM_TYPE, &source_ci_key, title, description,
  "P2", metadata)`

SECRET HYGIENE: `recertification_campaigns` has NO sensitive free-text column (unlike
`legal_holds.reason`) — name / review_type / reviewer_group / counts / dates are GOVERNANCE
metadata (not secrets or credentials), appropriate for execute-tier shift_queue viewers who action
recertification work. Slice 1 surfaces ONLY these campaign-level fields; a follow-up must NOT add
member lists, provider identifiers beyond the campaign, or rationale/free-text (codex MINOR).

### job_is_schedulable (ryuki-engine/src/scheduler.rs)
Add `"recertification_overdue_scan"` to the allowlist (it is a safe-internal write, NOT
read-only, so it goes in the explicit branch beside `legal_hold_expiry_scan`).

### shift_queue const (ryuki-api/src/repos/shift_queue.rs)
`pub const RECERTIFICATION_OVERDUE_ITEM_TYPE: &str = "recertification-overdue";`

### Migration 129 (next free; highest is 128)
- Seed ONE enabled `recertification_overdue_scan` schedule. Fixed UUID
  `88888888-8888-4888-8888-888888888888` — a valid v4 that continues the established seed
  sequence (restore=5555, secret=6666, legal-hold=7777 → recert=8888) and collides with none of
  them. Daily 86400s, next_run_at NOW(), created_by 'system', `ON CONFLICT (id) DO NOTHING` so a
  re-run is a clean no-op.
- Partial unique index for STRUCTURAL dedup (at most one OPEN item per campaign INSTANCE), via
  `CREATE UNIQUE INDEX IF NOT EXISTS` (idempotent):
  `uq_shift_queue_open_recertification_overdue ON shift_queue (item_type, (metadata->>'source_ci_key'))
   WHERE resolved = false AND item_type = 'recertification-overdue'`. (The grain is the composite
   `{id}@{start_date_ms}` source_ci_key above, so distinct campaign instances never collide.)

## Tests
- Engine: `classify_recertification_overdue` boundaries (now > end → Overdue; now < end →
  NotYetDue; exact `now == end` → Overdue, since `>=`); `is_actionable`/`as_str`.
- Engine: `job_is_schedulable("recertification_overdue_scan")` is true.
- Scheduler (DB): `migration_129_is_idempotent_and_index_dedups` — re-run seed = no-op; assert the
  seeded row contract (name/job_kind/interval 86400/enabled/created_by) for the fixed UUID; a 2nd
  direct OPEN item for the same source_ci_key hits the partial unique index (mirrors
  `migration_126_is_idempotent_and_index_dedups`).
- Scheduler (DB): seed an Active campaign with `end_date` in the past → run `run_job` → ONE
  `recertification-overdue` shift_queue item appears with `due_state: "overdue"`; a NOT-overdue
  (future end_date) Active campaign enqueues nothing; a Completed campaign enqueues nothing;
  re-running the scan is idempotent (dedup).

## Out of scope (follow-ups)
- "Ending soon" warnings (a `soon_window` like legal-hold's 30 days) — slice 1 is overdue-only.
- Any auto-transition of the campaign status or auto-revocation of access — OUT OF CONTRACT
  (no-live-access-changes); closing a campaign stays a deliberate human action.
