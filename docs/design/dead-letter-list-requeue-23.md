# Dead-lettered agent-job list + requeue (#23 follow-up)

Status: design (awaiting plan review). Additive operator-visibility/recovery
endpoints for the dead-letter feature shipped in #23. NO migration, NO engine
change. CI-verifiable. Picked by the fresh 24-agent analysis swarm (3 lenses).

## Goal
`expire_leases` dead-letters poison jobs (`delivery_attempts >= MAX_REDISPATCHES=5`
→ `DeadLettered`, mig 121) and emits a Critical `job.dead_lettered` alert — but there
is NO operator endpoint to SEE dead-lettered jobs or RECOVER them. They are an
operational black hole. Add a list (visibility) + a requeue (recovery).

## Endpoints (admin-tier, under `/api/admin/agents/`)
The `/api/admin` prefix gate applies the `admin` floor (and blocks agent-token auth);
each handler ALSO re-checks `admin` as defense-in-depth, exactly like `admin_revoke_agent`.

### GET /api/admin/agents/dead-lettered-jobs → `admin_dead_lettered_jobs`
- `check_permission(&session,"admin")` else `forbidden`; `get_db()` else `db_err`.
- `SELECT id::text, request_id::text, platform, mode, delivery_attempts, created_at,
  updated_at FROM agent_jobs WHERE status='DeadLettered' ORDER BY updated_at DESC
  LIMIT 500`. **NO `spec`/`live_context`** — the job spec is an opaque payload and
  `live_context` is the CP-signed grant; neither is exposed (secret hygiene). Return
  `{dead_lettered_jobs: [...], count}` via a `DeadLetteredJobView` FromRow+Serialize.

### POST /api/admin/agents/dead-lettered-jobs/{job_id}/requeue → `admin_requeue_dead_lettered_job`
- `check_permission(admin)`; `get_db`; `Uuid::parse_str(job_id)` else `not_found`.
- `tx`. Steps, in the project's established lock order **requests → agent_jobs** (the
  dispatch / live-apply path already locks `requests FOR UPDATE` then touches
  `agent_jobs`, agents.rs:1900; `expire_leases`/`poll_job` lock only `agent_jobs` —
  so NO path locks job→request, hence this order cannot deadlock):
  1. `SELECT request_id::text, status, platform FROM agent_jobs WHERE id=$1` (a plain
     read, NO lock held across the next step — keeps the lock order request-first).
     - `None` → `not_found` (404).
     - `status != 'DeadLettered'` → `conflict` (409, "only DeadLettered jobs can be
       requeued"). Also the idempotency guard: a SECOND requeue sees `Pending` → 409.
  2. **PARENT-REQUEST GUARD (MAJOR)**: `SELECT status FROM requests WHERE
     id = request_id FOR UPDATE`.
     - `None` → `conflict` (409, "parent request not found; cannot requeue an
       orphaned job") — never re-dispatch work with no governing request (also covers
       the mig-054 fixture jobs whose request_id has no `requests` row).
     - decode via `db_status_to_request_status`; if `.is_concluded()` (Failed /
       Rejected / Cancelled / Completed / Operational / Protecting / Retired) →
       `conflict` (409, "parent request has concluded (<status>); cannot requeue").
       Only an ACTIVE request (Draft..Executing..Verifying) may have its job requeued.
       The `FOR UPDATE` serializes against a concurrent reject/fail/cancel (those CAS
       the request row), so requeue-vs-close resolves to one valid outcome.
- `UPDATE agent_jobs SET status='Pending', agent_id=NULL, attempt_id=NULL,
  fencing_token=NULL, cp_nonce=NULL, lease_deadline=NULL, delivery_attempts=0,
  updated_at=NOW() WHERE id=$1 AND status='DeadLettered' AND mode IN ('OfflineDryRun',
  'LivePlan')`.
  - Mirrors the `expire_leases` redispatch reset EXACTLY (same NULL-ed lease fields),
    but `delivery_attempts → 0` (a fresh redispatch budget — see below) and guarded
    to `DeadLettered` + non-mutating mode.
  - `mode IN ('OfflineDryRun','LivePlan')` is defense-in-depth: the dead-letter
    UPDATE is itself mode-scoped to those two (LiveApply → `ReconcileRequired`, never
    `DeadLettered`), so a DeadLettered job is ALWAYS non-mutating — requeue-to-Pending
    can never re-dispatch a live mutation.
  - `rows_affected != 1` → `conflict` (raced; fail-safe).
- `record_audit_tx(security_audit("agent-job-requeue", Some("dead-lettered"),
  "pending", {job_id, request_id, platform}))`; `commit`.
- Return `{job_id, status:"Pending", requeued:true}`.
- Residual (noted, pre-existing): a cancel that lands strictly AFTER a committed
  requeue leaves a Pending job under a now-cancelled request — but that is the SAME
  property the system already has for any not-yet-leased job at cancel time (cancel/
  fail do not terminate Pending agent_jobs; they wind down via lease/reconcile).
  Fully closing it = making cancel/fail terminate Pending jobs, a separate change.

## Why requeue resets `delivery_attempts` to 0
A DeadLettered job has `delivery_attempts >= 5`. Requeue WITHOUT reset → `Pending`
with `attempts=5`, so the very NEXT lease expiry re-dead-letters it immediately
(`>= 5`). Resetting to 0 gives the operator-recovered job a full fresh redispatch
budget. The cap still protects against infinite AUTO-loops; an operator requeue is an
explicit, audited human intervention that resets the budget. (Tradeoff: if the
underlying fault is unfixed it will re-dead-letter after 5 more attempts and resurface
— acceptable; the operator owns the decision.)

## Routes + collision (agents.rs router ~2472)
```
.route("/api/admin/agents/dead-lettered-jobs", get(admin_dead_lettered_jobs))
.route("/api/admin/agents/dead-lettered-jobs/{job_id}/requeue", post(admin_requeue_dead_lettered_job))
```
At the segment after `/api/admin/agents/`, the existing routes use a `{agent_id}`
param (`/approve`, `/revoke`) PLUS static siblings `liveness` + `live-apply-jobs`.
matchit (axum 0.8) allows static + param siblings with STATIC taking precedence, so
the new static `dead-lettered-jobs` routes to the new handler and `{agent_id}` still
catches real agent ids — no build panic (same precedent as `liveness`). agent_ids
cannot equal `dead-lettered-jobs` (reserved-word safe, same assumption the existing
statics already rely on). A router-build test asserts no panic + the statics resolve.

## Tests (agents.rs db-tests — mirror `db_poison_cap_dead_letters_and_alerts`)
NOTE: `seed_expired_leased_job` uses a RANDOM `request_id` with no `requests` row, so
the requeue HAPPY tests must seed a REAL parent request (an ACTIVE status, e.g.
`Executing`) and point the job at it (a small `seed_dead_lettered_job(pool, platform,
request_id)` helper: seed at attempts=5 then `expire_leases`). The list test can use
the random-request_id helper (the list does not touch the parent).
1. **list happy**: dead-letter 2 jobs → GET returns both with metadata; the response
   carries NO `spec`/`live_context` keys; a Pending/other-status job is excluded.
2. **requeue happy**: real ACTIVE parent + a dead-lettered job → POST requeue → 200;
   the row is `Pending`, `delivery_attempts=0`, lease fields NULL; an
   `agent-job-requeue` audit row exists.
3. **requeue rejects non-dead-lettered**: a Pending job → 409.
4. **requeue unknown id** → 404 (and a non-UUID job_id → 404).
5. **requeue idempotency**: first requeue 200, second (now Pending) → 409.
6. **requeue rejects a concluded parent (MAJOR)**: a dead-lettered job whose
   parent request is `Cancelled` (and a second case `Failed`) → 409 and the job is
   UNCHANGED (still `DeadLettered`, `delivery_attempts` not reset). Also: an orphan
   job (request_id with no `requests` row) → 409.
7. **post-requeue cap still applies (MINOR)**: requeue a job, then run it back
   through the fresh budget (re-lease + `expire_leases` x6) and assert it
   dead-letters AGAIN — proving the audited reset does not let a poisoned job escape
   the automatic cap.
8. **admin-gated**: a non-admin session → 403 for BOTH list + requeue (no state change).
9. **router builds** + the statics aren't shadowed (oneshot, no DB).

## Files
- sources/ryuki-api/src/agents.rs (`admin_dead_lettered_jobs` +
  `admin_requeue_dead_lettered_job` + `DeadLetteredJobView` + 2 routes + tests).
  NO migration, NO engine change.

## Out of scope (follow-ups)
- Bulk requeue-all-dead-lettered. Pagination/filtering on the list (LIMIT 500 noted).
- Portal "Dead-lettered jobs" view (S6 agents view).
