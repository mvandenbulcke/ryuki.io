# #23 — CP-side poison-job cap / dead-letter

Status: design — plan-review APPROVE (2 minors + 2 nits folded in:
per-replica concurrency wording + a concurrency test, migration-wording precision,
and a brand-new-insert-defaults-0 test).

## Goal
A non-mutating agent job (`OfflineDryRun` / `LivePlan`) whose lease expires is
reset to `Pending` **unconditionally** by `expire_leases`
(`sources/ryuki-api/src/agents.rs`) — forever. If an agent keeps leasing the job
and crashing/timing out (a malformed spec, an OOM, a partition), it poison-loops
indefinitely: it is re-leased, expires, re-dispatched, re-leased… with no cap and
no terminal state, silently burning agent capacity and never surfacing. There is
no `attempts`/retry column and no dead-letter status today (confirmed: grep of
`migrations/*.sql` + the job lifecycle).

Add a CONTROL-PLANE poison-job cap: count lease-expiry redispatches per job and,
after a bounded number, move the job to a terminal `DeadLettered` state instead
of re-dispatching it, emitting one alert-worthy domain event so operators see it.

`LiveApply` is already safe — its lease expiry goes to `ReconcileRequired` (never
auto-redispatched), so it cannot poison-loop and is OUT of scope here.

## Why in `expire_leases` (not the durable scheduler)
The poison loop is created by `expire_leases` itself (the redispatch UPDATE), so
the cap belongs exactly there. `expire_leases` runs in the standalone
`spawn_lease_expiry_sweep` loop (every 30s); the cap is pure CP bookkeeping
(count + terminal status + an event), fully CI-verifiable without any agent.

## Data model — migration 121 (idempotent)
1. `ALTER TABLE agent_jobs ADD COLUMN IF NOT EXISTS delivery_attempts INT NOT NULL
   DEFAULT 0;` — the count of lease-expiry REDISPATCHES this job has taken. 0 for a
   never-expired job. Only the non-mutating redispatch path increments it.
2. Extend the status CHECK to admit the new terminal value (the original is the
   inline-named `agent_jobs_status_check` from mig 054):
   ```sql
   ALTER TABLE agent_jobs DROP CONSTRAINT IF EXISTS agent_jobs_status_check;
   ALTER TABLE agent_jobs ADD CONSTRAINT agent_jobs_status_check
       CHECK (status IN ('Pending','Leased','Running','Succeeded','Failed',
                         'Expired','ReconcileRequired','LiveRefused','DeadLettered'));
   ```
   Guarded (DROP IF EXISTS + re-add) so re-application is SAFE (not literally a
   no-op — it drops and re-adds the constraint, which sqlx never re-runs for an
   applied migration anyway; a manual re-run also succeeds). Widening the CHECK is
   safe with existing rows (old values are a subset of the new set) and the
   migration's table lock prevents writes in the drop/add gap. No seed, no index
   change (existing `idx_agent_jobs_platform_status` already serves status lookups).

No change to `AGENT_JOB_COLUMNS` / the agent-facing job row: `delivery_attempts`
is internal CP bookkeeping the agent never needs, so the lease/fetch/ack paths and
their decode struct stay untouched (zero blast radius on the hot agent path).

## Constant
`MAX_REDISPATCHES` = 5 (a single `const` in `agents.rs`, easy to retune). A job is
redispatched at most 5 times; on the 6th lease expiry (`delivery_attempts >= 5`)
it is dead-lettered. Total dispatch attempts before dead-letter = 6 (1 initial +
5 redispatches).

## Engine — `event_alerts.rs` (pure, make a dead-letter alert-worthy)
1. New classifier `severity_for_agent_job_status(to_status)`:
   `"dead-lettered" => Some(Critical)` else `None`. Rationale: a job that
   exhausted every redispatch is a HARD execution failure — that request's work
   will never run without operator intervention — so it ranks with a `failed`
   request (Critical), above the recoverable `offline` agent (Warning). (Severity
   tier remains a review question; Critical is the proposed default.)
2. Add `"dead-lettered"` to `alert_worthy_statuses()` (the coarse SQL-filter
   union) — the existing `alert_status_union_matches_the_classifiers` test then
   forces a classifier to cover it (satisfied by #1).
3. Add a `"agent_job" => to_status.and_then(severity_for_agent_job_status)` arm to
   `classify()`.
4. Unit tests: dead-lettered→Critical; a non-dead-letter agent_job status→None;
   `classify("agent_job", Some("dead-lettered"))`→Critical; cross-aggregate
   spurious pair stays None.

## API — `expire_leases` restructured (ONE transaction, atomic)
Today it runs three pool-level UPDATEs. To emit an event per dead-lettered job it
becomes one `tx`:
1. **Dead-letter the at-cap rows** (terminal, no redispatch):
   ```sql
   UPDATE agent_jobs SET status='DeadLettered', updated_at=NOW()
   WHERE status IN ('Leased','Running') AND mode IN ('OfflineDryRun','LivePlan')
     AND lease_deadline < NOW() AND delivery_attempts >= $MAX_REDISPATCHES
   RETURNING id::text, request_id::text, platform, mode, delivery_attempts
   ```
   For each returned row emit a `domain_events` row via the existing
   `repos::domain_events::insert(&mut *tx, …)`: `event_type='job.dead_lettered'`,
   `aggregate_type='agent_job'`, `aggregate_id=id`, `site=None`,
   `environment=None` (agent jobs are platform-wide infra, like agent-offline),
   `actor='system'`, payload minimal:
   `{"to_status":"dead-lettered","platform":…,"mode":…,"request_id":…,
     "delivery_attempts":…,"note":"lease expired repeatedly; poison-job cap reached"}`.
   `to_status` present → it lands in `GET /api/events/alerts` (Critical).
2. **Redispatch + increment the under-cap rows** (the existing reset, now counting):
   ```sql
   UPDATE agent_jobs
      SET status='Pending', agent_id=NULL, attempt_id=NULL, fencing_token=NULL,
          cp_nonce=NULL, lease_deadline=NULL,
          delivery_attempts = delivery_attempts + 1, updated_at=NOW()
   WHERE status IN ('Leased','Running') AND mode IN ('OfflineDryRun','LivePlan')
     AND lease_deadline < NOW() AND delivery_attempts < $MAX_REDISPATCHES
   ```
   The two predicates are mutually exclusive on `delivery_attempts`, so order is
   immaterial; dead-letter runs first for clarity.
3. **LiveApply → ReconcileRequired** (unchanged).
4. `tx.commit()`. Return `dead_count + redispatched + reconcile`. Keep the
   existing `tracing::info!` (add `dead_lettered = dead_count`).

Lock/visibility: `expire_leases` is a PER-REPLICA global sweep (NOT leader-elected
— each replica's `spawn_lease_expiry_sweep` runs it every 30s). It is safe under
concurrent sweepers: PostgreSQL serializes concurrent UPDATEs on the same row and
RECHECKS the `status` + `delivery_attempts` predicates after waiting on the row
lock, so two replicas cannot both increment `4→5` (the second sees 5, `< MAX`
fails) nor both dead-letter at 5 (the second sees `DeadLettered`, the
`Leased/Running` predicate fails) — exactly one increment and exactly one
dead-letter+event per job. Wrapping the sweep in one tx keeps the dead-letter
UPDATE + its events atomic (an event can never be emitted for a job that was not
actually dead-lettered, and vice versa). The `EXPIRE_TEST_LOCK` already serializes
any test that calls `expire_leases`.

## Tests (new `agents::tests::db_*`, under `EXPIRE_TEST_LOCK`, cleaned up)
1. **Cap reached → dead-letter + alert event.** Seed an `OfflineDryRun` job; loop
   6 times { set it `Leased` with `lease_deadline = NOW() - 1min`; call
   `expire_leases` }. Assert: after 5 cycles it is `Pending` with
   `delivery_attempts = 5`; the 6th cycle flips it to `DeadLettered` and inserts
   exactly one `domain_events` row (`event_type='job.dead_lettered'`,
   `aggregate_type='agent_job'`, payload `to_status='dead-lettered'`,
   `delivery_attempts=5`).
2. **Under-cap redispatch increments.** One expiry → `Pending`,
   `delivery_attempts = 1`, no dead-letter event.
3. **LiveApply never dead-lettered.** A `LiveApply` job past its deadline → still
   `ReconcileRequired`, `delivery_attempts` unchanged (0), no event — even if
   `delivery_attempts` is forced ≥ MAX.
4. **DeadLettered is terminal.** A second `expire_leases` after dead-letter does
   NOT touch the row (status no longer in Leased/Running) and emits no new event.
5. **Per-replica concurrency (review requirement).** Under `EXPIRE_TEST_LOCK`, seed ONE expired
   non-mutating job and run two `expire_leases(&pool)` calls concurrently
   (`tokio::join!`). At `delivery_attempts = 4`: assert exactly one increment (→5)
   and ZERO dead-letter events. At `delivery_attempts = 5`: assert exactly one
   `DeadLettered` row and EXACTLY one `job.dead_lettered` event (proves the
   row-lock predicate recheck prevents a double-increment / double-emit across
   replicas).
6. **Brand-new insert defaults (review requirement).** A fresh `create_agent_job` (which omits
   `delivery_attempts`) reads back `delivery_attempts = 0` — the `NOT NULL DEFAULT
   0` column is safe for existing INSERTs and needs no `AGENT_JOB_COLUMNS` change.
7. **Engine:** the `event_alerts` unit tests above (run in the engine suite).
8. **Migration 121 idempotency** (re-run is safe; column + widened constraint both
   present; an existing-value insert still passes the widened CHECK).

## Files
- migrations/121_agent_jobs_delivery_attempts.sql (new)
- sources/ryuki-engine/src/event_alerts.rs (classifier + union + classify + tests)
- sources/ryuki-api/src/agents.rs (`MAX_REDISPATCHES`, `expire_leases` rewrite,
  db tests)
- `repos::domain_events::insert` reused as-is.

## Out of scope (follow-ups)
- An operator endpoint to LIST or REQUEUE dead-lettered jobs (reset status to
  Pending + zero `delivery_attempts`). This slice makes them terminal + visible;
  manual recovery is a follow-up.
- A notification draft (email/bell) on dead-letter — the alert-feed entry covers
  visibility; a `draft_for_alert` notification mirroring agent-offline is a
  follow-up if desired.
- Per-platform / per-mode redispatch caps (the single constant suffices now).
