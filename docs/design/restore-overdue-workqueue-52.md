# #52 — Route overdue restore tests into the work queue

Status: design — codex plan-review round 1 NEEDS-CHANGES, all fixed below. Reuses
the #40/#39/#19 durable-scheduler SAFE-INTERNAL-WRITE recipe.
Codex fixes folded in: (blocker) gate on `is_at_risk()` — the classifier returns
`NeverTested`, not `Overdue`, for never-succeeded; (major) `ON CONFLICT DO NOTHING`
so a race can't abort the tick; (major) documented the `source_ci_key` global-
identity invariant (aligned with the #47 aggregate's GROUP BY); (minor) exact
threshold-boundary tests.

## Goal
`backup_restore_test_recency` (`GET`, contracts.rs:22186) already classifies each
protected system's restore-test recency as Overdue via the pure
`ryuki_engine::backup_recency::classify_restore_recency` (over
`restore_requests::restore_test_recency`, #47). But the only way an operator learns
a system is overdue is by polling that read endpoint. Nothing PROACTIVELY surfaces
it as actionable work. Add a scheduled `restore_overdue_scan` that finds systems
whose last SUCCESSFUL restore test is overdue (or which have never succeeded) and
enqueues ONE open `shift_queue` work item per system — deduped — so overdue
recoverability shows up in the operations queue without manual polling.

## Scope (first slice): AT-RISK (overdue OR never-tested)
A system is flagged when `classify_restore_recency(...).is_at_risk()` is true.
CODEX FIX (blocker): the classifier returns `RestoreTestRecency::NeverTested` (NOT
`Overdue`) when `last_successful_test IS NULL`, and `Overdue` only for a stale-but-
once-successful system. `is_at_risk()` = `!matches!(self, Current)` covers BOTH —
so the scan flags stale AND never-succeeded systems (the latter ordered most-at-
risk first by the recency query). The metadata `reason` carries
`recency.as_str()` (`"overdue"` | `"never_tested"`) so the two are not conflated.
This reuses the tested #47 classifier verbatim.

FAILED-latest (a system whose last success is recent but whose MOST RECENT
restore_request is `Failed`) is a deliberate OUT-OF-SCOPE follow-up — it needs a
distinct "latest-status" query, and the overdue signal is the higher-value,
already-built one. (Codex-review question: must failed-latest be in this slice?)

## Why a durable-scheduler job
Leader-elected (one replica ticks), so each system is flagged once per cadence
across the fleet — the right place for recurring fan-out. The scheduler is a
platform-wide internal principal, so it scans ALL sites (`restore_test_recency(tx,
None, None)`). Safe-internal-write: it READS `restore_requests` and WRITES only our
own `shift_queue` — no provider/live call.

## Constant
`RESTORE_OVERDUE_DAYS` = 90 (matches the `overdue_after_days` default of the #47
read endpoint). A single const in `scheduler.rs`, easy to retune; the scan runs
daily (interval 86400).

## Dedup (shift_queue has NO natural key)
`shift_queue` has only a PK on `id`; there is no unique constraint to lean on. The
enqueue is therefore an atomic single-statement INSERT guarded by NOT EXISTS of an
OPEN item for the same system+type:
```sql
INSERT INTO shift_queue (item_type, title, description, priority, metadata)
SELECT 'restore-test-overdue', $1, $2, 'P2', $3::jsonb
WHERE NOT EXISTS (
    SELECT 1 FROM shift_queue
    WHERE item_type = 'restore-test-overdue'
      AND resolved = false
      AND metadata->>'source_ci_key' = $4
)
ON CONFLICT DO NOTHING
```
`rows_affected()` (0 or 1) tells the scan whether it enqueued. The `WHERE NOT
EXISTS` avoids even attempting the insert in the common (already-queued) case;
CODEX FIX (major): the untargeted `ON CONFLICT DO NOTHING` is the belt-and-
suspenders so that if a split-brain tick or a future non-leader writer ever races
between the check and the insert, the second insert hits the partial unique index
and is silently dropped — it does NOT error and abort the whole scheduler tick.
Under the normal SINGLE-LEADER tick (like #39's single-emit) only one replica
scans per tick, so the race is already impossible; the ON CONFLICT just makes it
structurally safe. (Untargeted DO NOTHING is correct here: `id` is auto-generated
so the PK never conflicts; the only other unique index is the partial one below.)
Semantics: while an open item exists the scan is a no-op for that system; once an
operator RESOLVES it (`resolved=true`) and the system is STILL overdue at the next
scan, a fresh item is created (correct re-flag); once the system is tested
successfully it is no longer overdue and nothing is created.

CODEX FIX (major — identity invariant): the dedup key and the all-sites scan key on
`source_ci_key` ALONE. This is intentional and consistent with the data model:
`restore_requests.source_ci_key` is `NOT NULL` (mig 007), and the #47 aggregate
`restore_test_recency` itself GROUPs BY `source_ci_key` alone (no site/env) — so the
whole recency surface already treats `source_ci_key` as the GLOBAL system identity.
Matching that grouping in the dedup key is therefore correct; adding site/env would
DIVERGE from the aggregate that produces the rows. The helper requires a non-empty
`source_ci_key` (a unique index permits multiple NULLs, but the column is NOT NULL
and the helper rejects empty), so the dedup can never be silently bypassed.

## Engine
`scheduler.rs`: add `"restore_overdue_scan"` to the explicit `job_is_schedulable`
allowlist (safe-internal-write — reads restore_requests, writes shift_queue, no
provider/live call). Test: schedulable but NOT read_only.

## API `run_job` arm `"restore_overdue_scan"` (ALL on the tick tx)
1. `let rows = restore_requests::restore_test_recency(&mut **tx, None, None).await?;`
   (generalize that fn's signature to `impl PgExecutor` so it runs on the tx; the
   existing `&PgPool` caller is unaffected — `&PgPool: PgExecutor`.)
2. For each row, classify with the pure engine
   `classify_restore_recency(last_unix, now_unix, RESTORE_OVERDUE_DAYS*86400)`
   (`last_unix` = `last_successful_test.map(|t| t.timestamp())`, `now_unix` =
   `Utc::now().timestamp()`); if `recency.is_at_risk()`, build a secret-free
   title/description/metadata and call the new
   `repos::shift_queue::enqueue_if_absent(&mut **tx, …)` (the INSERT…WHERE NOT
   EXISTS…ON CONFLICT DO NOTHING above). Count the rows_affected.
   - title: `"Restore test {reason}: {source_ci_key}"` (reason = `recency.as_str()`)
   - description (overdue): `"No successful restore test in over {N} days (last success: {ts}). Verify recoverability."`; (never_tested): `"No successful restore test on record ({total} request(s), 0 verified). Verify recoverability."`
   - metadata: `{"source_ci_key":…, "last_successful_test":…|null, "successful_test_count":…, "reason": recency.as_str()}`
   - `source_ci_key` is a config-item identifier (an asset key, not a secret) — the
     same value already returned by the public #47 read endpoint.
3. `detail` aggregate-only: `"enqueued N restore-overdue item(s)"` (a count — never
   per-system ids — surfaced via /api/ops/scheduler/executions).

## New repo `sources/ryuki-api/src/repos/shift_queue.rs`
Executor-generic (`impl PgExecutor`) so the scan writes on `&mut *tx`:
`enqueue_if_absent(executor, source_ci_key, title, description, priority, metadata)
-> Result<u64, sqlx::Error>` (returns rows_affected). This is the FIRST reusable
shift_queue writer (today every INSERT is inline in tests); kept minimal and
scoped to this need. Registered in `repos/mod.rs`.

## Migration 122
Seed ONE enabled daily `restore_overdue_scan` schedule (interval 86400, fixed id,
ON CONFLICT DO NOTHING). NO new table. ADD a PARTIAL UNIQUE INDEX to make the dedup
STRUCTURAL as well as procedural (defense-in-depth + documents the intended key):
```sql
CREATE UNIQUE INDEX IF NOT EXISTS uq_shift_queue_open_restore_overdue
    ON shift_queue (item_type, (metadata->>'source_ci_key'))
    WHERE resolved = false AND item_type = 'restore-test-overdue';
```
This makes a duplicate open item impossible even if a future non-leader path
enqueues. (Codex-review question: keep the partial unique index, or rely solely on
the single-leader NOT EXISTS? The index constrains only `resolved=false` rows so it
does not block the post-resolution re-flag.)

## Tests (new `*_db_tests`, serialized, cleaned up)
1. Seed `restore_requests` for a `source_ci_key` whose last Verified/Completed is
   >90d old (updated_at backdated); seed a guaranteed-due `restore_overdue_scan`
   schedule; tick once → exactly one OPEN `shift_queue` row with
   `item_type='restore-test-overdue'`, `metadata->>'source_ci_key'` = the system,
   priority P2; detail exactly `enqueued <N> restore-overdue item(s)`.
2. Dedup: a second tick does NOT create a duplicate (still one open item).
3. Recently-tested system (last success < 90d) → no item.
4. Never-succeeded system (requests exist, none Verified/Completed) → flagged, with
   `metadata.reason='never_tested'` (NOT `overdue`).
5. Re-flag after resolution: mark the item `resolved=true`; a subsequent tick (still
   overdue) creates a NEW open item.
6. Boundary (codex minor): a system whose last success is EXACTLY
   `RESTORE_OVERDUE_DAYS*86400` seconds old → NOT flagged (classifier uses
   `age > threshold`); at `+1` second → flagged. Locks the queue behavior at the
   threshold, not just directionally.
7. Engine `job_is_schedulable` matrix (restore_overdue_scan schedulable, not
   read_only); migration 122 idempotency + the partial unique index rejects a
   second open duplicate (direct INSERT of a second open row for the same
   item_type+source_ci_key errors / is DO-NOTHING'd).

## Files
- migrations/122_restore_overdue_scan.sql (new — seed schedule + partial unique index)
- sources/ryuki-engine/src/scheduler.rs (allowlist + test)
- sources/ryuki-api/src/repos/shift_queue.rs (new — enqueue_if_absent) + repos/mod.rs
- sources/ryuki-api/src/repos/restore_requests.rs (restore_test_recency → impl PgExecutor)
- sources/ryuki-api/src/scheduler.rs (run_job arm + tests)

## Out of scope (follow-ups)
- FAILED-latest restore test routing (distinct latest-status query).
- DR-PLAN drill overdue (`dr_test_runs` / `dr_plans.plan_json.next_test_due`) — a
  separate signal/source from restore-request recency.
- Auto-assignment / priority escalation of the enqueued item.
- A domain-event/alert on enqueue (the work queue itself is the surface here).
