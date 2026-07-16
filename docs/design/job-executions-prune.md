# Scheduler job_executions retention prune — bound the unbounded run history

Status: SHIPPED (run-3 discovery swarm, CONFIRMED M/S). Plan review NEEDS-CHANGES → APPROVE (the
one-shot-DELETE MAJOR fixed with a per-run batch cap; keep sized to the 5-min cadence; NULLS LAST +
keep/cap guard + stable tiebreak), implementation review APPROVE (tie-case test now forces an identical
timestamp; doc wording). Directly serves the standing goal's
disk-space concern: `job_executions` (mig 095) appends a row for EVERY scheduler run — the hourly
self-health probe alone is ~720 rows/month, plus every scan/sweep — and NOTHING ever prunes it, so
it grows without bound. A new durable-scheduler PRUNE job-kind keeps a bounded newest-N per schedule.
Additive: ONE scheduler job-kind arm + ONE seed migration + the engine `job_is_schedulable`
allowlist entry. NO hot-path, NO HTTP surface, NO per-row engine CLASSIFIER (unlike the expiry
scans — it is a pure retention DELETE, not a classify-and-enqueue).

## The gap (verified)
`job_executions` (id TEXT PK, schedule_id FK→schedules ON DELETE CASCADE, job_kind, status, detail,
started_at, finished_at; index `(schedule_id, started_at DESC)`) is written on every tick
(scheduler.rs:783) and read newest-first, but there is NO prune — `rg prune|retention|DELETE FROM …
job_executions` finds none. The FK CASCADE only removes rows when a SCHEDULE is deleted (schedules
persist), so it does not bound a live schedule's history. The table grows forever.

## Design — a newest-N-per-schedule prune (mirrors the scheduler job-kind shape)
A daily PRUNE job that keeps the newest `KEEP_PER_SCHEDULE` rows per `schedule_id` and deletes the
rest — regardless of age, so every schedule retains its recent history for debugging while total
rows are bounded to `KEEP_PER_SCHEDULE × #schedules` (adversarial review preferred newest-N over a
pure time-window, which would wipe a quiet schedule's whole history).

### Retention constant — sized to the FASTEST cadence (MAJOR 2)
The seeded schedules' fastest cadence is `connection_health_sweep` at **300s (5 min)** = 288 runs/day
(others: 2× hourly, the rest daily). So `keep_per_schedule = 10000` gives the 5-min sweep ~35 days,
the hourly probes ~14 months, the daily scans ~27 years — all BOUNDED (total ≤ 10000 × #live
schedules ≈ <100k rows, a small table). Over-retaining the slow schedules is harmless (rows are
tiny); the point is the hard logical bound + ≥30 days for the fastest schedule.

### Prune helper + scheduler arm (ryuki-api/src/scheduler.rs) — BATCHED (MAJOR 1)
A small free fn, unit-testable with a low `keep` + cap. A PER-RUN CAP bounds the victim set so the
FIRST prune of a years-old backlog never does one giant unbounded DELETE (WAL/locks/dead-tuples/
statement-timeout); a large backlog drains over a few daily runs, then steady-state deletes only the
day's new over-cap rows:
```
async fn prune_job_executions(conn, keep_per_schedule: i64, max_per_run: i64) -> Result<u64, sqlx::Error> {
  if keep_per_schedule <= 0 || max_per_run <= 0 { return Ok(0); }   // guard (MINOR) — never delete-all
  DELETE FROM job_executions WHERE id IN (
    SELECT id FROM (
      SELECT id, started_at, ROW_NUMBER() OVER (
        PARTITION BY schedule_id ORDER BY started_at DESC NULLS LAST, id DESC
      ) AS rn
      FROM job_executions
    ) ranked WHERE rn > $1                 -- the over-cap rows
    ORDER BY started_at ASC, id ASC        -- delete the GLOBALLY OLDEST over-cap rows first
    LIMIT $2                               -- per-run cap
  ) → rows_affected()
}
```
The `"job_executions_prune" =>` run_job arm calls it with `const KEEP_PER_SCHEDULE: i64 = 10000` +
`const MAX_PER_RUN: i64 = 20000`, returning `Some("pruned {n} old job_executions row(s)")`.
- `started_at` is `NOT NULL` (mig 095:53) so no NULLs arise, but `NULLS LAST` is added defensively
  (MINOR) so a hypothetical NULL could never be retained ahead of real rows.
- `id DESC` is a STABLE TIE-BREAK (NOT chronological — ids are not time-sortable), only to make
  "newest N" deterministic when two rows share `started_at`. A tie-case test covers it.
- SELF-DELETION SAFE: the prune's OWN `job_executions` row is recorded by the tick AFTER `run_job`
  returns, and even once written it is within the newest-N, so the prune never deletes its own run.
- SECRET HYGIENE: `job_executions.detail` is the scheduler's own status text (never credentials);
  the prune only DELETEs — it surfaces nothing.

### job_is_schedulable (ryuki-engine/src/scheduler.rs)
Add `"job_executions_prune"` to the safe-internal-write allowlist (it WRITES — a DELETE on our own
history — so NOT read-only) + the matrix/`_live` negatives.

### Migration 131 (next free; highest is 130)
Seed ONE enabled `job_executions_prune` schedule. Fixed UUID
`aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa` (continues the seed sequence restore=5/secret=6/legal-hold=7/
recert=8/cert=9 → prune=a; collides with none). Daily 86400s, next_run_at NOW(), created_by
'system', `ON CONFLICT (id) DO NOTHING`. NO partial-unique-index (a prune, not a deduped enqueue).

## Tests
- Engine: `job_is_schedulable("job_executions_prune")` true (safe-internal-write) + the matrix/`_live`
  negatives.
- Scheduler (DB): `migration_131_is_idempotent` (re-run the seed → no-op; assert the seeded-row
  contract). [No index-dedup assertion — this migration adds no index.]
- Scheduler (DB): seed schedule A with 5 job_executions rows (staggered started_at) + schedule B
  with 2 rows → `prune_job_executions(conn, keep=3, max_per_run=100)` → A keeps exactly its NEWEST 3
  (the 2 OLDEST deleted), B (≤3) UNTOUCHED; the survivors are the newest by started_at; a second
  prune is a clean no-op (0 deleted). Returns the right count.
- Scheduler (DB) — BATCH CAP: seed A with 6 rows, `keep=2, max_per_run=2` → first call deletes 2
  (the oldest), second deletes 2, third deletes 0 (now at the 2-row cap) — proving the per-run cap
  drains a backlog over multiple runs.
- Scheduler (DB) — TIE-BREAK: two rows with the SAME `started_at` beyond the cap → the prune is
  deterministic (the `id DESC` partition tiebreaker picks a fixed survivor), no error.
- Helper GUARD: `keep_per_schedule <= 0` (or `max_per_run <= 0`) returns 0 and deletes NOTHING.

## Out of scope (the sibling run-3 prune)
- `connection_health_checks` history prune — same newest-N-per-connection shape, its own change.
- A configurable retention (env/config knob) — slice 1 uses a code constant.
