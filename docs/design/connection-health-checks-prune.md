# connection_health_checks retention prune — bound the fastest-growing history table

Status: SHIPPED (run-3 discovery swarm, CONFIRMED M/S). Plan review NEEDS-CHANGES → APPROVE (the
daily-cap throughput MAJOR fixed by running HOURLY; a closed PruneTarget enum for injection-safety);
implementation review NEEDS-CHANGES×2 → APPROVE (a retention index matching the prune's window ORDER BY,
with explicit `checked_at DESC NULLS LAST` so the planner skips the sort; the test now asserts the
newest survive). The HIGHEST disk-value prune: the seeded
`connection_health_sweep` runs every 300s (5 min) and appends ONE `connection_health_checks` row PER
integration connection PER sweep → ~288 rows/day/connection, unbounded. Reuses the proven,
review-approved `job_executions_prune` pattern (720a1d0) by GENERALIZING its helper. Additive: ONE
generalized helper + ONE scheduler job-kind arm + ONE seed migration.

## The gap (verified)
`connection_health_checks` (mig 102: id TEXT PK, connection_id TEXT FK→integration_connections ON
DELETE CASCADE, checked_at TIMESTAMPTZ, endpoint_status, credential_status, message; index
`(connection_id, checked_at DESC)`) is appended by the 5-min sweep (integration.rs:1173) and read
newest-first, but NOTHING prunes it. The FK CASCADE only removes rows when a CONNECTION is deleted
(connections persist), so a live connection's health history grows without bound — the fastest of
all the run-3 unbounded tables (5-min × per-connection). No append-only/BEFORE-DELETE trigger, so the
prune DELETE is allowed.

## Design — generalize the job_executions prune helper, then add a 2nd job-kind
The `job_executions_prune` (720a1d0) keep-newest-N-per-partition + per-run-cap logic is identical
here; only the table / partition column / timestamp column differ. So:

### Generalized helper + a CLOSED-SET enum (ryuki-api/src/scheduler.rs)
The SQL identifiers come from a closed `PruneTarget` enum (review note: an allowlist is a stronger
guarantee than raw `&'static str` — the table/partition/ts can ONLY be one of the enum's hardcoded
triples, never an arbitrary string):
```
enum PruneTarget { JobExecutions, ConnectionHealthChecks }
impl PruneTarget { fn parts(&self) -> (&'static str, &'static str, &'static str) {
    JobExecutions          => ("job_executions",          "schedule_id",   "started_at"),
    ConnectionHealthChecks => ("connection_health_checks", "connection_id", "checked_at"),
}}
async fn prune_history_newest_n(conn, target: PruneTarget, keep, cap) -> Result<u64, sqlx::Error>
```
Same guarded + batched window-DELETE as `prune_job_executions`, with the enum's `(table, partition,
ts)` `format!`'d into the SQL — injection-safe by construction (no caller-supplied string reaches the
SQL; keep/cap stay bound `$1`/`$2`). `prune_job_executions(conn, keep, cap)` becomes a thin wrapper
`prune_history_newest_n(conn, PruneTarget::JobExecutions, keep, cap)` so the existing prune tests are
unchanged.

### Scheduler arm (ryuki-api/src/scheduler.rs run_job) — HOURLY (review MAJOR)
`"connection_health_checks_prune" =>` calls `prune_history_newest_n(tx,
PruneTarget::ConnectionHealthChecks, KEEP_PER_CONNECTION = 10000, MAX_PER_RUN = 20000)`.
THROUGHPUT (review MAJOR): at the 5-min sweep, each connection adds ~288 rows/DAY, so a DAILY prune
with cap=20000 only keeps up below ~70 connections — above that the table would grow despite the
prune. So this prune runs **HOURLY** (interval 3600s, vs the daily job_executions prune): per-run
growth is #connections × 12, so cap=20000 keeps up to ~1666 connections (huge headroom for a control
plane) with gentle per-run deletes, and a first-prune backlog drains 24× faster. `keep=10000` →
~35 days/connection (bounded ≤ 10000 × #connections). Returns
`Some("pruned {n} old connection_health_checks row(s)")`.

### job_is_schedulable (ryuki-engine/src/scheduler.rs)
Add `"connection_health_checks_prune"` to the safe-internal-write allowlist + the matrix/`_live`
negatives.

### Migration 132 (next free; highest is 131)
Seed ONE enabled **hourly** `connection_health_checks_prune` schedule (interval 3600s — see the
throughput rationale above; this differs from the daily job_executions prune because per-connection
growth is far faster). Fixed UUID `bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb` (continues the seed sequence
…cert=9999, prune=aaaa → chc-prune=bbbb; collides with none). `ON CONFLICT (id) DO NOTHING`. PLUS a
RETENTION INDEX (review note): `(connection_id, checked_at DESC, id DESC)` matching the prune's window
ORDER BY exactly, so the hourly ranking scan on this fastest-growing table is an ordered index scan
(no sort) — the mig-102 index `(connection_id, checked_at DESC)` is not exact for the `id DESC`
tiebreak.

## Tests
- Engine: `job_is_schedulable("connection_health_checks_prune")` true + the matrix/`_live` negatives.
- Scheduler (DB): the existing `prune_*` tests already cover the generalized helper's behavior via
  the `prune_job_executions` wrapper (newest-N, batch cap, tie-break, guard) — ADD one
  connection_health_checks-specific DB test: seed a connection + > keep checks (staggered checked_at)
  via `prune_history_newest_n(conn, "connection_health_checks", "connection_id", "checked_at", keep=3,
  cap=100)` → keeps the newest 3 per connection, a 2nd connection with ≤3 untouched. (Clear the table
  first for determinism, as with job_executions.)
- Scheduler (DB): `migration_132_is_idempotent` (re-run the seed → no-op; assert the seeded-row
  contract). NO index-dedup assertion (no index).
- Regression: the `prune_job_executions` wrapper still passes the existing 3 prune tests unchanged.

## Out of scope
- A configurable retention (env/config knob) — slice uses code constants, same as job_executions.
- Secret hygiene: the prune only DELETEs + reports a count; it never surfaces `message`/status.
