# #19 — Scheduled connection-health sweep

Status: design. Reuses the #40 durable-scheduler SAFE-INTERNAL-WRITE recipe
(it is #40 applied to integration connections instead of synthetic checks).

## Goal
On-demand connection health exists: a test-connection handler runs
`test_connection_stub(&conn)` (a DRY-RUN stub — no live provider call) and records
a `connection_health_checks` row; `integration_health_history` reads the series.
There is no PROACTIVE sweep, so the health history only has data when an operator
manually tests a connection. Add a scheduled `connection_health_sweep` that probes
every enabled connection on a cadence and records each result, so the health
dashboard/history stays fresh without manual probes.

## Why a durable-scheduler job (not a standalone spawn)
The durable scheduler is leader-elected (only one replica ticks), so connections
are probed once per cadence across the fleet — not once per replica. Connection
probing is exactly the kind of recurring fan-out where that matters. (The existing
standalone spawns — slo_breach/budget_breach/agent_offline — predate this and run
per-replica; the scheduler is the blessed #1 mechanism for new recurring work.)

## No dedup needed
Unlike #39/#44, this records a time series: every probe inserts a fresh
`connection_health_checks` row (the point is the history). So NO marker column, NO
claim — just list → probe → insert, exactly like #40's synthetic run.

## Engine
`scheduler.rs`: add `"connection_health_sweep"` to the explicit `job_is_schedulable`
allowlist (safe-internal write — `test_connection_stub` is a pure dry-run, the
insert writes only our own `connection_health_checks`; NO provider/live call). Test:
schedulable but NOT read_only.

## API `run_job` arm `"connection_health_sweep"` (ALL on the tick tx)
1. List ALL integration connections (codex fix: `integration_connections` has NO
   `enabled` column — do not invent a filter; probe every connection).
2. For each, run `test_connection_stub(&conn)` (pure dry-run) and insert a
   `connection_health_checks` row via a tx-aware repo fn (mirror the on-demand
   probe's INSERT, executor-generic so it runs on `&mut *tx`). credential_status:
   use a DETERMINISTIC STUB value (codex fix — do NOT call the live
   `resolve_credentials`; the safety argument is stub-only), e.g. the same
   ref-presence verdict the stub implies.
3. Also UPDATE the connection's `last_test_at` / `last_test_result` in the SAME tx
   (codex fix) — mirror the on-demand probe so the integrations list shows the
   scheduled freshness (the portal table reads those columns).
4. `detail` aggregate-only: `"probed N connection(s)"`.
A DB error rolls back within the schedule's savepoint (existing tick semantics).

## Migration 120
Seed one enabled `connection_health_sweep` schedule (every 300s — connection
freshness on a 5-min cadence; SLO/dashboards tolerate that), fixed id, ON CONFLICT
DO NOTHING. NO new index (codex: migration 102 already created
`idx_connection_health_checks_conn` on `(connection_id, checked_at DESC)`). No new
table or column.

## Scale (codex note)
Growth is ~`288 * connection_count` rows/day at the 300s cadence — fine for dozens
of connections. A retention/pruning policy for `connection_health_checks` is a
follow-up if connection cardinality ever grows to hundreds.

## Tests (new *_db_tests, serialized, cleanup)
1. Seed 2 connections and a guaranteed-due connection_health_sweep schedule; tick
   once → each connection gains a new connection_health_checks row AND its
   last_test_at/last_test_result are updated; detail matches exactly
   `probed <N> connection(s)`, no per-connection id leak.
2. A second tick adds another row per connection (time series grows — no dedup),
   proving it is not a one-shot.
3. Engine job_is_schedulable matrix (connection_health_sweep schedulable, not
   read_only); migration 120 idempotency.

## Files
- migrations/120_connection_health_sweep.sql (new)
- sources/ryuki-engine/src/scheduler.rs (allowlist + test)
- sources/ryuki-api/src/scheduler.rs (run_job arm + tests)
- sources/ryuki-api/src/repos or integration.rs (a tx-aware list-enabled +
  insert-health-check; reuse the on-demand probe's SQL).

## Out of scope (follow-ups)
- Emitting a domain event / alert on a health-status TRANSITION (healthy↔degraded)
  — this slice only records the series; transition alerting is a follow-up.
- Live (non-stub) probes — that is the live-execution lane (owner-domain).
- Per-connection probe cadence.
