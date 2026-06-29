# Background-loop liveness in platform_self_health (swarm follow-on)

Status: design — codex plan-review round 1 NEEDS-CHANGES, all fixed below. Builds on
the background-loop timeout slice (background.rs). Fresh-swarm rank #3/#5.
Codex fixes (2 rounds): (blocker) timeout-AND-backoff-aware threshold
`2*iteration_timeout(interval) + 2*interval` — a 2x-interval (and even a bare
2*timeout) budget false-positived on a slow timed iteration + a backoff retry;
(major) `down` justified by the actual contract (platform_self_health is the
status/monitoring endpoint, NOT the k8s gate at /healthz,/readyz — so down is a page,
not a drain); (minor) lock never held across await + poison-tolerant lock; (minor)
the down detail names the overdue loops (sorted); (nit) saturating threshold math.

## Goal
`platform_self_health` probes database, migrations, and SCHEDULER liveness (an
enabled schedule overdue past 2x its interval ⇒ down), but NOT the 5 standalone
background loops (lease_expiry/idempotency/slo_breach/budget_breach/agent_offline).
Now that those loops are timeout-bounded + backoff-driven (the prior slice), a loop
that wedges (every iteration timing out / erroring past its backoff, or a panic
that killed the task) is invisible to operators. Add a per-loop last-success
heartbeat + a `background_loops` probe in `platform_self_health`, mirroring the
scheduler probe's overdue-heartbeat APPROACH but with a timeout-aware threshold
(these loops are timeout-bounded, so a bare 2x-interval rule would false-positive —
see Pure verdict).

## Heartbeat registry (`sources/ryuki-api/src/background.rs`)
A process-global registry of each loop's last successful iteration:
```rust
struct LoopHeartbeat { interval_secs: u64, last_success: Instant }
static LOOP_HEARTBEATS: Mutex<HashMap<&'static str, LoopHeartbeat>> = ...;

/// Register a loop at spawn with its cadence. Seeds last_success = now() as the
/// baseline, so a loop that NEVER completes a first iteration goes overdue once it
/// passes the timeout-aware threshold below (no separate "never ran" state needed).
pub fn register_loop(name: &'static str, interval_secs: u64);

/// Stamp a successful iteration (called in each loop's Ok arm).
pub fn record_loop_success(name: &'static str);

/// Snapshot for the probe: (name, interval_secs, age_secs) per loop, where
/// age_secs = last_success.elapsed().as_secs() computed at call time.
pub fn loop_liveness() -> Vec<LoopLiveness>;   // LoopLiveness { name, interval_secs, age_secs }
```
LOCK HYGIENE (codex minor): the registry is a `std::sync::Mutex<HashMap<...>>` in a
`LazyLock`. All three fns are SYNCHRONOUS and never hold the guard across an
`.await` — `loop_liveness()` copies each entry into the returned `Vec` while holding
the lock, then DROPS the lock before the (pure) classifier runs. Use the existing
poison-tolerant `lock_or_recover` (main.rs:1143) — or an equivalent local helper —
instead of `.unwrap()` on a poisoned lock (these are best-effort heartbeats; a
poisoned lock must not crash the health handler). `Instant` (monotonic) is the
clock — immune to wall-clock jumps.

Why baseline-at-register: avoids a "NeverRan" special case. A healthy loop refreshes
`last_success` each iteration; a wedged or never-started loop's age grows past the
timeout-aware threshold and trips the probe. (The ticker skips the immediate first
tick, so the first real success lands ~1 interval in — far within the budget.)
register_loop runs as the FIRST statement of the spawned future (before any await)
so the baseline is set the instant the task starts.

## Pure verdict (`background.rs`, mirrors classify_scheduler_liveness)
THRESHOLD (codex blocker fix): a 2x-INTERVAL budget is WRONG — the loop work is
timeout-bounded at `iteration_timeout(interval) = max(4*interval, 300s)`, so a
legitimately-slow iteration (the loop blocks in `work.await` for up to that timeout,
recording nothing) plus the interval wait can exceed 2x interval and falsely report
`down`. The silence budget must be TIMEOUT-AND-BACKOFF-aware (codex round 2): one slow
iteration can consume the full `iteration_timeout` (T), then the loop sleeps a
backoff (≥ 1 interval I) and the retry can consume another T before recording
success — a legitimately-healthy silence of up to ~`2T + 2I`. So:
```
overdue_secs(interval) = 2 * iteration_timeout(interval).as_secs()
                         + 2 * interval_secs                      // all saturating
```
i.e. two full timed iterations plus the inter-attempt waits. This never
false-positives on one timed-out iteration + a retry, and a loop that REPEATEDLY
times out (a real wedge) still crosses it within a few cycles. Detection lag scales
with the loop's own timeout (≈11 min for the 30s loops, ~10 h for the 3600s
idempotency sweep) — the deliberate price of zero false 503s on a status endpoint.
```rust
/// Pure: a loop is overdue when age_secs > 2*iteration_timeout(interval) + 2*interval.
/// ANY overdue loop ⇒ down (a persistently-wedged loop is page-worthy). `healthy`
/// when none overdue; `degraded` only when no loops are registered (informational).
/// The `down` detail NAMES each overdue loop with its age + threshold (sorted),
/// so the aggregate probe is actionable.
pub fn classify_loop_liveness(entries: &[LoopLiveness]) -> ryuki_engine::self_health::DependencyProbe;
```
SEVERITY = `down` (codex major — justified, not parity-only): `platform_self_health`
is the dependency/STATUS endpoint (`GET /api/platform/.../dependencies`), NOT the
k8s gate — the k8s liveness/readiness probes hit `/healthz` + `/readyz` (the basic
`health` fn), per deploy/kubernetes/base/deployments.yaml. So a loop `down` makes
this monitoring endpoint 503 — a page-worthy signal (Prometheus/alerting), exactly
like the scheduler probe — and does NOT drain/restart the replica. A real wedge
(past 2 full timed iterations) warrants paging; `down` here is safe + consistent.

## Wire the 5 loops (`agents.rs`, `idempotency.rs`, `contracts.rs`)
Each loop's spawn fn: call `background::register_loop(NAME, interval_secs)` once
BEFORE the loop, and `background::record_loop_success(NAME)` in the Ok arm (right
where it resets `consecutive_failures = 0`). `NAME` is a per-loop `&'static str`
const matching the loop (e.g. `"lease_expiry_sweep"`, `"idempotency_sweep"`,
`"slo_breach_scan"`, `"budget_breach_scan"`, `"agent_offline_scan"`). The Ok-side
`emitted` logging is unchanged.

## Probe in `platform_self_health` (`main.rs`)
After the scheduler probe, add:
```rust
// 4. Background-loop liveness — in-memory heartbeats, no DB needed.
probes.push(crate::background::classify_loop_liveness(&crate::background::loop_liveness()));
```
A `down` loop probe makes `aggregate(&probes)` non-serving ⇒ 503, exactly like a
down scheduler. No DB dependency (the registry is in-memory), so it works even when
the DB is down (and the DB probe already covers that case separately).

## Tests
- `classify_loop_liveness` (pure, no registry, no DB): empty ⇒ degraded; all ages
  ≤ threshold ⇒ healthy; one age > threshold ⇒ down AND the down detail NAMES the
  overdue loop (codex minor — assert the name + that it is sorted/deterministic when
  multiple overdue); boundary at `2*iteration_timeout(interval) + 2*interval`
  exactly ⇒ healthy, `+1` ⇒ down (mirrors the scheduler's strict `>` semantics).
  Cover a small interval (30 ⇒ 2*300+60 = 660s) and the long one (3600 ⇒
  2*14400+7200 = 36000s) so the timeout-and-backoff-aware formula is pinned, not a
  bare 2x interval.
- Registry round-trip (unique test loop name to avoid cross-test static
  contention): `register_loop("test-loop-<uuid>", 10)` then `record_loop_success`
  → `loop_liveness()` contains the entry with a small age (≈0); a registered-but-
  not-recorded loop has age ≈ since-register (small, not overdue).
- (no platform_self_health integration unit test — the registry is only populated
  when the real loops spawn; the pure classifier + round-trip cover the logic.)

## Files
- sources/ryuki-api/src/background.rs (registry + register_loop/record_loop_success/
  loop_liveness/classify_loop_liveness + LoopLiveness + tests)
- sources/ryuki-api/src/agents.rs (2 loops: register + record_loop_success)
- sources/ryuki-api/src/idempotency.rs (1 loop)
- sources/ryuki-api/src/contracts.rs (2 loops)
- sources/ryuki-api/src/main.rs (the 4th probe in platform_self_health)
- NO migration, NO engine change (DependencyProbe reused).

## Out of scope (follow-ups)
- ~~A per-loop breakdown in the health JSON~~ SHIPPED — `GET
  /api/platform/health/loops` (see loop-liveness-breakdown.md): per-loop name /
  interval / age / threshold / overdue, sharing the extracted `loop_overdue_threshold`
  with this aggregate so the two never drift.
- Persisting heartbeats to the DB for cross-replica visibility (in-memory is the
  right scope — each replica reports its OWN loops' health).
