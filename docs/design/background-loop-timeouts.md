# Background-loop per-iteration timeouts (swarm follow-on to #26)

Status: design — plan-review round 1 NEEDS-CHANGES, all fixed below. Found by
the fresh missing-feature swarm. Review fixes: (major) weakened the
cancellation-rollback claim + asserted all 5 work fns are retry-idempotent; (major)
added a unit-tested `note_failure` helper so "a timeout advances backoff like an
error" is tested, not untested glue; (minor) `MissedTickBehavior::Skip` on all 5
loops to avoid post-backoff catch-up bursts.

## Goal
The durable scheduler bounds every tick with a per-iteration `tokio::time::timeout`
(`scheduler.rs:567`, swarm #26): a tick that escapes the DB-level statement/lock
timeouts (#12) via an application-level stall is aborted and retried, never
starving the loop. The FIVE older standalone background loops never got that
guard — verified zero `tokio::time::timeout` in `spawn_lease_expiry_sweep`,
`spawn_agent_offline_scan` (agents.rs), `spawn_idempotency_sweep` (idempotency.rs),
`spawn_slo_breach_scan`, `spawn_budget_breach_scan` (contracts.rs). A wedged
iteration in any of them (a hang not bounded by the 30s `statement_timeout` — e.g.
a connection-acquire stall, or many statements) pins that loop forever.

Extend the scheduler's per-iteration timeout guard to all 5 loops, consistently.

## Why still needed despite the pool statement timeout (#12)
The pool sets `statement_timeout=30s` + `lock_timeout=10s` on every connection, so a
single hung SQL statement IS bounded. But that is per-STATEMENT, not per-ITERATION:
a loop body runs several statements and can stall in connection acquisition or
application code between them. The scheduler added the tokio timeout precisely as
this application-level backstop; the 5 standalone loops are the lone gap. This is
defense-in-depth + consistency, not a duplicate of #12.

## Design — two PURE, tested helpers (new `sources/ryuki-api/src/background.rs`)
All 5 loops already share the same shape: an `interval` ticker + a `match
work(&pool).await { Ok => reset, Err => #31 exponential backoff }`. Rather than
duplicate the timeout 5× (or force a generic loop helper that would drop the
per-loop `Ok`-side `emitted` logging that 3 of the 5 do), extract the two pieces
that are worth testing ONCE:

```rust
/// Per-iteration timeout: 4× the interval, floor 300s — the scheduler's guard
/// (scheduler.rs:560). Generous (≥10× the 30s statement timeout) so only a true
/// application stall trips it, never a legitimately long batch.
pub fn iteration_timeout(interval_secs: u64) -> Duration {
    Duration::from_secs(interval_secs.saturating_mul(4).max(300))
}

/// The #31 exponential-backoff schedule shared by every background loop:
/// 0 failures → 0 extra intervals, then 1, 3, 7, 15, 15… (capped at 2^4−1).
pub fn loop_backoff(consecutive_failures: u32) -> u64 {
    (1u64 << consecutive_failures.min(4)) - 1
}

/// Record ONE iteration failure (a returned error OR a timeout — they are treated
/// identically for backoff): increment the counter (saturating) and return the
/// backoff intervals to sleep. Both the `Failed` and `TimedOut` arms of every loop
/// call this, so the rule "a timeout advances backoff exactly like an error" is
/// captured in ONE unit-tested place (review note — the per-loop glue is otherwise
/// untested). Returns `loop_backoff(*consecutive_failures)` AFTER the increment.
pub fn note_failure(consecutive_failures: &mut u32) -> u64 {
    *consecutive_failures = consecutive_failures.saturating_add(1);
    loop_backoff(*consecutive_failures)
}

/// Outcome of one bounded iteration. A timeout is a FAILURE for backoff, logged
/// distinctly from a returned error.
pub enum IterError<E> { Failed(E), TimedOut }

/// Run one iteration under `timeout`. Returns the work's value on completion, the
/// inner error as `Failed`, or `TimedOut` if it overran (the future is dropped).
/// SAFETY (review note): dropping the future cancels it at the current await point —
/// rolling back the IN-FLIGHT transaction IFF it had not yet committed. A drop
/// during `tx.commit()` leaves the commit outcome unknown, and a work fn that uses
/// MULTIPLE transactions keeps its already-committed ones. This is safe ONLY
/// because every one of the 5 work fns is RETRY-IDEMPOTENT (they are recurring
/// scans designed to be re-run): expire_leases (single tx; re-running re-claims
/// the same expired leases), agent_offline_scan_once (per-agent tx, deduped by the
/// `offline_alerted` flag so a re-run never double-emits), sweep_expired_records
/// (idempotent DELETE of expired idempotency rows), slo_breach_scan_once /
/// budget_breach_scan_once (breach events deduped by the same to_status/marker
/// pattern as the other scans). So a partial-then-cancelled iteration is simply
/// re-done next tick with no double-effect. (Verified at implementation: confirm
/// none of the 5 has a non-transactional side effect — e.g. an in-memory mutation
/// or external call — that a mid-drop would leave inconsistent.)
pub async fn run_bounded<T, E>(
    timeout: Duration,
    fut: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, IterError<E>> {
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(IterError::Failed(e)),
        Err(_elapsed) => Err(IterError::TimedOut),
    }
}
```
Register `mod background;` in `main.rs`.

## Each of the 5 loops (minimal, behavior-preserving)
Compute `let timeout = background::iteration_timeout(interval_secs);` once, then:
```rust
match background::run_bounded(timeout, work(&pool)).await {
    Ok(value) => { /* EXACT existing Ok branch — reset counter; loops that log
                      `emitted > 0` keep doing so with `value` */ }
    Err(err) => {
        let backoff = background::note_failure(&mut consecutive_failures);
        match err {
            background::IterError::Failed(e) =>
                tracing::error!(error = %e, consecutive_failures, backoff_intervals = backoff,
                                "<loop> failed; backing off"),
            background::IterError::TimedOut =>
                tracing::error!(timeout_secs = timeout.as_secs(), consecutive_failures,
                                backoff_intervals = backoff,
                                "<loop> exceeded its iteration timeout; backing off"),
        }
        tokio::time::sleep(Duration::from_secs(interval_secs.saturating_mul(backoff))).await;
    }
}
```
The `Ok` arm is byte-for-byte each loop's current success behavior (preserving the
`emitted` logs and resetting `consecutive_failures = 0`). Both `Err` variants route
through `note_failure` (so a timeout advances backoff EXACTLY like a returned
error — verified by `note_failure`'s unit test, not untested per-loop glue), with a
distinct log line. `note_failure`/`loop_backoff` replace each loop's inline
`(1 << min(4)) - 1` (one tested schedule).

### MissedTickBehavior::Skip on ALL 5 (review minor)
The scheduler sets `ticker.set_missed_tick_behavior(Skip)`; `agent_offline`,
`slo_breach`, `budget_breach` already do, but `spawn_lease_expiry_sweep` and
`spawn_idempotency_sweep` do NOT — so after a long backoff/timeout the default
`Burst` would fire catch-up ticks. Add `Skip` to those two (and confirm the other
three) so a recovered loop resumes on the next aligned boundary, not a burst —
matching the scheduler.

## Tests (unit, in `background.rs` — NO DB, fully CI-verifiable)
1. `run_bounded` — a fast `Ok` future → `Ok(value)`; an `Err` future →
   `IterError::Failed`; a future that sleeps PAST the timeout → `IterError::TimedOut`
   (use `#[tokio::test(start_paused = true)]` + `tokio::time::sleep` longer than the
   timeout for deterministic, instant virtual-time timeout — no real wall sleep).
2. `note_failure` — drives the "timeout counts as a failure" rule: starting
   from 0, successive calls return `1, 3, 7, 15, 15` and leave the counter at
   `1, 2, 3, 4, 5`; saturates (no overflow) at `u32::MAX`. Both loop `Err` arms call
   this, so a `TimedOut` advancing backoff identically to a `Failed` is covered here
   rather than in untested per-loop glue.
3. `loop_backoff` — the exact schedule: 0→0, 1→1, 2→3, 3→7, 4→15, 5→15, 99→15.
4. `iteration_timeout` — `iteration_timeout(30)==300` (floor), `iteration_timeout(100)==400` (4×).

The new behavior — a hung iteration is detected (`run_bounded`→`TimedOut`, test 1)
and advances the same backoff as an error (`note_failure`, test 2) — is the
COMPOSITION of two tested units; the per-loop wiring is thin glue that calls both.

## Files
- sources/ryuki-api/src/background.rs (new — 3 fns + IterError + unit tests)
- sources/ryuki-api/src/main.rs (`mod background;`)
- sources/ryuki-api/src/agents.rs (spawn_lease_expiry_sweep, spawn_agent_offline_scan)
- sources/ryuki-api/src/idempotency.rs (spawn_idempotency_sweep)
- sources/ryuki-api/src/contracts.rs (spawn_slo_breach_scan, spawn_budget_breach_scan)

## Out of scope (follow-ups — also swarm findings)
- Background-loop LIVENESS in `platform_self_health` (last-success timestamp per
  loop + an overdue probe) — swarm rank #3/#5; a natural next slice on top of this.
- Migrating the 5 loops onto the durable scheduler (they predate it; a larger
  refactor).
