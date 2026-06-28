//! Shared helpers for the standalone background loops (#26 follow-on).
//!
//! The durable scheduler (`scheduler.rs`) bounds every tick with a per-iteration
//! `tokio::time::timeout` so an application-level stall — one not caught by the
//! pool's per-statement `statement_timeout`/`lock_timeout` (#12) — cannot pin the
//! loop forever. The five older standalone loops (lease-expiry, agent-offline,
//! idempotency sweep, SLO-breach, budget-breach) predate that guard. These two
//! pure helpers + `run_bounded` extend the same defense-in-depth to all of them
//! without duplicating the timeout/backoff arithmetic in each loop.

use std::time::Duration;

/// Per-iteration timeout: 4x the interval, floor 300s — the same formula as
/// `spawn_scheduler`'s `tick_timeout` in `scheduler.rs`. Generous (>= 10x the 30s
/// statement timeout) so only a true application stall trips it, never a
/// legitimately long batch. `saturating_mul` keeps a pathological interval from
/// overflowing (real call sites pass small constants).
pub fn iteration_timeout(interval_secs: u64) -> Duration {
    Duration::from_secs(interval_secs.saturating_mul(4).max(300))
}

/// The #31 exponential-backoff schedule shared by every background loop:
/// 0 failures -> 0 extra intervals, then 1, 3, 7, 15, 15... (capped at 2^4-1).
pub fn loop_backoff(consecutive_failures: u32) -> u64 {
    (1u64 << consecutive_failures.min(4)) - 1
}

/// Record ONE iteration failure (a returned error OR a timeout — they are treated
/// identically for backoff): increment the counter (saturating) and return the
/// backoff intervals to sleep. Both the `Failed` and `TimedOut` arms of every loop
/// call this, so the rule "a timeout advances backoff exactly like an error" is
/// captured in ONE unit-tested place. Returns `loop_backoff(*consecutive_failures)`
/// AFTER the increment.
pub fn note_failure(consecutive_failures: &mut u32) -> u64 {
    *consecutive_failures = consecutive_failures.saturating_add(1);
    loop_backoff(*consecutive_failures)
}

/// Outcome of one bounded iteration. A timeout is a FAILURE for backoff, logged
/// distinctly from a returned error.
pub enum IterError<E> {
    /// The work future completed but returned an error.
    Failed(E),
    /// The work future overran the per-iteration timeout and was dropped.
    TimedOut,
}

/// Run one iteration under `timeout`. Returns the work's value on completion, the
/// inner error as `Failed`, or `TimedOut` if it overran (the future is dropped).
///
/// SAFETY: dropping the future cancels it at the current await point — rolling back
/// the IN-FLIGHT transaction IFF it had not yet committed. A drop during
/// `tx.commit()` leaves the commit outcome unknown, and a work fn that uses MULTIPLE
/// transactions keeps its already-committed ones. This is safe ONLY because every
/// one of the 5 work fns is RETRY-IDEMPOTENT (they are recurring scans designed to
/// be re-run): `expire_leases` (single tx; re-running re-claims the same expired
/// leases), `agent_offline_scan_once` (per-agent tx, deduped by the
/// `offline_alerted` flag so a re-run never double-emits), `sweep_expired_records`
/// (idempotent DELETE of expired idempotency rows), `slo_breach_scan_once` /
/// `budget_breach_scan_once` (breach events deduped by the same `to_status`/marker
/// pattern as the other scans). So a partial-then-cancelled iteration is simply
/// re-done next tick with no double-effect.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn run_bounded_ok_passes_value_through() {
        let out = run_bounded(Duration::from_secs(10), async { Ok::<_, &str>(42) }).await;
        assert!(matches!(out, Ok(42)));
    }

    #[tokio::test(start_paused = true)]
    async fn run_bounded_err_maps_to_failed() {
        let out = run_bounded(Duration::from_secs(10), async { Err::<u8, _>("boom") }).await;
        assert!(matches!(out, Err(IterError::Failed("boom"))));
    }

    #[tokio::test(start_paused = true)]
    async fn run_bounded_overrun_maps_to_timed_out() {
        // The work sleeps PAST the timeout. With a paused clock, the timeout fires
        // in virtual time — no real wall sleep.
        let out = run_bounded(Duration::from_secs(10), async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok::<_, &str>(1)
        })
        .await;
        assert!(matches!(out, Err(IterError::<&str>::TimedOut)));
    }

    #[test]
    fn note_failure_advances_backoff_like_an_error() {
        let mut failures: u32 = 0;
        // Successive failures return 1, 3, 7, 15, 15 and advance the counter.
        assert_eq!(note_failure(&mut failures), 1);
        assert_eq!(failures, 1);
        assert_eq!(note_failure(&mut failures), 3);
        assert_eq!(failures, 2);
        assert_eq!(note_failure(&mut failures), 7);
        assert_eq!(failures, 3);
        assert_eq!(note_failure(&mut failures), 15);
        assert_eq!(failures, 4);
        assert_eq!(note_failure(&mut failures), 15);
        assert_eq!(failures, 5);
    }

    #[test]
    fn note_failure_saturates_without_panic() {
        let mut failures: u32 = u32::MAX;
        // saturating_add at the ceiling must not overflow/panic.
        assert_eq!(note_failure(&mut failures), 15);
        assert_eq!(failures, u32::MAX);
    }

    #[test]
    fn loop_backoff_matches_the_capped_schedule() {
        assert_eq!(loop_backoff(0), 0);
        assert_eq!(loop_backoff(1), 1);
        assert_eq!(loop_backoff(2), 3);
        assert_eq!(loop_backoff(3), 7);
        assert_eq!(loop_backoff(4), 15);
        assert_eq!(loop_backoff(5), 15);
        assert_eq!(loop_backoff(99), 15);
    }

    #[test]
    fn iteration_timeout_floors_then_scales() {
        assert_eq!(iteration_timeout(30), Duration::from_secs(300));
        assert_eq!(iteration_timeout(100), Duration::from_secs(400));
        // The saturating_mul guard does not overflow at the ceiling.
        assert_eq!(iteration_timeout(u64::MAX), Duration::from_secs(u64::MAX));
    }
}
