//! Shared helpers for the standalone background loops (#26 follow-on).
//!
//! The durable scheduler (`scheduler.rs`) bounds every tick with a per-iteration
//! `tokio::time::timeout` so an application-level stall — one not caught by the
//! pool's per-statement `statement_timeout`/`lock_timeout` (#12) — cannot pin the
//! loop forever. The five older standalone loops (lease-expiry, agent-offline,
//! idempotency sweep, SLO-breach, budget-breach) predate that guard. These two
//! pure helpers + `run_bounded` extend the same defense-in-depth to all of them
//! without duplicating the timeout/backoff arithmetic in each loop.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant};

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

// ---------------------------------------------------------------------------
// Heartbeat registry — per-loop last-success liveness for platform_self_health.
// ---------------------------------------------------------------------------

/// One registered loop's heartbeat state. `last_success` is a monotonic
/// `Instant` (immune to wall-clock jumps), refreshed on each successful
/// iteration; `interval_secs` is the loop's cadence, used to derive the
/// timeout-and-backoff-aware silence budget.
struct LoopHeartbeat {
    interval_secs: u64,
    last_success: Instant,
}

/// Process-global registry of each background loop's last successful iteration.
/// Best-effort heartbeats: a poisoned lock must never crash the health handler,
/// so all access goes through `lock_or_recover`. Guarded by a `std::sync::Mutex`
/// (never held across an await — all registry fns are synchronous).
static LOOP_HEARTBEATS: LazyLock<Mutex<HashMap<&'static str, LoopHeartbeat>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// A snapshot of one loop's liveness for the pure classifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopLiveness {
    pub name: &'static str,
    pub interval_secs: u64,
    pub age_secs: u64,
}

/// Acquire a mutex guard, recovering from poisoning instead of panicking. These
/// heartbeats are best-effort; a poisoned lock (from a panic elsewhere) must
/// never cascade into a health-handler outage. Mirrors `main.rs:lock_or_recover`.
fn lock_or_recover<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Register a loop at spawn with its cadence. Seeds `last_success = now()` as the
/// baseline, so a loop that NEVER completes a first iteration goes overdue once
/// it passes the timeout-aware threshold (no separate "never ran" state needed).
/// Call as the FIRST statement of the spawned future, before any await.
pub fn register_loop(name: &'static str, interval_secs: u64) {
    let mut map = lock_or_recover(&LOOP_HEARTBEATS);
    map.insert(
        name,
        LoopHeartbeat {
            interval_secs,
            last_success: Instant::now(),
        },
    );
}

/// Stamp a successful iteration (called in each loop's Ok arm). `register_loop`
/// is the sole owner of a loop's cadence and always runs FIRST (the first
/// statement of the spawned future), so the entry exists. If it is somehow
/// missing (a `record` before `register` — a programming error), this is a no-op
/// rather than inserting a cadence-less (`interval=0`) entry that would carry a
/// wrong silence budget.
pub fn record_loop_success(name: &'static str) {
    let mut map = lock_or_recover(&LOOP_HEARTBEATS);
    if let Some(hb) = map.get_mut(name) {
        hb.last_success = Instant::now();
    }
}

/// Snapshot for the probe: `(name, interval_secs, age_secs)` per loop, where
/// `age_secs = last_success.elapsed().as_secs()` computed under the lock. Copies
/// every entry into the returned `Vec` and DROPS the lock before returning, so
/// the (pure) classifier never runs while holding the mutex.
pub fn loop_liveness() -> Vec<LoopLiveness> {
    let map = lock_or_recover(&LOOP_HEARTBEATS);
    map.iter()
        .map(|(name, hb)| LoopLiveness {
            name,
            interval_secs: hb.interval_secs,
            age_secs: hb.last_success.elapsed().as_secs(),
        })
        .collect()
    // guard dropped here, before classify_loop_liveness runs
}

/// Pure verdict: a loop is overdue when
/// `age_secs > 2*iteration_timeout(interval) + 2*interval` (all saturating) —
/// two full timed iterations plus the inter-attempt waits, so one slow/timed-out
/// iteration plus a backoff retry never false-positives. ANY overdue loop ⇒
/// `down` (a persistently-wedged loop is page-worthy on this status endpoint);
/// `healthy` when none overdue; `degraded` only when no loops are registered
/// (informational). The `down` detail NAMES each overdue loop (sorted) with its
/// age + threshold, so the aggregate probe is actionable.
pub fn classify_loop_liveness(
    entries: &[LoopLiveness],
) -> ryuki_engine::self_health::DependencyProbe {
    use ryuki_engine::self_health::DependencyProbe;
    if entries.is_empty() {
        return DependencyProbe::degraded("background_loops", "no background loops registered");
    }
    let mut overdue: Vec<(&'static str, u64, u64)> = entries
        .iter()
        .filter_map(|e| {
            let threshold = 2u64
                .saturating_mul(iteration_timeout(e.interval_secs).as_secs())
                .saturating_add(2u64.saturating_mul(e.interval_secs));
            if e.age_secs > threshold {
                Some((e.name, e.age_secs, threshold))
            } else {
                None
            }
        })
        .collect();
    if overdue.is_empty() {
        return DependencyProbe::healthy("background_loops");
    }
    overdue.sort_by(|a, b| a.0.cmp(b.0));
    let detail = overdue
        .iter()
        .map(|(name, age, threshold)| format!("{name} (age {age}s > threshold {threshold}s)"))
        .collect::<Vec<_>>()
        .join(", ");
    DependencyProbe::down(
        "background_loops",
        format!("{} background loop(s) wedged: {detail}", overdue.len()),
    )
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

    use ryuki_engine::self_health::DependencyHealth;

    fn entry(name: &'static str, interval_secs: u64, age_secs: u64) -> LoopLiveness {
        LoopLiveness {
            name,
            interval_secs,
            age_secs,
        }
    }

    /// `2*iteration_timeout(interval) + 2*interval` — the silence budget the
    /// classifier compares against. Pinned here independently so a regression in
    /// the formula is caught, not silently mirrored.
    fn threshold(interval_secs: u64) -> u64 {
        2 * iteration_timeout(interval_secs).as_secs() + 2 * interval_secs
    }

    #[test]
    fn classify_empty_is_degraded() {
        let probe = classify_loop_liveness(&[]);
        assert_eq!(probe.health, DependencyHealth::Degraded);
        assert_eq!(probe.name, "background_loops");
    }

    #[test]
    fn classify_all_fresh_is_healthy() {
        let entries = [entry("a", 30, 0), entry("b", 3600, 10)];
        let probe = classify_loop_liveness(&entries);
        assert_eq!(probe.health, DependencyHealth::Healthy);
        assert_eq!(probe.name, "background_loops");
        assert_eq!(probe.detail, None);
    }

    #[test]
    fn classify_one_overdue_is_down_and_names_the_loop() {
        let entries = [
            entry("fresh_loop", 30, 0),
            entry("wedged_loop", 30, threshold(30) + 1),
        ];
        let probe = classify_loop_liveness(&entries);
        assert_eq!(probe.health, DependencyHealth::Down);
        let detail = probe.detail.expect("down probe must carry a detail");
        assert!(detail.contains("wedged_loop"), "detail: {detail}");
        assert!(!detail.contains("fresh_loop"), "detail: {detail}");
        // The detail must be ACTIONABLE: the overdue count PREFIX and the
        // age/threshold numbers, not just the name. Pin "1 background loop"
        // specifically (a bare '1' would also match the age digits).
        assert!(
            detail.contains("1 background loop"),
            "detail names the overdue count: {detail}"
        );
        assert!(
            detail.contains("threshold"),
            "detail names the threshold: {detail}"
        );
    }

    #[test]
    fn classify_multiple_overdue_are_sorted_by_name() {
        let entries = [
            entry("zeta", 30, threshold(30) + 1),
            entry("alpha", 30, threshold(30) + 1),
        ];
        let probe = classify_loop_liveness(&entries);
        assert_eq!(probe.health, DependencyHealth::Down);
        let detail = probe.detail.expect("down probe must carry a detail");
        let alpha = detail.find("alpha").expect("alpha named");
        let zeta = detail.find("zeta").expect("zeta named");
        assert!(alpha < zeta, "overdue loops must be sorted: {detail}");
    }

    #[test]
    fn classify_boundary_interval_30_exact_is_healthy_plus_one_is_down() {
        // interval 30 ⇒ 2*300 + 60 = 660s.
        assert_eq!(threshold(30), 660);
        let at = [entry("loop30", 30, threshold(30))];
        assert_eq!(
            classify_loop_liveness(&at).health,
            DependencyHealth::Healthy,
            "exactly at threshold ⇒ healthy (strict >)"
        );
        let over = [entry("loop30", 30, threshold(30) + 1)];
        assert_eq!(classify_loop_liveness(&over).health, DependencyHealth::Down);
    }

    #[test]
    fn classify_boundary_interval_3600_exact_is_healthy_plus_one_is_down() {
        // interval 3600 ⇒ 2*14400 + 7200 = 36000s.
        assert_eq!(threshold(3600), 36000);
        let at = [entry("loop3600", 3600, threshold(3600))];
        assert_eq!(
            classify_loop_liveness(&at).health,
            DependencyHealth::Healthy,
            "exactly at threshold ⇒ healthy (strict >)"
        );
        let over = [entry("loop3600", 3600, threshold(3600) + 1)];
        assert_eq!(classify_loop_liveness(&over).health, DependencyHealth::Down);
    }

    #[test]
    fn registry_round_trip_records_a_fresh_loop_with_tiny_age() {
        // Unique name avoids cross-test contention on the process-global static.
        let name: &'static str =
            Box::leak(format!("test-loop-{}", uuid::Uuid::new_v4()).into_boxed_str());
        register_loop(name, 10);
        record_loop_success(name);
        let snapshot = loop_liveness();
        let mine = snapshot
            .iter()
            .find(|e| e.name == name)
            .expect("registered loop must appear in the snapshot");
        assert_eq!(mine.interval_secs, 10);
        // Freshly recorded ⇒ effectively zero age (well under the budget).
        assert!(mine.age_secs <= 1, "age_secs was {}", mine.age_secs);
    }

    #[test]
    fn register_only_loop_is_fresh_and_healthy_on_its_baseline() {
        // Pins the baseline-at-register design (no separate "never ran" state): a
        // just-registered loop with NO success yet has a tiny age and classifies
        // Healthy on its register-time baseline — not a false positive before its
        // first iteration.
        let name: &'static str =
            Box::leak(format!("test-loop-baseline-{}", uuid::Uuid::new_v4()).into_boxed_str());
        register_loop(name, 30);
        // No record_loop_success — only the register baseline.
        let snapshot = loop_liveness();
        let mine = snapshot
            .iter()
            .find(|e| e.name == name)
            .expect("registered loop appears even without a success yet");
        assert_eq!(mine.interval_secs, 30);
        assert!(mine.age_secs <= 1, "baseline age was {}", mine.age_secs);
        assert_eq!(
            classify_loop_liveness(std::slice::from_ref(mine)).health,
            DependencyHealth::Healthy,
            "a just-registered loop must not be a false-positive overdue"
        );
    }
}
