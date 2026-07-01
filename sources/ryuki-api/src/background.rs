//! Shared helpers for the standalone background loops (#26 follow-on).
//!
//! The durable scheduler (`scheduler.rs`) bounds every tick with a per-iteration
//! `tokio::time::timeout` so an application-level stall — one not caught by the
//! pool's per-statement `statement_timeout`/`lock_timeout` (#12) — cannot pin the
//! loop forever. The five older standalone loops (lease-expiry, agent-offline,
//! idempotency sweep, SLO-breach, budget-breach) predate that guard. These two
//! pure helpers + `run_bounded` extend the same defense-in-depth to all of them
//! without duplicating the timeout/backoff arithmetic in each loop.

use serde::Serialize;
use sqlx::PgPool;
use std::collections::{BTreeSet, HashMap};
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::time::{interval, MissedTickBehavior};

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

/// Silence budget: a loop is overdue once `age_secs` EXCEEDS this — two full timed
/// iterations plus the inter-attempt waits (`2*iteration_timeout(interval) +
/// 2*interval`, all saturating), so one slow/timed-out iteration plus a backoff
/// retry never false-positives. The SINGLE source of truth shared by
/// `classify_loop_liveness` (aggregate) and `loop_status_report` (per-loop), so the
/// two views cannot drift.
pub fn loop_overdue_threshold(interval_secs: u64) -> u64 {
    2u64.saturating_mul(iteration_timeout(interval_secs).as_secs())
        .saturating_add(2u64.saturating_mul(interval_secs))
}

/// Pure verdict: ANY overdue loop ⇒ `down` (a persistently-wedged loop is
/// page-worthy on this status endpoint); `healthy` when none overdue; `degraded`
/// only when no loops are registered (informational). The `down` detail NAMES each
/// overdue loop (sorted) with its age + threshold, so the aggregate probe is
/// actionable.
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
            let threshold = loop_overdue_threshold(e.interval_secs);
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

/// One loop's per-loop status for the `/api/platform/health/loops` breakdown.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LoopStatus {
    pub name: &'static str,
    pub interval_secs: u64,
    pub age_secs: u64,
    pub threshold_secs: u64,
    pub overdue: bool,
}

/// Per-loop breakdown (pure): each snapshot mapped to its silence budget + overdue
/// verdict, sorted by name for a stable response. Uses the SAME
/// `loop_overdue_threshold` + `age > threshold` rule as `classify_loop_liveness`, so
/// the per-loop view and the aggregate always agree.
pub fn loop_status_report(entries: &[LoopLiveness]) -> Vec<LoopStatus> {
    let mut report: Vec<LoopStatus> = entries
        .iter()
        .map(|e| {
            let threshold = loop_overdue_threshold(e.interval_secs);
            LoopStatus {
                name: e.name,
                interval_secs: e.interval_secs,
                age_secs: e.age_secs,
                threshold_secs: threshold,
                overdue: e.age_secs > threshold,
            }
        })
        .collect();
    report.sort_by(|a, b| a.name.cmp(b.name));
    report
}

/// Aggregate verdict derived from the per-loop breakdown — kept consistent with
/// `classify_loop_liveness`: no loops ⇒ `degraded`; any overdue ⇒ `down`; else
/// `healthy`.
pub fn loop_overall_status(report: &[LoopStatus]) -> &'static str {
    if report.is_empty() {
        "degraded"
    } else if report.iter().any(|l| l.overdue) {
        "down"
    } else {
        "healthy"
    }
}

/// Build the `(http_status, body)` for the loops endpoint as a PURE fn, so the
/// 200/503 mapping is deterministically testable WITHOUT the process-global
/// registry. Alerting-safe + consistent with the sibling `/dependencies` probe: a
/// wedged loop ⇒ 503, else 200. The body always carries the full breakdown.
pub fn loop_liveness_payload(report: Vec<LoopStatus>) -> (u16, serde_json::Value) {
    let overall = loop_overall_status(&report);
    let overdue = report.iter().filter(|l| l.overdue).count();
    let code = if overall == "down" { 503 } else { 200 };
    (
        code,
        serde_json::json!({
            "loops": report,
            "overall": overall,
            "overdue_count": overdue,
            "registered_count": report.len(),
        }),
    )
}

// ---------------------------------------------------------------------------
// Wedge alerting — edge-triggered `background_loop.overdue` domain events.
//
// The health probe (`classify_loop_liveness`, `/api/platform/health/loops`) is
// PULL-based: a wedged loop only shows as a 503 when someone asks. This monitor
// makes the same in-memory liveness PUSH a queryable/acknowledgeable domain event
// the moment a loop crosses its overdue threshold, and a (non-alerting) recovery
// event when it comes back — so operators are PAGED, not just able to poll.
//
// Design (reviewed by GPT-5 Codex against the per-process semantics):
//   * PER-REPLICA, NOT leader-gated. The heartbeat registry is in-memory and
//     process-local; a wedge is a dead/hung tokio task on ONE process that no other
//     replica can observe. So the monitor runs on every replica and emits for the
//     loops it can actually see — exactly mirroring the per-process health probe.
//     The 5 watched scans are themselves un-leader-gated, so this is consistent.
//   * IN-MEMORY edge-trigger (the `alerted` set below), NO DB dedup. A restart
//     re-seeds every loop's `last_success` to now (healthy) AND clears the alerted
//     set together, so a restart re-arms cleanly instead of spuriously re-paging; a
//     still-broken fresh process correctly re-pages after one full threshold. A
//     leader change does not restart the process, so the edge state survives it.
//   * ASYMMETRIC durability. `overdue` (critical) is AT-LEAST-ONCE: the alerted
//     set advances only AFTER a successful insert, so a failed/aborted emit retries
//     next tick (a duplicate is possible only on an unknown commit outcome — fine
//     for a rare wedge; a LOST page would not be). `recovered` (non-alerting) is
//     best-effort: re-arming is decoupled from its insert (see `rearm_recovered`),
//     so losing a recovered event never masks a later real re-wedge.
// ---------------------------------------------------------------------------

/// Heartbeat registry name for the wedge monitor itself. The monitor is a
/// registered loop, so the existing health probe is its watchdog-of-watchdog: a
/// dead monitor cannot emit its own event, but it surfaces as a 503 on
/// `/api/platform/health/loops` (and re-emits once it recovers).
const LOOP_MONITOR_NAME: &str = "background_loop_monitor";

/// This process's replica identity, stamped into every wedge event so two
/// replicas independently observing the SAME loop name wedged produce
/// distinguishable rows (the per-replica model is intentional — see the module
/// note). Prefers an explicit `RYUKI_REPLICA_ID` (so deployments that treat the
/// hostname as sensitive can supply a sanitized value), then `HOSTNAME` (the k8s
/// pod name), then a `pid-<n>` fallback. Resolved once per process.
static REPLICA_ID: LazyLock<String> = LazyLock::new(|| {
    let from_env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    from_env("RYUKI_REPLICA_ID")
        .or_else(|| from_env("HOSTNAME"))
        .unwrap_or_else(|| format!("pid-{}", std::process::id()))
});

/// The edge transitions between two monitor ticks: loops that JUST crossed into
/// overdue, and loops that JUST recovered. `newly_overdue` carries the full
/// `LoopLiveness` so the emitter can stamp age/interval/threshold into the
/// payload; `newly_recovered` needs only the name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopAlertTransitions {
    pub newly_overdue: Vec<LoopLiveness>,
    pub newly_recovered: Vec<&'static str>,
}

impl LoopAlertTransitions {
    /// No edges this tick — the common case (nothing to emit).
    pub fn is_empty(&self) -> bool {
        self.newly_overdue.is_empty() && self.newly_recovered.is_empty()
    }
}

/// PURE edge classifier. Given the current liveness snapshot and the set of loop
/// names ALREADY reported overdue (as of the last successful tick), return the
/// transitions to emit. Edge-triggered: a name still overdue AND already alerted
/// is NOT re-reported; a freshly-overdue name IS; a previously-alerted name that
/// is no longer overdue (or has vanished from the registry — which never happens,
/// entries are append-only) recovers. Uses the SAME strict `age_secs >
/// loop_overdue_threshold(interval)` rule as `classify_loop_liveness`, so the event
/// and the health probe can never disagree about what "overdue" means. No clock,
/// no IO — fully unit-testable. Output is sorted for deterministic emission order.
pub fn classify_loop_alert_transitions(
    entries: &[LoopLiveness],
    already_alerted: &BTreeSet<&'static str>,
) -> LoopAlertTransitions {
    let is_overdue = |e: &LoopLiveness| e.age_secs > loop_overdue_threshold(e.interval_secs);

    let mut newly_overdue: Vec<LoopLiveness> = entries
        .iter()
        .filter(|e| is_overdue(e) && !already_alerted.contains(e.name))
        .cloned()
        .collect();
    newly_overdue.sort_by(|a, b| a.name.cmp(b.name));

    let currently_overdue: BTreeSet<&'static str> =
        entries.iter().filter(|e| is_overdue(e)).map(|e| e.name).collect();
    let mut newly_recovered: Vec<&'static str> = already_alerted
        .iter()
        .filter(|name| !currently_overdue.contains(*name))
        .copied()
        .collect();
    newly_recovered.sort_unstable();

    LoopAlertTransitions {
        newly_overdue,
        newly_recovered,
    }
}

/// Insert ONE `background_loop.{overdue,recovered}` domain event. `site`/`env` are
/// NULL: a wedged loop is platform infrastructure with no site/env axis, so the
/// event is platform-wide visible (NOT a B0 scope leak — there is no site to
/// leak). `to_status` lives in the payload (there is no column) because the alert
/// feed prefilters on `payload->>'to_status'`. Single-statement, so it takes a
/// pooled connection directly.
async fn emit_loop_event(
    pool: &PgPool,
    loop_name: &str,
    event_type: &str,
    to_status: &str,
    overdue: Option<&LoopLiveness>,
) -> Result<(), sqlx::Error> {
    let mut payload = serde_json::json!({
        "to_status": to_status,
        "loop": loop_name,
        "replica": REPLICA_ID.as_str(),
    });
    if let Some(e) = overdue {
        payload["age_secs"] = serde_json::json!(e.age_secs);
        payload["interval_secs"] = serde_json::json!(e.interval_secs);
        payload["threshold_secs"] = serde_json::json!(loop_overdue_threshold(e.interval_secs));
    }
    crate::repos::domain_events::insert(
        pool,
        crate::repos::domain_events::NewEvent {
            event_type,
            aggregate_type: "background_loop",
            aggregate_id: loop_name,
            site: None,
            environment: None,
            actor: "system",
            payload,
        },
    )
    .await?;
    Ok(())
}

/// Re-arm overdue paging for recovered loops. PURE: drops every recovered loop
/// from `alerted` UNCONDITIONALLY. Re-arming is driven by PHYSICAL recovery, never
/// by whether the (best-effort, non-alerting) `recovered` event later emits — so a
/// lost/aborted `recovered` insert can never keep a name in `alerted` and SUPPRESS
/// a future real re-wedge's `overdue` page. (Without this decoupling, a loop that
/// pages overdue, physically recovers, fails to emit `recovered`, then re-wedges
/// would be silently masked — especially after an operator acked the first alert.)
fn rearm_recovered(alerted: &mut BTreeSet<&'static str>, newly_recovered: &[&'static str]) {
    for &name in newly_recovered {
        alerted.remove(name);
    }
}

/// Emit the tick's transitions with deliberately ASYMMETRIC durability:
///
/// * `overdue` (CRITICAL) is at-least-once. `alerted` advances ONLY after a
///   successful insert, and `?` aborts the batch on failure, so the next tick
///   re-derives and retries any un-emitted overdue edge. A duplicate is possible
///   only when a committed insert's outcome is unknown (a mid-insert timeout
///   abort) — acceptable for a rare wedge; a LOST page would not be.
/// * `recovered` (non-alerting) is best-effort. Re-arming happens FIRST and
///   synchronously (`rearm_recovered`, before any await, so it survives a dropped
///   future), and the insert itself is allowed to fail — a missing `recovered`
///   only leaves a dangling overdue in the feed, never a masked page.
async fn emit_loop_transitions(
    pool: &PgPool,
    transitions: &LoopAlertTransitions,
    alerted: &mut BTreeSet<&'static str>,
) -> Result<(), sqlx::Error> {
    // Re-arm BEFORE emitting (and before any await): the safety-critical step must
    // not depend on the recovered insert succeeding.
    rearm_recovered(alerted, &transitions.newly_recovered);
    // Critical `overdue` pages go out FIRST so a hanging best-effort `recovered`
    // insert can never delay a real page by a full iteration timeout.
    for e in &transitions.newly_overdue {
        emit_loop_event(pool, e.name, "background_loop.overdue", "overdue", Some(e)).await?;
        alerted.insert(e.name);
    }
    for &name in &transitions.newly_recovered {
        if let Err(e) =
            emit_loop_event(pool, name, "background_loop.recovered", "recovered", None).await
        {
            tracing::warn!(
                loop_name = name,
                error = %e,
                "background_loop.recovered emit failed; loop already re-armed (best-effort event lost)"
            );
        }
    }
    Ok(())
}

/// Spawn the wedge monitor. Call once at startup, AFTER (or alongside) the loops
/// it watches — registration order does not matter because every loop seeds a
/// healthy baseline at register time. The monitor is itself registered, bounded,
/// and backed-off exactly like the scans it watches, so a wedged monitor is caught
/// by the same health probe. Runs until the runtime shuts down.
pub fn spawn_loop_monitor(pool: PgPool, interval_secs: u64) {
    tokio::spawn(async move {
        register_loop(LOOP_MONITOR_NAME, interval_secs);
        let mut ticker = interval(Duration::from_secs(interval_secs));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        ticker.tick().await; // skip the immediate first tick (just started)
        let timeout = iteration_timeout(interval_secs);
        let mut consecutive_failures: u32 = 0;
        // Loop names this process has already paged as overdue. Edge state — see
        // the module note for why it is in-memory and per-process, not DB-backed.
        let mut alerted: BTreeSet<&'static str> = BTreeSet::new();
        loop {
            ticker.tick().await;
            let snapshot = loop_liveness();
            let transitions = classify_loop_alert_transitions(&snapshot, &alerted);
            // `emit_loop_transitions` is a no-op (instant Ok) when there are no
            // edges, so the monitor still records a heartbeat every tick — keeping
            // ITS OWN liveness fresh in the registry (the watchdog-of-watchdog).
            match run_bounded(
                timeout,
                emit_loop_transitions(&pool, &transitions, &mut alerted),
            )
            .await
            {
                Ok(()) => {
                    consecutive_failures = 0;
                    record_loop_success(LOOP_MONITOR_NAME);
                    if !transitions.is_empty() {
                        tracing::warn!(
                            newly_overdue = transitions.newly_overdue.len(),
                            newly_recovered = transitions.newly_recovered.len(),
                            "background-loop monitor emitted wedge transition events"
                        );
                    }
                }
                Err(err) => {
                    let backoff = note_failure(&mut consecutive_failures);
                    match err {
                        IterError::Failed(e) => tracing::error!(
                            error = %e,
                            consecutive_failures,
                            backoff_intervals = backoff,
                            "background-loop monitor emit failed; backing off (will retry edges)"
                        ),
                        IterError::TimedOut => tracing::error!(
                            timeout_secs = timeout.as_secs(),
                            consecutive_failures,
                            backoff_intervals = backoff,
                            "background-loop monitor exceeded its iteration timeout; backing off"
                        ),
                    }
                    tokio::time::sleep(Duration::from_secs(
                        interval_secs.saturating_mul(backoff),
                    ))
                    .await;
                }
            }
        }
    });
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

    // ── per-loop breakdown (pure) ────────────────────────────────────────────

    #[test]
    fn loop_overdue_threshold_matches_formula_and_saturates() {
        // iteration_timeout(i) = max(i*4, 300); threshold = 2*that + 2*i.
        assert_eq!(loop_overdue_threshold(10), 2 * 300 + 2 * 10); // 620
        assert_eq!(loop_overdue_threshold(30), 2 * 300 + 2 * 30); // 660
        assert_eq!(loop_overdue_threshold(3600), 2 * 14400 + 2 * 3600); // 36000
                                                                        // Saturating: an absurd interval must not overflow/panic.
        assert_eq!(loop_overdue_threshold(u64::MAX), u64::MAX);
    }

    #[test]
    fn loop_status_report_marks_overdue_and_sorts_by_name() {
        // interval 10 → threshold 620. age 619 fresh, 621 overdue.
        let entries = [
            entry("zeta", 10, 621),
            entry("alpha", 10, 619),
            entry("mid", 30, 660), // exactly at threshold (660) is NOT overdue (>)
        ];
        let report = loop_status_report(&entries);
        // Sorted by name.
        assert_eq!(
            report.iter().map(|l| l.name).collect::<Vec<_>>(),
            vec!["alpha", "mid", "zeta"]
        );
        let by = |n: &str| report.iter().find(|l| l.name == n).unwrap();
        assert!(!by("alpha").overdue, "619 <= 620 is fresh");
        assert_eq!(by("alpha").threshold_secs, 620);
        assert!(
            !by("mid").overdue,
            "age == threshold is NOT overdue (strict >)"
        );
        assert!(by("zeta").overdue, "621 > 620 is overdue");
    }

    #[test]
    fn loop_overall_status_and_payload_cases() {
        // Empty → degraded, HTTP 200.
        let (code, body) = loop_liveness_payload(loop_status_report(&[]));
        assert_eq!(code, 200);
        assert_eq!(body["overall"], "degraded");
        assert_eq!(body["registered_count"], 0);

        // All fresh → healthy, HTTP 200.
        let fresh = [entry("a", 10, 5), entry("b", 30, 5)];
        let (code, body) = loop_liveness_payload(loop_status_report(&fresh));
        assert_eq!(code, 200);
        assert_eq!(body["overall"], "healthy");
        assert_eq!(body["overdue_count"], 0);
        assert_eq!(body["loops"].as_array().unwrap().len(), 2);

        // Any overdue → down, HTTP 503.
        let wedged = [entry("a", 10, 5), entry("b", 10, 9999)];
        let (code, body) = loop_liveness_payload(loop_status_report(&wedged));
        assert_eq!(code, 503);
        assert_eq!(body["overall"], "down");
        assert_eq!(body["overdue_count"], 1);
    }

    #[test]
    fn per_loop_overdue_set_agrees_with_the_aggregate() {
        // The per-loop view and classify_loop_liveness share the threshold, so a
        // report with any overdue loop ⇔ the aggregate is Down; all-fresh ⇔ Healthy.
        let wedged = [entry("a", 10, 5), entry("b", 10, 9999)];
        assert!(loop_status_report(&wedged).iter().any(|l| l.overdue));
        assert_eq!(
            classify_loop_liveness(&wedged).health,
            DependencyHealth::Down
        );
        let fresh = [entry("a", 10, 5), entry("b", 30, 5)];
        assert!(!loop_status_report(&fresh).iter().any(|l| l.overdue));
        assert_eq!(
            classify_loop_liveness(&fresh).health,
            DependencyHealth::Healthy
        );
    }

    // ── edge-triggered wedge transitions (pure) ──────────────────────────────

    fn alerted(names: &[&'static str]) -> BTreeSet<&'static str> {
        names.iter().copied().collect()
    }

    #[test]
    fn transitions_fire_overdue_once_then_stay_silent_until_recovery() {
        // interval 30 ⇒ threshold 660. age 661 is overdue, 660 is not.
        let wedged = [entry("scheduler", 30, threshold(30) + 1)];

        // Tick 1: nothing alerted yet ⇒ a fresh overdue edge.
        let t1 = classify_loop_alert_transitions(&wedged, &alerted(&[]));
        assert_eq!(
            t1.newly_overdue.iter().map(|e| e.name).collect::<Vec<_>>(),
            vec!["scheduler"]
        );
        assert!(t1.newly_recovered.is_empty());

        // Tick 2: already alerted AND still overdue ⇒ NO re-emit (edge-triggered).
        let t2 = classify_loop_alert_transitions(&wedged, &alerted(&["scheduler"]));
        assert!(
            t2.is_empty(),
            "a still-overdue, already-alerted loop must not re-page"
        );

        // Tick 3: the loop recovered (fresh age) while still in the alerted set ⇒
        // a recovery edge, no new overdue.
        let recovered = [entry("scheduler", 30, 5)];
        let t3 = classify_loop_alert_transitions(&recovered, &alerted(&["scheduler"]));
        assert_eq!(t3.newly_recovered, vec!["scheduler"]);
        assert!(t3.newly_overdue.is_empty());
    }

    #[test]
    fn transition_at_exact_threshold_is_not_overdue() {
        // Strict `>`: exactly at the threshold is healthy, so no edge fires.
        let at = [entry("loop30", 30, threshold(30))];
        assert!(classify_loop_alert_transitions(&at, &alerted(&[])).is_empty());
    }

    #[test]
    fn transition_overdue_on_the_very_first_tick_emits() {
        // A loop that is already wedged the first time the monitor looks (empty
        // alerted set) must still page — no "seen before" precondition.
        let wedged = [entry("lease_expiry", 30, threshold(30) + 100)];
        let t = classify_loop_alert_transitions(&wedged, &alerted(&[]));
        assert_eq!(
            t.newly_overdue.iter().map(|e| e.name).collect::<Vec<_>>(),
            vec!["lease_expiry"]
        );
    }

    #[test]
    fn transitions_are_sorted_and_handle_mixed_edges() {
        // zeta + alpha freshly overdue (unsorted input), gamma was alerted but is
        // now fresh ⇒ recovered. Output must be name-sorted on both axes.
        let entries = [
            entry("zeta", 30, threshold(30) + 1),
            entry("alpha", 30, threshold(30) + 1),
            entry("gamma", 30, 5),
        ];
        let t = classify_loop_alert_transitions(&entries, &alerted(&["gamma"]));
        assert_eq!(
            t.newly_overdue.iter().map(|e| e.name).collect::<Vec<_>>(),
            vec!["alpha", "zeta"]
        );
        assert_eq!(t.newly_recovered, vec!["gamma"]);
    }

    #[test]
    fn alerted_loop_absent_from_snapshot_recovers() {
        // Registry entries are append-only so this should never happen, but the
        // classifier must treat a vanished alerted loop as recovered, not wedged.
        let t = classify_loop_alert_transitions(&[], &alerted(&["ghost"]));
        assert_eq!(t.newly_recovered, vec!["ghost"]);
        assert!(t.newly_overdue.is_empty());
    }

    #[test]
    fn all_fresh_with_empty_alerted_is_no_edges() {
        let fresh = [entry("a", 30, 5), entry("b", 3600, 10)];
        assert!(classify_loop_alert_transitions(&fresh, &alerted(&[])).is_empty());
    }

    #[test]
    fn rearm_is_decoupled_so_a_re_wedge_re_pages_even_if_recovered_was_lost() {
        // Regression for the masked-wedge bug: episode-1 overdue is paged, the loop
        // physically recovers, but the `recovered` event is LOST (insert failed).
        // Re-arming must STILL drop the loop from `alerted`, so a real episode-2
        // wedge produces a fresh `overdue` page (not silently suppressed — which
        // matters most if the operator already acked the episode-1 alert).
        let mut state = alerted(&["scheduler"]); // episode 1 already paged

        // Physical recovery this tick.
        let recovered_snap = [entry("scheduler", 30, 5)];
        let plan = classify_loop_alert_transitions(&recovered_snap, &state);
        assert_eq!(plan.newly_recovered, vec!["scheduler"]);

        // Re-arm runs UNCONDITIONALLY (models the recovered emit then failing).
        rearm_recovered(&mut state, &plan.newly_recovered);
        assert!(
            state.is_empty(),
            "a recovered loop is re-armed regardless of the recovered emit outcome"
        );

        // Episode 2: the loop wedges again before any successful recovered emit.
        let rewedge = [entry("scheduler", 30, threshold(30) + 1)];
        let plan2 = classify_loop_alert_transitions(&rewedge, &state);
        assert_eq!(
            plan2.newly_overdue.iter().map(|e| e.name).collect::<Vec<_>>(),
            vec!["scheduler"],
            "a real re-wedge must page again even if the prior recovered event was lost"
        );
    }

    #[test]
    fn rearm_only_touches_recovered_names() {
        // Re-arming a recovered loop must not disturb an unrelated still-overdue
        // loop's alerted membership.
        let mut state = alerted(&["wedged", "recovered_one"]);
        rearm_recovered(&mut state, &["recovered_one"]);
        assert!(state.contains("wedged"), "still-wedged loop stays alerted");
        assert!(!state.contains("recovered_one"), "recovered loop is re-armed");
    }

    #[test]
    fn replica_id_is_non_empty_and_stable() {
        // Resolves once per process; whatever the source, it must be a usable tag.
        assert!(!REPLICA_ID.is_empty());
        assert_eq!(REPLICA_ID.as_str(), REPLICA_ID.as_str());
    }
}

// ---------------------------------------------------------------------------
// DB-gated integration tests for the wedge-event emit path. Each SKIPS when
// RYUKI_DATABASE_URL is unset. Proves the end-to-end alert/ack wiring the pure
// classifier tests cannot reach.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod loop_monitor_db_tests {
    use super::*;
    use crate::database::DB_TEST_SERIAL;
    use crate::repos::domain_events;

    async fn global_pool() -> Option<&'static PgPool> {
        let url = std::env::var("RYUKI_DATABASE_URL").ok()?;
        crate::database::try_connect_with_url(&url, 5, 1, 300, 30, 1800).await;
        let pool = crate::database::get_db()
            .expect("RYUKI_DATABASE_URL is set but the DB connection failed");
        let _ = crate::database::run_migrations(pool).await;
        Some(pool)
    }

    fn alert_statuses() -> Vec<String> {
        ryuki_engine::event_alerts::alert_worthy_statuses()
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    /// An emitted `background_loop.overdue` surfaces in the alert feed's coarse
    /// prefilter (`payload->>'to_status'`) AND is acknowledgeable; the paired
    /// `recovered` event does NOT surface (it is non-alerting). This exercises the
    /// real `domain_events` insert + `list_alerts` + `ack_alert` paths, which the
    /// pure classifier tests cannot.
    #[tokio::test]
    async fn db_overdue_event_is_alertable_and_ackable_recovered_is_not() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let loop_name: &'static str =
            Box::leak(format!("test-wedge-{}", uuid::Uuid::new_v4()).into_boxed_str());
        let snapshot = LoopLiveness {
            name: loop_name,
            interval_secs: 30,
            age_secs: 9999,
        };

        emit_loop_event(
            pool,
            loop_name,
            "background_loop.overdue",
            "overdue",
            Some(&snapshot),
        )
        .await
        .expect("emit overdue");
        emit_loop_event(pool, loop_name, "background_loop.recovered", "recovered", None)
            .await
            .expect("emit recovered");

        // The alert feed surfaces ONLY the overdue event for this loop.
        let statuses = alert_statuses();
        let alerts = domain_events::list_alerts(pool, Some(loop_name), &statuses, &[], &[], 50)
            .await
            .expect("list_alerts");
        assert_eq!(alerts.len(), 1, "exactly the overdue event is alert-worthy");
        let overdue = &alerts[0];
        assert_eq!(overdue.aggregate_type, "background_loop");
        assert_eq!(overdue.event_type, "background_loop.overdue");
        assert_eq!(overdue.payload["to_status"], serde_json::json!("overdue"));
        // interval 30 ⇒ threshold 2*300 + 2*30 = 660.
        assert_eq!(overdue.payload["threshold_secs"], serde_json::json!(660));
        assert!(overdue.site.is_none(), "platform-wide: no site");
        assert!(overdue.environment.is_none(), "platform-wide: no environment");
        assert!(
            overdue.payload.get("replica").is_some(),
            "replica identity is stamped for multi-replica disambiguation"
        );

        // It is ackable through the SAME alert-worthy gate the feed uses.
        let acked =
            domain_events::ack_alert(pool, overdue.id, "operator:test", Some("ack"), &statuses)
                .await
                .expect("ack_alert");
        assert!(acked, "an alert-worthy overdue event is ackable");

        // Cleanup: ack first (FK child), then both events.
        sqlx::query("DELETE FROM alert_acks WHERE event_id = $1")
            .bind(overdue.id)
            .execute(pool)
            .await
            .ok();
        sqlx::query(
            "DELETE FROM domain_events WHERE aggregate_type = 'background_loop' AND aggregate_id = $1",
        )
        .bind(loop_name)
        .execute(pool)
        .await
        .ok();
    }
}
