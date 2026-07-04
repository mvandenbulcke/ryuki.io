//! Scheduled drift-recheck cadence (missing-feature #31, slice 1) — the PURE core.
//!
//! A live-applied ("operational") deployment only stays trustworthy if it is
//! re-verified against real infrastructure periodically: configuration can drift
//! out of band between applies (someone hand-edits a resource, a provider mutates
//! state). #43 verifies convergence AT apply time; #31 maintains the ONGOING
//! cadence.
//!
//! This slice is the pure decision core plus a CP-side scan (registered in the
//! scheduler) that FLAGS operational deployments overdue for a drift re-check into
//! the shift queue — the scheduling brain. It performs NO live/provider call: it
//! reads platform state (which deployments are operational and when each was last
//! verified against live infra) and enqueues a deduped work item per overdue one.
//! The agent-driven LivePlan re-check that performs the ACTUAL detection — reusing
//! [`crate::post_apply::classify_post_apply`] over the re-plan summary — is slice 2.
//!
//! Pure and no-IO so the whole decision is unit-testable without a scheduler or DB.

/// Default interval between drift re-checks of an operational deployment. A
/// deployment whose last successful live verification is older than this is due
/// for a re-check. 14 days balances catching out-of-band drift promptly against
/// the cost of a live re-plan per deployment; an operator can retune the seeded
/// schedule's cadence without a code change.
pub const DRIFT_RECHECK_INTERVAL_DAYS: i64 = 14;

/// Maximum LivePlan drift-recheck jobs the dispatch scan (#31 slice 2b-2) will
/// CREATE in a single tick. The dispatch scan is the first schedule that fans out
/// into `agent_jobs`; without a cap, the first tick after enabling it (or after a
/// large backlog accumulates) would enqueue one job per overdue deployment all at
/// once, swamping the agent queue. Capping per tick bounds that burst — the
/// remaining overdue deployments are picked up on subsequent ticks (the already-
/// dispatched ones are skipped by the in-flight dedup), and the scan reports how
/// many it deferred so the operator can raise this bound or the cadence if the
/// backlog is genuinely large. NOT a silent truncation.
pub const DRIFT_RECHECK_DISPATCH_MAX_PER_TICK: usize = 200;

/// The `agent_jobs.origin` marker a scheduler-created drift-recheck LivePlan job carries (#31 slice 2).
/// NULL origin = a normal operator/request-path job. The CP only classifies drift for jobs with this origin,
/// so a normal operator plan (which is EXPECTED to show changes) never emits a spurious drift event.
pub const DRIFT_RECHECK_JOB_ORIGIN: &str = "drift_recheck";

/// Is an operational deployment due for a drift re-check? True when the last
/// successful live verification is at least `interval_days` old.
///
/// Fail-safe on clock skew: a `last_verified` in the FUTURE (age < 0) is treated
/// as NOT due, so a skewed clock never spuriously floods the queue. A
/// non-positive `interval_days` is treated as "always due" only when the age is
/// itself non-negative — but callers pass the positive [`DRIFT_RECHECK_INTERVAL_DAYS`].
pub fn is_drift_recheck_due(
    last_verified: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
    interval_days: i64,
) -> bool {
    let age_days = (now - last_verified).num_days();
    age_days >= 0 && age_days >= interval_days
}

/// Priority tier for an overdue drift re-check, by how long the deployment has
/// gone unverified (`age_days`). Hygiene by default (P3); a deployment more than
/// TWICE the interval unverified escalates to P2 — a long-unverified live
/// deployment is a real operational risk, not just a reminder. Never returns a
/// pager-worthy P1: slice 1 only flags STALENESS (we have not checked), not
/// confirmed drift; confirmed drift (slice 2) is what escalates further.
pub fn drift_recheck_priority(age_days: i64, interval_days: i64) -> &'static str {
    if interval_days > 0 && age_days >= interval_days.saturating_mul(2) {
        "P2"
    } else {
        "P3"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    #[test]
    fn due_only_when_at_least_interval_old() {
        let now = Utc::now();
        let interval = DRIFT_RECHECK_INTERVAL_DAYS;
        // Verified longer ago than the interval → due.
        assert!(is_drift_recheck_due(
            now - Duration::days(interval + 1),
            now,
            interval
        ));
        // Exactly the interval old → due (>=).
        assert!(is_drift_recheck_due(
            now - Duration::days(interval),
            now,
            interval
        ));
        // Fresher than the interval → not due.
        assert!(!is_drift_recheck_due(
            now - Duration::days(interval - 1),
            now,
            interval
        ));
    }

    #[test]
    fn future_last_verified_is_never_due() {
        // Clock skew must never spuriously flag a deployment.
        let now = Utc::now();
        assert!(!is_drift_recheck_due(
            now + Duration::days(5),
            now,
            DRIFT_RECHECK_INTERVAL_DAYS
        ));
    }

    #[test]
    fn priority_escalates_past_twice_the_interval() {
        let interval = DRIFT_RECHECK_INTERVAL_DAYS;
        // Just overdue → hygiene P3.
        assert_eq!(drift_recheck_priority(interval, interval), "P3");
        assert_eq!(drift_recheck_priority(interval + 1, interval), "P3");
        assert_eq!(drift_recheck_priority(2 * interval - 1, interval), "P3");
        // Twice the interval unverified or worse → P2.
        assert_eq!(drift_recheck_priority(2 * interval, interval), "P2");
        assert_eq!(drift_recheck_priority(10 * interval, interval), "P2");
    }

    #[test]
    fn priority_is_never_pager_worthy_p1() {
        // Slice 1 flags staleness, not confirmed drift — it must never page P1.
        for age in [0, 14, 28, 100, 10_000] {
            let p = drift_recheck_priority(age, DRIFT_RECHECK_INTERVAL_DAYS);
            assert!(
                p == "P2" || p == "P3",
                "unexpected priority {p} for age {age}"
            );
        }
    }
}
