//! Pure classification of operational domain events into alerts (#11, slice 2a).
//!
//! The `domain_events` stream (API side, swarm #11) records every committed
//! state change. Not every event is operationally actionable — this module is
//! the single, pure source of truth for WHICH events are alert-worthy and at
//! what severity, so the alert feed and any later alert-routing share one rule
//! set. No IO: it maps an event's type + outcome to an optional severity.

/// Alert severity, ordered low → high. `as_str` gives the stable wire value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

impl AlertSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            AlertSeverity::Info => "info",
            AlertSeverity::Warning => "warning",
            AlertSeverity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AlertRule {
    aggregate_type: &'static str,
    to_status: &'static str,
    severity: AlertSeverity,
}

/// One canonical registry drives precise classification, the coarse SQL status
/// prefilter, and acknowledgement eligibility. Adding an alert rule anywhere
/// else would let the read and mutation boundaries drift.
const ALERT_RULES: &[AlertRule] = &[
    AlertRule {
        aggregate_type: "request",
        to_status: "failed",
        severity: AlertSeverity::Critical,
    },
    AlertRule {
        aggregate_type: "request",
        to_status: "drift-detected",
        severity: AlertSeverity::Critical,
    },
    AlertRule {
        aggregate_type: "request",
        to_status: "rejected",
        severity: AlertSeverity::Warning,
    },
    AlertRule {
        aggregate_type: "request",
        to_status: "cancelled",
        severity: AlertSeverity::Info,
    },
    AlertRule {
        aggregate_type: "slo",
        to_status: "breached",
        severity: AlertSeverity::Critical,
    },
    AlertRule {
        aggregate_type: "budget",
        to_status: "breached",
        severity: AlertSeverity::Warning,
    },
    AlertRule {
        aggregate_type: "agent",
        to_status: "offline",
        severity: AlertSeverity::Warning,
    },
    AlertRule {
        aggregate_type: "agent_job",
        to_status: "dead-lettered",
        severity: AlertSeverity::Critical,
    },
    AlertRule {
        aggregate_type: "agent_job",
        to_status: "reconcile-required",
        severity: AlertSeverity::Critical,
    },
    AlertRule {
        aggregate_type: "background_loop",
        to_status: "overdue",
        severity: AlertSeverity::Critical,
    },
];

fn severity_for(aggregate_type: &str, to_status: &str) -> Option<AlertSeverity> {
    ALERT_RULES
        .iter()
        .find(|rule| rule.aggregate_type == aggregate_type && rule.to_status == to_status)
        .map(|rule| rule.severity)
}

/// Classify a request-lifecycle event by its terminal outcome (`to_status`).
///
/// A request reaching a NEGATIVE terminal state is operationally actionable: a
/// `failed` request is a critical signal (execution broke), a `rejected` one a
/// warning (an approver blocked it), and a `cancelled` one informational (a
/// requester withdrew it). `drift-detected` (#43) is a live apply that succeeded
/// but whose post-apply re-plan still shows pending changes — real infrastructure
/// did NOT converge to the approved plan; silent divergence is at least as severe
/// as a loud failure, so it ranks Critical. Every other transition (intake/
/// validated/planned/approved/executing/verifying/completed/…) is normal flow and
/// NOT an alert (including `verified`, which is post-apply GOOD news).
///
/// Keyed on `to_status` rather than the event type so it stays correct as new
/// request event types are added — the outcome is what matters.
pub fn severity_for_request_status(to_status: &str) -> Option<AlertSeverity> {
    severity_for("request", to_status)
}

/// Classify an SLO-scan event (#11 slice 2b) by its `to_status`. A `breached`
/// SLO is a critical operational signal; `recovered` is good news, not an alert.
pub fn severity_for_slo_status(to_status: &str) -> Option<AlertSeverity> {
    severity_for("slo", to_status)
}

/// Classify a budget-scan event (#11 slice 2c) by its `to_status`. A `breached`
/// cost/capacity budget is a WARNING (a spend/headroom threshold was crossed) —
/// a tier below an SLO breach, which is a reliability-contract violation.
/// `recovered` is not an alert.
pub fn severity_for_budget_status(to_status: &str) -> Option<AlertSeverity> {
    severity_for("budget", to_status)
}

/// Classify an agent-liveness event (#11 slice 2d) by its `to_status`. An
/// `offline` agent is a WARNING — execution for its platform is impaired until a
/// healthy agent checks in — operationally important but not, on its own, a
/// reliability-contract breach. `online` (recovery) is not an alert.
pub fn severity_for_agent_status(to_status: &str) -> Option<AlertSeverity> {
    severity_for("agent", to_status)
}

/// Classify an agent-job lifecycle event (#23) by its `to_status`. A
/// `dead-lettered` job is CRITICAL — it exhausted every lease-expiry redispatch
/// (the poison-job cap), so that request's work will never run without operator
/// intervention. A `reconcile-required` job is ALSO CRITICAL — a LiveApply lease
/// expired mid-run, so REAL provider infrastructure is in an unknown state and an
/// operator MUST reconcile before any re-dispatch; the costliest job mode must not
/// fail more quietly than the recoverable dead-letter path. Both rank with a
/// `failed` request, above the recoverable `offline` agent (a warning). Every
/// other agent-job status is normal flow and NOT an alert.
pub fn severity_for_agent_job_status(to_status: &str) -> Option<AlertSeverity> {
    severity_for("agent_job", to_status)
}

/// Classify a background-loop wedge event by its `to_status`. An `overdue` loop
/// is CRITICAL — a wedged scheduler/scan tick has silently stopped scheduled work,
/// the highest-impact operational failure (it ranks with a `failed` request and a
/// `dead-lettered` job). `recovered` is good news, not an alert. UNLIKE the
/// admin-cancel/force-fail statuses (deliberately kept OUT of the alert union to
/// avoid paging on a human-initiated action), `overdue` is exactly what we WANT to
/// page on — it is an unattended liveness failure.
pub fn severity_for_background_loop_status(to_status: &str) -> Option<AlertSeverity> {
    severity_for("background_loop", to_status)
}

/// The UNION of every alert-worthy `to_status` across all aggregate types.
/// Exposed so the alert feed can push this filter INTO its SQL query — alerts
/// are rare relative to all events, so filtering a recent-N page in memory would
/// yield near-empty pages. The DB filter is intentionally coarse (a single
/// `to_status` set); [`classify`] then applies the precise per-aggregate rule
/// and drops any spurious (aggregate, status) pair. A unit test keeps this union
/// in lock-step with the per-aggregate classifiers.
pub fn alert_worthy_statuses() -> &'static [&'static str] {
    static STATUSES: std::sync::LazyLock<Vec<&'static str>> = std::sync::LazyLock::new(|| {
        let mut statuses = Vec::new();
        for rule in ALERT_RULES {
            if !statuses.contains(&rule.to_status) {
                statuses.push(rule.to_status);
            }
        }
        statuses
    });
    STATUSES.as_slice()
}

/// Exact `(aggregate_type, to_status)` pairs accepted as alerts. Repository
/// mutation boundaries use this closed registry rather than the coarse status
/// union above: a status that is alert-worthy for one aggregate must never make
/// a different aggregate acknowledgeable.
pub fn alert_worthy_pairs() -> &'static [(&'static str, &'static str)] {
    static PAIRS: std::sync::LazyLock<Vec<(&'static str, &'static str)>> =
        std::sync::LazyLock::new(|| {
            ALERT_RULES
                .iter()
                .map(|rule| (rule.aggregate_type, rule.to_status))
                .collect()
        });
    PAIRS.as_slice()
}

/// Classify any domain event into an optional alert severity. `request`
/// aggregates key on their terminal status (slice 1); `slo` aggregates on the
/// breach-scan status (slice 2b). Future operational emitters extend this match.
pub fn classify(aggregate_type: &str, to_status: Option<&str>) -> Option<AlertSeverity> {
    to_status.and_then(|status| severity_for(aggregate_type, status))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_request_outcomes_are_alerts_with_ranked_severity() {
        assert_eq!(
            severity_for_request_status("failed"),
            Some(AlertSeverity::Critical)
        );
        assert_eq!(
            severity_for_request_status("rejected"),
            Some(AlertSeverity::Warning)
        );
        assert_eq!(
            severity_for_request_status("cancelled"),
            Some(AlertSeverity::Info)
        );
        // #43: post-apply drift ranks with a failed request (silent divergence).
        assert_eq!(
            severity_for_request_status("drift-detected"),
            Some(AlertSeverity::Critical)
        );
    }

    #[test]
    fn normal_flow_states_are_not_alerts() {
        for ok in [
            "intake",
            "validated",
            "planned",
            "approved",
            "executing",
            "verifying",
            "completed",
            "operational",
            // #43: a converged post-apply verification is GOOD news, not an alert.
            "verified",
        ] {
            assert_eq!(severity_for_request_status(ok), None, "{ok} must not alert");
        }
    }

    #[test]
    fn dead_lettered_and_reconcile_required_agent_jobs_are_critical_others_are_not() {
        // A poison-capped job is a hard execution failure → Critical.
        assert_eq!(
            severity_for_agent_job_status("dead-lettered"),
            Some(AlertSeverity::Critical)
        );
        // A LiveApply lease expiry leaves real infra in an unknown state → Critical
        // (the costliest mode must not alert weaker than the dead-letter path).
        assert_eq!(
            severity_for_agent_job_status("reconcile-required"),
            Some(AlertSeverity::Critical)
        );
        // Every normal agent-job status is not an alert (incl. a bare "reconcile"
        // that is NOT the real "reconcile-required" status).
        for ok in ["pending", "leased", "running", "succeeded", "reconcile"] {
            assert_eq!(
                severity_for_agent_job_status(ok),
                None,
                "{ok} must not alert"
            );
        }
    }

    #[test]
    fn alert_status_union_matches_the_classifiers() {
        // Every status in the coarse SQL-filter union must classify as an alert
        // for SOME aggregate, so the in-SQL filter and the per-aggregate severity
        // labels can never drift.
        for s in alert_worthy_statuses() {
            assert!(
                severity_for_request_status(s).is_some()
                    || severity_for_slo_status(s).is_some()
                    || severity_for_budget_status(s).is_some()
                    || severity_for_agent_status(s).is_some()
                    || severity_for_agent_job_status(s).is_some()
                    || severity_for_background_loop_status(s).is_some(),
                "{s} is in the alert union but no aggregate classifies it as an alert"
            );
        }

        for (aggregate_type, to_status) in alert_worthy_pairs() {
            assert!(
                classify(aggregate_type, Some(to_status)).is_some(),
                "exact alert pair ({aggregate_type}, {to_status}) must classify"
            );
        }
        for status in alert_worthy_statuses() {
            assert!(
                alert_worthy_pairs()
                    .iter()
                    .any(|(_, pair_status)| pair_status == status),
                "coarse alert status {status} must occur in the exact pair registry"
            );
        }
    }

    #[test]
    fn classify_handles_request_and_slo_aggregates() {
        assert_eq!(
            classify("request", Some("failed")),
            Some(AlertSeverity::Critical)
        );
        assert_eq!(classify("request", Some("completed")), None);
        assert_eq!(classify("request", None), None);
        assert_eq!(
            classify("slo", Some("breached")),
            Some(AlertSeverity::Critical)
        );
        // 'recovered' is good news, not an alert.
        assert_eq!(classify("slo", Some("recovered")), None);
        // A breached budget is a warning (cost/capacity), below an SLO breach.
        assert_eq!(
            classify("budget", Some("breached")),
            Some(AlertSeverity::Warning)
        );
        assert_eq!(classify("budget", Some("recovered")), None);
        // An offline agent is a warning; coming back online is not an alert.
        assert_eq!(
            classify("agent", Some("offline")),
            Some(AlertSeverity::Warning)
        );
        assert_eq!(classify("agent", Some("online")), None);
        // A dead-lettered agent job is critical (poison-job cap reached); a
        // non-dead-letter agent_job status is not an alert.
        assert_eq!(
            classify("agent_job", Some("dead-lettered")),
            Some(AlertSeverity::Critical)
        );
        assert_eq!(classify("agent_job", Some("running")), None);
        // A wedged background loop is critical (silent scheduling stop); recovery
        // is good news, not an alert; a normal monitor tick has no to_status.
        assert_eq!(
            classify("background_loop", Some("overdue")),
            Some(AlertSeverity::Critical)
        );
        assert_eq!(classify("background_loop", Some("recovered")), None);
        assert_eq!(classify("background_loop", None), None);
        // Cross-aggregate spurious pairs never alert (a request can't be
        // 'dead-lettered', an agent_job can't be 'failed').
        assert_eq!(classify("request", Some("dead-lettered")), None);
        assert_eq!(classify("agent_job", Some("failed")), None);
        // Cross-aggregate spurious pairs never alert (a request can't be
        // 'breached', an slo can't be 'failed').
        assert_eq!(classify("slo", Some("failed")), None);
        assert_eq!(classify("request", Some("breached")), None);
        // An unknown aggregate type never alerts (until an emitter + rule exist).
        assert_eq!(classify("widget", Some("failed")), None);
    }
}
