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

/// Classify a request-lifecycle event by its terminal outcome (`to_status`).
///
/// A request reaching a NEGATIVE terminal state is operationally actionable: a
/// `failed` request is a critical signal (execution broke), a `rejected` one a
/// warning (an approver blocked it), and a `cancelled` one informational (a
/// requester withdrew it). Every other transition (intake/validated/planned/
/// approved/executing/verifying/completed/…) is normal flow and NOT an alert.
///
/// Keyed on `to_status` rather than the event type so it stays correct as new
/// request event types are added — the outcome is what matters.
pub fn severity_for_request_status(to_status: &str) -> Option<AlertSeverity> {
    match to_status {
        "failed" => Some(AlertSeverity::Critical),
        "rejected" => Some(AlertSeverity::Warning),
        "cancelled" => Some(AlertSeverity::Info),
        _ => None,
    }
}

/// Classify an SLO-scan event (#11 slice 2b) by its `to_status`. A `breached`
/// SLO is a critical operational signal; `recovered` is good news, not an alert.
pub fn severity_for_slo_status(to_status: &str) -> Option<AlertSeverity> {
    match to_status {
        "breached" => Some(AlertSeverity::Critical),
        _ => None,
    }
}

/// Classify a budget-scan event (#11 slice 2c) by its `to_status`. A `breached`
/// cost/capacity budget is a WARNING (a spend/headroom threshold was crossed) —
/// a tier below an SLO breach, which is a reliability-contract violation.
/// `recovered` is not an alert.
pub fn severity_for_budget_status(to_status: &str) -> Option<AlertSeverity> {
    match to_status {
        "breached" => Some(AlertSeverity::Warning),
        _ => None,
    }
}

/// Classify an agent-liveness event (#11 slice 2d) by its `to_status`. An
/// `offline` agent is a WARNING — execution for its platform is impaired until a
/// healthy agent checks in — operationally important but not, on its own, a
/// reliability-contract breach. `online` (recovery) is not an alert.
pub fn severity_for_agent_status(to_status: &str) -> Option<AlertSeverity> {
    match to_status {
        "offline" => Some(AlertSeverity::Warning),
        _ => None,
    }
}

/// Classify an agent-job lifecycle event (#23) by its `to_status`. A
/// `dead-lettered` job is CRITICAL — it exhausted every lease-expiry redispatch
/// (the poison-job cap), so that request's work will never run without operator
/// intervention. That ranks it with a `failed` request (a hard execution
/// failure), above the recoverable `offline` agent (a warning). Every other
/// agent-job status is normal flow and NOT an alert.
pub fn severity_for_agent_job_status(to_status: &str) -> Option<AlertSeverity> {
    match to_status {
        "dead-lettered" => Some(AlertSeverity::Critical),
        _ => None,
    }
}

/// The UNION of every alert-worthy `to_status` across all aggregate types.
/// Exposed so the alert feed can push this filter INTO its SQL query — alerts
/// are rare relative to all events, so filtering a recent-N page in memory would
/// yield near-empty pages. The DB filter is intentionally coarse (a single
/// `to_status` set); [`classify`] then applies the precise per-aggregate rule
/// and drops any spurious (aggregate, status) pair. A unit test keeps this union
/// in lock-step with the per-aggregate classifiers.
pub fn alert_worthy_statuses() -> &'static [&'static str] {
    &[
        "failed",
        "rejected",
        "cancelled",
        "breached",
        "offline",
        "dead-lettered",
    ]
}

/// Classify any domain event into an optional alert severity. `request`
/// aggregates key on their terminal status (slice 1); `slo` aggregates on the
/// breach-scan status (slice 2b). Future operational emitters extend this match.
pub fn classify(aggregate_type: &str, to_status: Option<&str>) -> Option<AlertSeverity> {
    match aggregate_type {
        "request" => to_status.and_then(severity_for_request_status),
        "slo" => to_status.and_then(severity_for_slo_status),
        "budget" => to_status.and_then(severity_for_budget_status),
        "agent" => to_status.and_then(severity_for_agent_status),
        "agent_job" => to_status.and_then(severity_for_agent_job_status),
        _ => None,
    }
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
        ] {
            assert_eq!(severity_for_request_status(ok), None, "{ok} must not alert");
        }
    }

    #[test]
    fn dead_lettered_agent_job_is_critical_others_are_not() {
        // A poison-capped job is a hard execution failure → Critical.
        assert_eq!(
            severity_for_agent_job_status("dead-lettered"),
            Some(AlertSeverity::Critical)
        );
        // Every normal agent-job status is not an alert.
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
                    || severity_for_agent_job_status(s).is_some(),
                "{s} is in the alert union but no aggregate classifies it as an alert"
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
