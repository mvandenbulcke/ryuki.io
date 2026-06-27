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

/// The request terminal statuses that are alert-worthy — the exact inverse keys
/// of [`severity_for_request_status`]. Exposed so the alert feed can push this
/// filter INTO its SQL query: alerts are rare relative to all transitions, so
/// filtering a recent-N page in memory would yield near-empty pages. Keep this
/// in lock-step with `severity_for_request_status` (a unit test enforces it).
pub fn alert_worthy_request_statuses() -> &'static [&'static str] {
    &["failed", "rejected", "cancelled"]
}

/// Classify any domain event into an optional alert severity. Currently only
/// `request` aggregates are emitted (slice 1); future operational emitters
/// (capacity/SLO breach, agent-offline) extend this match. `to_status` is the
/// request payload's terminal status when the aggregate is a request.
pub fn classify(aggregate_type: &str, to_status: Option<&str>) -> Option<AlertSeverity> {
    match aggregate_type {
        "request" => to_status.and_then(severity_for_request_status),
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
    fn alert_status_list_matches_the_classifier() {
        // Every status in the SQL-filter list must classify as an alert, and no
        // status outside it may — so the in-SQL filter and the severity label
        // can never drift.
        for s in alert_worthy_request_statuses() {
            assert!(
                severity_for_request_status(s).is_some(),
                "{s} is in the alert list but not classified as an alert"
            );
        }
    }

    #[test]
    fn classify_only_alerts_request_aggregates() {
        assert_eq!(
            classify("request", Some("failed")),
            Some(AlertSeverity::Critical)
        );
        assert_eq!(classify("request", Some("completed")), None);
        assert_eq!(classify("request", None), None);
        // An unknown aggregate type never alerts (until an emitter + rule exist).
        assert_eq!(classify("widget", Some("failed")), None);
    }
}
