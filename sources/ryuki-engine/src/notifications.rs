/// Pure notification model and draft-synthesis functions.
///
/// This module is PURE — no I/O, no locks, no process-local state.
/// All functions are deterministic given their inputs.
use serde::{Deserialize, Serialize};

/// Severity level for a portal notification.
///
/// Serialises as PascalCase to match the DB CHECK constraint values
/// ('Info', 'Success', 'Warning', 'Critical').
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Info,
    Success,
    Warning,
    Critical,
}

/// Whether the recipient is a named role or a specific user principal.
///
/// Serialises as PascalCase to match the DB CHECK constraint values
/// ('Role', 'User').
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecipientKind {
    Role,
    User,
}

/// A not-yet-persisted notification ready for the repo layer to INSERT.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationDraft {
    pub recipient_kind: RecipientKind,
    pub recipient_id: String,
    /// The lifecycle action that triggered this notification, e.g. "request.approve".
    pub event: String,
    pub severity: Severity,
    pub title: String,
    pub body: String,
}

/// The API/serialization model for a persisted notification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Notification {
    pub id: String,
    pub recipient_kind: RecipientKind,
    pub recipient_id: String,
    pub event: String,
    /// The related request UUID as a string, if any.
    pub request_id: Option<String>,
    pub severity: Severity,
    pub title: String,
    pub body: String,
    /// True iff the querying user has a read receipt for this notification
    /// (resolved per-user, so a shared role notification reads independently).
    pub read: bool,
    /// RFC 3339-formatted timestamp.
    pub created_at: String,
}

/// Pure: produce the notification draft(s) for a lifecycle transition.
///
/// `owner` is `requests.created_by` (None when the row has no owner principal).
/// Bodies are synthesised from structured fields ONLY — user-supplied free-text
/// (reason/detail) is intentionally excluded so no secrets leak through this path.
/// Returns an empty Vec for transitions that do not warrant a notification.
pub fn drafts_for_transition(
    action: &str,
    request_id: &str,
    owner: Option<&str>,
) -> Vec<NotificationDraft> {
    match action {
        "request.plan" => vec![NotificationDraft {
            recipient_kind: RecipientKind::Role,
            recipient_id: "DatacenterApprover".to_string(),
            event: action.to_string(),
            severity: Severity::Info,
            title: "Request awaiting approval".to_string(),
            body: format!("Request {request_id} is planned and awaiting approval."),
        }],

        "request.approve" => match owner {
            Some(o) => vec![NotificationDraft {
                recipient_kind: RecipientKind::User,
                recipient_id: o.to_string(),
                event: action.to_string(),
                severity: Severity::Success,
                title: "Request approved".to_string(),
                body: format!("Request {request_id} has been approved."),
            }],
            None => vec![],
        },

        "request.reject" => match owner {
            Some(o) => vec![NotificationDraft {
                recipient_kind: RecipientKind::User,
                recipient_id: o.to_string(),
                event: action.to_string(),
                severity: Severity::Warning,
                title: "Request rejected".to_string(),
                body: format!("Request {request_id} was rejected."),
            }],
            None => vec![],
        },

        "request.verify" => match owner {
            Some(o) => vec![NotificationDraft {
                recipient_kind: RecipientKind::User,
                recipient_id: o.to_string(),
                event: action.to_string(),
                severity: Severity::Success,
                title: "Request completed".to_string(),
                body: format!("Request {request_id} has completed successfully."),
            }],
            None => vec![],
        },

        "request.cancel" => match owner {
            Some(o) => vec![NotificationDraft {
                recipient_kind: RecipientKind::User,
                recipient_id: o.to_string(),
                event: action.to_string(),
                severity: Severity::Warning,
                title: "Request cancelled".to_string(),
                body: format!("Request {request_id} was cancelled."),
            }],
            None => vec![],
        },

        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── request.plan ─────────────────────────────────────────────────────────

    #[test]
    fn plan_produces_role_draft() {
        let drafts = drafts_for_transition("request.plan", "req-abc", Some("alice"));
        assert_eq!(drafts.len(), 1);
        let d = &drafts[0];
        assert_eq!(d.recipient_kind, RecipientKind::Role);
        assert_eq!(d.recipient_id, "DatacenterApprover");
        assert_eq!(d.severity, Severity::Info);
        assert_eq!(d.event, "request.plan");
        assert!(
            d.body.contains("req-abc"),
            "body must contain the request id"
        );
        // Ensure no free-text secrets leak: body is purely structured
        assert!(
            !d.body.contains("alice"),
            "body must not contain the owner id"
        );
    }

    #[test]
    fn plan_with_no_owner_still_produces_role_draft() {
        // plan always notifies the approver role, regardless of owner
        let drafts = drafts_for_transition("request.plan", "req-xyz", None);
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].recipient_kind, RecipientKind::Role);
    }

    // ── request.approve ──────────────────────────────────────────────────────

    #[test]
    fn approve_with_owner_produces_user_draft() {
        let drafts = drafts_for_transition("request.approve", "req-001", Some("bob"));
        assert_eq!(drafts.len(), 1);
        let d = &drafts[0];
        assert_eq!(d.recipient_kind, RecipientKind::User);
        assert_eq!(d.recipient_id, "bob");
        assert_eq!(d.severity, Severity::Success);
        assert_eq!(d.event, "request.approve");
        assert!(
            d.body.contains("req-001"),
            "body must contain the request id"
        );
    }

    #[test]
    fn approve_without_owner_produces_no_draft() {
        let drafts = drafts_for_transition("request.approve", "req-001", None);
        assert!(drafts.is_empty());
    }

    // ── request.reject ───────────────────────────────────────────────────────

    #[test]
    fn reject_with_owner_produces_warning_draft() {
        let drafts = drafts_for_transition("request.reject", "req-002", Some("carol"));
        assert_eq!(drafts.len(), 1);
        let d = &drafts[0];
        assert_eq!(d.recipient_kind, RecipientKind::User);
        assert_eq!(d.recipient_id, "carol");
        assert_eq!(d.severity, Severity::Warning);
        assert_eq!(d.event, "request.reject");
        assert!(d.body.contains("req-002"));
    }

    #[test]
    fn reject_without_owner_produces_no_draft() {
        let drafts = drafts_for_transition("request.reject", "req-002", None);
        assert!(drafts.is_empty());
    }

    // ── request.verify ───────────────────────────────────────────────────────

    #[test]
    fn verify_with_owner_produces_success_draft() {
        let drafts = drafts_for_transition("request.verify", "req-003", Some("dave"));
        assert_eq!(drafts.len(), 1);
        let d = &drafts[0];
        assert_eq!(d.recipient_kind, RecipientKind::User);
        assert_eq!(d.recipient_id, "dave");
        assert_eq!(d.severity, Severity::Success);
        assert_eq!(d.event, "request.verify");
        assert!(d.body.contains("req-003"));
    }

    #[test]
    fn verify_without_owner_produces_no_draft() {
        let drafts = drafts_for_transition("request.verify", "req-003", None);
        assert!(drafts.is_empty());
    }

    // ── request.cancel ───────────────────────────────────────────────────────

    #[test]
    fn cancel_with_owner_produces_warning_draft() {
        let drafts = drafts_for_transition("request.cancel", "req-004", Some("eve"));
        assert_eq!(drafts.len(), 1);
        let d = &drafts[0];
        assert_eq!(d.recipient_kind, RecipientKind::User);
        assert_eq!(d.recipient_id, "eve");
        assert_eq!(d.severity, Severity::Warning);
        assert_eq!(d.event, "request.cancel");
        assert!(d.body.contains("req-004"));
    }

    #[test]
    fn cancel_without_owner_produces_no_draft() {
        let drafts = drafts_for_transition("request.cancel", "req-004", None);
        assert!(drafts.is_empty());
    }

    // ── unmapped actions ─────────────────────────────────────────────────────

    #[test]
    fn unmapped_action_produces_no_draft() {
        for action in &["request.lock", "request.execute", "request.archive", ""] {
            let drafts = drafts_for_transition(action, "req-999", Some("frank"));
            assert!(
                drafts.is_empty(),
                "expected no drafts for action '{action}'"
            );
        }
    }

    // ── body purity (no free-text leakage) ───────────────────────────────────

    #[test]
    fn bodies_contain_request_id_not_caller_secrets() {
        // The function signature deliberately omits any `reason`/`detail` parameter.
        // This test verifies: (a) the request id IS present in the body, and (b) a
        // hypothetical free-text secret that was NOT passed in does NOT appear.
        let rid = "req-purity-check-001";
        let free_text_secret = "TOP_SECRET_vault_token_abc123";
        for action in &[
            "request.approve",
            "request.reject",
            "request.verify",
            "request.cancel",
        ] {
            // Note: free_text_secret is intentionally NOT passed — drafts_for_transition
            // has no parameter for it.
            let drafts = drafts_for_transition(action, rid, Some("owner-principal"));
            for d in &drafts {
                assert!(d.body.contains(rid), "body must contain the request id");
                // The secret was never a parameter, so it must never appear in output.
                assert!(
                    !d.body.contains(free_text_secret),
                    "body must not contain free-text secrets that were not provided"
                );
                // The owner principal appears only as recipient_id, never in the body.
                assert!(
                    !d.body.contains("owner-principal"),
                    "body must not contain the owner principal id"
                );
            }
        }
    }
}
