//! Pure multi-role approval quorum evaluation (#4).
//!
//! Builds on separation-of-duties (#3, already enforced: an approver cannot be
//! the requester, and `request_approval_decisions` is UNIQUE per
//! (request, approval lifecycle epoch, role)).
//! A QUORUM additionally requires breadth: at least N distinct approval ROLES and
//! N distinct APPROVERS, with NO rejection. This module evaluates a request's
//! recorded decisions against a quorum policy. Pure: the API reads the decision
//! rows and passes them in; nothing here decides whether to ADVANCE the request
//! (enforcement in the approval flow is a separate step).

use serde::Serialize;
use std::collections::BTreeSet;

/// One recorded approval-route decision (a `request_approval_decisions` row).
#[derive(Debug, Clone)]
pub struct ApprovalDecision {
    /// The approval-route role this decision satisfies (e.g. `DatacenterApprover`).
    pub role: String,
    /// `approved` | `rejected` (case-insensitive).
    pub decision: String,
    /// The verified approver principal (`AuthSession.user_id`).
    pub actor: String,
}

/// The evaluated quorum state for one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QuorumStatus {
    /// Distinct roles that APPROVED.
    pub approved_roles: usize,
    /// Distinct principals that APPROVED.
    pub distinct_approvers: usize,
    /// Any rejection present — a rejected route blocks quorum outright.
    pub rejected: bool,
    pub required_roles: usize,
    pub required_approvers: usize,
    /// True iff not rejected AND both breadth thresholds are met.
    pub quorum_met: bool,
    /// Distinct approving roles (sorted).
    pub roles_satisfied: Vec<String>,
    /// Distinct approving principals (sorted).
    pub approvers: Vec<String>,
}

/// Evaluate quorum. Met iff there is NO rejection AND the distinct approving
/// roles ≥ `required_roles` AND the distinct approvers ≥ `required_approvers`.
///
/// A single rejection blocks quorum regardless of approvals — a rejected route
/// cannot be "out-voted" (rejections are terminal in this model). Distinctness
/// matters: one principal approving two roles counts as ONE approver, so a true
/// multi-party quorum cannot be met by a single actor wearing many hats.
pub fn evaluate_quorum(
    decisions: &[ApprovalDecision],
    required_roles: usize,
    required_approvers: usize,
) -> QuorumStatus {
    // Normalise (trim) before any comparison/counting. Without this, whitespace
    // variation — `" alice"` vs `"alice"`, or `" approved "` — would let a SINGLE
    // principal masquerade as multiple distinct approvers (defeating the
    // multi-party quorum) or slip a decision past the keyword match. Distinctness
    // is then over the trimmed identity.
    let is = |d: &ApprovalDecision, kw: &str| d.decision.trim().eq_ignore_ascii_case(kw);
    let rejected = decisions.iter().any(|d| is(d, "rejected"));

    let roles: BTreeSet<&str> = decisions
        .iter()
        .filter(|d| is(d, "approved"))
        .map(|d| d.role.trim())
        .collect();
    let approvers: BTreeSet<&str> = decisions
        .iter()
        .filter(|d| is(d, "approved"))
        .map(|d| d.actor.trim())
        .collect();

    let quorum_met =
        !rejected && roles.len() >= required_roles && approvers.len() >= required_approvers;

    QuorumStatus {
        approved_roles: roles.len(),
        distinct_approvers: approvers.len(),
        rejected,
        required_roles,
        required_approvers,
        quorum_met,
        roles_satisfied: roles.iter().map(|s| s.to_string()).collect(),
        approvers: approvers.iter().map(|s| s.to_string()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(role: &str, decision: &str, actor: &str) -> ApprovalDecision {
        ApprovalDecision {
            role: role.into(),
            decision: decision.into(),
            actor: actor.into(),
        }
    }

    #[test]
    fn two_roles_two_approvers_meets_quorum() {
        let d = [
            dec("DatacenterApprover", "approved", "alice"),
            dec("SecurityApprover", "approved", "bob"),
        ];
        let q = evaluate_quorum(&d, 2, 2);
        assert!(q.quorum_met);
        assert_eq!(q.approved_roles, 2);
        assert_eq!(q.distinct_approvers, 2);
        assert!(!q.rejected);
    }

    #[test]
    fn one_role_short_of_quorum() {
        let d = [dec("DatacenterApprover", "approved", "alice")];
        let q = evaluate_quorum(&d, 2, 2);
        assert!(!q.quorum_met);
        assert_eq!(q.approved_roles, 1);
    }

    #[test]
    fn any_rejection_blocks_quorum_even_if_thresholds_met() {
        let d = [
            dec("DatacenterApprover", "approved", "alice"),
            dec("SecurityApprover", "approved", "bob"),
            dec("ComplianceApprover", "rejected", "carol"),
        ];
        let q = evaluate_quorum(&d, 2, 2);
        assert!(q.rejected);
        assert!(!q.quorum_met, "a rejection is terminal");
    }

    #[test]
    fn one_actor_many_roles_is_one_approver() {
        // The same principal approving two roles must NOT satisfy a 2-approver quorum.
        let d = [
            dec("DatacenterApprover", "approved", "alice"),
            dec("SecurityApprover", "approved", "alice"),
        ];
        let q = evaluate_quorum(&d, 2, 2);
        assert_eq!(q.approved_roles, 2);
        assert_eq!(q.distinct_approvers, 1);
        assert!(!q.quorum_met, "one actor cannot form a multi-party quorum");
    }

    #[test]
    fn whitespace_cannot_spoof_distinct_approvers() {
        // One principal must not become two approvers via whitespace variation,
        // and a padded decision keyword must still count.
        let d = [
            dec("DatacenterApprover", "approved", "alice"),
            dec("SecurityApprover", " approved ", " alice "),
        ];
        let q = evaluate_quorum(&d, 2, 2);
        assert_eq!(
            q.approved_roles, 2,
            "both padded decisions count as approved"
        );
        assert_eq!(q.distinct_approvers, 1, "trimmed identity is one approver");
        assert!(!q.quorum_met, "one actor cannot form a 2-approver quorum");
        assert_eq!(q.approvers, vec!["alice"], "approver list is normalised");
    }

    #[test]
    fn empty_is_not_met() {
        let q = evaluate_quorum(&[], 1, 1);
        assert!(!q.quorum_met);
        assert_eq!(q.approved_roles, 0);
        assert!(q.roles_satisfied.is_empty());
    }

    #[test]
    fn distinct_lists_are_deduped_and_sorted() {
        let d = [
            dec("RoleB", "approved", "zed"),
            dec("RoleA", "approved", "amy"),
            dec("RoleA", "approved", "amy"), // duplicate (role,actor)
        ];
        let q = evaluate_quorum(&d, 1, 1);
        assert_eq!(q.roles_satisfied, vec!["RoleA", "RoleB"]);
        assert_eq!(q.approvers, vec!["amy", "zed"]);
    }
}
