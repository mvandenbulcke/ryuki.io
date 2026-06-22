//! Admin delegation-boundary REVIEW assessment (dry-run).
//!
//! Turns the static `admin/delegation-boundary` descriptor into a real engine:
//! given a proposed delegation-boundary review it evaluates the contract's guards
//! and decides `boundary-recorded` (every criterion met — the delegation boundary
//! is reviewed and ready to be put forward for a SEPARATELY-approved live change)
//! or `block` (with the specific reasons). By contract this NEVER grants, revokes,
//! mutates, or synchronizes delegated authority, assigns roles, calls Graph/providers,
//! or dispatches notifications — so there is no admit-to-delegate decision.
//!
//! Guard kinds:
//! - INPUT guards block when the request field is absent (delegate role, site
//!   scope, approval route, expiry, separation-of-duties review, break-glass
//!   review, redacted evidence), each mapped to a declared blockedReason.
//! - STRUCTURAL guards are satisfied by the dry-run posture itself — live
//!   delegation is always blocked because the engine mechanically performs no
//!   live delegation change; this needs no operator input.
//!
//! PURE / dry-run: no I/O, no live delegation change. Output is the decision +
//! reasons (redacted) — never raw user/group/membership rows, approval payloads,
//! provider payloads, recipient data, or tenant/object/principal/group identifiers,
//! credential/token values, or private network values.

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum BoundaryDecision {
    /// A required review input is unmet — the boundary cannot be put forward.
    Block,
    /// Every criterion is met; the delegation boundary is reviewed and ready for a
    /// separately-approved live change (still gated, never auto-applied).
    BoundaryRecorded,
}

impl BoundaryDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::BoundaryRecorded => "boundary-recorded",
        }
    }
}

/// A proposed delegation-boundary review request. Every field is optional; an
/// absent input fails its guard.
#[derive(Debug, Clone, Default)]
pub struct DelegationBoundaryInput {
    pub delegate_role: Option<String>,
    pub site_scope: Option<String>,
    pub approval_route: Option<String>,
    pub expiry: Option<String>,
    /// A separation-of-duties REVIEW reference/summary — never raw membership rows.
    pub separation_of_duties: Option<String>,
    /// A break-glass REVIEW reference/summary.
    pub break_glass: Option<String>,
    pub evidence_manifest: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GuardStatus {
    pub name: String,
    pub satisfied: bool,
    /// `input` (driven by a request field) | `structural` (held by the dry-run
    /// posture itself).
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DelegationBoundaryResult {
    pub decision: String,
    pub guards: Vec<GuardStatus>,
    pub blocked_reasons: Vec<String>,
    pub reasons: Vec<String>,
}

/// Input guards: each maps to a contract `blockedReason` and BLOCKS when its
/// request field is absent.
const INPUT_GUARDS: &[(&str, &str)] = &[
    ("delegate-role-known", "delegate-role-missing"),
    ("site-scope-known", "site-scope-missing"),
    ("approval-route-assigned", "approval-route-missing"),
    ("expiry-set", "expiry-missing"),
    (
        "separation-of-duties-reviewed",
        "separation-of-duties-missing",
    ),
    ("break-glass-reviewed", "break-glass-review-missing"),
    ("evidence-redacted", "evidence-not-redacted"),
];

/// Guards satisfied by the dry-run posture itself — there is no request input for
/// them because the engine mechanically guarantees the property: live delegation
/// is always blocked (the engine performs no live delegation change).
const STRUCTURAL_GUARDS: &[&str] = &["live-delegation-blocked"];

fn present(field: &Option<String>) -> bool {
    field.as_deref().is_some_and(|s| !s.trim().is_empty())
}

fn input_present(input: &DelegationBoundaryInput, guard: &str) -> bool {
    match guard {
        "delegate-role-known" => present(&input.delegate_role),
        "site-scope-known" => present(&input.site_scope),
        "approval-route-assigned" => present(&input.approval_route),
        "expiry-set" => present(&input.expiry),
        "separation-of-duties-reviewed" => present(&input.separation_of_duties),
        "break-glass-reviewed" => present(&input.break_glass),
        "evidence-redacted" => present(&input.evidence_manifest),
        _ => false,
    }
}

/// Evaluate a proposed delegation-boundary review request. `block` when any
/// required input guard is unmet; otherwise `boundary-recorded` — every criterion
/// is met and the boundary is ready for a separately-approved live change. This
/// engine NEVER changes live delegation.
pub fn evaluate_delegation_boundary(input: &DelegationBoundaryInput) -> DelegationBoundaryResult {
    let mut guards = Vec::new();
    let mut blocked_reasons = Vec::new();

    for (name, reason) in INPUT_GUARDS {
        let satisfied = input_present(input, name);
        guards.push(GuardStatus {
            name: (*name).into(),
            satisfied,
            kind: "input".into(),
        });
        if !satisfied {
            blocked_reasons.push((*reason).into());
        }
    }

    for name in STRUCTURAL_GUARDS {
        guards.push(GuardStatus {
            name: (*name).into(),
            satisfied: true,
            kind: "structural".into(),
        });
    }

    let (decision, reason) = if blocked_reasons.is_empty() {
        (
            BoundaryDecision::BoundaryRecorded,
            "Boundary recorded — every criterion met; live delegation change remains a separately-approved step".to_string(),
        )
    } else {
        (
            BoundaryDecision::Block,
            format!(
                "Blocked — {} required review criterion/criteria unmet",
                blocked_reasons.len()
            ),
        )
    };

    DelegationBoundaryResult {
        decision: decision.as_str().into(),
        guards,
        blocked_reasons,
        reasons: vec![reason],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_input() -> DelegationBoundaryInput {
        DelegationBoundaryInput {
            delegate_role: Some("site-approver".into()),
            site_scope: Some("DEFRA".into()),
            approval_route: Some("datacenter-final-approval".into()),
            expiry: Some("2026-12-31".into()),
            separation_of_duties: Some("sod-review-1".into()),
            break_glass: Some("bg-review-1".into()),
            evidence_manifest: Some("ev-1".into()),
        }
    }

    #[test]
    fn records_boundary_for_complete_request() {
        let r = evaluate_delegation_boundary(&complete_input());
        assert_eq!(r.decision, "boundary-recorded");
        assert!(r.blocked_reasons.is_empty());
    }

    #[test]
    fn never_changes_live_delegation() {
        let r = evaluate_delegation_boundary(&complete_input());
        assert_ne!(r.decision, "admit");
        assert_ne!(r.decision, "delegate");
        assert!(r.decision == "boundary-recorded" || r.decision == "block");
    }

    #[test]
    fn blocks_when_input_guards_missing() {
        let r = evaluate_delegation_boundary(&DelegationBoundaryInput::default());
        assert_eq!(r.decision, "block");
        for reason in [
            "delegate-role-missing",
            "site-scope-missing",
            "approval-route-missing",
            "expiry-missing",
            "separation-of-duties-missing",
            "break-glass-review-missing",
            "evidence-not-redacted",
        ] {
            assert!(
                r.blocked_reasons.contains(&reason.to_string()),
                "expected blocked reason {reason}: {:?}",
                r.blocked_reasons
            );
        }
    }

    #[test]
    fn missing_approval_route_alone_blocks() {
        let mut input = complete_input();
        input.approval_route = None;
        let r = evaluate_delegation_boundary(&input);
        assert_eq!(r.decision, "block");
        assert!(
            r.blocked_reasons
                .contains(&"approval-route-missing".to_string())
        );
        assert!(
            !r.blocked_reasons
                .contains(&"site-scope-missing".to_string())
        );
    }

    #[test]
    fn whitespace_only_input_fails_its_guard() {
        let mut input = complete_input();
        input.separation_of_duties = Some("   ".into());
        let r = evaluate_delegation_boundary(&input);
        assert_eq!(r.decision, "block");
        assert!(
            r.blocked_reasons
                .contains(&"separation-of-duties-missing".to_string())
        );
    }

    #[test]
    fn structural_guard_always_satisfied() {
        let r = evaluate_delegation_boundary(&complete_input());
        assert!(
            r.guards.iter().any(|g| g.name == "live-delegation-blocked"
                && g.satisfied
                && g.kind == "structural"),
            "live-delegation-blocked must be present, satisfied, structural"
        );
    }

    #[test]
    fn decision_values_are_block_or_boundary_recorded() {
        for d in [BoundaryDecision::Block, BoundaryDecision::BoundaryRecorded] {
            assert!(["block", "boundary-recorded"].contains(&d.as_str()));
        }
    }
}
