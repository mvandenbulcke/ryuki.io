//! Admin feature-flag governance READINESS assessment (dry-run).
//!
//! Turns the static `admin/feature-flag-governance` descriptor into a real engine:
//! given a proposed feature-flag change it evaluates the contract's governance
//! guards and decides `governance-recorded` (every criterion met — the change is
//! reviewed and ready to be put forward for a SEPARATELY-approved live toggle) or
//! `block` (with the specific reasons). By contract this NEVER toggles a flag,
//! mutates rollout/targeting/policy/workflow state, calls providers, or dispatches
//! notifications — so there is no admit-to-toggle decision. The live toggle is
//! always blocked: this engine only records governance readiness.
//!
//! Guard kinds:
//! - INPUT guards block when the request field is absent (owner, approval route,
//!   blast-radius review, rollback plan, redacted evidence), each mapped to a
//!   declared blockedReason.
//! - STRUCTURAL guards are satisfied by the dry-run posture itself: the live
//!   toggle is always blocked because the engine mechanically performs no flag
//!   change; this needs no operator input.
//!
//! PURE / dry-run: no I/O, no flag change. Output is the decision + reasons
//! (redacted) — never raw flag/targeting/user/group rows, audit logs, provider
//! payloads, recipient data, or tenant/object/principal/group identifiers,
//! credential/token values.

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum FeatureFlagDecision {
    /// A required governance input is unmet — the change cannot be put forward.
    Block,
    /// Every criterion is met; the feature-flag change is reviewed and ready for a
    /// separately-approved live toggle (still gated, never auto-toggled).
    GovernanceRecorded,
}

impl FeatureFlagDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::GovernanceRecorded => "governance-recorded",
        }
    }
}

/// A proposed feature-flag governance readiness request. Every field is optional;
/// an absent gated input fails its guard.
#[derive(Debug, Clone, Default)]
pub struct FeatureFlagInput {
    pub owner: Option<String>,
    pub approval_route: Option<String>,
    /// A blast-radius REVIEW reference/summary.
    pub blast_radius: Option<String>,
    pub rollback_plan: Option<String>,
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
pub struct FeatureFlagResult {
    pub decision: String,
    pub guards: Vec<GuardStatus>,
    pub blocked_reasons: Vec<String>,
    pub reasons: Vec<String>,
}

/// Input guards: each maps to a contract `blockedReason` and BLOCKS when its
/// request field is absent.
const INPUT_GUARDS: &[(&str, &str)] = &[
    ("owner-assigned", "feature-owner-missing"),
    ("approval-route-assigned", "approval-route-missing"),
    ("blast-radius-reviewed", "blast-radius-unknown"),
    ("rollback-plan-ready", "rollback-plan-missing"),
    ("evidence-redacted", "evidence-not-redacted"),
];

/// Guards satisfied by the dry-run posture itself — there is no request input for
/// them because the engine mechanically guarantees the property: the live toggle
/// is always blocked (the engine performs no flag change).
const STRUCTURAL_GUARDS: &[&str] = &["live-toggle-blocked"];

fn present(field: &Option<String>) -> bool {
    field.as_deref().is_some_and(|s| !s.trim().is_empty())
}

fn input_present(input: &FeatureFlagInput, guard: &str) -> bool {
    match guard {
        "owner-assigned" => present(&input.owner),
        "approval-route-assigned" => present(&input.approval_route),
        "blast-radius-reviewed" => present(&input.blast_radius),
        "rollback-plan-ready" => present(&input.rollback_plan),
        "evidence-redacted" => present(&input.evidence_manifest),
        _ => false,
    }
}

/// Evaluate a proposed feature-flag governance readiness request. `block` when any
/// required input guard is unmet; otherwise `governance-recorded` — every criterion
/// is met and the change is ready for a separately-approved live toggle. This
/// engine NEVER toggles a flag.
pub fn evaluate_feature_flag(input: &FeatureFlagInput) -> FeatureFlagResult {
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
            FeatureFlagDecision::GovernanceRecorded,
            "Governance recorded — every criterion met; live toggle remains a separately-approved step".to_string(),
        )
    } else {
        (
            FeatureFlagDecision::Block,
            format!(
                "Blocked — {} required governance criterion/criteria unmet",
                blocked_reasons.len()
            ),
        )
    };

    FeatureFlagResult {
        decision: decision.as_str().into(),
        guards,
        blocked_reasons,
        reasons: vec![reason],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_input() -> FeatureFlagInput {
        FeatureFlagInput {
            owner: Some("platform-team".into()),
            approval_route: Some("change-approver".into()),
            blast_radius: Some("single-service".into()),
            rollback_plan: Some("toggle-off-runbook".into()),
            evidence_manifest: Some("ev-1".into()),
        }
    }

    #[test]
    fn records_governance_for_complete_request() {
        let r = evaluate_feature_flag(&complete_input());
        assert_eq!(r.decision, "governance-recorded");
        assert!(r.blocked_reasons.is_empty());
    }

    #[test]
    fn never_toggles_a_flag() {
        let r = evaluate_feature_flag(&complete_input());
        assert_ne!(r.decision, "admit");
        assert_ne!(r.decision, "toggle");
        assert!(r.decision == "governance-recorded" || r.decision == "block");
    }

    #[test]
    fn blocks_when_input_guards_missing() {
        let r = evaluate_feature_flag(&FeatureFlagInput::default());
        assert_eq!(r.decision, "block");
        for reason in [
            "feature-owner-missing",
            "approval-route-missing",
            "blast-radius-unknown",
            "rollback-plan-missing",
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
    fn missing_rollback_plan_alone_blocks() {
        let mut input = complete_input();
        input.rollback_plan = None;
        let r = evaluate_feature_flag(&input);
        assert_eq!(r.decision, "block");
        assert!(
            r.blocked_reasons
                .contains(&"rollback-plan-missing".to_string())
        );
        assert!(
            !r.blocked_reasons
                .contains(&"feature-owner-missing".to_string())
        );
    }

    #[test]
    fn whitespace_only_input_fails_its_guard() {
        let mut input = complete_input();
        input.approval_route = Some("   ".into());
        let r = evaluate_feature_flag(&input);
        assert_eq!(r.decision, "block");
        assert!(
            r.blocked_reasons
                .contains(&"approval-route-missing".to_string())
        );
    }

    #[test]
    fn live_toggle_guard_is_structural_and_satisfied() {
        let r = evaluate_feature_flag(&complete_input());
        assert!(
            r.guards
                .iter()
                .any(|g| g.name == "live-toggle-blocked" && g.satisfied && g.kind == "structural"),
            "live-toggle-blocked must be present, satisfied, structural"
        );
    }

    #[test]
    fn decision_values_are_block_or_governance_recorded() {
        for d in [
            FeatureFlagDecision::Block,
            FeatureFlagDecision::GovernanceRecorded,
        ] {
            assert!(["block", "governance-recorded"].contains(&d.as_str()));
        }
    }
}
