//! Operations maintenance-communication READINESS assessment (dry-run).
//!
//! Turns the static `operations/maintenance-comm` descriptor into a real engine:
//! given a proposed maintenance-notification request it evaluates the contract's
//! readiness guards and decides `comm-plan-recorded` (every criterion met — the
//! notification plan is reviewed and ready to be put forward for a SEPARATELY-
//! approved live dispatch) or `block` (with the specific reasons). By contract
//! this NEVER dispatches a notification or exposes recipient data — so there is no
//! admit-to-dispatch decision.
//!
//! Guard kinds: every guard is an INPUT guard — it blocks when its request field
//! is absent, each mapped to a declared blockedReason. There are no structural
//! guards (the descriptor declares a reason for every required guard); the
//! `raw-recipient-data` blockedReason is a structural posture reason this readiness
//! engine never emits (it handles no recipient data).
//!
//! PURE / dry-run: no I/O, no live dispatch. Output is the decision + reasons
//! (redacted) — never raw recipient data.

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum CommDecision {
    /// A required readiness input is unmet — the plan cannot be put forward.
    Block,
    /// Every criterion is met; the notification plan is reviewed and ready for a
    /// separately-approved live dispatch (still gated, never auto-dispatched).
    CommPlanRecorded,
}

impl CommDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::CommPlanRecorded => "comm-plan-recorded",
        }
    }
}

/// A proposed maintenance-communication readiness request. Every field is
/// optional; an absent gated input fails its guard.
#[derive(Debug, Clone, Default)]
pub struct MaintenanceCommInput {
    pub maintenance_window: Option<String>,
    pub affected_services: Option<String>,
    pub owner: Option<String>,
    pub audience: Option<String>,
    pub message_type: Option<String>,
    pub approval_route: Option<String>,
    pub evidence_manifest: Option<String>,
    // Context-only — recorded, NOT gated (the contract declares no blockedReason
    // for them); the engine reaches its decision without reading these.
    pub ci_relationship_summary: Option<String>,
    pub support_group: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GuardStatus {
    pub name: String,
    pub satisfied: bool,
    /// `input` (driven by a request field). This engine has only input guards.
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MaintenanceCommResult {
    pub decision: String,
    pub guards: Vec<GuardStatus>,
    pub blocked_reasons: Vec<String>,
    pub reasons: Vec<String>,
}

/// Input guards: each maps to a contract `blockedReason` and BLOCKS when its
/// request field is absent.
const INPUT_GUARDS: &[(&str, &str)] = &[
    ("maintenance-window-known", "maintenance-window-missing"),
    ("affected-ci-known", "affected-ci-unknown"),
    ("owner-known", "owner-unknown"),
    ("audience-approved", "audience-unapproved"),
    ("message-template-approved", "message-template-missing"),
    ("approval-route-assigned", "approval-missing"),
    ("evidence-redacted", "evidence-not-redacted"),
];

fn present(field: &Option<String>) -> bool {
    field.as_deref().is_some_and(|s| !s.trim().is_empty())
}

fn input_present(input: &MaintenanceCommInput, guard: &str) -> bool {
    match guard {
        "maintenance-window-known" => present(&input.maintenance_window),
        "affected-ci-known" => present(&input.affected_services),
        "owner-known" => present(&input.owner),
        "audience-approved" => present(&input.audience),
        "message-template-approved" => present(&input.message_type),
        "approval-route-assigned" => present(&input.approval_route),
        "evidence-redacted" => present(&input.evidence_manifest),
        _ => false,
    }
}

/// Evaluate a proposed maintenance-communication readiness request. `block` when
/// any required input guard is unmet; otherwise `comm-plan-recorded` — every
/// criterion is met and the plan is ready for a separately-approved live dispatch.
/// This engine NEVER dispatches a notification.
pub fn evaluate_maintenance_comm(input: &MaintenanceCommInput) -> MaintenanceCommResult {
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

    let (decision, reason) = if blocked_reasons.is_empty() {
        (
            CommDecision::CommPlanRecorded,
            "Communication plan recorded — every criterion met; live dispatch remains a separately-approved step".to_string(),
        )
    } else {
        (
            CommDecision::Block,
            format!(
                "Blocked — {} required readiness criterion/criteria unmet",
                blocked_reasons.len()
            ),
        )
    };

    MaintenanceCommResult {
        decision: decision.as_str().into(),
        guards,
        blocked_reasons,
        reasons: vec![reason],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_input() -> MaintenanceCommInput {
        MaintenanceCommInput {
            maintenance_window: Some("2026-12-31T22:00Z".into()),
            affected_services: Some("billing,auth".into()),
            owner: Some("ops-team".into()),
            audience: Some("internal-ops".into()),
            message_type: Some("planned-maintenance".into()),
            approval_route: Some("comms-approver".into()),
            evidence_manifest: Some("ev-1".into()),
            ci_relationship_summary: Some("rel-1".into()),
            support_group: Some("sg-1".into()),
        }
    }

    #[test]
    fn records_plan_for_complete_request() {
        let r = evaluate_maintenance_comm(&complete_input());
        assert_eq!(r.decision, "comm-plan-recorded");
        assert!(r.blocked_reasons.is_empty());
    }

    #[test]
    fn never_dispatches() {
        let r = evaluate_maintenance_comm(&complete_input());
        assert_ne!(r.decision, "admit");
        assert_ne!(r.decision, "dispatch");
        assert!(r.decision == "comm-plan-recorded" || r.decision == "block");
    }

    #[test]
    fn blocks_with_all_reasons_when_empty() {
        let r = evaluate_maintenance_comm(&MaintenanceCommInput::default());
        assert_eq!(r.decision, "block");
        assert_eq!(r.blocked_reasons.len(), INPUT_GUARDS.len());
        for (_, reason) in INPUT_GUARDS {
            assert!(
                r.blocked_reasons.contains(&reason.to_string()),
                "expected blocked reason {reason}: {:?}",
                r.blocked_reasons
            );
        }
    }

    #[test]
    fn missing_audience_alone_blocks() {
        let mut input = complete_input();
        input.audience = None;
        let r = evaluate_maintenance_comm(&input);
        assert_eq!(r.decision, "block");
        assert!(
            r.blocked_reasons
                .contains(&"audience-unapproved".to_string())
        );
        assert!(!r.blocked_reasons.contains(&"owner-unknown".to_string()));
    }

    #[test]
    fn whitespace_only_input_fails_its_guard() {
        let mut input = complete_input();
        input.approval_route = Some("   ".into());
        let r = evaluate_maintenance_comm(&input);
        assert_eq!(r.decision, "block");
        assert!(r.blocked_reasons.contains(&"approval-missing".to_string()));
    }

    #[test]
    fn context_only_fields_do_not_affect_decision() {
        let mut bare = complete_input();
        bare.ci_relationship_summary = None;
        bare.support_group = None;
        let r = evaluate_maintenance_comm(&bare);
        assert_eq!(r.decision, "comm-plan-recorded");
        assert!(r.blocked_reasons.is_empty());
    }

    #[test]
    fn decision_values_are_block_or_plan_recorded() {
        for d in [CommDecision::Block, CommDecision::CommPlanRecorded] {
            assert!(["block", "comm-plan-recorded"].contains(&d.as_str()));
        }
    }
}
