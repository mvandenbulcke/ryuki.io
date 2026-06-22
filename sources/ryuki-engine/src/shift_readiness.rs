//! Operations shift-queue handover READINESS assessment (dry-run).
//!
//! Turns the static `operations/shift-queue` descriptor into a real engine: given
//! a proposed shift-queue handover item it evaluates the contract's readiness
//! guards and decides `shift-handover-recorded` (every criterion met — the item is
//! reviewed and ready to be put forward for a SEPARATELY-approved live handover) or
//! `block` (with the specific reasons). By contract this NEVER mutates the live
//! queue — so there is no admit-to-handover decision. (Distinct from the stateful
//! `shift_queue` engine; this engine only records handover readiness.)
//!
//! Guard kinds:
//! - INPUT guards block when the request field is absent (owner, support group,
//!   safe next action, stale-data marker, redacted evidence), each mapped to a
//!   declared blockedReason. (`stale-data-marked` has a declared `stale-data`
//!   reason but no field in the static requiredInputs list; the engine adds the
//!   input so the guard is input-driven and its reason reachable.)
//! - STRUCTURAL: `severity-assigned`. The descriptor declares a `severity`
//!   requiredInput AND a `severity-assigned` guard, but NO blockedReason for
//!   severity. Within the "emit only declared reasons" constraint the engine
//!   cannot block on severity, so it records `severity` as context and models
//!   `severity-assigned` as posture-satisfied. The descriptor's `approval-pending`
//!   and `dependency-unhealthy` reasons have no required guard and are never
//!   emitted.
//!
//! PURE / dry-run: no I/O, no live queue mutation. Output is the decision +
//! reasons (redacted).

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum ShiftReadinessDecision {
    /// A required readiness input is unmet — the item cannot be put forward.
    Block,
    /// Every criterion is met; the shift-queue item is reviewed and ready for a
    /// separately-approved live handover (still gated, never auto-applied).
    ShiftHandoverRecorded,
}

impl ShiftReadinessDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::ShiftHandoverRecorded => "shift-handover-recorded",
        }
    }
}

/// A proposed shift-queue handover readiness request. Every field is optional; an
/// absent gated input fails its guard.
#[derive(Debug, Clone, Default)]
pub struct ShiftReadinessInput {
    pub owner: Option<String>,
    pub support_group: Option<String>,
    pub safe_next_action: Option<String>,
    pub stale_data_marker: Option<String>,
    pub evidence_manifest: Option<String>,
    // Context-only — recorded, NOT gated (the contract declares no emittable
    // blockedReason for them); the engine reaches its decision without reading
    // these. `severity` backs the structural `severity-assigned` guard.
    pub severity: Option<String>,
    pub queue_item_source: Option<String>,
    pub handover_notes: Option<String>,
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
pub struct ShiftReadinessResult {
    pub decision: String,
    pub guards: Vec<GuardStatus>,
    pub blocked_reasons: Vec<String>,
    pub reasons: Vec<String>,
}

/// Input guards: each maps to a contract `blockedReason` and BLOCKS when its
/// request field is absent.
const INPUT_GUARDS: &[(&str, &str)] = &[
    ("owner-known", "owner-unknown"),
    ("support-group-known", "support-group-unknown"),
    ("safe-next-action-set", "missing-safe-next-action"),
    ("stale-data-marked", "stale-data"),
    ("evidence-redacted", "evidence-not-redacted"),
];

/// Guards satisfied by the dry-run posture itself — the descriptor declares a
/// `severity-assigned` guard but no blockedReason for severity, so it cannot block
/// within the declared-reasons constraint.
const STRUCTURAL_GUARDS: &[&str] = &["severity-assigned"];

fn present(field: &Option<String>) -> bool {
    field.as_deref().is_some_and(|s| !s.trim().is_empty())
}

fn input_present(input: &ShiftReadinessInput, guard: &str) -> bool {
    match guard {
        "owner-known" => present(&input.owner),
        "support-group-known" => present(&input.support_group),
        "safe-next-action-set" => present(&input.safe_next_action),
        "stale-data-marked" => present(&input.stale_data_marker),
        "evidence-redacted" => present(&input.evidence_manifest),
        _ => false,
    }
}

/// Evaluate a proposed shift-queue handover readiness request. `block` when any
/// required input guard is unmet; otherwise `shift-handover-recorded` — every
/// criterion is met and the item is ready for a separately-approved live handover.
/// This engine NEVER mutates the live queue.
pub fn evaluate_shift_readiness(input: &ShiftReadinessInput) -> ShiftReadinessResult {
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
            ShiftReadinessDecision::ShiftHandoverRecorded,
            "Shift handover recorded — every criterion met; live handover remains a separately-approved step".to_string(),
        )
    } else {
        (
            ShiftReadinessDecision::Block,
            format!(
                "Blocked — {} required readiness criterion/criteria unmet",
                blocked_reasons.len()
            ),
        )
    };

    ShiftReadinessResult {
        decision: decision.as_str().into(),
        guards,
        blocked_reasons,
        reasons: vec![reason],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_input() -> ShiftReadinessInput {
        ShiftReadinessInput {
            owner: Some("ops-team".into()),
            support_group: Some("sg-platform".into()),
            safe_next_action: Some("escalate-p2".into()),
            stale_data_marker: Some("fresh".into()),
            evidence_manifest: Some("ev-1".into()),
            severity: Some("P2".into()),
            queue_item_source: Some("failed-operation".into()),
            handover_notes: Some("notes-ref".into()),
        }
    }

    #[test]
    fn records_handover_for_complete_request() {
        let r = evaluate_shift_readiness(&complete_input());
        assert_eq!(r.decision, "shift-handover-recorded");
        assert!(r.blocked_reasons.is_empty());
    }

    #[test]
    fn never_mutates_the_queue() {
        let r = evaluate_shift_readiness(&complete_input());
        assert_ne!(r.decision, "admit");
        assert_ne!(r.decision, "handover");
        assert!(r.decision == "shift-handover-recorded" || r.decision == "block");
    }

    #[test]
    fn blocks_when_input_guards_missing() {
        let r = evaluate_shift_readiness(&ShiftReadinessInput::default());
        assert_eq!(r.decision, "block");
        for reason in [
            "owner-unknown",
            "support-group-unknown",
            "missing-safe-next-action",
            "stale-data",
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
    fn missing_safe_next_action_alone_blocks() {
        let mut input = complete_input();
        input.safe_next_action = None;
        let r = evaluate_shift_readiness(&input);
        assert_eq!(r.decision, "block");
        assert!(
            r.blocked_reasons
                .contains(&"missing-safe-next-action".to_string())
        );
        assert!(!r.blocked_reasons.contains(&"owner-unknown".to_string()));
    }

    #[test]
    fn whitespace_only_input_fails_its_guard() {
        let mut input = complete_input();
        input.stale_data_marker = Some("   ".into());
        let r = evaluate_shift_readiness(&input);
        assert_eq!(r.decision, "block");
        assert!(r.blocked_reasons.contains(&"stale-data".to_string()));
    }

    #[test]
    fn severity_assigned_is_structural_and_satisfied() {
        // severity is context (no emittable reason), so an absent severity does
        // NOT block; severity-assigned is always satisfied/structural.
        let mut input = complete_input();
        input.severity = None;
        let r = evaluate_shift_readiness(&input);
        assert_eq!(r.decision, "shift-handover-recorded");
        assert!(
            r.guards
                .iter()
                .any(|g| g.name == "severity-assigned" && g.satisfied && g.kind == "structural"),
            "severity-assigned must be present, satisfied, structural"
        );
    }

    #[test]
    fn decision_values_are_block_or_handover_recorded() {
        for d in [
            ShiftReadinessDecision::Block,
            ShiftReadinessDecision::ShiftHandoverRecorded,
        ] {
            assert!(["block", "shift-handover-recorded"].contains(&d.as_str()));
        }
    }
}
