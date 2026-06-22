//! Operations degradation-mode change READINESS assessment (dry-run).
//!
//! Turns the static `operations/degradation-mode` descriptor into a real engine:
//! given a proposed degradation-mode change it evaluates the contract's readiness
//! guards and decides `degradation-review-recorded` (every criterion met — the
//! change is reviewed and ready to be put forward for a SEPARATELY-approved live
//! action) or `block` (with the specific reasons). By contract this NEVER executes
//! a write or changes live degradation state — so there is no admit-to-execute
//! decision. (Distinct from the stateful `degradation_mode` engine, which owns the
//! live enter/exit state machine; this engine only records change readiness.)
//!
//! Guard kinds:
//! - INPUT guards block when the request field is absent (affected scope,
//!   dependency status, stale-data marker, safe remediation, owner, redacted
//!   evidence), each mapped to a declared blockedReason.
//! - STRUCTURAL guards are satisfied by the dry-run posture itself: write
//!   execution is always blocked because the engine mechanically performs no
//!   write; this needs no operator input (its `write-execution-requested` reason
//!   is a posture reason this readiness engine never emits).
//!
//! PURE / dry-run: no I/O, no live degradation change. Output is the decision +
//! reasons (redacted).

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum DegradationReadinessDecision {
    /// A required readiness input is unmet — the change cannot be put forward.
    Block,
    /// Every criterion is met; the degradation-mode change is reviewed and ready
    /// for a separately-approved live action (still gated, never auto-applied).
    DegradationReviewRecorded,
}

impl DegradationReadinessDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::DegradationReviewRecorded => "degradation-review-recorded",
        }
    }
}

/// A proposed degradation-mode change readiness request. Every field is optional;
/// an absent gated input fails its guard.
#[derive(Debug, Clone, Default)]
pub struct DegradationReadinessInput {
    pub affected_scope: Option<String>,
    pub dependency_status: Option<String>,
    pub stale_data_marker: Option<String>,
    pub safe_remediation: Option<String>,
    pub owner: Option<String>,
    pub evidence_manifest: Option<String>,
    // Context-only — recorded, NOT gated (the contract declares no blockedReason
    // for it); the engine reaches its decision without reading it.
    pub degradation_state: Option<String>,
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
pub struct DegradationReadinessResult {
    pub decision: String,
    pub guards: Vec<GuardStatus>,
    pub blocked_reasons: Vec<String>,
    pub reasons: Vec<String>,
}

/// Input guards: each maps to a contract `blockedReason` and BLOCKS when its
/// request field is absent.
const INPUT_GUARDS: &[(&str, &str)] = &[
    ("affected-scope-known", "affected-scope-unknown"),
    ("dependency-status-known", "dependency-status-unknown"),
    ("stale-data-marked", "stale-data-unmarked"),
    ("safe-remediation-set", "unsafe-remediation"),
    ("owner-known", "owner-unknown"),
    ("evidence-redacted", "evidence-not-redacted"),
];

/// Guards satisfied by the dry-run posture itself — there is no request input for
/// them because the engine mechanically guarantees the property: write execution
/// is always blocked (the engine performs no write).
const STRUCTURAL_GUARDS: &[&str] = &["write-execution-blocked"];

fn present(field: &Option<String>) -> bool {
    field.as_deref().is_some_and(|s| !s.trim().is_empty())
}

fn input_present(input: &DegradationReadinessInput, guard: &str) -> bool {
    match guard {
        "affected-scope-known" => present(&input.affected_scope),
        "dependency-status-known" => present(&input.dependency_status),
        "stale-data-marked" => present(&input.stale_data_marker),
        "safe-remediation-set" => present(&input.safe_remediation),
        "owner-known" => present(&input.owner),
        "evidence-redacted" => present(&input.evidence_manifest),
        _ => false,
    }
}

/// Evaluate a proposed degradation-mode change readiness request. `block` when any
/// required input guard is unmet; otherwise `degradation-review-recorded` — every
/// criterion is met and the change is ready for a separately-approved live action.
/// This engine NEVER changes live degradation state.
pub fn evaluate_degradation_readiness(
    input: &DegradationReadinessInput,
) -> DegradationReadinessResult {
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
            DegradationReadinessDecision::DegradationReviewRecorded,
            "Degradation review recorded — every criterion met; live action remains a separately-approved step".to_string(),
        )
    } else {
        (
            DegradationReadinessDecision::Block,
            format!(
                "Blocked — {} required readiness criterion/criteria unmet",
                blocked_reasons.len()
            ),
        )
    };

    DegradationReadinessResult {
        decision: decision.as_str().into(),
        guards,
        blocked_reasons,
        reasons: vec![reason],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_input() -> DegradationReadinessInput {
        DegradationReadinessInput {
            affected_scope: Some("site:DEFRA".into()),
            dependency_status: Some("degraded".into()),
            stale_data_marker: Some("fresh".into()),
            safe_remediation: Some("read-only-fallback".into()),
            owner: Some("ops-team".into()),
            evidence_manifest: Some("ev-1".into()),
            degradation_state: Some("partial".into()),
        }
    }

    #[test]
    fn records_review_for_complete_request() {
        let r = evaluate_degradation_readiness(&complete_input());
        assert_eq!(r.decision, "degradation-review-recorded");
        assert!(r.blocked_reasons.is_empty());
    }

    #[test]
    fn never_executes_a_write() {
        let r = evaluate_degradation_readiness(&complete_input());
        assert_ne!(r.decision, "admit");
        assert_ne!(r.decision, "execute");
        assert!(r.decision == "degradation-review-recorded" || r.decision == "block");
    }

    #[test]
    fn blocks_when_input_guards_missing() {
        let r = evaluate_degradation_readiness(&DegradationReadinessInput::default());
        assert_eq!(r.decision, "block");
        for reason in [
            "affected-scope-unknown",
            "dependency-status-unknown",
            "stale-data-unmarked",
            "unsafe-remediation",
            "owner-unknown",
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
    fn missing_safe_remediation_alone_blocks() {
        let mut input = complete_input();
        input.safe_remediation = None;
        let r = evaluate_degradation_readiness(&input);
        assert_eq!(r.decision, "block");
        assert!(
            r.blocked_reasons
                .contains(&"unsafe-remediation".to_string())
        );
        assert!(!r.blocked_reasons.contains(&"owner-unknown".to_string()));
    }

    #[test]
    fn whitespace_only_input_fails_its_guard() {
        let mut input = complete_input();
        input.affected_scope = Some("   ".into());
        let r = evaluate_degradation_readiness(&input);
        assert_eq!(r.decision, "block");
        assert!(
            r.blocked_reasons
                .contains(&"affected-scope-unknown".to_string())
        );
    }

    #[test]
    fn write_execution_guard_is_structural_and_satisfied() {
        let r = evaluate_degradation_readiness(&complete_input());
        assert!(
            r.guards.iter().any(|g| g.name == "write-execution-blocked"
                && g.satisfied
                && g.kind == "structural"),
            "write-execution-blocked must be present, satisfied, structural"
        );
    }

    #[test]
    fn context_only_field_does_not_affect_decision() {
        let mut bare = complete_input();
        bare.degradation_state = None;
        let r = evaluate_degradation_readiness(&bare);
        assert_eq!(r.decision, "degradation-review-recorded");
        assert!(r.blocked_reasons.is_empty());
    }

    #[test]
    fn decision_values_are_block_or_review_recorded() {
        for d in [
            DegradationReadinessDecision::Block,
            DegradationReadinessDecision::DegradationReviewRecorded,
        ] {
            assert!(["block", "degradation-review-recorded"].contains(&d.as_str()));
        }
    }
}
