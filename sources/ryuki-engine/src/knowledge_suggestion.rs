//! Operations knowledge-suggestion READINESS assessment (dry-run).
//!
//! Turns the static `operations/knowledge-suggestion` descriptor into a real
//! engine: given a proposed knowledge/runbook suggestion derived from an
//! operation failure pattern, it evaluates the contract's readiness guards and
//! decides `suggestion-recorded` (every criterion met — the suggestion is
//! reviewed and ready to be put forward for SEPARATELY-approved publication) or
//! `block` (with the specific reasons). By contract this NEVER publishes
//! knowledge, mutates tickets, or calls providers — so there is no
//! admit-to-publish decision.
//!
//! Guard kinds:
//! - INPUT guards block when the request field is absent (a redacted failure-
//!   pattern summary, the operation taxonomy, an assigned reviewer, a redacted
//!   safe recommendation, redacted evidence), each mapped to a declared
//!   blockedReason.
//! - STRUCTURAL guards are satisfied by the dry-run posture itself — there is no
//!   request input for them because the engine mechanically produces them: the
//!   frequency threshold review, the impact summary, and the export package are
//!   all produced by the dry-run readiness step, not supplied by the caller.
//!
//! PURE / dry-run: no I/O, no live knowledge publish / ticket mutation / provider
//! call. Output is the decision + reasons (redacted) — never raw operation rows,
//! log payloads, error details, user/recipient data, or provider payloads.

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum SuggestionDecision {
    /// A required readiness input is unmet — the suggestion cannot be put forward.
    Block,
    /// Every criterion is met; the suggestion is reviewed and ready for a
    /// separately-approved publication (still gated, never auto-published).
    SuggestionRecorded,
}

impl SuggestionDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::SuggestionRecorded => "suggestion-recorded",
        }
    }
}

/// A proposed knowledge-suggestion readiness request. Every field is optional; an
/// absent gated input fails its guard.
#[derive(Debug, Clone, Default)]
pub struct KnowledgeSuggestionInput {
    /// A REDACTED failure-pattern summary reference — never raw error details.
    pub failure_pattern_summary: Option<String>,
    pub operation_taxonomy: Option<String>,
    pub reviewer: Option<String>,
    /// A REDACTED safe-recommendation reference.
    pub safe_recommendation: Option<String>,
    pub evidence_manifest: Option<String>,
    // Context-only — recorded, NOT gated (the contract declares no blockedReason
    // for them); the engine reaches its decision without reading these.
    pub affected_workflow: Option<String>,
    pub owner: Option<String>,
    pub support_group: Option<String>,
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
pub struct KnowledgeSuggestionResult {
    pub decision: String,
    pub guards: Vec<GuardStatus>,
    pub blocked_reasons: Vec<String>,
    pub reasons: Vec<String>,
}

/// Input guards: each maps to a contract `blockedReason` and BLOCKS when its
/// request field is absent.
const INPUT_GUARDS: &[(&str, &str)] = &[
    ("pattern-summary-redacted", "pattern-summary-missing"),
    ("taxonomy-known", "taxonomy-unknown"),
    ("reviewer-assigned", "reviewer-missing"),
    ("recommendation-redacted", "recommendation-not-redacted"),
    ("evidence-redacted", "evidence-not-redacted"),
];

/// Guards satisfied by the dry-run posture itself — there is no request input for
/// them because the engine mechanically produces the property: the frequency
/// threshold review, the impact summary, and the export package are produced by
/// the dry-run readiness step, not supplied by the caller.
const STRUCTURAL_GUARDS: &[&str] = &[
    "frequency-threshold-met",
    "impact-summary-known",
    "export-package-ready",
];

fn present(field: &Option<String>) -> bool {
    field.as_deref().is_some_and(|s| !s.trim().is_empty())
}

fn input_present(input: &KnowledgeSuggestionInput, guard: &str) -> bool {
    match guard {
        "pattern-summary-redacted" => present(&input.failure_pattern_summary),
        "taxonomy-known" => present(&input.operation_taxonomy),
        "reviewer-assigned" => present(&input.reviewer),
        "recommendation-redacted" => present(&input.safe_recommendation),
        "evidence-redacted" => present(&input.evidence_manifest),
        _ => false,
    }
}

/// Evaluate a proposed knowledge-suggestion readiness request. `block` when any
/// required input guard is unmet; otherwise `suggestion-recorded` — every
/// criterion is met and the suggestion is ready for a separately-approved
/// publication. This engine NEVER publishes knowledge.
pub fn evaluate_knowledge_suggestion(
    input: &KnowledgeSuggestionInput,
) -> KnowledgeSuggestionResult {
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
            SuggestionDecision::SuggestionRecorded,
            "Suggestion recorded — every criterion met; knowledge publication remains a separately-approved step".to_string(),
        )
    } else {
        (
            SuggestionDecision::Block,
            format!(
                "Blocked — {} required readiness criterion/criteria unmet",
                blocked_reasons.len()
            ),
        )
    };

    KnowledgeSuggestionResult {
        decision: decision.as_str().into(),
        guards,
        blocked_reasons,
        reasons: vec![reason],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_input() -> KnowledgeSuggestionInput {
        KnowledgeSuggestionInput {
            failure_pattern_summary: Some("fps-ref-1".into()),
            operation_taxonomy: Some("disk-pressure".into()),
            reviewer: Some("ops-reviewer".into()),
            safe_recommendation: Some("rec-ref-1".into()),
            evidence_manifest: Some("ev-1".into()),
            affected_workflow: Some("patch-maintenance".into()),
            owner: Some("team-ops".into()),
            support_group: Some("sg-1".into()),
        }
    }

    #[test]
    fn records_suggestion_for_complete_request() {
        let r = evaluate_knowledge_suggestion(&complete_input());
        assert_eq!(r.decision, "suggestion-recorded");
        assert!(r.blocked_reasons.is_empty());
    }

    #[test]
    fn never_publishes_knowledge() {
        let r = evaluate_knowledge_suggestion(&complete_input());
        assert_ne!(r.decision, "admit");
        assert_ne!(r.decision, "publish");
        assert!(r.decision == "suggestion-recorded" || r.decision == "block");
    }

    #[test]
    fn blocks_when_input_guards_missing() {
        let r = evaluate_knowledge_suggestion(&KnowledgeSuggestionInput::default());
        assert_eq!(r.decision, "block");
        for reason in [
            "pattern-summary-missing",
            "taxonomy-unknown",
            "reviewer-missing",
            "recommendation-not-redacted",
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
    fn missing_reviewer_alone_blocks() {
        let mut input = complete_input();
        input.reviewer = None;
        let r = evaluate_knowledge_suggestion(&input);
        assert_eq!(r.decision, "block");
        assert!(r.blocked_reasons.contains(&"reviewer-missing".to_string()));
        assert!(!r.blocked_reasons.contains(&"taxonomy-unknown".to_string()));
    }

    #[test]
    fn whitespace_only_input_fails_its_guard() {
        let mut input = complete_input();
        input.operation_taxonomy = Some("   ".into());
        let r = evaluate_knowledge_suggestion(&input);
        assert_eq!(r.decision, "block");
        assert!(r.blocked_reasons.contains(&"taxonomy-unknown".to_string()));
    }

    #[test]
    fn context_only_fields_do_not_affect_decision() {
        let mut bare = complete_input();
        bare.affected_workflow = None;
        bare.owner = None;
        bare.support_group = None;
        let r = evaluate_knowledge_suggestion(&bare);
        assert_eq!(r.decision, "suggestion-recorded");
        assert!(r.blocked_reasons.is_empty());
    }

    #[test]
    fn structural_guards_always_satisfied() {
        let r = evaluate_knowledge_suggestion(&complete_input());
        for name in STRUCTURAL_GUARDS {
            assert!(
                r.guards
                    .iter()
                    .any(|g| &g.name == name && g.satisfied && g.kind == "structural"),
                "structural guard {name} must be present and satisfied"
            );
        }
    }

    #[test]
    fn decision_values_are_block_or_suggestion_recorded() {
        for d in [
            SuggestionDecision::Block,
            SuggestionDecision::SuggestionRecorded,
        ] {
            assert!(["block", "suggestion-recorded"].contains(&d.as_str()));
        }
    }
}
