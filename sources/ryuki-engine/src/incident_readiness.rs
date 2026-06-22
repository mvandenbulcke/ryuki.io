//! Operations incident-context READINESS assessment (dry-run).
//!
//! Turns the static `operations/incident-context` descriptor into a real engine:
//! given a proposed incident-context enrichment it evaluates the contract's
//! readiness guards and decides `incident-context-recorded` (every criterion met —
//! the context is reviewed and ready to be put forward for a SEPARATELY-approved
//! live action) or `block` (with the specific reasons). By contract this NEVER
//! mutates an incident or exposes raw provider payloads — so there is no
//! admit-to-execute decision. (Distinct from the stateful `incident_context`
//! engine; this engine only records context readiness.)
//!
//! Guard kinds: every guard is an INPUT guard — it blocks when its request field
//! is absent, each mapped to a declared blockedReason. (The descriptor declares
//! `stale-data-unmarked` and `missing-safe-next-action` reasons whose
//! corresponding inputs are not in the static requiredInputs list; the engine
//! adds them so those guards are input-driven and their reasons reachable, rather
//! than modeling a review deliverable as always-satisfied.) The
//! `raw-provider-payload` blockedReason is a structural posture reason this engine
//! never emits (it handles no provider payloads).
//!
//! PURE / dry-run: no I/O, no incident mutation. Output is the decision + reasons
//! (redacted) — never raw provider payloads.

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum IncidentReadinessDecision {
    /// A required readiness input is unmet — the context cannot be put forward.
    Block,
    /// Every criterion is met; the incident context is reviewed and ready for a
    /// separately-approved live action (still gated, never auto-applied).
    IncidentContextRecorded,
}

impl IncidentReadinessDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::IncidentContextRecorded => "incident-context-recorded",
        }
    }
}

/// A proposed incident-context readiness request. Every field is optional; an
/// absent gated input fails its guard.
#[derive(Debug, Clone, Default)]
pub struct IncidentReadinessInput {
    pub incident_context: Option<String>,
    pub ci_identity: Option<String>,
    pub owner: Option<String>,
    pub support_group: Option<String>,
    pub stale_data_marker: Option<String>,
    pub safe_next_action: Option<String>,
    pub evidence_manifest: Option<String>,
    // Context-only — recorded, NOT gated (the contract declares no blockedReason
    // for them); the engine reaches its decision without reading these.
    pub application: Option<String>,
    pub site: Option<String>,
    pub environment: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GuardStatus {
    pub name: String,
    pub satisfied: bool,
    /// `input` (driven by a request field). This engine has only input guards.
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct IncidentReadinessResult {
    pub decision: String,
    pub guards: Vec<GuardStatus>,
    pub blocked_reasons: Vec<String>,
    pub reasons: Vec<String>,
}

/// Input guards: each maps to a contract `blockedReason` and BLOCKS when its
/// request field is absent.
const INPUT_GUARDS: &[(&str, &str)] = &[
    ("incident-linked", "incident-missing"),
    ("ci-identity-known", "ci-identity-unknown"),
    ("owner-known", "owner-unknown"),
    ("support-group-known", "support-group-unknown"),
    ("stale-data-marked", "stale-data-unmarked"),
    ("safe-next-action-set", "missing-safe-next-action"),
    ("evidence-redacted", "evidence-not-redacted"),
];

fn present(field: &Option<String>) -> bool {
    field.as_deref().is_some_and(|s| !s.trim().is_empty())
}

fn input_present(input: &IncidentReadinessInput, guard: &str) -> bool {
    match guard {
        "incident-linked" => present(&input.incident_context),
        "ci-identity-known" => present(&input.ci_identity),
        "owner-known" => present(&input.owner),
        "support-group-known" => present(&input.support_group),
        "stale-data-marked" => present(&input.stale_data_marker),
        "safe-next-action-set" => present(&input.safe_next_action),
        "evidence-redacted" => present(&input.evidence_manifest),
        _ => false,
    }
}

/// Evaluate a proposed incident-context readiness request. `block` when any
/// required input guard is unmet; otherwise `incident-context-recorded` — every
/// criterion is met and the context is ready for a separately-approved live
/// action. This engine NEVER mutates an incident.
pub fn evaluate_incident_readiness(input: &IncidentReadinessInput) -> IncidentReadinessResult {
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
            IncidentReadinessDecision::IncidentContextRecorded,
            "Incident context recorded — every criterion met; live action remains a separately-approved step".to_string(),
        )
    } else {
        (
            IncidentReadinessDecision::Block,
            format!(
                "Blocked — {} required readiness criterion/criteria unmet",
                blocked_reasons.len()
            ),
        )
    };

    IncidentReadinessResult {
        decision: decision.as_str().into(),
        guards,
        blocked_reasons,
        reasons: vec![reason],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_input() -> IncidentReadinessInput {
        IncidentReadinessInput {
            incident_context: Some("INC-1234".into()),
            ci_identity: Some("app-srv-01".into()),
            owner: Some("ops-team".into()),
            support_group: Some("sg-platform".into()),
            stale_data_marker: Some("fresh".into()),
            safe_next_action: Some("notify-owner".into()),
            evidence_manifest: Some("ev-1".into()),
            application: Some("billing".into()),
            site: Some("DEFRA".into()),
            environment: Some("production".into()),
        }
    }

    #[test]
    fn records_context_for_complete_request() {
        let r = evaluate_incident_readiness(&complete_input());
        assert_eq!(r.decision, "incident-context-recorded");
        assert!(r.blocked_reasons.is_empty());
    }

    #[test]
    fn never_mutates_an_incident() {
        let r = evaluate_incident_readiness(&complete_input());
        assert_ne!(r.decision, "admit");
        assert_ne!(r.decision, "execute");
        assert!(r.decision == "incident-context-recorded" || r.decision == "block");
    }

    #[test]
    fn blocks_with_all_reasons_when_empty() {
        let r = evaluate_incident_readiness(&IncidentReadinessInput::default());
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
    fn missing_safe_next_action_alone_blocks() {
        let mut input = complete_input();
        input.safe_next_action = None;
        let r = evaluate_incident_readiness(&input);
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
        input.ci_identity = Some("   ".into());
        let r = evaluate_incident_readiness(&input);
        assert_eq!(r.decision, "block");
        assert!(
            r.blocked_reasons
                .contains(&"ci-identity-unknown".to_string())
        );
    }

    #[test]
    fn context_only_fields_do_not_affect_decision() {
        let mut bare = complete_input();
        bare.application = None;
        bare.site = None;
        bare.environment = None;
        let r = evaluate_incident_readiness(&bare);
        assert_eq!(r.decision, "incident-context-recorded");
        assert!(r.blocked_reasons.is_empty());
    }

    #[test]
    fn decision_values_are_block_or_context_recorded() {
        for d in [
            IncidentReadinessDecision::Block,
            IncidentReadinessDecision::IncidentContextRecorded,
        ] {
            assert!(["block", "incident-context-recorded"].contains(&d.as_str()));
        }
    }
}
