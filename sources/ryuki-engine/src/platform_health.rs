//! Operations platform-health remediation-readiness assessment (dry-run).
//!
//! Turns the static `operations/platform-health` descriptor into a real engine:
//! given a proposed platform-health remediation review it evaluates the contract's
//! readiness guards and decides `health-review-recorded` (every criterion met —
//! the review is complete and ready to be put forward for a SEPARATELY-approved
//! live remediation) or `block` (with the specific reasons). By contract this
//! NEVER executes a remediation or exposes raw logs — so there is no
//! admit-to-remediate decision.
//!
//! Guard kinds: every guard is an INPUT guard — it blocks when its request field
//! is absent, each mapped to a declared blockedReason. There are no structural
//! guards (the descriptor declares a reason for every required guard); the
//! `raw-log-exposure` blockedReason is a structural posture reason this readiness
//! engine never emits (it handles no raw logs).
//!
//! PURE / dry-run: no I/O, no live remediation. Output is the decision + reasons
//! (redacted) — never raw log content.

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum HealthDecision {
    /// A required readiness input is unmet — the review cannot be put forward.
    Block,
    /// Every criterion is met; the health review is complete and ready for a
    /// separately-approved live remediation (still gated, never auto-remediated).
    HealthReviewRecorded,
}

impl HealthDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::HealthReviewRecorded => "health-review-recorded",
        }
    }
}

/// A proposed platform-health remediation-readiness request. Every field is
/// optional; an absent gated input fails its guard.
#[derive(Debug, Clone, Default)]
pub struct PlatformHealthInput {
    pub component: Option<String>,
    pub owner: Option<String>,
    /// The dependency/health STATE summary — drives the dependency-status guard.
    pub health_state: Option<String>,
    pub stale_data_marker: Option<String>,
    pub safe_remediation: Option<String>,
    pub evidence_manifest: Option<String>,
    // Context-only — recorded, NOT gated (the contract declares no blockedReason
    // for it); the engine reaches its decision without reading it.
    pub health_signal: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GuardStatus {
    pub name: String,
    pub satisfied: bool,
    /// `input` (driven by a request field). This engine has only input guards.
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PlatformHealthResult {
    pub decision: String,
    pub guards: Vec<GuardStatus>,
    pub blocked_reasons: Vec<String>,
    pub reasons: Vec<String>,
}

/// Input guards: each maps to a contract `blockedReason` and BLOCKS when its
/// request field is absent.
const INPUT_GUARDS: &[(&str, &str)] = &[
    ("component-registered", "component-unknown"),
    ("owner-known", "owner-unknown"),
    ("stale-data-marked", "stale-data-unmarked"),
    ("dependency-status-known", "dependency-status-unknown"),
    ("safe-remediation-set", "unsafe-remediation"),
    ("evidence-redacted", "evidence-not-redacted"),
];

fn present(field: &Option<String>) -> bool {
    field.as_deref().is_some_and(|s| !s.trim().is_empty())
}

fn input_present(input: &PlatformHealthInput, guard: &str) -> bool {
    match guard {
        "component-registered" => present(&input.component),
        "owner-known" => present(&input.owner),
        "stale-data-marked" => present(&input.stale_data_marker),
        "dependency-status-known" => present(&input.health_state),
        "safe-remediation-set" => present(&input.safe_remediation),
        "evidence-redacted" => present(&input.evidence_manifest),
        _ => false,
    }
}

/// Evaluate a proposed platform-health remediation-readiness request. `block` when
/// any required input guard is unmet; otherwise `health-review-recorded` — every
/// criterion is met and the review is ready for a separately-approved live
/// remediation. This engine NEVER executes a remediation.
pub fn evaluate_platform_health(input: &PlatformHealthInput) -> PlatformHealthResult {
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
            HealthDecision::HealthReviewRecorded,
            "Health review recorded — every criterion met; live remediation remains a separately-approved step".to_string(),
        )
    } else {
        (
            HealthDecision::Block,
            format!(
                "Blocked — {} required readiness criterion/criteria unmet",
                blocked_reasons.len()
            ),
        )
    };

    PlatformHealthResult {
        decision: decision.as_str().into(),
        guards,
        blocked_reasons,
        reasons: vec![reason],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_input() -> PlatformHealthInput {
        PlatformHealthInput {
            component: Some("api-gateway".into()),
            owner: Some("platform-team".into()),
            health_state: Some("degraded".into()),
            stale_data_marker: Some("fresh".into()),
            safe_remediation: Some("restart-rolling".into()),
            evidence_manifest: Some("ev-1".into()),
            health_signal: Some("p99-latency".into()),
        }
    }

    #[test]
    fn records_review_for_complete_request() {
        let r = evaluate_platform_health(&complete_input());
        assert_eq!(r.decision, "health-review-recorded");
        assert!(r.blocked_reasons.is_empty());
    }

    #[test]
    fn never_remediates() {
        let r = evaluate_platform_health(&complete_input());
        assert_ne!(r.decision, "admit");
        assert_ne!(r.decision, "remediate");
        assert!(r.decision == "health-review-recorded" || r.decision == "block");
    }

    #[test]
    fn blocks_with_all_reasons_when_empty() {
        let r = evaluate_platform_health(&PlatformHealthInput::default());
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
    fn missing_safe_remediation_alone_blocks() {
        let mut input = complete_input();
        input.safe_remediation = None;
        let r = evaluate_platform_health(&input);
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
        input.stale_data_marker = Some("   ".into());
        let r = evaluate_platform_health(&input);
        assert_eq!(r.decision, "block");
        assert!(
            r.blocked_reasons
                .contains(&"stale-data-unmarked".to_string())
        );
    }

    #[test]
    fn context_only_field_does_not_affect_decision() {
        let mut bare = complete_input();
        bare.health_signal = None;
        let r = evaluate_platform_health(&bare);
        assert_eq!(r.decision, "health-review-recorded");
        assert!(r.blocked_reasons.is_empty());
    }

    #[test]
    fn decision_values_are_block_or_review_recorded() {
        for d in [HealthDecision::Block, HealthDecision::HealthReviewRecorded] {
            assert!(["block", "health-review-recorded"].contains(&d.as_str()));
        }
    }
}
