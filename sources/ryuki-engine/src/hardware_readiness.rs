//! Operations hardware-lifecycle READINESS assessment (dry-run).
//!
//! Turns the static `operations/hardware-lifecycle` descriptor into a real engine:
//! given a proposed hardware-lifecycle action it evaluates the contract's readiness
//! guards and decides `hardware-lifecycle-recorded` (every criterion met — the
//! action is reviewed and ready to be put forward for a SEPARATELY-approved live
//! change) or `block` (with the specific reasons). By contract this NEVER changes
//! live hardware state — so there is no admit-to-execute decision. (Distinct from
//! the stateful `hardware_lifecycle` engine; this engine only records readiness.)
//!
//! Guard kinds: every guard is an INPUT guard — it blocks when its request field
//! is absent, each mapped to a declared blockedReason. The `support-risk`
//! blockedReason is a structural posture reason this readiness engine never emits.
//!
//! PURE / dry-run: no I/O, no live hardware change. Output is the decision +
//! reasons (redacted).

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum HardwareReadinessDecision {
    /// A required readiness input is unmet — the action cannot be put forward.
    Block,
    /// Every criterion is met; the hardware-lifecycle action is reviewed and ready
    /// for a separately-approved live change (still gated, never auto-applied).
    HardwareLifecycleRecorded,
}

impl HardwareReadinessDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::HardwareLifecycleRecorded => "hardware-lifecycle-recorded",
        }
    }
}

/// A proposed hardware-lifecycle readiness request. Every field is optional; an
/// absent gated input fails its guard.
#[derive(Debug, Clone, Default)]
pub struct HardwareReadinessInput {
    pub hardware_profile: Option<String>,
    pub site: Option<String>,
    pub support_status: Option<String>,
    pub firmware_baseline: Option<String>,
    pub capacity_role: Option<String>,
    pub owner: Option<String>,
    pub evidence_manifest: Option<String>,
    // Context-only — recorded, NOT gated (the contract declares no blockedReason
    // for them); the engine reaches its decision without reading these.
    pub lifecycle_state: Option<String>,
    pub refresh_window: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GuardStatus {
    pub name: String,
    pub satisfied: bool,
    /// `input` (driven by a request field). This engine has only input guards.
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HardwareReadinessResult {
    pub decision: String,
    pub guards: Vec<GuardStatus>,
    pub blocked_reasons: Vec<String>,
    pub reasons: Vec<String>,
}

/// Input guards: each maps to a contract `blockedReason` and BLOCKS when its
/// request field is absent.
const INPUT_GUARDS: &[(&str, &str)] = &[
    ("model-known", "model-unknown"),
    ("site-known", "site-unknown"),
    ("support-status-known", "support-status-unknown"),
    ("firmware-baseline-known", "firmware-baseline-unknown"),
    ("capacity-role-known", "capacity-role-unknown"),
    ("cmdb-owner-known", "cmdb-owner-unknown"),
    ("evidence-redacted", "evidence-not-redacted"),
];

fn present(field: &Option<String>) -> bool {
    field.as_deref().is_some_and(|s| !s.trim().is_empty())
}

fn input_present(input: &HardwareReadinessInput, guard: &str) -> bool {
    match guard {
        "model-known" => present(&input.hardware_profile),
        "site-known" => present(&input.site),
        "support-status-known" => present(&input.support_status),
        "firmware-baseline-known" => present(&input.firmware_baseline),
        "capacity-role-known" => present(&input.capacity_role),
        "cmdb-owner-known" => present(&input.owner),
        "evidence-redacted" => present(&input.evidence_manifest),
        _ => false,
    }
}

/// Evaluate a proposed hardware-lifecycle readiness request. `block` when any
/// required input guard is unmet; otherwise `hardware-lifecycle-recorded` — every
/// criterion is met and the action is ready for a separately-approved live change.
/// This engine NEVER changes live hardware state.
pub fn evaluate_hardware_readiness(input: &HardwareReadinessInput) -> HardwareReadinessResult {
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
            HardwareReadinessDecision::HardwareLifecycleRecorded,
            "Hardware lifecycle recorded — every criterion met; live change remains a separately-approved step".to_string(),
        )
    } else {
        (
            HardwareReadinessDecision::Block,
            format!(
                "Blocked — {} required readiness criterion/criteria unmet",
                blocked_reasons.len()
            ),
        )
    };

    HardwareReadinessResult {
        decision: decision.as_str().into(),
        guards,
        blocked_reasons,
        reasons: vec![reason],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_input() -> HardwareReadinessInput {
        HardwareReadinessInput {
            hardware_profile: Some("hpe-dl360".into()),
            site: Some("DEFRA".into()),
            support_status: Some("active".into()),
            firmware_baseline: Some("baseline-2026".into()),
            capacity_role: Some("compute".into()),
            owner: Some("dc-team".into()),
            evidence_manifest: Some("ev-1".into()),
            lifecycle_state: Some("in-service".into()),
            refresh_window: Some("2027-Q1".into()),
        }
    }

    #[test]
    fn records_lifecycle_for_complete_request() {
        let r = evaluate_hardware_readiness(&complete_input());
        assert_eq!(r.decision, "hardware-lifecycle-recorded");
        assert!(r.blocked_reasons.is_empty());
    }

    #[test]
    fn never_changes_live_hardware() {
        let r = evaluate_hardware_readiness(&complete_input());
        assert_ne!(r.decision, "admit");
        assert_ne!(r.decision, "execute");
        assert!(r.decision == "hardware-lifecycle-recorded" || r.decision == "block");
    }

    #[test]
    fn blocks_with_all_reasons_when_empty() {
        let r = evaluate_hardware_readiness(&HardwareReadinessInput::default());
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
    fn missing_firmware_baseline_alone_blocks() {
        let mut input = complete_input();
        input.firmware_baseline = None;
        let r = evaluate_hardware_readiness(&input);
        assert_eq!(r.decision, "block");
        assert!(
            r.blocked_reasons
                .contains(&"firmware-baseline-unknown".to_string())
        );
        assert!(!r.blocked_reasons.contains(&"site-unknown".to_string()));
    }

    #[test]
    fn whitespace_only_input_fails_its_guard() {
        let mut input = complete_input();
        input.capacity_role = Some("   ".into());
        let r = evaluate_hardware_readiness(&input);
        assert_eq!(r.decision, "block");
        assert!(
            r.blocked_reasons
                .contains(&"capacity-role-unknown".to_string())
        );
    }

    #[test]
    fn context_only_fields_do_not_affect_decision() {
        let mut bare = complete_input();
        bare.lifecycle_state = None;
        bare.refresh_window = None;
        let r = evaluate_hardware_readiness(&bare);
        assert_eq!(r.decision, "hardware-lifecycle-recorded");
        assert!(r.blocked_reasons.is_empty());
    }

    #[test]
    fn decision_values_are_block_or_lifecycle_recorded() {
        for d in [
            HardwareReadinessDecision::Block,
            HardwareReadinessDecision::HardwareLifecycleRecorded,
        ] {
            assert!(["block", "hardware-lifecycle-recorded"].contains(&d.as_str()));
        }
    }
}
