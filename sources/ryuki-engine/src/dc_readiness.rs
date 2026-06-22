//! Operations datacenter-readiness REVIEW assessment (dry-run).
//!
//! Turns the static `operations/datacenter-readiness` descriptor into a real
//! engine: given a proposed datacenter-readiness request it evaluates the
//! contract's guards and decides `datacenter-readiness-recorded` (every criterion
//! met — the request is reviewed and ready to be put forward for a SEPARATELY-
//! approved live provisioning) or `block` (with the specific reasons). By contract
//! this NEVER provisions or changes live datacenter state — so there is no
//! admit-to-provision decision. (Distinct from the stateful `datacenter_readiness`
//! engine; this engine only records review readiness.)
//!
//! Guard kinds: every guard is an INPUT guard — it blocks when its request field
//! is absent, each mapped to a declared blockedReason. (The descriptor declares
//! `rack-capacity-unknown`, `power-cooling-not-reviewed` and
//! `firmware-baseline-unknown` reasons whose corresponding inputs are not in the
//! static requiredInputs list; the engine adds those inputs so the guards are
//! input-driven and their reasons reachable, rather than modeling a review
//! deliverable as always-satisfied.) The `support-coverage-unknown` blockedReason
//! has no required guard and is a posture reason this engine never emits.
//!
//! PURE / dry-run: no I/O, no live provisioning. Output is the decision + reasons
//! (redacted).

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum DcReadinessDecision {
    /// A required readiness input is unmet — the request cannot be put forward.
    Block,
    /// Every criterion is met; the datacenter-readiness request is reviewed and
    /// ready for a separately-approved live provisioning (still gated, never auto).
    DatacenterReadinessRecorded,
}

impl DcReadinessDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::DatacenterReadinessRecorded => "datacenter-readiness-recorded",
        }
    }
}

/// A proposed datacenter-readiness review request. Every field is optional; an
/// absent gated input fails its guard.
#[derive(Debug, Clone, Default)]
pub struct DcReadinessInput {
    pub site: Option<String>,
    pub owner: Option<String>,
    pub rack_capacity: Option<String>,
    pub power_cooling: Option<String>,
    pub network_scope: Option<String>,
    pub storage_scope: Option<String>,
    pub firmware_baseline: Option<String>,
    pub evidence_manifest: Option<String>,
    // Context-only — recorded, NOT gated (the contract declares no blockedReason
    // for them); the engine reaches its decision without reading these.
    pub requester: Option<String>,
    pub cluster_profile: Option<String>,
    pub hardware_profile: Option<String>,
    pub capacity_need: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GuardStatus {
    pub name: String,
    pub satisfied: bool,
    /// `input` (driven by a request field). This engine has only input guards.
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DcReadinessResult {
    pub decision: String,
    pub guards: Vec<GuardStatus>,
    pub blocked_reasons: Vec<String>,
    pub reasons: Vec<String>,
}

/// Input guards: each maps to a contract `blockedReason` and BLOCKS when its
/// request field is absent.
const INPUT_GUARDS: &[(&str, &str)] = &[
    ("site-known", "site-unknown"),
    ("owner-known", "owner-unknown"),
    ("rack-capacity-known", "rack-capacity-unknown"),
    ("power-cooling-reviewed", "power-cooling-not-reviewed"),
    ("network-readiness-known", "network-readiness-unknown"),
    ("storage-readiness-known", "storage-readiness-unknown"),
    ("firmware-baseline-known", "firmware-baseline-unknown"),
    ("evidence-redacted", "evidence-not-redacted"),
];

fn present(field: &Option<String>) -> bool {
    field.as_deref().is_some_and(|s| !s.trim().is_empty())
}

fn input_present(input: &DcReadinessInput, guard: &str) -> bool {
    match guard {
        "site-known" => present(&input.site),
        "owner-known" => present(&input.owner),
        "rack-capacity-known" => present(&input.rack_capacity),
        "power-cooling-reviewed" => present(&input.power_cooling),
        "network-readiness-known" => present(&input.network_scope),
        "storage-readiness-known" => present(&input.storage_scope),
        "firmware-baseline-known" => present(&input.firmware_baseline),
        "evidence-redacted" => present(&input.evidence_manifest),
        _ => false,
    }
}

/// Evaluate a proposed datacenter-readiness review request. `block` when any
/// required input guard is unmet; otherwise `datacenter-readiness-recorded` — every
/// criterion is met and the request is ready for a separately-approved live
/// provisioning. This engine NEVER provisions.
pub fn evaluate_dc_readiness(input: &DcReadinessInput) -> DcReadinessResult {
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
            DcReadinessDecision::DatacenterReadinessRecorded,
            "Datacenter readiness recorded — every criterion met; live provisioning remains a separately-approved step".to_string(),
        )
    } else {
        (
            DcReadinessDecision::Block,
            format!(
                "Blocked — {} required readiness criterion/criteria unmet",
                blocked_reasons.len()
            ),
        )
    };

    DcReadinessResult {
        decision: decision.as_str().into(),
        guards,
        blocked_reasons,
        reasons: vec![reason],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_input() -> DcReadinessInput {
        DcReadinessInput {
            site: Some("DEFRA".into()),
            owner: Some("dc-team".into()),
            rack_capacity: Some("12U-free".into()),
            power_cooling: Some("reviewed".into()),
            network_scope: Some("prod".into()),
            storage_scope: Some("vsan".into()),
            firmware_baseline: Some("baseline-2026".into()),
            evidence_manifest: Some("ev-1".into()),
            requester: Some("req-1".into()),
            cluster_profile: Some("compute".into()),
            hardware_profile: Some("dl360".into()),
            capacity_need: Some("8-nodes".into()),
        }
    }

    #[test]
    fn records_readiness_for_complete_request() {
        let r = evaluate_dc_readiness(&complete_input());
        assert_eq!(r.decision, "datacenter-readiness-recorded");
        assert!(r.blocked_reasons.is_empty());
    }

    #[test]
    fn never_provisions() {
        let r = evaluate_dc_readiness(&complete_input());
        assert_ne!(r.decision, "admit");
        assert_ne!(r.decision, "provision");
        assert!(r.decision == "datacenter-readiness-recorded" || r.decision == "block");
    }

    #[test]
    fn blocks_with_all_reasons_when_empty() {
        let r = evaluate_dc_readiness(&DcReadinessInput::default());
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
    fn missing_power_cooling_alone_blocks() {
        let mut input = complete_input();
        input.power_cooling = None;
        let r = evaluate_dc_readiness(&input);
        assert_eq!(r.decision, "block");
        assert!(
            r.blocked_reasons
                .contains(&"power-cooling-not-reviewed".to_string())
        );
        assert!(!r.blocked_reasons.contains(&"site-unknown".to_string()));
    }

    #[test]
    fn whitespace_only_input_fails_its_guard() {
        let mut input = complete_input();
        input.rack_capacity = Some("   ".into());
        let r = evaluate_dc_readiness(&input);
        assert_eq!(r.decision, "block");
        assert!(
            r.blocked_reasons
                .contains(&"rack-capacity-unknown".to_string())
        );
    }

    #[test]
    fn context_only_fields_do_not_affect_decision() {
        let mut bare = complete_input();
        bare.requester = None;
        bare.cluster_profile = None;
        bare.hardware_profile = None;
        bare.capacity_need = None;
        let r = evaluate_dc_readiness(&bare);
        assert_eq!(r.decision, "datacenter-readiness-recorded");
        assert!(r.blocked_reasons.is_empty());
    }

    #[test]
    fn decision_values_are_block_or_readiness_recorded() {
        for d in [
            DcReadinessDecision::Block,
            DcReadinessDecision::DatacenterReadinessRecorded,
        ] {
            assert!(["block", "datacenter-readiness-recorded"].contains(&d.as_str()));
        }
    }
}
