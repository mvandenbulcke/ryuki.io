//! Operations network VLAN/port-group provisioning READINESS assessment (dry-run).
//!
//! Turns the static `operations/network-vlan` descriptor into a real engine: given
//! a proposed VLAN / port-group provisioning request it evaluates the contract's
//! readiness guards and decides `vlan-plan-recorded` (every criterion met — the
//! plan is reviewed and ready to be put forward for a SEPARATELY-approved live
//! network change) or `block` (with the specific reasons). By contract this NEVER
//! calls a provider or changes live network state — so there is no
//! admit-to-provision decision.
//!
//! Guard kinds: every guard is an INPUT guard — it blocks when its request field
//! is absent, each mapped to a declared blockedReason. There are no structural
//! guards: the descriptor declares a `*-missing`/`*-unknown` reason for every
//! required guard.
//!
//! PURE / dry-run: no I/O, no live network change. Output is the decision +
//! reasons (redacted) — never raw inventory rows or network identifiers.

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum VlanDecision {
    /// A required readiness input is unmet — the plan cannot be put forward.
    Block,
    /// Every criterion is met; the VLAN/port-group plan is reviewed and ready for
    /// a separately-approved live network change (still gated, never auto-applied).
    VlanPlanRecorded,
}

impl VlanDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::VlanPlanRecorded => "vlan-plan-recorded",
        }
    }
}

/// A proposed VLAN/port-group provisioning readiness request. Every field is
/// optional; an absent input fails its guard.
#[derive(Debug, Clone, Default)]
pub struct NetworkVlanInput {
    pub site: Option<String>,
    pub network_scope: Option<String>,
    /// Informs the switchport-capacity review.
    pub workload_profile: Option<String>,
    /// Informs the segmentation review.
    pub platform_profile: Option<String>,
    pub vlan_policy: Option<String>,
    pub portgroup_policy: Option<String>,
    pub redundancy_requirement: Option<String>,
    pub maintenance_window: Option<String>,
    pub owner: Option<String>,
    pub evidence_manifest: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GuardStatus {
    pub name: String,
    pub satisfied: bool,
    /// `input` (driven by a request field). This engine has only input guards.
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct NetworkVlanResult {
    pub decision: String,
    pub guards: Vec<GuardStatus>,
    pub blocked_reasons: Vec<String>,
    pub reasons: Vec<String>,
}

/// Input guards: each maps to a contract `blockedReason` and BLOCKS when its
/// request field is absent.
const INPUT_GUARDS: &[(&str, &str)] = &[
    ("site-known", "site-unknown"),
    ("network-scope-known", "network-scope-missing"),
    ("vlan-catalog-reviewed", "vlan-catalog-missing"),
    ("portgroup-policy-reviewed", "portgroup-policy-missing"),
    (
        "switchport-capacity-reviewed",
        "switchport-capacity-unknown",
    ),
    ("uplink-redundancy-reviewed", "uplink-redundancy-unknown"),
    ("segmentation-reviewed", "segmentation-unknown"),
    ("maintenance-window-known", "maintenance-window-missing"),
    ("owner-known", "owner-unknown"),
    ("evidence-redacted", "evidence-not-redacted"),
];

fn present(field: &Option<String>) -> bool {
    field.as_deref().is_some_and(|s| !s.trim().is_empty())
}

fn input_present(input: &NetworkVlanInput, guard: &str) -> bool {
    match guard {
        "site-known" => present(&input.site),
        "network-scope-known" => present(&input.network_scope),
        "vlan-catalog-reviewed" => present(&input.vlan_policy),
        "portgroup-policy-reviewed" => present(&input.portgroup_policy),
        "switchport-capacity-reviewed" => present(&input.workload_profile),
        "uplink-redundancy-reviewed" => present(&input.redundancy_requirement),
        "segmentation-reviewed" => present(&input.platform_profile),
        "maintenance-window-known" => present(&input.maintenance_window),
        "owner-known" => present(&input.owner),
        "evidence-redacted" => present(&input.evidence_manifest),
        _ => false,
    }
}

/// Evaluate a proposed VLAN/port-group provisioning readiness request. `block`
/// when any required input guard is unmet; otherwise `vlan-plan-recorded` — every
/// criterion is met and the plan is ready for a separately-approved live network
/// change. This engine NEVER changes live network state.
pub fn evaluate_network_vlan(input: &NetworkVlanInput) -> NetworkVlanResult {
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
            VlanDecision::VlanPlanRecorded,
            "VLAN plan recorded — every criterion met; live network change remains a separately-approved step".to_string(),
        )
    } else {
        (
            VlanDecision::Block,
            format!(
                "Blocked — {} required readiness criterion/criteria unmet",
                blocked_reasons.len()
            ),
        )
    };

    NetworkVlanResult {
        decision: decision.as_str().into(),
        guards,
        blocked_reasons,
        reasons: vec![reason],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_input() -> NetworkVlanInput {
        NetworkVlanInput {
            site: Some("DEFRA".into()),
            network_scope: Some("prod-east".into()),
            workload_profile: Some("db-tier".into()),
            platform_profile: Some("vmware-nsx".into()),
            vlan_policy: Some("vlan-cat-1".into()),
            portgroup_policy: Some("pg-policy-1".into()),
            redundancy_requirement: Some("dual-uplink".into()),
            maintenance_window: Some("2026-12-31T22:00Z".into()),
            owner: Some("net-team".into()),
            evidence_manifest: Some("ev-1".into()),
        }
    }

    #[test]
    fn records_plan_for_complete_request() {
        let r = evaluate_network_vlan(&complete_input());
        assert_eq!(r.decision, "vlan-plan-recorded");
        assert!(r.blocked_reasons.is_empty());
    }

    #[test]
    fn never_changes_live_network() {
        let r = evaluate_network_vlan(&complete_input());
        assert_ne!(r.decision, "admit");
        assert_ne!(r.decision, "provision");
        assert!(r.decision == "vlan-plan-recorded" || r.decision == "block");
    }

    #[test]
    fn blocks_with_all_reasons_when_empty() {
        let r = evaluate_network_vlan(&NetworkVlanInput::default());
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
    fn missing_segmentation_alone_blocks() {
        let mut input = complete_input();
        input.platform_profile = None;
        let r = evaluate_network_vlan(&input);
        assert_eq!(r.decision, "block");
        assert!(
            r.blocked_reasons
                .contains(&"segmentation-unknown".to_string())
        );
        assert!(!r.blocked_reasons.contains(&"site-unknown".to_string()));
    }

    #[test]
    fn whitespace_only_input_fails_its_guard() {
        let mut input = complete_input();
        input.vlan_policy = Some("   ".into());
        let r = evaluate_network_vlan(&input);
        assert_eq!(r.decision, "block");
        assert!(
            r.blocked_reasons
                .contains(&"vlan-catalog-missing".to_string())
        );
    }

    #[test]
    fn all_guards_are_input_kind() {
        let r = evaluate_network_vlan(&complete_input());
        assert_eq!(r.guards.len(), INPUT_GUARDS.len());
        assert!(r.guards.iter().all(|g| g.kind == "input" && g.satisfied));
    }

    #[test]
    fn decision_values_are_block_or_plan_recorded() {
        for d in [VlanDecision::Block, VlanDecision::VlanPlanRecorded] {
            assert!(["block", "vlan-plan-recorded"].contains(&d.as_str()));
        }
    }
}
