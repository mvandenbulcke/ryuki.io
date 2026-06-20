//! vSAN / ESXi (and Hyper-V / Proxmox) host lifecycle governance (dry-run plan).
//!
//! Turns the static `vsan-esxi-lifecycle` descriptor into a real engine: given a
//! proposed cluster/host lifecycle request (patch, firmware, maintenance-mode
//! sequencing) it evaluates the contract's required guards and, when met,
//! produces a dry-run LIFECYCLE PLAN that becomes approvable. By contract this
//! workflow NEVER executes — the `no-live-vsan-esxi-lifecycle` rule means it
//! never patches, remediates, enters maintenance mode, evacuates data, or
//! reconfigures clusters. So the decision is `block` or `lifecycle-planned`,
//! never an admit-to-execute; a separately-approved execution workflow performs
//! the live change.
//!
//! Guards: 10 INPUT guards (block when the request field is absent, each mapped
//! to a declared blockedReason), plus the platform-supported check
//! (`unsupported-hypervisor` when the platform is absent or not VMware/Hyper-V/
//! Proxmox), plus the DRY-RUN-PRODUCED guard `dry-run-plan-produced` (the engine
//! generates the plan, so it is ready by construction).
//!
//! PURE / dry-run: no I/O, no live lifecycle action. Output is redacted summaries
//! only — never hostnames, raw inventory rows, object identifiers, or payloads.

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum LifecycleDecision {
    /// A required input guard is unmet (or the hypervisor is unsupported) — the
    /// lifecycle plan cannot become approvable.
    Block,
    /// All guards met and the dry-run plan is produced; the lifecycle plan is
    /// approvable. Live execution remains a separately-approved workflow.
    LifecyclePlanned,
}

impl LifecycleDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::LifecyclePlanned => "lifecycle-planned",
        }
    }
}

/// A proposed vSAN/ESXi lifecycle request. Every field is optional; an absent
/// input fails its guard.
#[derive(Debug, Clone, Default)]
pub struct LifecycleInput {
    pub cluster_scope: Option<String>,
    pub site: Option<String>,
    /// VMware | Hyper-V | Proxmox (case-insensitive).
    pub hypervisor_platform: Option<String>,
    pub platform_profile: Option<String>,
    pub target_baseline: Option<String>,
    pub maintenance_window: Option<String>,
    pub capacity_decision: Option<String>,
    pub hardware_readiness: Option<String>,
    pub network_readiness: Option<String>,
    pub rollback_plan: Option<String>,
    pub evidence_manifest: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GuardStatus {
    pub name: String,
    pub satisfied: bool,
    /// `input` (driven by a request field) | `dry-run-produced` (engine-generated).
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct LifecycleResult {
    pub decision: String,
    pub guards: Vec<GuardStatus>,
    pub blocked_reasons: Vec<String>,
    /// The dry-run plan sections produced when the plan becomes approvable.
    pub plan_sections: Vec<String>,
    pub reasons: Vec<String>,
}

/// Input guards: each maps to a contract `blockedReason` and BLOCKS when its
/// input is absent.
const INPUT_GUARDS: &[(&str, &str)] = &[
    ("cluster-scope-known", "cluster-scope-missing"),
    ("site-known", "site-unknown"),
    ("platform-profile-known", "platform-profile-missing"),
    ("target-baseline-known", "target-baseline-missing"),
    ("hardware-readiness-reviewed", "hardware-readiness-missing"),
    ("network-readiness-reviewed", "network-readiness-missing"),
    ("capacity-admission-ready", "capacity-admission-missing"),
    ("maintenance-window-approved", "maintenance-window-missing"),
    ("rollback-plan-ready", "rollback-plan-missing"),
    ("evidence-redacted", "evidence-not-redacted"),
];

/// Hypervisors this contract supports (case-insensitive), per the catalog source
/// of truth (`vsan-esxi-lifecycle-contract.yaml`): VMware, Hyper-V, Proxmox. The
/// static descriptor JSON advertises a broader six-platform parity claim, but the
/// catalog is authoritative for the live evaluation.
const SUPPORTED_HYPERVISORS: &[&str] = &["vmware", "hyper-v", "proxmox"];

/// The dry-run plan sections produced once the lifecycle plan is approvable.
const PLAN_SECTIONS: &[&str] = &[
    "lifecycleSummary",
    "currentBaseline",
    "targetBaseline",
    "hardwareFirmwareReview",
    "networkStorageReadiness",
    "maintenanceModePlan",
    "capacityAndFailureDomainImpact",
    "rollbackPlan",
    "policyExceptions",
    "evidenceReferences",
];

fn present(field: &Option<String>) -> bool {
    field.as_deref().is_some_and(|s| !s.trim().is_empty())
}

fn input_present(input: &LifecycleInput, guard: &str) -> bool {
    match guard {
        "cluster-scope-known" => present(&input.cluster_scope),
        "site-known" => present(&input.site),
        "platform-profile-known" => present(&input.platform_profile),
        "target-baseline-known" => present(&input.target_baseline),
        "hardware-readiness-reviewed" => present(&input.hardware_readiness),
        "network-readiness-reviewed" => present(&input.network_readiness),
        "capacity-admission-ready" => present(&input.capacity_decision),
        "maintenance-window-approved" => present(&input.maintenance_window),
        "rollback-plan-ready" => present(&input.rollback_plan),
        "evidence-redacted" => present(&input.evidence_manifest),
        _ => false,
    }
}

/// True when a supported hypervisor platform is identified. An absent platform is
/// treated as unsupported (no supported hypervisor confirmed), since the contract
/// declares no separate "missing hypervisor" reason.
fn hypervisor_supported(input: &LifecycleInput) -> bool {
    input
        .hypervisor_platform
        .as_deref()
        .is_some_and(|p| SUPPORTED_HYPERVISORS.contains(&p.trim().to_ascii_lowercase().as_str()))
}

/// Evaluate a proposed vSAN/ESXi lifecycle request. `block` when any required
/// input guard is unmet or the hypervisor is unsupported; otherwise
/// `lifecycle-planned` — the dry-run plan is produced and approvable. This engine
/// NEVER returns an admit-to-execute decision; live change is a separate workflow.
pub fn evaluate_vsan_esxi_lifecycle(input: &LifecycleInput) -> LifecycleResult {
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

    // Platform-supported check (no dedicated guard name in the contract, but it
    // owns the `unsupported-hypervisor` blockedReason).
    if !hypervisor_supported(input) {
        blocked_reasons.push("unsupported-hypervisor".into());
    }

    // Dry-run-produced guard: satisfied by the engine generating the plan.
    guards.push(GuardStatus {
        name: "dry-run-plan-produced".into(),
        satisfied: true,
        kind: "dry-run-produced".into(),
    });

    let (decision, plan_sections, reason) = if blocked_reasons.is_empty() {
        (
            LifecycleDecision::LifecyclePlanned,
            PLAN_SECTIONS.iter().map(|s| (*s).to_string()).collect(),
            "Lifecycle planned — dry-run plan produced and approvable; live execution is a separately-approved workflow".to_string(),
        )
    } else {
        (
            LifecycleDecision::Block,
            Vec::new(),
            format!(
                "Blocked — {} lifecycle readiness guard(s) unmet; no plan produced",
                blocked_reasons.len()
            ),
        )
    };

    LifecycleResult {
        decision: decision.as_str().into(),
        guards,
        blocked_reasons,
        plan_sections,
        reasons: vec![reason],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_input() -> LifecycleInput {
        LifecycleInput {
            cluster_scope: Some("defra-general-cluster".into()),
            site: Some("DEFRA".into()),
            hypervisor_platform: Some("VMware".into()),
            platform_profile: Some("vsan-esa".into()),
            target_baseline: Some("esxi-8.0u2".into()),
            maintenance_window: Some("2026-07-01T00:00:00Z".into()),
            capacity_decision: Some("admitted".into()),
            hardware_readiness: Some("reviewed".into()),
            network_readiness: Some("reviewed".into()),
            rollback_plan: Some("snapshot+revert".into()),
            evidence_manifest: Some("ev-1".into()),
        }
    }

    #[test]
    fn plans_lifecycle_for_complete_request() {
        let r = evaluate_vsan_esxi_lifecycle(&complete_input());
        assert_eq!(r.decision, "lifecycle-planned");
        assert!(r.blocked_reasons.is_empty());
        assert_eq!(r.plan_sections.len(), PLAN_SECTIONS.len());
    }

    #[test]
    fn never_admits_to_execute() {
        let r = evaluate_vsan_esxi_lifecycle(&complete_input());
        assert_ne!(r.decision, "admit");
        assert!(r.decision == "lifecycle-planned" || r.decision == "block");
    }

    #[test]
    fn blocks_when_input_guards_missing() {
        let input = LifecycleInput {
            site: Some("DEFRA".into()),
            hypervisor_platform: Some("VMware".into()),
            ..Default::default()
        };
        let r = evaluate_vsan_esxi_lifecycle(&input);
        assert_eq!(r.decision, "block");
        assert!(r.plan_sections.is_empty());
        assert!(
            r.blocked_reasons
                .contains(&"cluster-scope-missing".to_string())
        );
        assert!(
            r.blocked_reasons
                .contains(&"rollback-plan-missing".to_string())
        );
        // site was supplied -> its guard passes.
        assert!(!r.blocked_reasons.contains(&"site-unknown".to_string()));
        // VMware is supported -> no unsupported-hypervisor.
        assert!(
            !r.blocked_reasons
                .contains(&"unsupported-hypervisor".to_string())
        );
    }

    #[test]
    fn unsupported_hypervisor_blocks() {
        let mut input = complete_input();
        input.hypervisor_platform = Some("KVM".into());
        let r = evaluate_vsan_esxi_lifecycle(&input);
        assert_eq!(r.decision, "block");
        assert!(
            r.blocked_reasons
                .contains(&"unsupported-hypervisor".to_string())
        );
    }

    #[test]
    fn absent_hypervisor_is_unsupported() {
        let mut input = complete_input();
        input.hypervisor_platform = None;
        let r = evaluate_vsan_esxi_lifecycle(&input);
        assert_eq!(r.decision, "block");
        assert!(
            r.blocked_reasons
                .contains(&"unsupported-hypervisor".to_string())
        );
    }

    #[test]
    fn supported_hypervisor_is_case_insensitive() {
        let mut input = complete_input();
        input.hypervisor_platform = Some("  hyper-v  ".into());
        let r = evaluate_vsan_esxi_lifecycle(&input);
        assert_eq!(r.decision, "lifecycle-planned");
    }

    #[test]
    fn whitespace_only_input_fails_its_guard() {
        let mut input = complete_input();
        input.rollback_plan = Some("   ".into());
        let r = evaluate_vsan_esxi_lifecycle(&input);
        assert_eq!(r.decision, "block");
        assert!(
            r.blocked_reasons
                .contains(&"rollback-plan-missing".to_string())
        );
    }

    #[test]
    fn decision_values_are_block_or_lifecycle_planned() {
        for d in [
            LifecycleDecision::Block,
            LifecycleDecision::LifecyclePlanned,
        ] {
            assert!(["block", "lifecycle-planned"].contains(&d.as_str()));
        }
    }
}
