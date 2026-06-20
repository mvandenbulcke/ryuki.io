//! vCenter object PLACEMENT governance (dry-run plan).
//!
//! Turns the static `vcenter-object-placement` descriptor into a real engine:
//! given a proposed placement request it evaluates the contract's required guards
//! and, when met, produces a dry-run PLACEMENT PLAN that becomes approvable. By
//! contract this workflow NEVER places anything (the `no-live-vcenter-placement`
//! rule), so the decision is `block` or `placement-planned`, never an
//! admit-to-place; a separately-approved workflow performs any live placement.
//!
//! Three of the guards are DATA-BACKED, not mere presence checks:
//! - `site-known` validates the site against the [`site_registry`] UN/LOCODE set.
//! - `folder-policy-known` confirms the site is a GOVERNED catalog site (its OU /
//!   folder pattern is derivable via [`customization_spec_governance`]).
//! - `cluster-capacity-admitted` requires the capacity decision to be an actual
//!   admit (chaining from the cluster-capacity-admission gate), not just present.
//!
//! The remaining guards are INPUT presence checks or DRY-RUN-PRODUCED (the engine
//! generates those plan sections). PURE / dry-run: no I/O beyond the embedded
//! catalog/registry; redacted summaries only — never raw inventory or object IDs.

use crate::{customization_spec_governance, site_registry};
use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum PlacementDecision {
    /// A required guard is unmet — the placement plan cannot become approvable.
    Block,
    /// All guards met and the dry-run plan is produced; the placement plan is
    /// approvable. Live placement remains a separately-approved workflow.
    PlacementPlanned,
}

impl PlacementDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::PlacementPlanned => "placement-planned",
        }
    }
}

/// A proposed vCenter object-placement request. Every field is optional; an
/// absent (or, for the data-backed guards, invalid) input fails its guard.
#[derive(Debug, Clone, Default)]
pub struct PlacementInput {
    pub placement_scope: Option<String>,
    pub workload_profile: Option<String>,
    pub site: Option<String>,
    pub environment: Option<String>,
    pub criticality: Option<String>,
    pub owner: Option<String>,
    /// The cluster-capacity-admission outcome; must be an admit to proceed.
    pub capacity_decision: Option<String>,
    pub network_profile: Option<String>,
    pub storage_profile: Option<String>,
    pub tag_policy: Option<String>,
    pub evidence_manifest: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GuardStatus {
    pub name: String,
    pub satisfied: bool,
    /// `input` | `data-backed` | `dry-run-produced`.
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PlacementResult {
    pub decision: String,
    pub guards: Vec<GuardStatus>,
    pub blocked_reasons: Vec<String>,
    /// The dry-run plan sections produced when the plan becomes approvable.
    pub plan_sections: Vec<String>,
    pub reasons: Vec<String>,
}

/// Input presence guards: each maps to a contract `blockedReason` and BLOCKS when
/// its request field is absent.
const INPUT_GUARDS: &[(&str, &str)] = &[
    ("environment-known", "environment-unknown"),
    ("network-profile-known", "network-profile-missing"),
    ("storage-policy-known", "storage-policy-missing"),
    ("tag-policy-known", "tag-policy-missing"),
    ("evidence-redacted", "evidence-not-redacted"),
];

/// Guards the dry-run engine satisfies by producing the corresponding plan
/// section — no request input drives them.
const PRODUCED_GUARDS: &[&str] = &[
    "resource-pool-policy-known",
    "datastore-policy-known",
    "dry-run-plan-produced",
];

/// The dry-run plan sections produced once the placement plan is approvable.
const PLAN_SECTIONS: &[&str] = &[
    "placementSummary",
    "folderPlan",
    "clusterResourcePoolPlan",
    "datastoreStoragePolicyPlan",
    "networkPlan",
    "tagPolicyPlan",
    "policyExceptions",
    "evidenceReferences",
];

fn present(field: &Option<String>) -> bool {
    field.as_deref().is_some_and(|s| !s.trim().is_empty())
}

fn input_present(input: &PlacementInput, guard: &str) -> bool {
    match guard {
        "environment-known" => present(&input.environment),
        "network-profile-known" => present(&input.network_profile),
        "storage-policy-known" => present(&input.storage_profile),
        "tag-policy-known" => present(&input.tag_policy),
        "evidence-redacted" => present(&input.evidence_manifest),
        _ => false,
    }
}

/// Trimmed, upper-cased site code. UN/LOCODEs are conventionally uppercase, and
/// `site_registry::is_valid_site` is case-sensitive while
/// `safe_facts_for_site` is case-insensitive; normalizing here means both
/// data-backed site guards evaluate the SAME value and never disagree on case.
fn normalized_site(input: &PlacementInput) -> Option<String> {
    let s = input.site.as_deref()?.trim();
    (!s.is_empty()).then(|| s.to_ascii_uppercase())
}

/// The site is a recognised UN/LOCODE in the site registry.
fn site_known(input: &PlacementInput) -> bool {
    normalized_site(input).is_some_and(|s| site_registry::is_valid_site(&s))
}

/// The site is a GOVERNED catalog site whose folder/OU placement is derivable.
/// (Today the active-registry site set and the governed-catalog site set
/// coincide, so this guard and `site-known` agree in practice; they measure
/// distinct facts — registry validity vs folder derivability — and would diverge
/// if a site were registry-active but absent from the governed catalog.)
fn folder_policy_known(input: &PlacementInput) -> bool {
    normalized_site(input)
        .is_some_and(|s| customization_spec_governance::safe_facts_for_site(&s).is_some())
}

/// Cluster capacity admission was ACCEPTED (chains from the admission gate's
/// `admit` decision) — not merely that some decision was supplied.
fn capacity_admitted(input: &PlacementInput) -> bool {
    input.capacity_decision.as_deref().is_some_and(|c| {
        let c = c.trim().to_ascii_lowercase();
        c == "admit" || c == "admitted"
    })
}

/// Evaluate a proposed object-placement request. `block` when any required guard
/// is unmet; otherwise `placement-planned` — the dry-run plan is produced and
/// approvable. This engine NEVER returns an admit-to-place decision; live
/// placement is a separately-approved workflow.
pub fn evaluate_object_placement(input: &PlacementInput) -> PlacementResult {
    let mut guards = Vec::new();
    let mut blocked_reasons = Vec::new();

    // site-known is the first guard (data-backed), then the input presence guards.
    let site_ok = site_known(input);
    guards.push(GuardStatus {
        name: "site-known".into(),
        satisfied: site_ok,
        kind: "data-backed".into(),
    });
    if !site_ok {
        blocked_reasons.push("site-unknown".into());
    }

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

    // Remaining data-backed guards.
    let folder_ok = folder_policy_known(input);
    guards.push(GuardStatus {
        name: "folder-policy-known".into(),
        satisfied: folder_ok,
        kind: "data-backed".into(),
    });
    if !folder_ok {
        blocked_reasons.push("folder-policy-missing".into());
    }

    let capacity_ok = capacity_admitted(input);
    guards.push(GuardStatus {
        name: "cluster-capacity-admitted".into(),
        satisfied: capacity_ok,
        kind: "data-backed".into(),
    });
    if !capacity_ok {
        blocked_reasons.push("cluster-capacity-missing".into());
    }

    // Dry-run-produced guards: satisfied by the engine generating the plan.
    for name in PRODUCED_GUARDS {
        guards.push(GuardStatus {
            name: (*name).into(),
            satisfied: true,
            kind: "dry-run-produced".into(),
        });
    }

    let (decision, plan_sections, reason) = if blocked_reasons.is_empty() {
        (
            PlacementDecision::PlacementPlanned,
            PLAN_SECTIONS.iter().map(|s| (*s).to_string()).collect(),
            "Placement planned — dry-run plan produced and approvable; live placement is a separately-approved workflow".to_string(),
        )
    } else {
        (
            PlacementDecision::Block,
            Vec::new(),
            format!(
                "Blocked — {} placement readiness guard(s) unmet; no plan produced",
                blocked_reasons.len()
            ),
        )
    };

    PlacementResult {
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

    fn complete_input() -> PlacementInput {
        PlacementInput {
            placement_scope: Some("single-vm".into()),
            workload_profile: Some("general".into()),
            // DEFRA is both a valid UN/LOCODE site and a governed catalog site.
            site: Some("DEFRA".into()),
            environment: Some("prod".into()),
            criticality: Some("tier-2".into()),
            owner: Some("team-platform".into()),
            capacity_decision: Some("admit".into()),
            network_profile: Some("vlan-100".into()),
            storage_profile: Some("gold".into()),
            tag_policy: Some("standard".into()),
            evidence_manifest: Some("ev-1".into()),
        }
    }

    #[test]
    fn plans_placement_for_complete_request() {
        let r = evaluate_object_placement(&complete_input());
        assert_eq!(r.decision, "placement-planned");
        assert!(r.blocked_reasons.is_empty());
        assert_eq!(r.plan_sections.len(), PLAN_SECTIONS.len());
    }

    #[test]
    fn never_admits_to_place() {
        let r = evaluate_object_placement(&complete_input());
        assert_ne!(r.decision, "admit");
        assert!(r.decision == "placement-planned" || r.decision == "block");
    }

    #[test]
    fn unknown_site_blocks_site_and_folder() {
        let mut input = complete_input();
        input.site = Some("ZZZZZ".into());
        let r = evaluate_object_placement(&input);
        assert_eq!(r.decision, "block");
        // An ungoverned/invalid site fails both the registry check and the
        // governed-catalog folder derivation.
        assert!(r.blocked_reasons.contains(&"site-unknown".to_string()));
        assert!(
            r.blocked_reasons
                .contains(&"folder-policy-missing".to_string())
        );
    }

    #[test]
    fn capacity_not_admitted_blocks() {
        // A capacity decision that is present but NOT an admit (e.g. review/block)
        // must not let placement proceed — it chains from the admission gate.
        let mut input = complete_input();
        input.capacity_decision = Some("review".into());
        let r = evaluate_object_placement(&input);
        assert_eq!(r.decision, "block");
        assert!(
            r.blocked_reasons
                .contains(&"cluster-capacity-missing".to_string())
        );
    }

    #[test]
    fn capacity_admitted_accepts_admitted_variant() {
        let mut input = complete_input();
        input.capacity_decision = Some("ADMITTED".into());
        let r = evaluate_object_placement(&input);
        assert_eq!(r.decision, "placement-planned");
    }

    #[test]
    fn site_is_case_normalized_for_both_data_backed_guards() {
        // A lowercase site must satisfy BOTH site-known (registry, case-sensitive
        // on raw input) and folder-policy-known (catalog) consistently after
        // normalization — not pass one and fail the other.
        let mut input = complete_input();
        input.site = Some("  defra  ".into());
        let r = evaluate_object_placement(&input);
        assert_eq!(r.decision, "placement-planned");
        assert!(
            r.guards
                .iter()
                .filter(|g| g.name == "site-known" || g.name == "folder-policy-known")
                .all(|g| g.satisfied)
        );
    }

    #[test]
    fn blocks_when_input_guards_missing() {
        let input = PlacementInput {
            site: Some("DEFRA".into()),
            capacity_decision: Some("admit".into()),
            ..Default::default()
        };
        let r = evaluate_object_placement(&input);
        assert_eq!(r.decision, "block");
        assert!(r.plan_sections.is_empty());
        assert!(
            r.blocked_reasons
                .contains(&"environment-unknown".to_string())
        );
        assert!(
            r.blocked_reasons
                .contains(&"tag-policy-missing".to_string())
        );
        // site + capacity were valid, so those guards pass.
        assert!(!r.blocked_reasons.contains(&"site-unknown".to_string()));
        assert!(
            !r.blocked_reasons
                .contains(&"cluster-capacity-missing".to_string())
        );
    }

    #[test]
    fn whitespace_only_input_fails_its_guard() {
        let mut input = complete_input();
        input.tag_policy = Some("   ".into());
        let r = evaluate_object_placement(&input);
        assert_eq!(r.decision, "block");
        assert!(
            r.blocked_reasons
                .contains(&"tag-policy-missing".to_string())
        );
    }

    #[test]
    fn decision_values_are_block_or_placement_planned() {
        for d in [
            PlacementDecision::Block,
            PlacementDecision::PlacementPlanned,
        ] {
            assert!(["block", "placement-planned"].contains(&d.as_str()));
        }
    }
}
