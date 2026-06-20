//! VM decommission QUARANTINE governance (dry-run plan).
//!
//! Turns the static `vm-decommission-quarantine` descriptor into a real engine:
//! given a proposed decommission request it evaluates the contract's required
//! guards and produces a dry-run QUARANTINE PLAN. By contract this workflow never
//! deletes anything — `final-disposition-blocked` is a PERMANENT safety hold:
//! deletion requires a separately-approved execution workflow, so the best
//! outcome here is `quarantine-planned`, never an admit-to-delete.
//!
//! Three guard kinds:
//! - INPUT guards (block when the corresponding input is absent): CMDB CI, owner
//!   approval, dependency review, backup retention, quarantine window, evidence.
//! - DRY-RUN-PRODUCED guards (the engine generates these plan sections, so they
//!   are ready by construction): request preflight, monitoring-disable plan,
//!   rollback plan.
//! - The permanent hold: final-disposition-blocked (always in place). The
//!   catalog lists this name in BOTH `requiredGuards` and `blockedReasons`; as a
//!   required guard it must be SATISFIED for planning to proceed, so the engine
//!   surfaces it as an always-satisfied permanent-hold guard plus a standing
//!   `final_disposition: "blocked"` field — never as a `blocked_reasons` entry.
//!
//! PURE / dry-run: no I/O, no live decommission/delete. Output is redacted
//! summaries only — never VM names, raw inventory rows, or object identifiers.

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum QuarantineDecision {
    /// A required input guard is unmet — quarantine planning cannot proceed.
    Block,
    /// All input guards met and the dry-run plan is produced; the quarantine plan
    /// is ready, with final disposition (deletion) held for separate approval.
    QuarantinePlanned,
}

impl QuarantineDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::QuarantinePlanned => "quarantine-planned",
        }
    }
}

/// A proposed VM decommission-quarantine request. Every field is optional; an
/// absent input fails its guard.
#[derive(Debug, Clone, Default)]
pub struct DecommissionQuarantineInput {
    pub ci_key: Option<String>,
    pub target_scope: Option<String>,
    pub site: Option<String>,
    pub environment: Option<String>,
    pub owner: Option<String>,
    pub business_justification: Option<String>,
    pub dependency_review: Option<String>,
    pub backup_retention_need: Option<String>,
    pub quarantine_window: Option<String>,
    pub cmdb_context: Option<String>,
    pub evidence_manifest: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GuardStatus {
    pub name: String,
    pub satisfied: bool,
    /// `input` (driven by a request field) | `dry-run-produced` (the engine
    /// generates this plan section) | `permanent-hold` (always in place).
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DecommissionQuarantineResult {
    pub decision: String,
    /// Always `"blocked"` — deletion is never auto-approved by this contract.
    pub final_disposition: String,
    pub guards: Vec<GuardStatus>,
    pub blocked_reasons: Vec<String>,
    /// The dry-run plan sections this engine produces when planning proceeds.
    pub plan_sections: Vec<String>,
    pub reasons: Vec<String>,
}

/// Input guards: each maps to a contract `blockedReason` and BLOCKS when its
/// input is absent.
const INPUT_GUARDS: &[(&str, &str)] = &[
    ("cmdb-ci-known", "cmdb-ci-unknown"),
    ("owner-approval-assigned", "owner-approval-missing"),
    ("dependency-impact-reviewed", "dependency-review-missing"),
    ("backup-retention-reviewed", "backup-retention-missing"),
    ("quarantine-window-approved", "quarantine-window-missing"),
    ("evidence-redacted", "evidence-not-redacted"),
];

/// Guards the dry-run engine satisfies by PRODUCING the corresponding plan
/// section — there is no request input for them; the plan itself is the evidence.
const PRODUCED_GUARDS: &[&str] = &[
    "request-preflight-ready",
    "monitoring-disable-reviewed",
    "rollback-plan-ready",
];

/// The dry-run plan sections produced once quarantine planning proceeds.
const PLAN_SECTIONS: &[&str] = &[
    "quarantineSummary",
    "dependencyReview",
    "backupRetentionReview",
    "monitoringPlan",
    "cmdbRetirementPlan",
    "quarantineWindow",
    "rollbackPlan",
    "finalDispositionHold",
    "evidenceReferences",
];

fn present(field: &Option<String>) -> bool {
    field.as_deref().is_some_and(|s| !s.trim().is_empty())
}

fn input_present(input: &DecommissionQuarantineInput, guard: &str) -> bool {
    match guard {
        "cmdb-ci-known" => present(&input.ci_key),
        "owner-approval-assigned" => present(&input.owner),
        "dependency-impact-reviewed" => present(&input.dependency_review),
        "backup-retention-reviewed" => present(&input.backup_retention_need),
        "quarantine-window-approved" => present(&input.quarantine_window),
        "evidence-redacted" => present(&input.evidence_manifest),
        _ => false,
    }
}

/// Evaluate a proposed decommission-quarantine request. `block` when any required
/// input guard is unmet; otherwise `quarantine-planned` — the dry-run plan is
/// produced and final disposition (deletion) is held for a separately-approved
/// execution workflow. This engine NEVER returns an admit-to-delete decision.
pub fn evaluate_decommission_quarantine(
    input: &DecommissionQuarantineInput,
) -> DecommissionQuarantineResult {
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

    // Dry-run-produced guards: satisfied by the engine generating the plan.
    for name in PRODUCED_GUARDS {
        guards.push(GuardStatus {
            name: (*name).into(),
            satisfied: true,
            kind: "dry-run-produced".into(),
        });
    }

    // Permanent hold: final disposition (deletion) is always blocked by contract.
    guards.push(GuardStatus {
        name: "final-disposition-blocked".into(),
        satisfied: true,
        kind: "permanent-hold".into(),
    });

    let (decision, plan_sections, reason) = if blocked_reasons.is_empty() {
        (
            QuarantineDecision::QuarantinePlanned,
            PLAN_SECTIONS.iter().map(|s| (*s).to_string()).collect(),
            "Quarantine planned — dry-run plan produced; final disposition (deletion) is held for a separately-approved execution workflow".to_string(),
        )
    } else {
        (
            QuarantineDecision::Block,
            Vec::new(),
            format!(
                "Blocked — {} required quarantine guard(s) unmet; no plan produced",
                blocked_reasons.len()
            ),
        )
    };

    DecommissionQuarantineResult {
        decision: decision.as_str().into(),
        // Deletion is structurally held regardless of the planning decision.
        final_disposition: "blocked".into(),
        guards,
        blocked_reasons,
        plan_sections,
        reasons: vec![reason],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_input() -> DecommissionQuarantineInput {
        DecommissionQuarantineInput {
            ci_key: Some("CI-1".into()),
            target_scope: Some("single-vm".into()),
            site: Some("DEFRA".into()),
            environment: Some("prod".into()),
            owner: Some("team-platform".into()),
            business_justification: Some("end of life".into()),
            dependency_review: Some("reviewed".into()),
            backup_retention_need: Some("90d".into()),
            quarantine_window: Some("2026-07-01..2026-07-30".into()),
            cmdb_context: Some("ctx".into()),
            evidence_manifest: Some("ev-1".into()),
        }
    }

    #[test]
    fn plans_quarantine_for_complete_request() {
        let r = evaluate_decommission_quarantine(&complete_input());
        assert_eq!(r.decision, "quarantine-planned");
        assert!(r.blocked_reasons.is_empty());
        assert_eq!(r.plan_sections.len(), PLAN_SECTIONS.len());
        // Final disposition is ALWAYS held, even on a clean plan.
        assert_eq!(r.final_disposition, "blocked");
    }

    #[test]
    fn never_admits_to_delete() {
        // Even a perfect request must not yield a delete-approved decision.
        let r = evaluate_decommission_quarantine(&complete_input());
        assert_ne!(r.decision, "admit");
        assert_eq!(r.final_disposition, "blocked");
        assert!(
            r.guards
                .iter()
                .any(|g| g.name == "final-disposition-blocked" && g.satisfied)
        );
    }

    #[test]
    fn blocks_when_input_guards_missing() {
        let input = DecommissionQuarantineInput {
            ci_key: Some("CI-1".into()),
            ..Default::default()
        };
        let r = evaluate_decommission_quarantine(&input);
        assert_eq!(r.decision, "block");
        assert!(r.plan_sections.is_empty());
        assert!(
            r.blocked_reasons
                .contains(&"owner-approval-missing".to_string())
        );
        assert!(
            r.blocked_reasons
                .contains(&"dependency-review-missing".to_string())
        );
        assert!(
            r.blocked_reasons
                .contains(&"evidence-not-redacted".to_string())
        );
        // CI was supplied, so its guard is satisfied.
        assert!(!r.blocked_reasons.contains(&"cmdb-ci-unknown".to_string()));
    }

    #[test]
    fn whitespace_only_input_fails_its_guard() {
        let mut input = complete_input();
        input.owner = Some("   ".into());
        let r = evaluate_decommission_quarantine(&input);
        assert_eq!(r.decision, "block");
        assert!(
            r.blocked_reasons
                .contains(&"owner-approval-missing".to_string())
        );
    }

    #[test]
    fn produced_guards_are_always_ready() {
        // The dry-run-produced guards need no input and are ready by construction.
        let r = evaluate_decommission_quarantine(&complete_input());
        for name in PRODUCED_GUARDS {
            assert!(
                r.guards
                    .iter()
                    .any(|g| &g.name == name && g.satisfied && g.kind == "dry-run-produced"),
                "produced guard {name} must be present and satisfied"
            );
        }
    }

    #[test]
    fn decision_values_are_block_or_quarantine_planned() {
        for d in [
            QuarantineDecision::Block,
            QuarantineDecision::QuarantinePlanned,
        ] {
            assert!(["block", "quarantine-planned"].contains(&d.as_str()));
        }
    }
}
