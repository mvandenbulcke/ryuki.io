//! ServiceNow future-API integration READINESS assessment (dry-run).
//!
//! Turns the static `servicenow-future-api` descriptor into a real engine: given a
//! proposed future-API integration request it evaluates the contract's readiness
//! guards and decides `readiness-recorded` (every criterion met — ready to be put
//! forward for a SEPARATELY-approved live-API enablement) or `block` (with the
//! specific reasons). By contract this NEVER calls ServiceNow, writes import sets,
//! mutates tickets, or syncs status — so there is no admit-to-enable decision;
//! `apiMode` is approval-readiness-only.
//!
//! Guard kinds:
//! - INPUT guards block when the request field is absent (approval record, secret
//!   reference, table-mapping summary, ROLLBACK plan, evidence manifest), each
//!   mapped to a declared blockedReason. Rollback readiness is a reviewer
//!   DELIVERABLE the catalog rule `approval-before-api-enablement` demands on
//!   equal footing with approval and table mapping, so it is input-gated (not
//!   structural).
//! - STRUCTURAL guards are satisfied by the dry-run posture itself — instance
//!   identifiers are always externalized, payloads are always redaction-reviewed,
//!   and the dry-run contract is in force. (These ARE mechanically guaranteed by
//!   the engine; unlike a rollback plan, they need no operator input.)
//! - `integration_scope` / `instance_profile` / `owner` are recorded as context
//!   only and are NOT gates (the contract declares no blockedReason for them).
//!
//! PURE / dry-run: no I/O, no live API call. Output is the decision + reasons
//! (redacted) — never instance URLs, table names, sys IDs, payloads, or secrets;
//! authentication is referenced by secret HANDLE only, never a value.

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum ReadinessDecision {
    /// A required readiness input is unmet — the integration cannot be put forward.
    Block,
    /// Every readiness criterion is met; the integration is ready for a
    /// separately-approved live-API enablement (still gated, never auto-enabled).
    ReadinessRecorded,
}

impl ReadinessDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::ReadinessRecorded => "readiness-recorded",
        }
    }
}

/// A proposed future-API integration readiness request. Every field is optional;
/// an absent input fails its guard.
#[derive(Debug, Clone, Default)]
pub struct FutureApiInput {
    pub approval_record: Option<String>,
    /// A secret HANDLE/reference only — never a credential value.
    pub secret_reference: Option<String>,
    pub table_mapping_summary: Option<String>,
    /// Operator-supplied rollback plan — a reviewer DELIVERABLE, input-gated.
    pub rollback_plan: Option<String>,
    pub evidence_manifest: Option<String>,
    // Context-only — recorded, NOT gated (the contract declares no blockedReason
    // for them); the engine reaches its decision without reading these.
    pub integration_scope: Option<String>,
    pub instance_profile: Option<String>,
    pub owner: Option<String>,
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
pub struct FutureApiResult {
    pub decision: String,
    pub guards: Vec<GuardStatus>,
    pub blocked_reasons: Vec<String>,
    pub reasons: Vec<String>,
}

/// Input guards: each maps to a contract `blockedReason` and BLOCKS when its
/// request field is absent.
const INPUT_GUARDS: &[(&str, &str)] = &[
    ("live-api-approval-recorded", "approval-missing"),
    ("secret-reference-ready", "secret-reference-missing"),
    ("table-mapping-reviewed", "table-mapping-missing"),
    ("rollback-plan-ready", "rollback-plan-missing"),
    ("evidence-redacted", "evidence-not-redacted"),
];

/// Guards satisfied by the dry-run posture itself — there is no request input for
/// them because the engine mechanically guarantees the property (identifiers
/// externalized, payloads redacted, dry-run contract in force). Unlike a rollback
/// plan, none of these is an operator deliverable, so none is input-gated.
const STRUCTURAL_GUARDS: &[&str] = &[
    "instance-identifiers-externalized",
    "payload-redaction-reviewed",
    "dry-run-contract-reviewed",
];

fn present(field: &Option<String>) -> bool {
    field.as_deref().is_some_and(|s| !s.trim().is_empty())
}

fn input_present(input: &FutureApiInput, guard: &str) -> bool {
    match guard {
        "live-api-approval-recorded" => present(&input.approval_record),
        "secret-reference-ready" => present(&input.secret_reference),
        "table-mapping-reviewed" => present(&input.table_mapping_summary),
        "rollback-plan-ready" => present(&input.rollback_plan),
        "evidence-redacted" => present(&input.evidence_manifest),
        _ => false,
    }
}

/// Evaluate a proposed future-API integration readiness request. `block` when any
/// required input guard is unmet; otherwise `readiness-recorded` — every criterion
/// is met and the integration is ready for a separately-approved live-API
/// enablement. This engine NEVER enables the live API.
pub fn evaluate_future_api(input: &FutureApiInput) -> FutureApiResult {
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
            ReadinessDecision::ReadinessRecorded,
            "Readiness recorded — every criterion met; live-API enablement remains a separately-approved step".to_string(),
        )
    } else {
        (
            ReadinessDecision::Block,
            format!(
                "Blocked — {} required readiness criterion/criteria unmet",
                blocked_reasons.len()
            ),
        )
    };

    FutureApiResult {
        decision: decision.as_str().into(),
        guards,
        blocked_reasons,
        reasons: vec![reason],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_input() -> FutureApiInput {
        FutureApiInput {
            approval_record: Some("CHG-approved".into()),
            secret_reference: Some("secret-handle://snow".into()),
            table_mapping_summary: Some("cmdb_ci -> normalized".into()),
            rollback_plan: Some("rollback-runbook-v1".into()),
            evidence_manifest: Some("ev-1".into()),
            integration_scope: Some("request-callback".into()),
            instance_profile: Some("prod-instance-profile".into()),
            owner: Some("team-platform".into()),
        }
    }

    #[test]
    fn records_readiness_for_complete_request() {
        let r = evaluate_future_api(&complete_input());
        assert_eq!(r.decision, "readiness-recorded");
        assert!(r.blocked_reasons.is_empty());
    }

    #[test]
    fn never_enables_live_api() {
        let r = evaluate_future_api(&complete_input());
        assert_ne!(r.decision, "admit");
        assert!(r.decision == "readiness-recorded" || r.decision == "block");
    }

    #[test]
    fn blocks_when_input_guards_missing() {
        let input = FutureApiInput {
            integration_scope: Some("request-callback".into()),
            owner: Some("team-platform".into()),
            ..Default::default()
        };
        let r = evaluate_future_api(&input);
        assert_eq!(r.decision, "block");
        for reason in [
            "approval-missing",
            "secret-reference-missing",
            "table-mapping-missing",
            "rollback-plan-missing",
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
    fn missing_approval_alone_blocks() {
        let mut input = complete_input();
        input.approval_record = None;
        let r = evaluate_future_api(&input);
        assert_eq!(r.decision, "block");
        assert!(r.blocked_reasons.contains(&"approval-missing".to_string()));
        // The other input guards are still satisfied.
        assert!(
            !r.blocked_reasons
                .contains(&"secret-reference-missing".to_string())
        );
    }

    #[test]
    fn missing_rollback_plan_alone_blocks() {
        // Rollback readiness is an operator deliverable the catalog rule demands
        // on equal footing with approval/table-mapping, so its blockedReason must
        // be reachable (not a never-emitted structural guard).
        let mut input = complete_input();
        input.rollback_plan = None;
        let r = evaluate_future_api(&input);
        assert_eq!(r.decision, "block");
        assert!(
            r.blocked_reasons
                .contains(&"rollback-plan-missing".to_string())
        );
    }

    #[test]
    fn context_only_fields_do_not_affect_decision() {
        // integration_scope / instance_profile / owner are recorded as context
        // and must never change the gate outcome.
        let mut bare = complete_input();
        bare.integration_scope = None;
        bare.instance_profile = None;
        bare.owner = None;
        let r = evaluate_future_api(&bare);
        assert_eq!(r.decision, "readiness-recorded");
        assert!(r.blocked_reasons.is_empty());
    }

    #[test]
    fn whitespace_only_input_fails_its_guard() {
        let mut input = complete_input();
        input.secret_reference = Some("   ".into());
        let r = evaluate_future_api(&input);
        assert_eq!(r.decision, "block");
        assert!(
            r.blocked_reasons
                .contains(&"secret-reference-missing".to_string())
        );
    }

    #[test]
    fn structural_guards_are_always_satisfied() {
        let r = evaluate_future_api(&complete_input());
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
    fn decision_values_are_block_or_readiness_recorded() {
        for d in [
            ReadinessDecision::Block,
            ReadinessDecision::ReadinessRecorded,
        ] {
            assert!(["block", "readiness-recorded"].contains(&d.as_str()));
        }
    }
}
