//! Catalog-driven policy guardrail evaluation.
//!
//! The platform advertises policy-driven governance, but the hard validation in
//! `request_lifecycle::validate_request` hand-transcribes a couple of rule IDs.
//! This module makes the guardrail catalog (`catalog/policy-guardrails.yaml`)
//! a REAL, evaluable engine: it parses the embedded catalog and reports, per
//! request + workflow, which guardrail rules are satisfied.
//!
//! It is PURE: the catalog is embedded at compile time (`include_str!`) and
//! parsed once into an immutable `LazyLock`; evaluation performs no I/O. It is
//! ADDITIVE — informational policy-readiness reporting. It deliberately does NOT
//! change `validate_request`'s hard gate (many rules require inputs like
//! `country`/`ouPlacement`/`backupPolicy` that a bare request lacks, so gating on
//! the full rule set would over-enforce; promoting rules to hard gates is an
//! owner-owned policy decision).

use crate::models::Request;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

/// The parsed guardrail catalog. Unknown YAML fields (policyFamilies,
/// futureWorkflowIds, per-rule evidence, …) are ignored by serde.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyGuardrails {
    pub version: u32,
    pub status: String,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PolicyRule {
    pub id: String,
    pub family: String,
    pub priority: String,
    #[serde(rename = "appliesTo", default)]
    pub applies_to: Vec<String>,
    #[serde(rename = "requiredInputs", default)]
    pub required_inputs: Vec<String>,
    /// The decision tier as authored in the catalog: `block` (hard),
    /// `review`, or `warn` (advisory). Passed through verbatim; only `block`
    /// counts toward `blocking_failures` in callers.
    pub decision: String,
    #[serde(rename = "failureMessage", default)]
    pub failure_message: String,
    #[serde(default)]
    pub remediation: String,
}

/// The outcome of evaluating one applicable rule against a request.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RuleDecision {
    pub rule_id: String,
    pub family: String,
    /// The rule's configured decision tier (`block` | `review` | `warn`).
    pub decision: String,
    /// True iff every required input is present on the request.
    pub passed: bool,
    pub missing_inputs: Vec<String>,
    /// The rule's failure message when not passed; empty when passed.
    pub message: String,
    pub remediation: String,
}

const GUARDRAILS_YAML: &str = include_str!("../../../catalog/policy-guardrails.yaml");

static GUARDRAILS: LazyLock<PolicyGuardrails> = LazyLock::new(|| {
    serde_yaml::from_str(GUARDRAILS_YAML).expect("embedded policy-guardrails.yaml must parse")
});

/// The parsed, immutable guardrail catalog.
pub fn guardrails() -> &'static PolicyGuardrails {
    &GUARDRAILS
}

/// Evaluate the guardrails for `request` under `workflow_id` (an offering id).
///
/// For each rule that `appliesTo` the workflow, every `requiredInput` must be
/// present (non-blank) on the request — direct fields for owner/site/
/// environment/criticality, otherwise `request.metadata`. PURE + informational:
/// it reports readiness, it does not gate the lifecycle.
pub fn evaluate(request: &Request, workflow_id: &str) -> Vec<RuleDecision> {
    GUARDRAILS
        .rules
        .iter()
        .filter(|r| r.applies_to.iter().any(|w| w == workflow_id))
        .map(|r| {
            let missing_inputs: Vec<String> = r
                .required_inputs
                .iter()
                .filter(|input| !request_input_present(request, input))
                .cloned()
                .collect();
            let passed = missing_inputs.is_empty();
            RuleDecision {
                rule_id: r.id.clone(),
                family: r.family.clone(),
                decision: r.decision.clone(),
                passed,
                message: if passed {
                    String::new()
                } else {
                    r.failure_message.clone()
                },
                remediation: if passed {
                    String::new()
                } else {
                    r.remediation.clone()
                },
                missing_inputs,
            }
        })
        .collect()
}

/// Whether a named guardrail input is present on the request. Inputs with a
/// first-class `Request` representation are read from that field; everything
/// else comes from the request's metadata bag (richer offering inputs). Without
/// the structural mappings, a request that DOES carry an approval route or
/// evidence manifest would be falsely reported as missing them.
fn request_input_present(request: &Request, input: &str) -> bool {
    match input {
        "owner" => !request.owner.trim().is_empty(),
        "site" => !request.site.trim().is_empty(),
        "environment" => !request.environment.trim().is_empty(),
        "criticality" => !request.criticality.trim().is_empty(),
        "approvalRoute" => !request.approval_route.is_empty(),
        "evidenceManifest" => request.evidence_manifest_id.is_some(),
        other => request
            .metadata
            .get(other)
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(owner: &str, site: &str, env: &str, crit: &str) -> Request {
        crate::request_lifecycle::create_request(
            "linux-server-deployment",
            crate::models::RequestType::ServerDeployment,
            "requester",
            owner,
            site,
            env,
            crit,
        )
        .expect("request")
    }

    #[test]
    fn test_guardrails_parse_and_cover_code_rule_ids() {
        let g = guardrails();
        assert_eq!(g.version, 1);
        assert!(!g.rules.is_empty(), "guardrails must parse with rules");
        let ids: std::collections::HashSet<&str> = g.rules.iter().map(|r| r.id.as_str()).collect();
        // Every rule id hand-referenced in validate_request must exist in the YAML
        // (locks out code/catalog drift).
        for id in [
            "p0-preflight-required-fields",
            "p0-site-ou-catalog-match",
            "p0-approval-authority-required",
            "p0-dry-run-before-approval",
        ] {
            assert!(
                ids.contains(id),
                "code rule '{id}' missing from the catalog"
            );
        }
    }

    #[test]
    fn test_evaluate_preflight_required_inputs_present() {
        let request = req("alice", "DEFRA", "production", "critical");
        let decisions = evaluate(&request, "request-preflight");
        let preflight = decisions
            .iter()
            .find(|d| d.rule_id == "p0-preflight-required-fields")
            .expect("preflight rule applies to request-preflight");
        assert!(
            preflight.passed,
            "owner/site/environment/criticality present"
        );
        assert!(preflight.missing_inputs.is_empty());
    }

    #[test]
    fn test_evaluate_reports_missing_richer_inputs() {
        // A bare request lacks country/ouPlacement (richer inputs in metadata),
        // so the site-OU rule reports them as missing — informational, not a gate.
        let request = req("alice", "DEFRA", "production", "critical");
        let decisions = evaluate(&request, "request-preflight");
        let site_ou = decisions
            .iter()
            .find(|d| d.rule_id == "p0-site-ou-catalog-match")
            .expect("site-ou rule applies to request-preflight");
        assert!(!site_ou.passed);
        assert!(site_ou.missing_inputs.contains(&"country".to_string()));
        assert!(!site_ou.message.is_empty());
    }

    #[test]
    fn test_evaluate_missing_core_field_flagged() {
        let mut request = req("alice", "DEFRA", "production", "critical");
        request.owner = String::new(); // clear owner (create_request rejects empty)
        let decisions = evaluate(&request, "request-preflight");
        let preflight = decisions
            .iter()
            .find(|d| d.rule_id == "p0-preflight-required-fields")
            .expect("preflight applies");
        assert!(!preflight.passed);
        assert!(preflight.missing_inputs.contains(&"owner".to_string()));
    }

    #[test]
    fn test_evaluate_unknown_workflow_has_no_rules() {
        let request = req("alice", "DEFRA", "production", "critical");
        assert!(evaluate(&request, "no-such-workflow").is_empty());
    }

    #[test]
    fn test_raw_request_type_slug_matches_no_rules_but_resolved_does() {
        // The catalog's appliesTo lists use RESOLVED offering ids
        // (linux-/windows-server-deployment), never the bare RequestType slug.
        // The handler must resolve before evaluating (the alternative — passing
        // the raw "server-deployment" slug — silently matches zero rules).
        let request = req("alice", "DEFRA", "production", "critical");
        assert!(
            evaluate(&request, "server-deployment").is_empty(),
            "the raw RequestType slug matches no catalog rules"
        );
        assert!(
            !evaluate(&request, "linux-server-deployment").is_empty(),
            "the resolved offering id matches the catalog rules"
        );
    }

    #[test]
    fn test_structural_fields_read_from_request_not_metadata() {
        // approvalRoute / evidenceManifest are first-class Request fields, not
        // metadata — a request that HAS them must not be reported as missing.
        let mut request = req("alice", "DEFRA", "production", "critical");
        // Without an approval route, the approval rule reports approvalRoute missing.
        let before = evaluate(&request, "request-preflight");
        let approval_before = before
            .iter()
            .find(|d| d.rule_id == "p0-approval-authority-required")
            .expect("approval rule applies");
        assert!(
            approval_before
                .missing_inputs
                .contains(&"approvalRoute".to_string())
        );

        // With it populated, the structural mapping satisfies the input.
        request.approval_route.push("Datacenter Approver".into());
        let after = evaluate(&request, "request-preflight");
        let approval_after = after
            .iter()
            .find(|d| d.rule_id == "p0-approval-authority-required")
            .expect("approval rule applies");
        assert!(
            !approval_after
                .missing_inputs
                .contains(&"approvalRoute".to_string()),
            "a populated approval_route satisfies the approvalRoute input"
        );
    }
}
