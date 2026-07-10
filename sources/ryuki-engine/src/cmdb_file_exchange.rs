//! ServiceNow CMDB file-exchange row VALIDATION (dry-run, file-based).
//!
//! Turns the static `cmdb-file-exchange` descriptor into a real engine: given a
//! proposed normalized CMDB import row it validates the row against the contract's
//! rejection reasons and decides `accepted` (importable in the dry-run preview) or
//! `rejected` (with the specific reasons). Site validation is DATA-BACKED — the
//! site code is checked against the governed [`site_registry`].
//!
//! PURE / dry-run: no live ServiceNow API call, file-based only. The output is the
//! decision + rejection reasons (redacted), never raw CMDB rows or provider
//! payloads. `ambiguous-ci-identity` is a BATCH-level reason (duplicate CI
//! identity across the import set) and is intentionally not evaluated here, where
//! a single row carries no cross-row context.

use crate::site_registry;
use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum RowDecision {
    /// The row passes every per-row check and is importable in the dry-run preview.
    Accepted,
    /// The row fails one or more checks and is rejected with reasons.
    Rejected,
}

impl RowDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }
}

/// A proposed normalized CMDB import row (subset of the contract's
/// `normalizedImportFields` — the identity + the fields the rejection reasons
/// check). Every field is optional; absence (or, for the site, invalidity) fails
/// the corresponding check.
#[derive(Debug, Clone, Default)]
pub struct CmdbRowInput {
    pub ci_name: Option<String>,
    pub fqdn: Option<String>,
    pub ci_class: Option<String>,
    pub environment: Option<String>,
    pub business_owner: Option<String>,
    pub support_group: Option<String>,
    pub site_code: Option<String>,
    pub evidence_reference: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CmdbRowResult {
    pub decision: String,
    pub rejection_reasons: Vec<String>,
    pub reasons: Vec<String>,
}

fn present(field: &Option<String>) -> bool {
    field.as_deref().is_some_and(|s| !s.trim().is_empty())
}

/// The site code is RECOGNISED by the registry (trimmed + upper-cased, since
/// canonical UN/LOCODE and custom codes are uppercase). Membership only — a CMDB record can
/// legitimately reference a recognised but currently-INACTIVE site, so this uses
/// `is_known_site` rather than the active-only `is_valid_site`.
fn site_known(input: &CmdbRowInput) -> bool {
    input
        .site_code
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .is_some_and(|s| site_registry::is_known_site(&s.to_ascii_uppercase()))
}

/// Validate a proposed normalized CMDB import row. `accepted` when every per-row
/// check passes; otherwise `rejected` with the specific contract rejection
/// reasons. This is dry-run preview validation — no live ServiceNow call, no
/// import is performed.
pub fn evaluate_cmdb_row(input: &CmdbRowInput) -> CmdbRowResult {
    let mut rejection_reasons = Vec::new();

    if !present(&input.ci_name) {
        rejection_reasons.push("missing-ci-identity".into());
    }
    if !site_known(input) {
        rejection_reasons.push("unknown-site-code".into());
    }
    if !present(&input.business_owner) {
        rejection_reasons.push("missing-owner".into());
    }
    if !present(&input.support_group) {
        rejection_reasons.push("missing-support-group".into());
    }
    // The contract enumerates no authoritative environment vocabulary, so the
    // engine does NOT invent an allowlist: `invalid-environment` is flagged only
    // when the environment is absent. Any non-empty value is accepted rather than
    // risk rejecting a legitimate environment (sandbox, dr, sit, …) the catalog
    // does not list.
    if !present(&input.environment) {
        rejection_reasons.push("invalid-environment".into());
    }
    if !present(&input.evidence_reference) {
        rejection_reasons.push("missing-evidence-reference".into());
    }

    let (decision, reason) = if rejection_reasons.is_empty() {
        (
            RowDecision::Accepted,
            "Accepted — row passes every per-row CMDB import check (dry-run preview)".to_string(),
        )
    } else {
        (
            RowDecision::Rejected,
            format!(
                "Rejected — {} per-row CMDB import check(s) failed",
                rejection_reasons.len()
            ),
        )
    };

    CmdbRowResult {
        decision: decision.as_str().into(),
        rejection_reasons,
        reasons: vec![reason],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_row() -> CmdbRowInput {
        CmdbRowInput {
            ci_name: Some("app-srv-01".into()),
            fqdn: Some("app-srv-01.corp.local".into()),
            ci_class: Some("server".into()),
            environment: Some("prod".into()),
            business_owner: Some("team-platform".into()),
            support_group: Some("platform-ops".into()),
            // DEFRA is a recognised registry site (and a UN/LOCODE).
            site_code: Some("DEFRA".into()),
            evidence_reference: Some("ev-1".into()),
        }
    }

    #[test]
    fn accepts_complete_valid_row() {
        let r = evaluate_cmdb_row(&complete_row());
        assert_eq!(r.decision, "accepted");
        assert!(r.rejection_reasons.is_empty());
    }

    #[test]
    fn rejects_unknown_site_code() {
        let mut row = complete_row();
        row.site_code = Some("ZZZZZ".into());
        let r = evaluate_cmdb_row(&row);
        assert_eq!(r.decision, "rejected");
        assert!(
            r.rejection_reasons
                .contains(&"unknown-site-code".to_string())
        );
    }

    #[test]
    fn site_code_is_case_normalized() {
        let mut row = complete_row();
        row.site_code = Some("  defra  ".into());
        let r = evaluate_cmdb_row(&row);
        assert_eq!(r.decision, "accepted");
    }

    #[test]
    fn recognised_but_inactive_site_is_accepted() {
        // A CI can reference a recognised but currently-inactive site. DEHAM
        // (Hamburg) is a registry site that is not in the small active set, so it
        // must NOT be rejected as unknown-site-code (membership, not active-only).
        let mut row = complete_row();
        row.site_code = Some("DEHAM".into());
        let r = evaluate_cmdb_row(&row);
        assert!(
            !r.rejection_reasons
                .contains(&"unknown-site-code".to_string()),
            "a recognised (if inactive) site must not be unknown-site-code: {:?}",
            r.rejection_reasons
        );
        assert_eq!(r.decision, "accepted");
    }

    #[test]
    fn absent_environment_is_invalid_environment() {
        let mut row = complete_row();
        row.environment = None;
        let r = evaluate_cmdb_row(&row);
        assert_eq!(r.decision, "rejected");
        assert!(
            r.rejection_reasons
                .contains(&"invalid-environment".to_string())
        );
    }

    #[test]
    fn any_non_empty_environment_is_accepted() {
        // No authoritative environment vocabulary in the contract, so a value the
        // engine doesn't recognise (e.g. sandbox) must NOT be falsely rejected.
        let mut row = complete_row();
        row.environment = Some("sandbox".into());
        let r = evaluate_cmdb_row(&row);
        assert_eq!(r.decision, "accepted");
    }

    #[test]
    fn rejects_missing_identity_owner_support_evidence() {
        let row = CmdbRowInput {
            // Only a valid site + environment supplied.
            environment: Some("prod".into()),
            site_code: Some("DEFRA".into()),
            ..Default::default()
        };
        let r = evaluate_cmdb_row(&row);
        assert_eq!(r.decision, "rejected");
        for reason in [
            "missing-ci-identity",
            "missing-owner",
            "missing-support-group",
            "missing-evidence-reference",
        ] {
            assert!(
                r.rejection_reasons.contains(&reason.to_string()),
                "expected rejection reason {reason}: {:?}",
                r.rejection_reasons
            );
        }
        // Site + environment were valid -> their reasons are absent.
        assert!(
            !r.rejection_reasons
                .contains(&"unknown-site-code".to_string())
        );
        assert!(
            !r.rejection_reasons
                .contains(&"invalid-environment".to_string())
        );
    }

    #[test]
    fn whitespace_only_field_is_treated_as_missing() {
        let mut row = complete_row();
        row.business_owner = Some("   ".into());
        let r = evaluate_cmdb_row(&row);
        assert_eq!(r.decision, "rejected");
        assert!(r.rejection_reasons.contains(&"missing-owner".to_string()));
    }

    #[test]
    fn decision_values_are_accepted_or_rejected() {
        for d in [RowDecision::Accepted, RowDecision::Rejected] {
            assert!(["accepted", "rejected"].contains(&d.as_str()));
        }
    }
}
