//! Catalog-driven VMware guest-customization governance.
//!
//! Turns the static `customization-spec-governance` descriptor into a real
//! engine. It embeds the site catalog (`catalog/site-catalog.yaml`) and, for a
//! given site, DERIVES the expected safe Windows customization facts (spec
//! reference, OU pattern, domain, timezone, DHCP network behavior, organization)
//! and detects DRIFT when a proposed customization disagrees with the catalog.
//!
//! PURE / dry-run: the catalog is embedded at compile time (`include_str!`) and
//! parsed once into an immutable `LazyLock`; evaluation performs no I/O and makes
//! no live vCenter / directory calls. Only catalog-derived SAFE facts are
//! exposed — never raw directory values, passwords, or object identifiers.

use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

const SITE_CATALOG_YAML: &str = include_str!("../../../catalog/site-catalog.yaml");

static SITE_CATALOG: LazyLock<SiteCatalog> = LazyLock::new(|| {
    serde_yaml::from_str(SITE_CATALOG_YAML).expect("embedded site-catalog.yaml must parse")
});

/// The parsed site catalog. Unknown YAML fields (version, status, source,
/// catalogMode, safeXmlFactsOnly, …) are ignored by serde.
#[derive(Debug, Clone, Deserialize)]
struct SiteCatalog {
    domain: String,
    #[serde(rename = "ouPattern")]
    ou_pattern: String,
    network: String,
    organization: String,
    #[serde(rename = "windowsBehavior", default)]
    windows_behavior: Vec<String>,
    #[serde(default)]
    sites: Vec<SiteCustomization>,
}

#[derive(Debug, Clone, Deserialize)]
struct SiteCustomization {
    spec: String,
    country: String,
    site: String,
    #[serde(rename = "timezoneCode")]
    timezone_code: u32,
}

/// The safe Windows customization facts derived from the catalog for a site.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SafeFacts {
    pub customization_spec_reference: String,
    pub site_code: String,
    pub country_code: String,
    pub timezone_code: u32,
    pub ou_pattern_reference: String,
    pub domain_reference: String,
    pub organization_label: String,
    pub dhcp_network_behavior: bool,
    pub windows_behavior: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum SpecDecision {
    Admit,
    Review,
    Block,
}

impl SpecDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::Review => "review",
            Self::Block => "block",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DriftSignal {
    pub name: String,
    /// `ok` | `mismatch` | `reviewed-dry-run`.
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CustomizationResult {
    pub decision: String,
    pub site: String,
    pub safe_facts: Option<SafeFacts>,
    pub drift: Vec<DriftSignal>,
    pub reasons: Vec<String>,
}

/// A proposed customization to check for drift. Every field is optional — only
/// the fields that are present are compared against the catalog expectation.
#[derive(Debug, Clone, Default)]
pub struct ProposedSpec {
    pub spec_reference: Option<String>,
    pub country_code: Option<String>,
    pub timezone_code: Option<u32>,
    pub ou: Option<String>,
    pub domain: Option<String>,
    /// e.g. `DHCP` / `Static`.
    pub network_behavior: Option<String>,
}

/// Drift signals the contract requires but for which there is no live spec
/// inventory to compare against (no real vCenter customization specs / freshness
/// telemetry) — always reviewed in dry-run.
const DRY_RUN_DRIFT: &[&str] = &[
    "missing-expected-spec",
    // No structured proposed-windows-behavior input channel, so this contract
    // signal is surfaced as reviewed-dry-run rather than silently omitted.
    "windows-behavior-mismatch",
    "stale-spec-inventory",
];

/// Substitute `<SITE>`/`<COUNTRY>` in the catalog OU pattern.
fn derive_ou(pattern: &str, site: &str, country: &str) -> String {
    pattern
        .replace("<SITE>", site)
        .replace("<COUNTRY>", country)
}

/// Derive the expected safe facts for a site from the embedded catalog. Returns
/// `None` when the site carries no governed customization spec.
pub fn safe_facts_for_site(site: &str) -> Option<SafeFacts> {
    let cat = &*SITE_CATALOG;
    let entry = cat
        .sites
        .iter()
        .find(|s| s.site.eq_ignore_ascii_case(site))?;
    Some(SafeFacts {
        customization_spec_reference: entry.spec.clone(),
        site_code: entry.site.clone(),
        country_code: entry.country.clone(),
        timezone_code: entry.timezone_code,
        ou_pattern_reference: derive_ou(&cat.ou_pattern, &entry.site, &entry.country),
        domain_reference: cat.domain.clone(),
        organization_label: cat.organization.clone(),
        dhcp_network_behavior: cat.network.eq_ignore_ascii_case("DHCP"),
        windows_behavior: cat.windows_behavior.clone(),
    })
}

/// Compare a proposed string field against the catalog expectation. Returns
/// `None` when no proposed value was supplied (not compared), else
/// `Some(mismatch)`. The detail NEVER echoes the caller's raw proposed value —
/// only the catalog-derived `expected` value appears, keeping the output to safe
/// facts only (the caller-supplied string could be arbitrary / log-sensitive).
fn check_field(
    drift: &mut Vec<DriftSignal>,
    name: &str,
    expected: &str,
    proposed: Option<&str>,
) -> Option<bool> {
    let p = proposed?;
    let matches = p.eq_ignore_ascii_case(expected);
    drift.push(DriftSignal {
        name: name.into(),
        status: if matches { "ok" } else { "mismatch" }.into(),
        detail: if matches {
            format!("matches catalog ({expected})")
        } else {
            format!("proposed value does not match catalog ({expected})")
        },
    });
    Some(!matches)
}

/// Evaluate a guest-customization governance request: derive the catalog safe
/// facts for the site and flag drift against any provided proposed values.
/// `block` for an unknown site, `review` when any proposed value drifts from the
/// catalog, `admit` when the facts derive cleanly with no drift.
pub fn evaluate_customization_spec(site: &str, proposed: &ProposedSpec) -> CustomizationResult {
    let Some(facts) = safe_facts_for_site(site) else {
        return CustomizationResult {
            decision: SpecDecision::Block.as_str().into(),
            site: site.into(),
            safe_facts: None,
            drift: vec![DriftSignal {
                name: "unknown-spec".into(),
                status: "mismatch".into(),
                detail: format!(
                    "DRY-RUN: site {site} has no governed customization spec in the catalog"
                ),
            }],
            reasons: vec![format!(
                "Blocked — no governed customization spec for unknown site {site}"
            )],
        };
    };

    let mut drift = Vec::new();
    // `compared` counts how many proposed values were actually checked; `admit`
    // requires at least one (a bare facts query verifies nothing, so it cannot
    // claim an admission — it returns `review` with the derived facts).
    let mut compared = 0u32;
    let mut mismatches = 0u32;
    let expected_network = if facts.dhcp_network_behavior {
        "DHCP"
    } else {
        "Static"
    };

    for (name, expected, proposed) in [
        (
            "unknown-spec",
            facts.customization_spec_reference.as_str(),
            proposed.spec_reference.as_deref(),
        ),
        (
            "country-site-mismatch",
            facts.country_code.as_str(),
            proposed.country_code.as_deref(),
        ),
        (
            "ou-pattern-mismatch",
            facts.ou_pattern_reference.as_str(),
            proposed.ou.as_deref(),
        ),
        (
            "domain-mismatch",
            facts.domain_reference.as_str(),
            proposed.domain.as_deref(),
        ),
        (
            "network-behavior-mismatch",
            expected_network,
            proposed.network_behavior.as_deref(),
        ),
    ] {
        if let Some(mismatch) = check_field(&mut drift, name, expected, proposed) {
            compared += 1;
            if mismatch {
                mismatches += 1;
            }
        }
    }

    // Timezone is numeric; compare separately when provided.
    if let Some(tz) = proposed.timezone_code {
        compared += 1;
        let matches = tz == facts.timezone_code;
        if !matches {
            mismatches += 1;
        }
        drift.push(DriftSignal {
            name: "timezone-mismatch".into(),
            status: if matches { "ok" } else { "mismatch" }.into(),
            detail: if matches {
                format!("matches catalog ({})", facts.timezone_code)
            } else {
                format!(
                    "proposed value does not match catalog ({})",
                    facts.timezone_code
                )
            },
        });
    }

    for name in DRY_RUN_DRIFT {
        drift.push(DriftSignal {
            name: (*name).into(),
            status: "reviewed-dry-run".into(),
            detail: format!("DRY-RUN: {name} reviewed (no live customization-spec inventory)"),
        });
    }

    let (decision, reason) = if mismatches > 0 {
        (
            SpecDecision::Review,
            format!(
                "Review — {mismatches} proposed customization value(s) drift from the site catalog"
            ),
        )
    } else if compared == 0 {
        (
            SpecDecision::Review,
            "Review — catalog safe facts derived; supply a proposed customization to admit"
                .to_string(),
        )
    } else {
        (
            SpecDecision::Admit,
            format!(
                "Admit — all {compared} proposed customization value(s) match the catalog safe facts"
            ),
        )
    };

    CustomizationResult {
        decision: decision.as_str().into(),
        site: site.into(),
        safe_facts: Some(facts),
        drift,
        reasons: vec![reason],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_safe_facts_for_known_site() {
        let facts = safe_facts_for_site("DEFRA").expect("DEFRA is a governed site");
        assert_eq!(
            facts.customization_spec_reference,
            "defra-windows-customization"
        );
        assert_eq!(facts.country_code, "DE");
        assert_eq!(facts.timezone_code, 105);
        assert_eq!(
            facts.ou_pattern_reference,
            "OU=Servers,OU=DEFRA,OU=DE,DC=corp,DC=local"
        );
        assert_eq!(facts.domain_reference, "CORP.local");
        assert!(facts.dhcp_network_behavior);
        assert!(facts.windows_behavior.contains(&"Sysprep".to_string()));
    }

    #[test]
    fn site_lookup_is_case_insensitive() {
        assert!(safe_facts_for_site("defra").is_some());
        assert!(safe_facts_for_site("GbLoN").is_some());
    }

    #[test]
    fn blocks_unknown_site() {
        let r = evaluate_customization_spec("ZZZZZ", &ProposedSpec::default());
        assert_eq!(r.decision, "block");
        assert!(r.safe_facts.is_none());
        assert!(r.drift.iter().any(|d| d.name == "unknown-spec"));
    }

    #[test]
    fn reviews_when_no_proposed_values() {
        // No proposed spec -> derive the safe facts but verify nothing -> review
        // (an admission claim requires at least one compared value).
        let r = evaluate_customization_spec("DEFRA", &ProposedSpec::default());
        assert_eq!(r.decision, "review");
        assert!(r.safe_facts.is_some());
        // Only the reviewed-dry-run signals are present (nothing was compared).
        assert_eq!(r.drift.len(), DRY_RUN_DRIFT.len());
    }

    #[test]
    fn admits_when_proposed_matches_catalog() {
        let proposed = ProposedSpec {
            country_code: Some("DE".into()),
            timezone_code: Some(105),
            ou: Some("OU=Servers,OU=DEFRA,OU=DE,DC=corp,DC=local".into()),
            domain: Some("CORP.local".into()),
            network_behavior: Some("dhcp".into()),
            ..Default::default()
        };
        let r = evaluate_customization_spec("DEFRA", &proposed);
        assert_eq!(r.decision, "admit");
    }

    #[test]
    fn reviews_on_ou_drift() {
        let proposed = ProposedSpec {
            ou: Some("OU=Servers,OU=WRONG,OU=DE,DC=corp,DC=local".into()),
            ..Default::default()
        };
        let r = evaluate_customization_spec("DEFRA", &proposed);
        assert_eq!(r.decision, "review");
        assert!(
            r.drift
                .iter()
                .any(|d| d.name == "ou-pattern-mismatch" && d.status == "mismatch")
        );
    }

    #[test]
    fn reviews_on_timezone_and_country_drift() {
        let proposed = ProposedSpec {
            country_code: Some("FR".into()),
            timezone_code: Some(85),
            ..Default::default()
        };
        let r = evaluate_customization_spec("DEFRA", &proposed);
        assert_eq!(r.decision, "review");
        assert!(
            r.drift
                .iter()
                .any(|d| d.name == "country-site-mismatch" && d.status == "mismatch")
        );
        assert!(
            r.drift
                .iter()
                .any(|d| d.name == "timezone-mismatch" && d.status == "mismatch")
        );
    }

    #[test]
    fn decision_values_match_contract() {
        for d in [
            SpecDecision::Admit,
            SpecDecision::Review,
            SpecDecision::Block,
        ] {
            assert!(["admit", "review", "block"].contains(&d.as_str()));
        }
    }
}
