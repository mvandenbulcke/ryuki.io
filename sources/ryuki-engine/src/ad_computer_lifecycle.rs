use crate::{models::*, site_registry};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

const DIRECTORY_DN_SUFFIX: &str = "DC=corp,DC=local";
const SITE_SCOPED_OU_LEAVES: &[&str] = &[
    "Servers",
    "Workstations",
    "DMZ",
    "Management",
    "Testing",
    "Development",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComputerStatus {
    Active,
    Disabled,
    Quarantined,
    Deleted,
}

impl std::fmt::Display for ComputerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComputerStatus::Active => write!(f, "Active"),
            ComputerStatus::Disabled => write!(f, "Disabled"),
            ComputerStatus::Quarantined => write!(f, "Quarantined"),
            ComputerStatus::Deleted => write!(f, "Deleted"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ADComputer {
    pub id: String,
    pub name: String,
    pub site: String,
    pub ou_path: String,
    pub status: ComputerStatus,
    pub last_logon: String,
    pub os: String,
    pub created_at: String,
    pub metadata: HashMap<String, String>,
}

fn computer_id() -> String {
    Uuid::new_v4().to_string()
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn active_site_code(site: &str) -> Result<String, String> {
    let code = site_registry::normalize_site_code_for_lookup(site)
        .map_err(|_| format!("Unknown or empty site: {site}"))?;
    if site_registry::is_valid_site(&code) {
        Ok(code)
    } else {
        Err(format!("Unknown or empty site: {site}"))
    }
}

fn computer_name_parts(name: &str) -> Option<(&str, &str, &str)> {
    let mut parts = name.rsplitn(3, '-');
    let number = parts.next()?;
    let role = parts.next()?;
    let site = parts.next()?;
    (!site.is_empty() && !role.is_empty() && !number.is_empty()).then_some((site, role, number))
}

fn validate_naming_convention(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Computer name cannot be empty".into());
    }
    let Some((site, role, number)) = computer_name_parts(name) else {
        return Err(format!(
            "Invalid computer name '{}': must match pattern SITE-ROLE-NN (e.g. DEFRA-SRV-01)",
            name
        ));
    };
    if !site_registry::is_valid_site(site) {
        return Err(format!("Unknown site code '{}' in computer name", site));
    }
    if !["SRV", "WS", "DC", "MGMT", "TEST", "DEV"].contains(&role) {
        return Err(format!(
            "Unknown role code '{}' in computer name. Must be SRV, WS, DC, MGMT, TEST, or DEV",
            role
        ));
    }
    if number.len() < 2 || number.len() > 4 || !number.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!(
            "Invalid sequence number '{}' in computer name. Must be 2-4 digits",
            number
        ));
    }
    Ok(())
}

fn validate_ou_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("OU path cannot be empty".into());
    }
    if !path.is_ascii() || path.trim() != path {
        return Err("OU path must be canonical ASCII without surrounding whitespace".into());
    }
    Ok(())
}

fn site_scoped_ou(leaf: &str, site: &str) -> String {
    format!("OU={leaf},OU={site},{DIRECTORY_DN_SUFFIX}")
}

fn canonical_prestage_ou_for_parts(role: &str, site: &str) -> Result<String, String> {
    let ou_path = match role {
        "SRV" => site_scoped_ou("Servers", site),
        "WS" => site_scoped_ou("Workstations", site),
        // Domain Controllers is the one directory-wide container in the
        // metadata-only policy. The canonical computer name remains site-bound.
        "DC" => format!("OU=Domain Controllers,{DIRECTORY_DN_SUFFIX}"),
        "MGMT" => site_scoped_ou("Management", site),
        "TEST" => site_scoped_ou("Testing", site),
        "DEV" => site_scoped_ou("Development", site),
        _ => return Err(format!("Unknown role code '{role}'")),
    };
    Ok(ou_path)
}

/// Return the one server-derived initial OU for a canonical computer name.
pub fn canonical_prestage_ou(name: &str) -> Result<String, String> {
    validate_naming_convention(name)?;
    let (site, role, _) = computer_name_parts(name).expect("validated computer name");
    canonical_prestage_ou_for_parts(role, site)
}

/// Validate a requested move against the closed, site-bound OU policy and
/// return its canonical representation. Callers never persist an arbitrary DN.
fn canonical_move_ou(name: &str, site: &str, requested: &str) -> Result<String, String> {
    validate_ou_path(requested)?;
    let (name_site, role, _) = computer_name_parts(name)
        .ok_or_else(|| "computer name does not contain a canonical site and role".to_string())?;
    if name_site != site {
        return Err("computer name site does not match persisted owner site".into());
    }

    if role == "DC" {
        let canonical = canonical_prestage_ou_for_parts(role, site)?;
        return (requested == canonical)
            .then_some(canonical)
            .ok_or_else(|| {
                "domain controllers must remain in the canonical directory container".into()
            });
    }

    SITE_SCOPED_OU_LEAVES
        .iter()
        .map(|leaf| site_scoped_ou(leaf, site))
        .find(|candidate| candidate == requested)
        .ok_or_else(|| {
            "target OU is not a canonical container for the computer's owner site".into()
        })
}

pub fn prestage_computer(name: &str, site: &str, ou_path: &str) -> Result<ADComputer, String> {
    if name.is_empty() {
        return Err("Computer name cannot be empty".into());
    }
    let canonical_site = active_site_code(site)?;
    validate_naming_convention(name)?;

    let (embedded_site, role, _) = computer_name_parts(name).expect("validated computer name");
    let canonical_embedded_site = site_registry::normalize_site_code_for_lookup(embedded_site)
        .map_err(|_| format!("Unknown site code '{embedded_site}' in computer name"))?;
    if embedded_site != canonical_embedded_site {
        return Err(format!(
            "Computer name must use canonical site code '{canonical_embedded_site}' (found '{embedded_site}')"
        ));
    }
    if canonical_embedded_site != canonical_site {
        return Err(format!(
            "Computer name site '{canonical_embedded_site}' does not match declared site '{canonical_site}'"
        ));
    }
    let canonical_ou = canonical_prestage_ou_for_parts(role, &canonical_site)?;
    if ou_path != canonical_ou {
        return Err(format!(
            "OU path does not match the server-derived directory namespace; expected '{canonical_ou}'"
        ));
    }

    Ok(ADComputer {
        id: computer_id(),
        name: name.to_string(),
        site: canonical_site,
        ou_path: canonical_ou,
        status: ComputerStatus::Active,
        last_logon: now_iso(),
        os: "Windows Server 2022".to_string(),
        created_at: now_iso(),
        metadata: HashMap::from([
            ("prestaged".into(), "true".into()),
            ("dry_run".into(), "true".into()),
            (
                "note".into(),
                "DRY-RUN: Prestaged computer object. No live AD calls.".into(),
            ),
        ]),
    })
}

pub fn validate_computer(name: &str) -> Result<ValidationResult, String> {
    if name.is_empty() {
        return Err("Computer name cannot be empty".into());
    }

    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut failed_rules: Vec<String> = Vec::new();
    let mut remediation: Vec<String> = Vec::new();

    if let Err(e) = validate_naming_convention(name) {
        errors.push(e.clone());
        failed_rules.push("p0-computer-naming-convention".into());
        remediation
            .push("Rename the computer to match SITE-ROLE-NN format (e.g. DEFRA-SRV-01)".into());
    }

    if let Some((site, _, _)) = computer_name_parts(name)
        && !site_registry::is_valid_site(site)
    {
        errors.push(format!("Unknown site code '{}' in computer name", site));
        failed_rules.push("p0-site-code-valid".into());
        remediation.push(format!(
            "Use an active site code from: {:?}",
            site_registry::get_active_site_codes().unwrap_or_default()
        ));
    }

    warnings.push("DRY-RUN: No live AD validation performed".into());
    warnings.push("DRY-RUN: OU existence and permissions not verified".into());

    Ok(ValidationResult {
        passed: errors.is_empty(),
        errors,
        warnings,
        failed_rules,
        remediation,
    })
}

pub fn move_computer(name: &str, target_ou: &str) -> Result<ADComputer, String> {
    if name.is_empty() {
        return Err("Computer name cannot be empty".into());
    }
    if target_ou.is_empty() {
        return Err("Target OU cannot be empty".into());
    }
    validate_naming_convention(name)?;

    let (site, _, _) = computer_name_parts(name).expect("validated computer name");
    let target_ou = canonical_move_ou(name, site, target_ou)?;

    Ok(ADComputer {
        id: computer_id(),
        name: name.to_string(),
        site: site.to_string(),
        ou_path: target_ou.clone(),
        status: ComputerStatus::Active,
        last_logon: now_iso(),
        os: "Windows Server 2022".to_string(),
        created_at: now_iso(),
        metadata: HashMap::from([
            ("moved".into(), "true".into()),
            ("previous_ou".into(), site_scoped_ou("Servers", site)),
            ("dry_run".into(), "true".into()),
            (
                "note".into(),
                format!(
                    "DRY-RUN: Moved computer '{}' to '{}'. No live AD calls.",
                    name, target_ou
                ),
            ),
        ]),
    })
}

pub fn disable_computer(name: &str, reason: &str) -> Result<ADComputer, String> {
    if name.is_empty() {
        return Err("Computer name cannot be empty".into());
    }
    if reason.is_empty() {
        return Err("Disable reason cannot be empty".into());
    }
    validate_naming_convention(name)?;

    let (site, _, _) = computer_name_parts(name).expect("validated computer name");
    let ou_path = canonical_prestage_ou(name)?;

    Ok(ADComputer {
        id: computer_id(),
        name: name.to_string(),
        site: site.to_string(),
        ou_path,
        status: ComputerStatus::Disabled,
        last_logon: now_iso(),
        os: "Windows Server 2022".to_string(),
        created_at: now_iso(),
        metadata: HashMap::from([
            ("disabled".into(), "true".into()),
            ("disable_reason".into(), reason.to_string()),
            ("dry_run".into(), "true".into()),
            (
                "note".into(),
                format!(
                    "DRY-RUN: Disabled computer '{}'. Reason: {}. No live AD calls.",
                    name, reason
                ),
            ),
        ]),
    })
}

pub fn enable_computer(name: &str) -> Result<ADComputer, String> {
    if name.is_empty() {
        return Err("Computer name cannot be empty".into());
    }
    validate_naming_convention(name)?;

    let (site, _, _) = computer_name_parts(name).expect("validated computer name");
    let ou_path = canonical_prestage_ou(name)?;

    Ok(ADComputer {
        id: computer_id(),
        name: name.to_string(),
        site: site.to_string(),
        ou_path,
        status: ComputerStatus::Active,
        last_logon: now_iso(),
        os: "Windows Server 2022".to_string(),
        created_at: now_iso(),
        metadata: HashMap::from([
            ("enabled".into(), "true".into()),
            ("dry_run".into(), "true".into()),
            (
                "note".into(),
                format!("DRY-RUN: Enabled computer '{}'. No live AD calls.", name),
            ),
        ]),
    })
}

pub fn delete_computer(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Computer name cannot be empty".into());
    }
    validate_naming_convention(name)?;
    Ok(())
}

// ─── Model-based pure transition functions (for persistence layer) ────────────

/// Move an existing computer to a new OU. The computer is loaded from the DB
/// before calling this; the function validates the target OU path and returns a
/// clone with the updated `ou_path`.
///
/// Predecessor guard: only `Active` computers can be moved. Disabled,
/// Quarantined, and Deleted computers are locked in place — moving them would
/// silently bypass lifecycle controls.
pub fn move_computer_model(computer: &ADComputer, target_ou: &str) -> Result<ADComputer, String> {
    if computer.status != ComputerStatus::Active {
        return Err(format!(
            "Cannot move a computer that is '{}'; it must be Active",
            computer.status
        ));
    }
    let target_ou = canonical_move_ou(&computer.name, &computer.site, target_ou)?;
    Ok(ADComputer {
        ou_path: target_ou,
        ..computer.clone()
    })
}

/// Disable a computer that was loaded from the DB.
///
/// Predecessor guards:
/// - `reason` must not be empty (caller should pre-validate at the handler
///   boundary, but this is a second line of defence).
/// - Must be `Active`. Quarantine is a distinct security state and can only be
///   left through an explicit quarantine-release transition, not ordinary
///   disable/enable authority.
/// - Must not already be `Disabled` — idempotent disable would silently
///   overwrite the existing `disable_reason`.
/// - Must not be `Deleted` — a deleted computer cannot be further modified.
pub fn disable_computer_model(computer: &ADComputer, reason: &str) -> Result<ADComputer, String> {
    if reason.is_empty() {
        return Err("Disable reason cannot be empty".into());
    }
    match computer.status {
        ComputerStatus::Disabled => {
            return Err("Computer is already Disabled".into());
        }
        ComputerStatus::Deleted => {
            return Err("Cannot disable a deleted computer".into());
        }
        ComputerStatus::Quarantined => {
            return Err(
                "Cannot disable a quarantined computer; explicit quarantine release is required"
                    .into(),
            );
        }
        ComputerStatus::Active => {}
    }
    let mut metadata = computer.metadata.clone();
    metadata.insert("disable_reason".into(), reason.to_string());
    Ok(ADComputer {
        status: ComputerStatus::Disabled,
        metadata,
        ..computer.clone()
    })
}

/// Re-enable a computer that was loaded from the DB. Guards: the computer must
/// currently be `Disabled` — enabling an Active, Quarantined, or Deleted object
/// is a state conflict.
pub fn enable_computer_model(computer: &ADComputer) -> Result<ADComputer, String> {
    if computer.status != ComputerStatus::Disabled {
        return Err(format!(
            "Cannot enable a computer that is '{}'; it must be Disabled",
            computer.status
        ));
    }
    let mut metadata = computer.metadata.clone();
    metadata.remove("disable_reason");
    Ok(ADComputer {
        status: ComputerStatus::Active,
        metadata,
        ..computer.clone()
    })
}

/// Server-derived evidence for the only transition that may leave quarantine.
/// Request/approval actors remain in the durable recovery-review row and audit
/// chain rather than caller-controlled computer metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineRecoveryDecision {
    pub review_id: String,
    pub reason: String,
    pub approved_at: String,
}

/// Release a reviewed quarantine into `Disabled`, never directly into Active.
/// The persistence layer separately proves that `review_id` names a fresh,
/// maker-checker-approved row for this exact computer/version.
pub fn release_quarantine_model(
    computer: &ADComputer,
    decision: &QuarantineRecoveryDecision,
) -> Result<ADComputer, String> {
    if computer.status != ComputerStatus::Quarantined {
        return Err("Only a quarantined computer can complete reviewed recovery".into());
    }
    Uuid::parse_str(&decision.review_id)
        .map_err(|_| "Quarantine recovery review id must be a UUID".to_string())?;
    let reason = decision.reason.trim();
    if reason.is_empty() || reason.len() > 1024 {
        return Err("Quarantine recovery reason must contain 1-1024 bytes".into());
    }
    if decision.approved_at.trim().is_empty() {
        return Err("Quarantine recovery approval timestamp is required".into());
    }
    if !computer
        .metadata
        .get("quarantine_reason")
        .is_some_and(|value| !value.trim().is_empty())
    {
        return Err("Quarantine evidence is missing; recovery requires manual review".into());
    }

    let mut metadata = computer.metadata.clone();
    metadata.insert(
        "quarantine_release_review_id".into(),
        decision.review_id.clone(),
    );
    metadata.insert("quarantine_release_reason".into(), reason.to_string());
    metadata.insert(
        "quarantine_release_approved_at".into(),
        decision.approved_at.clone(),
    );
    metadata.insert(
        "disable_reason".into(),
        "reviewed quarantine recovery; explicit enable still required".into(),
    );

    Ok(ADComputer {
        status: ComputerStatus::Disabled,
        metadata,
        ..computer.clone()
    })
}

/// Soft-delete a computer that was loaded from the DB. Guards: must not already
/// be `Deleted`.
pub fn delete_computer_model(computer: &ADComputer) -> Result<ADComputer, String> {
    match computer.status {
        ComputerStatus::Deleted => return Err("Computer is already deleted".into()),
        ComputerStatus::Quarantined => {
            return Err(
                "Cannot delete a quarantined computer; explicit quarantine recovery review is required"
                    .into(),
            );
        }
        ComputerStatus::Active | ComputerStatus::Disabled => {}
    }
    Ok(ADComputer {
        status: ComputerStatus::Deleted,
        ..computer.clone()
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationResult {
    pub site: String,
    pub unmatched_ad_objects: Vec<ADComputer>,
    pub missing_from_cmdb: Vec<String>,
    pub total_ad_objects: usize,
    pub total_cmdb_objects: usize,
    pub dry_run: bool,
}

pub fn reconcile_computers(site: &str) -> Result<ReconciliationResult, String> {
    if site.is_empty() || !site_registry::is_valid_site(site) {
        return Err(format!("Unknown or empty site: {}", site));
    }

    let ad_objects: Vec<ADComputer> = vec![
        ADComputer {
            id: computer_id(),
            name: format!("{}-SRV-01", site),
            site: site.to_string(),
            ou_path: site_scoped_ou("Servers", site),
            status: ComputerStatus::Active,
            last_logon: now_iso(),
            os: "Windows Server 2022".to_string(),
            created_at: now_iso(),
            metadata: HashMap::new(),
        },
        ADComputer {
            id: computer_id(),
            name: format!("{}-SRV-02", site),
            site: site.to_string(),
            ou_path: site_scoped_ou("Servers", site),
            status: ComputerStatus::Active,
            last_logon: now_iso(),
            os: "Windows Server 2019".to_string(),
            created_at: now_iso(),
            metadata: HashMap::new(),
        },
        ADComputer {
            id: computer_id(),
            name: format!("{}-WS-01", site),
            site: site.to_string(),
            ou_path: site_scoped_ou("Workstations", site),
            status: ComputerStatus::Active,
            last_logon: now_iso(),
            os: "Windows 11".to_string(),
            created_at: now_iso(),
            metadata: HashMap::new(),
        },
    ];

    let cmdb_computer_names: Vec<String> =
        vec![format!("{}-SRV-01", site), format!("{}-SRV-02", site)];

    let missing_from_cmdb: Vec<String> = ad_objects
        .iter()
        .filter(|ad| !cmdb_computer_names.contains(&ad.name))
        .map(|ad| ad.name.clone())
        .collect();

    Ok(ReconciliationResult {
        site: site.to_string(),
        unmatched_ad_objects: ad_objects
            .iter()
            .filter(|ad| !cmdb_computer_names.contains(&ad.name))
            .cloned()
            .collect(),
        missing_from_cmdb,
        total_ad_objects: ad_objects.len(),
        total_cmdb_objects: cmdb_computer_names.len(),
        dry_run: true,
    })
}

pub fn get_orphaned(site: &str) -> Result<Vec<ADComputer>, String> {
    if site.is_empty() || !site_registry::is_valid_site(site) {
        return Err(format!("Unknown or empty site: {}", site));
    }

    let ninety_days_ago = chrono::Utc::now() - chrono::Duration::days(120);
    let orphaned = vec![
        ADComputer {
            id: computer_id(),
            name: format!("{}-SRV-03", site),
            site: site.to_string(),
            ou_path: site_scoped_ou("Servers", site),
            status: ComputerStatus::Active,
            last_logon: ninety_days_ago.to_rfc3339(),
            os: "Windows Server 2016".to_string(),
            created_at: (ninety_days_ago - chrono::Duration::days(365)).to_rfc3339(),
            metadata: HashMap::from([
                ("orphaned".into(), "true".into()),
                ("days_since_logon".into(), "120".into()),
                ("dry_run".into(), "true".into()),
            ]),
        },
        ADComputer {
            id: computer_id(),
            name: format!("{}-WS-99", site),
            site: site.to_string(),
            ou_path: site_scoped_ou("Workstations", site),
            status: ComputerStatus::Disabled,
            last_logon: (ninety_days_ago - chrono::Duration::days(60)).to_rfc3339(),
            os: "Windows 10".to_string(),
            created_at: (ninety_days_ago - chrono::Duration::days(730)).to_rfc3339(),
            metadata: HashMap::from([
                ("orphaned".into(), "true".into()),
                ("days_since_logon".into(), "180".into()),
                ("dry_run".into(), "true".into()),
            ]),
        },
    ];

    Ok(orphaned)
}

pub fn seed_examples() -> Vec<ADComputer> {
    let now = now_iso();
    vec![
        ADComputer {
            id: computer_id(),
            name: "DEFRA-SRV-01".to_string(),
            site: "DEFRA".to_string(),
            ou_path: "OU=Servers,OU=DEFRA,DC=corp,DC=local".to_string(),
            status: ComputerStatus::Active,
            last_logon: now.clone(),
            os: "Windows Server 2022".to_string(),
            created_at: now.clone(),
            metadata: HashMap::from([("role".into(), "web-server".into())]),
        },
        ADComputer {
            id: computer_id(),
            name: "DEFRA-DC-01".to_string(),
            site: "DEFRA".to_string(),
            ou_path: "OU=Domain Controllers,DC=corp,DC=local".to_string(),
            status: ComputerStatus::Active,
            last_logon: now.clone(),
            os: "Windows Server 2022".to_string(),
            created_at: now.clone(),
            metadata: HashMap::from([("role".into(), "domain-controller".into())]),
        },
        ADComputer {
            id: computer_id(),
            name: "GBLON-SRV-01".to_string(),
            site: "GBLON".to_string(),
            ou_path: "OU=Servers,OU=GBLON,DC=corp,DC=local".to_string(),
            status: ComputerStatus::Active,
            last_logon: now.clone(),
            os: "Windows Server 2019".to_string(),
            created_at: now.clone(),
            metadata: HashMap::from([("role".into(), "app-server".into())]),
        },
        ADComputer {
            id: computer_id(),
            name: "GBLON-SRV-02".to_string(),
            site: "GBLON".to_string(),
            ou_path: "OU=Servers,OU=GBLON,DC=corp,DC=local".to_string(),
            status: ComputerStatus::Disabled,
            last_logon: (chrono::Utc::now() - chrono::Duration::days(150)).to_rfc3339(),
            os: "Windows Server 2016".to_string(),
            created_at: now.clone(),
            metadata: HashMap::from([
                ("role".into(), "legacy-app".into()),
                (
                    "disabled_reason".into(),
                    "Decommission pending review".into(),
                ),
            ]),
        },
        ADComputer {
            id: computer_id(),
            name: "NLAMS-TEST-01".to_string(),
            site: "NLAMS".to_string(),
            ou_path: "OU=Testing,OU=NLAMS,DC=corp,DC=local".to_string(),
            status: ComputerStatus::Quarantined,
            last_logon: (chrono::Utc::now() - chrono::Duration::days(30)).to_rfc3339(),
            os: "Windows Server 2022".to_string(),
            created_at: now.clone(),
            metadata: HashMap::from([
                ("role".into(), "test-server".into()),
                (
                    "quarantine_reason".into(),
                    "Security incident investigation".into(),
                ),
            ]),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_naming_convention_valid() {
        assert!(validate_naming_convention("DEFRA-SRV-01").is_ok());
        assert!(validate_naming_convention("GBLON-DC-02").is_ok());
        assert!(validate_naming_convention("NLAMS-WS-100").is_ok());
        assert!(validate_naming_convention("FRPAR-MGMT-01").is_ok());
        assert!(validate_naming_convention("FRPAR-TEST-42").is_ok());
        assert!(validate_naming_convention("NLAMS-DEV-9999").is_ok());
    }

    #[test]
    fn test_validate_naming_convention_invalid_site() {
        assert!(validate_naming_convention("INVALID-SRV-01").is_err());
        assert!(validate_naming_convention("XX-SRV-01").is_err());
    }

    #[test]
    fn test_validate_naming_convention_invalid_role() {
        assert!(validate_naming_convention("DEFRA-APP-01").is_err());
        assert!(validate_naming_convention("DEFRA-DB-01").is_err());
    }

    #[test]
    fn test_validate_naming_convention_invalid_number() {
        assert!(validate_naming_convention("DEFRA-SRV-1").is_err());
        assert!(validate_naming_convention("DEFRA-SRV-ABCD").is_err());
    }

    #[test]
    fn test_prestage_computer_success() {
        let computer = prestage_computer(
            "DEFRA-SRV-01",
            "DEFRA",
            "OU=Servers,OU=DEFRA,DC=corp,DC=local",
        )
        .unwrap();
        assert_eq!(computer.name, "DEFRA-SRV-01");
        assert_eq!(computer.site, "DEFRA");
        assert_eq!(computer.ou_path, "OU=Servers,OU=DEFRA,DC=corp,DC=local");
        assert_eq!(computer.status, ComputerStatus::Active);
        assert!(computer.metadata.contains_key("prestaged"));
    }

    #[test]
    fn test_prestage_rejects_foreign_site_prefix() {
        let error = prestage_computer(
            "GBLON-SRV-01",
            "DEFRA",
            "OU=Servers,OU=DEFRA,DC=corp,DC=local",
        )
        .expect_err("an authorized declared site must not claim another site's namespace");

        assert!(error.contains("does not match declared site"));
    }

    #[test]
    fn test_prestage_canonicalizes_declared_site_but_requires_canonical_name_prefix() {
        let computer = prestage_computer(
            "DEFRA-SRV-01",
            "de fra",
            "OU=Servers,OU=DEFRA,DC=corp,DC=local",
        )
        .expect("a supported display-form alias should resolve to the registered active site");
        assert_eq!(computer.site, "DEFRA");

        let error = prestage_computer(
            "defra-SRV-01",
            "DEFRA",
            "OU=Servers,OU=DEFRA,DC=corp,DC=local",
        )
        .expect_err("the globally unique name must use the registry's canonical site code");
        assert!(error.contains("must use canonical site code 'DEFRA'"));
    }

    #[test]
    fn test_prestage_rejects_caller_chosen_foreign_or_noncanonical_ou() {
        for unsafe_ou in [
            "OU=Servers,OU=GBLON,DC=corp,DC=local",
            "OU=Servers,DC=corp,DC=local",
            "OU=DMZ,OU=DEFRA,DC=corp,DC=local",
        ] {
            let error = prestage_computer("DEFRA-SRV-01", "DEFRA", unsafe_ou)
                .expect_err("prestage must persist the server-derived role/site OU only");
            assert!(error.contains("server-derived directory namespace"));
        }
    }

    #[test]
    fn test_prestage_derives_role_specific_ou() {
        assert_eq!(
            canonical_prestage_ou("DEFRA-WS-01").unwrap(),
            "OU=Workstations,OU=DEFRA,DC=corp,DC=local"
        );
        assert_eq!(
            canonical_prestage_ou("DEFRA-DC-01").unwrap(),
            "OU=Domain Controllers,DC=corp,DC=local"
        );
    }

    #[test]
    fn test_prestage_accepts_registered_hyphenated_custom_site() {
        const SITE: &str = "LEGACY-AD-CUSTOM";
        site_registry::upsert_site(
            site_registry::SiteEntry {
                unlocode: SITE.into(),
                name: "Legacy AD custom test site".into(),
                country: "Test country".into(),
                country_code: "ZZ".into(),
                timezone: "UTC".into(),
                active: true,
            },
            site_registry::SiteCodeSystem::Custom,
        )
        .unwrap();

        let name = format!("{SITE}-SRV-01");
        let ou_path = format!("OU=Servers,OU={SITE},DC=corp,DC=local");
        let computer = prestage_computer(&name, SITE, &ou_path).unwrap();
        assert_eq!(computer.site, SITE);
    }

    #[test]
    fn test_prestage_computer_invalid_site() {
        let result = prestage_computer(
            "DEFRA-SRV-01",
            "INVALID",
            "OU=Servers,OU=DEFRA,DC=corp,DC=local",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_prestage_computer_invalid_name() {
        let result = prestage_computer(
            "BAD-SRV-01",
            "DEFRA",
            "OU=Servers,OU=DEFRA,DC=corp,DC=local",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_computer_valid() {
        let result = validate_computer("DEFRA-SRV-01").unwrap();
        assert!(result.passed);
    }

    #[test]
    fn test_validate_computer_invalid() {
        let result = validate_computer("DEFRA-APP-01").unwrap();
        assert!(!result.passed);
        assert!(result.errors.iter().any(|e| e.contains("role code")));
    }

    #[test]
    fn test_validate_computer_unknown_site() {
        let result = validate_computer("ZZZZ-SRV-01").unwrap();
        assert!(!result.passed);
    }

    #[test]
    fn test_move_computer_success() {
        let computer = move_computer("DEFRA-SRV-01", "OU=DMZ,OU=DEFRA,DC=corp,DC=local").unwrap();
        assert_eq!(computer.ou_path, "OU=DMZ,OU=DEFRA,DC=corp,DC=local");
        assert_eq!(computer.status, ComputerStatus::Active);
        assert!(computer.metadata.contains_key("moved"));
    }

    #[test]
    fn test_move_computer_invalid_target_ou() {
        let result = move_computer("DEFRA-SRV-01", "OU=Invalid,DC=corp,DC=local");
        assert!(result.is_err());

        let foreign = move_computer("DEFRA-SRV-01", "OU=DMZ,OU=GBLON,DC=corp,DC=local");
        assert!(foreign.is_err());
    }

    #[test]
    fn test_disable_computer_success() {
        let computer = disable_computer("DEFRA-SRV-01", "Scheduled maintenance").unwrap();
        assert_eq!(computer.status, ComputerStatus::Disabled);
        assert!(computer.metadata.contains_key("disabled"));
        assert!(
            computer
                .metadata
                .get("disable_reason")
                .unwrap()
                .contains("Scheduled maintenance")
        );
    }

    #[test]
    fn test_disable_computer_empty_reason() {
        let result = disable_computer("DEFRA-SRV-01", "");
        assert!(result.is_err());
    }

    #[test]
    fn test_enable_computer_success() {
        let computer = enable_computer("DEFRA-SRV-01").unwrap();
        assert_eq!(computer.status, ComputerStatus::Active);
        assert!(computer.metadata.contains_key("enabled"));
    }

    #[test]
    fn test_delete_computer_success() {
        let result = delete_computer("DEFRA-SRV-01");
        assert!(result.is_ok());
    }

    #[test]
    fn test_reconcile_computers_success() {
        let result = reconcile_computers("DEFRA").unwrap();
        assert_eq!(result.site, "DEFRA");
        assert_eq!(result.total_ad_objects, 3);
        assert_eq!(result.total_cmdb_objects, 2);
        assert_eq!(result.missing_from_cmdb.len(), 1);
        assert!(
            result
                .missing_from_cmdb
                .contains(&"DEFRA-WS-01".to_string())
        );
        assert!(result.dry_run);
    }

    #[test]
    fn test_reconcile_computers_invalid_site() {
        let result = reconcile_computers("INVALID");
        assert!(result.is_err());
    }

    #[test]
    fn test_get_orphaned_success() {
        let orphaned = get_orphaned("GBLON").unwrap();
        assert!(!orphaned.is_empty());
        for computer in &orphaned {
            assert!(computer.metadata.contains_key("orphaned"));
        }
    }

    #[test]
    fn test_get_orphaned_invalid_site() {
        let result = get_orphaned("INVALID");
        assert!(result.is_err());
    }

    #[test]
    fn test_seed_examples() {
        let examples = seed_examples();
        assert_eq!(examples.len(), 5);
        let names: Vec<&str> = examples.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"DEFRA-SRV-01"));
        assert!(names.contains(&"DEFRA-DC-01"));
        assert!(names.contains(&"GBLON-SRV-01"));
        assert!(names.contains(&"GBLON-SRV-02"));
        assert!(names.contains(&"NLAMS-TEST-01"));
    }

    #[test]
    fn test_computer_status_display() {
        assert_eq!(ComputerStatus::Active.to_string(), "Active");
        assert_eq!(ComputerStatus::Disabled.to_string(), "Disabled");
        assert_eq!(ComputerStatus::Quarantined.to_string(), "Quarantined");
        assert_eq!(ComputerStatus::Deleted.to_string(), "Deleted");
    }

    #[test]
    fn test_prestage_empty_name() {
        let result = prestage_computer("", "DEFRA", "OU=Servers,OU=DEFRA,DC=corp,DC=local");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_empty_name() {
        let result = validate_computer("");
        assert!(result.is_err());
    }

    // ── model-based predecessor-guard tests ────────────────────────────────────

    fn make_computer(status: ComputerStatus) -> ADComputer {
        ADComputer {
            id: Uuid::new_v4().to_string(),
            name: "DEFRA-SRV-01".into(),
            site: "DEFRA".into(),
            ou_path: "OU=Servers,OU=DEFRA,DC=corp,DC=local".into(),
            status,
            last_logon: chrono::Utc::now().to_rfc3339(),
            os: "Windows Server 2022".into(),
            created_at: chrono::Utc::now().to_rfc3339(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn move_deleted_computer_is_err() {
        let deleted = make_computer(ComputerStatus::Deleted);
        let result = move_computer_model(&deleted, "OU=DMZ,OU=DEFRA,DC=corp,DC=local");
        assert!(result.is_err(), "moving a Deleted computer must fail");
        assert!(result.unwrap_err().contains("Deleted"));
    }

    #[test]
    fn move_disabled_computer_is_err() {
        let disabled = make_computer(ComputerStatus::Disabled);
        let result = move_computer_model(&disabled, "OU=DMZ,OU=DEFRA,DC=corp,DC=local");
        assert!(result.is_err(), "moving a Disabled computer must fail");
    }

    #[test]
    fn disable_already_disabled_is_err() {
        let disabled = make_computer(ComputerStatus::Disabled);
        let err = disable_computer_model(&disabled, "some reason")
            .expect_err("disabling an already-Disabled computer must fail");
        assert!(
            err.to_lowercase().contains("disabled"),
            "error message should mention Disabled: {err}"
        );
    }

    #[test]
    fn disable_deleted_computer_is_err() {
        let deleted = make_computer(ComputerStatus::Deleted);
        let result = disable_computer_model(&deleted, "reason");
        assert!(result.is_err(), "disabling a Deleted computer must fail");
    }

    #[test]
    fn quarantined_computer_cannot_be_cycled_through_disabled_to_active() {
        let mut quarantined = make_computer(ComputerStatus::Quarantined);
        quarantined.metadata.insert(
            "quarantine_reason".into(),
            "Security incident investigation".into(),
        );

        let error = disable_computer_model(&quarantined, "ordinary maintenance")
            .expect_err("ordinary disable authority must not release quarantine");

        assert!(error.contains("explicit quarantine release"));
        assert_eq!(quarantined.status, ComputerStatus::Quarantined);
        assert_eq!(
            quarantined
                .metadata
                .get("quarantine_reason")
                .map(String::as_str),
            Some("Security incident investigation")
        );
    }

    #[test]
    fn active_disable_then_enable_remains_supported() {
        let active = make_computer(ComputerStatus::Active);
        let disabled = disable_computer_model(&active, "Scheduled maintenance")
            .expect("Active computer may be disabled");
        assert_eq!(disabled.status, ComputerStatus::Disabled);

        let enabled = enable_computer_model(&disabled).expect("Disabled computer may be enabled");
        assert_eq!(enabled.status, ComputerStatus::Active);
        assert!(!enabled.metadata.contains_key("disable_reason"));
    }

    fn reviewed_recovery() -> QuarantineRecoveryDecision {
        QuarantineRecoveryDecision {
            review_id: "10000000-0000-4000-8000-000000000001".into(),
            reason: "Independent review confirmed the hold can be released".into(),
            approved_at: "2026-07-15T10:00:00Z".into(),
        }
    }

    #[test]
    fn reviewed_quarantine_recovery_leaves_computer_disabled_and_preserves_hold_evidence() {
        let mut quarantined = make_computer(ComputerStatus::Quarantined);
        quarantined.metadata.insert(
            "quarantine_reason".into(),
            "Security incident investigation".into(),
        );

        let recovered = release_quarantine_model(&quarantined, &reviewed_recovery())
            .expect("a typed reviewed recovery may leave quarantine");

        assert_eq!(recovered.status, ComputerStatus::Disabled);
        assert_eq!(
            recovered
                .metadata
                .get("quarantine_reason")
                .map(String::as_str),
            Some("Security incident investigation")
        );
        assert_eq!(
            recovered
                .metadata
                .get("quarantine_release_review_id")
                .map(String::as_str),
            Some("10000000-0000-4000-8000-000000000001")
        );
        assert!(recovered.metadata.contains_key("disable_reason"));
    }

    #[test]
    fn quarantine_is_terminal_without_complete_typed_review_evidence() {
        let mut quarantined = make_computer(ComputerStatus::Quarantined);
        quarantined
            .metadata
            .insert("quarantine_reason".into(), "investigation".into());

        assert!(disable_computer_model(&quarantined, "maintenance").is_err());
        assert!(enable_computer_model(&quarantined).is_err());
        assert!(delete_computer_model(&quarantined).is_err());
        assert!(move_computer_model(&quarantined, "OU=DMZ,OU=DEFRA,DC=corp,DC=local").is_err());

        let mut malformed = reviewed_recovery();
        malformed.review_id = "caller-chosen-label".into();
        assert!(release_quarantine_model(&quarantined, &malformed).is_err());

        let mut missing_reason = reviewed_recovery();
        missing_reason.reason.clear();
        assert!(release_quarantine_model(&quarantined, &missing_reason).is_err());
    }

    #[test]
    fn ordinary_lifecycle_cannot_launder_quarantine_into_active() {
        let mut frontier = vec![make_computer(ComputerStatus::Quarantined)];
        frontier[0]
            .metadata
            .insert("quarantine_reason".into(), "investigation".into());

        for _ in 0..4 {
            let mut next = Vec::new();
            for state in &frontier {
                if let Ok(value) = disable_computer_model(state, "ordinary") {
                    next.push(value);
                }
                if let Ok(value) = enable_computer_model(state) {
                    next.push(value);
                }
                if let Ok(value) = delete_computer_model(state) {
                    next.push(value);
                }
            }
            assert!(
                next.iter()
                    .all(|state| state.status != ComputerStatus::Active),
                "no bounded ordinary path from quarantine may reach Active"
            );
            frontier.extend(next);
        }
    }

    #[test]
    fn enable_active_computer_is_err() {
        let active = make_computer(ComputerStatus::Active);
        let result = enable_computer_model(&active);
        assert!(result.is_err(), "enabling an Active computer must fail");
    }

    #[test]
    fn delete_already_deleted_is_err() {
        let deleted = make_computer(ComputerStatus::Deleted);
        let result = delete_computer_model(&deleted);
        assert!(
            result.is_err(),
            "deleting an already-Deleted computer must fail"
        );
    }

    #[test]
    fn delete_quarantined_computer_is_err() {
        let quarantined = make_computer(ComputerStatus::Quarantined);
        let error = delete_computer_model(&quarantined)
            .expect_err("ordinary delete must not erase quarantine state");
        assert!(error.contains("quarantine recovery review"));
    }
}
