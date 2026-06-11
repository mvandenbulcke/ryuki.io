use crate::models::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

const VALID_SITES: &[&str] = &["DEBER", "DEFRA", "FRPAR", "GBLON", "NLAMS"];

const VALID_OU_PREFIXES: &[&str] = &[
    "OU=Servers",
    "OU=Workstations",
    "OU=DMZ",
    "OU=Management",
    "OU=Testing",
    "OU=Development",
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
    format!(
        "adc-{}",
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    )
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn validate_naming_convention(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Computer name cannot be empty".into());
    }
    let parts: Vec<&str> = name.split('-').collect();
    if parts.len() != 3 {
        return Err(format!(
            "Invalid computer name '{}': must match pattern SITE-ROLE-NN (e.g. DEFRA-SRV-01)",
            name
        ));
    }
    let site = parts[0];
    if !VALID_SITES.contains(&site) {
        return Err(format!("Unknown site code '{}' in computer name", site));
    }
    let role = parts[1];
    if !["SRV", "WS", "DC", "MGMT", "TEST", "DEV"].contains(&role) {
        return Err(format!(
            "Unknown role code '{}' in computer name. Must be SRV, WS, DC, MGMT, TEST, or DEV",
            role
        ));
    }
    let number = parts[2];
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
    if !VALID_OU_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
    {
        return Err(format!(
            "OU path must start with a valid OU prefix: {:?}",
            VALID_OU_PREFIXES
        ));
    }
    Ok(())
}

pub fn prestage_computer(name: &str, site: &str, ou_path: &str) -> Result<ADComputer, String> {
    if name.is_empty() {
        return Err("Computer name cannot be empty".into());
    }
    if site.is_empty() || !VALID_SITES.contains(&site) {
        return Err(format!("Unknown or empty site: {}", site));
    }
    if ou_path.is_empty() {
        return Err("OU path cannot be empty".into());
    }
    validate_naming_convention(name)?;
    validate_ou_path(ou_path)?;

    Ok(ADComputer {
        id: computer_id(),
        name: name.to_string(),
        site: site.to_string(),
        ou_path: ou_path.to_string(),
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

    let parts: Vec<&str> = name.split('-').collect();
    if parts.len() == 3 {
        let site = parts[0];
        if !VALID_SITES.contains(&site) {
            errors.push(format!("Unknown site code '{}' in computer name", site));
            failed_rules.push("p0-site-code-valid".into());
            remediation.push(format!("Use a valid site code from: {:?}", VALID_SITES));
        }
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
    validate_ou_path(target_ou)?;
    validate_naming_convention(name)?;

    let parts: Vec<&str> = name.split('-').collect();
    let site = parts[0].to_string();

    Ok(ADComputer {
        id: computer_id(),
        name: name.to_string(),
        site,
        ou_path: target_ou.to_string(),
        status: ComputerStatus::Active,
        last_logon: now_iso(),
        os: "Windows Server 2022".to_string(),
        created_at: now_iso(),
        metadata: HashMap::from([
            ("moved".into(), "true".into()),
            ("previous_ou".into(), "OU=Servers,DC=corp,DC=local".into()),
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

    let parts: Vec<&str> = name.split('-').collect();
    let site = parts[0].to_string();

    Ok(ADComputer {
        id: computer_id(),
        name: name.to_string(),
        site,
        ou_path: "OU=Disabled,DC=corp,DC=local".to_string(),
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

    let parts: Vec<&str> = name.split('-').collect();
    let site = parts[0].to_string();

    Ok(ADComputer {
        id: computer_id(),
        name: name.to_string(),
        site,
        ou_path: "OU=Servers,DC=corp,DC=local".to_string(),
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
    if site.is_empty() || !VALID_SITES.contains(&site) {
        return Err(format!("Unknown or empty site: {}", site));
    }

    let ad_objects: Vec<ADComputer> = vec![
        ADComputer {
            id: computer_id(),
            name: format!("{}-SRV-01", site),
            site: site.to_string(),
            ou_path: "OU=Servers,DC=corp,DC=local".to_string(),
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
            ou_path: "OU=Servers,DC=corp,DC=local".to_string(),
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
            ou_path: "OU=Workstations,DC=corp,DC=local".to_string(),
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
    if site.is_empty() || !VALID_SITES.contains(&site) {
        return Err(format!("Unknown or empty site: {}", site));
    }

    let ninety_days_ago = chrono::Utc::now() - chrono::Duration::days(120);
    let orphaned = vec![
        ADComputer {
            id: computer_id(),
            name: format!("{}-SRV-03", site),
            site: site.to_string(),
            ou_path: "OU=Servers,DC=corp,DC=local".to_string(),
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
            ou_path: "OU=Workstations,DC=corp,DC=local".to_string(),
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
        let computer =
            prestage_computer("DEFRA-SRV-01", "DEFRA", "OU=Servers,DC=corp,DC=local").unwrap();
        assert_eq!(computer.name, "DEFRA-SRV-01");
        assert_eq!(computer.site, "DEFRA");
        assert_eq!(computer.status, ComputerStatus::Active);
        assert!(computer.metadata.contains_key("prestaged"));
    }

    #[test]
    fn test_prestage_computer_invalid_site() {
        let result = prestage_computer("DEFRA-SRV-01", "INVALID", "OU=Servers,DC=corp,DC=local");
        assert!(result.is_err());
    }

    #[test]
    fn test_prestage_computer_invalid_name() {
        let result = prestage_computer("BAD-SRV-01", "DEFRA", "OU=Servers,DC=corp,DC=local");
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
        let computer = move_computer("DEFRA-SRV-01", "OU=DMZ,DC=corp,DC=local").unwrap();
        assert_eq!(computer.ou_path, "OU=DMZ,DC=corp,DC=local");
        assert_eq!(computer.status, ComputerStatus::Active);
        assert!(computer.metadata.contains_key("moved"));
    }

    #[test]
    fn test_move_computer_invalid_target_ou() {
        let result = move_computer("DEFRA-SRV-01", "OU=Invalid,DC=corp,DC=local");
        assert!(result.is_err());
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
        assert!(result.missing_from_cmdb.contains(&"DEFRA-WS-01".to_string()));
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
        let result = prestage_computer("", "DEFRA", "OU=Servers,DC=corp,DC=local");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_empty_name() {
        let result = validate_computer("");
        assert!(result.is_err());
    }
}
