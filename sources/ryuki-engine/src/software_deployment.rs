use crate::models::*;
use serde_json::{Value, json};
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

const VALID_SITES: &[&str] = &["DEBER", "DEFRA", "FRPAR", "GBLON", "NLAMS"];

static PACKAGE_STORE: OnceLock<Mutex<Vec<ApprovedPackage>>> = OnceLock::new();
static DEPLOYMENT_STORE: OnceLock<Mutex<Vec<DeploymentRecord>>> = OnceLock::new();

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ApprovedPackage {
    pub id: String,
    pub name: String,
    pub version: String,
    pub vendor: String,
    pub package_type: PackageType,
    pub approved_by: String,
    pub approved_date: String,
    pub site_scope: SiteScope,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum PackageType {
    Msi,
    Exe,
    Apt,
    Rpm,
    Script,
}

impl std::fmt::Display for PackageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackageType::Msi => write!(f, "msi"),
            PackageType::Exe => write!(f, "exe"),
            PackageType::Apt => write!(f, "apt"),
            PackageType::Rpm => write!(f, "rpm"),
            PackageType::Script => write!(f, "script"),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum SiteScope {
    All,
    Specific(Vec<String>),
}

impl SiteScope {
    fn covers(&self, site: &str) -> bool {
        match self {
            SiteScope::All => true,
            SiteScope::Specific(sites) => sites.iter().any(|s| s == site),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct DeploymentRequest {
    pub server_name: String,
    pub package_id: String,
    pub target_version: String,
    pub scheduled_time: String,
    pub requester: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct DeploymentRecord {
    pub id: String,
    pub server_name: String,
    pub package_id: String,
    pub package_name: String,
    pub target_version: String,
    pub scheduled_time: String,
    pub requester: String,
    pub status: DeploymentStatus,
    pub approved_by: Option<String>,
    pub plan: Option<DeploymentPlan>,
    pub executed_at: Option<String>,
    pub verified_at: Option<String>,
    pub evidence: Vec<EvidenceItem>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum DeploymentStatus {
    Draft,
    Validated,
    Planned,
    Approved,
    Executing,
    Executed,
    Verified,
    Completed,
    Failed,
    Rejected,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct DeploymentPlan {
    pub pre_snapshot: String,
    pub post_snapshot: String,
    pub install_steps: Vec<String>,
    pub rollback_steps: Vec<String>,
    pub estimated_duration_minutes: u32,
    pub reboot_required: bool,
}

fn package_store() -> &'static Mutex<Vec<ApprovedPackage>> {
    PACKAGE_STORE.get_or_init(|| Mutex::new(seed_packages()))
}

fn deployment_store() -> &'static Mutex<Vec<DeploymentRecord>> {
    DEPLOYMENT_STORE.get_or_init(|| Mutex::new(seed_deployments()))
}

fn seed_packages() -> Vec<ApprovedPackage> {
    vec![
        ApprovedPackage {
            id: "pkg-zabbix-agent".into(),
            name: "Zabbix Agent 7.0".into(),
            version: "7.0.4".into(),
            vendor: "Zabbix LLC".into(),
            package_type: PackageType::Msi,
            approved_by: "security-team".into(),
            approved_date: "2026-05-15".into(),
            site_scope: SiteScope::All,
        },
        ApprovedPackage {
            id: "pkg-crowdstrike-sensor".into(),
            name: "CrowdStrike Falcon Sensor".into(),
            version: "7.11.0".into(),
            vendor: "CrowdStrike".into(),
            package_type: PackageType::Exe,
            approved_by: "security-team".into(),
            approved_date: "2026-05-20".into(),
            site_scope: SiteScope::All,
        },
        ApprovedPackage {
            id: "pkg-veeam-agent".into(),
            name: "Veeam Agent for Windows".into(),
            version: "6.1.2".into(),
            vendor: "Veeam Software".into(),
            package_type: PackageType::Msi,
            approved_by: "backup-team".into(),
            approved_date: "2026-04-10".into(),
            site_scope: SiteScope::Specific(vec!["DEFRA".into(), "GBLON".into(), "NLAMS".into()]),
        },
        ApprovedPackage {
            id: "pkg-qualys-agent".into(),
            name: "Qualys Cloud Agent".into(),
            version: "5.2.0".into(),
            vendor: "Qualys Inc.".into(),
            package_type: PackageType::Rpm,
            approved_by: "compliance-team".into(),
            approved_date: "2026-06-01".into(),
            site_scope: SiteScope::All,
        },
        ApprovedPackage {
            id: "pkg-ms-teams".into(),
            name: "Microsoft Teams".into(),
            version: "24091.214.2846.4154".into(),
            vendor: "Microsoft".into(),
            package_type: PackageType::Exe,
            approved_by: "workplace-team".into(),
            approved_date: "2026-05-28".into(),
            site_scope: SiteScope::All,
        },
    ]
}

fn seed_deployments() -> Vec<DeploymentRecord> {
    vec![
        DeploymentRecord {
            id: "dep-001".into(),
            server_name: "w-defra-srv-01".into(),
            package_id: "pkg-zabbix-agent".into(),
            package_name: "Zabbix Agent 7.0".into(),
            target_version: "7.0.4".into(),
            scheduled_time: "2026-06-15T22:00:00Z".into(),
            requester: "ops-team".into(),
            status: DeploymentStatus::Completed,
            approved_by: Some("admin".into()),
            plan: None,
            executed_at: Some("2026-06-14T22:05:00Z".into()),
            verified_at: Some("2026-06-14T22:12:00Z".into()),
            evidence: vec![],
        },
        DeploymentRecord {
            id: "dep-002".into(),
            server_name: "l-gblon-srv-03".into(),
            package_id: "pkg-crowdstrike-sensor".into(),
            package_name: "CrowdStrike Falcon Sensor".into(),
            target_version: "7.11.0".into(),
            scheduled_time: "2026-06-18T23:00:00Z".into(),
            requester: "security-team".into(),
            status: DeploymentStatus::Draft,
            approved_by: None,
            plan: None,
            executed_at: None,
            verified_at: None,
            evidence: vec![],
        },
        DeploymentRecord {
            id: "dep-003".into(),
            server_name: "w-nlams-srv-02".into(),
            package_id: "pkg-qualys-agent".into(),
            package_name: "Qualys Cloud Agent".into(),
            target_version: "5.2.0".into(),
            scheduled_time: "2026-06-20T01:00:00Z".into(),
            requester: "compliance-team".into(),
            status: DeploymentStatus::Draft,
            approved_by: None,
            plan: None,
            executed_at: None,
            verified_at: None,
            evidence: vec![],
        },
    ]
}

pub fn get_approved_packages(site: Option<&str>) -> Vec<ApprovedPackage> {
    let store = package_store().lock().unwrap();
    match site {
        None => store.clone(),
        Some(site) => store
            .iter()
            .filter(|p| p.site_scope.covers(site))
            .cloned()
            .collect(),
    }
}

pub fn validate_deployment(request: &DeploymentRequest) -> Result<ValidationResult, String> {
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut failed_rules: Vec<String> = Vec::new();
    let mut remediation: Vec<String> = Vec::new();

    if request.server_name.is_empty() {
        errors.push("Server name is required".into());
        failed_rules.push("p0-server-name-required".into());
        remediation.push("Provide a valid server name.".into());
    }

    if request.package_id.is_empty() {
        errors.push("Package ID is required".into());
        failed_rules.push("p0-package-id-required".into());
        remediation.push("Provide a valid package ID.".into());
    }

    if request.target_version.is_empty() {
        errors.push("Target version is required".into());
        failed_rules.push("p0-target-version-required".into());
        remediation.push("Provide a target package version.".into());
    }

    if request.requester.is_empty() {
        errors.push("Requester is required".into());
        failed_rules.push("p0-requester-required".into());
        remediation.push("Provide the requester identity.".into());
    }

    let packages = package_store().lock().unwrap();
    let package = packages.iter().find(|p| p.id == request.package_id);

    if package.is_none() {
        errors.push(format!(
            "Package {} is not in the approved catalog",
            request.package_id
        ));
        failed_rules.push("p0-approved-package-required".into());
        remediation.push(format!(
            "Request approval for package {} or choose an approved package.",
            request.package_id
        ));
    }

    if request.scheduled_time.is_empty() {
        warnings.push("No scheduled time provided — deployment will be immediate (dry-run)".into());
    }

    warnings.push("DRY-RUN: Server online status verified (simulated)".into());
    warnings.push("DRY-RUN: No conflicting deployments detected (simulated)".into());

    Ok(ValidationResult {
        passed: errors.is_empty(),
        errors,
        warnings,
        failed_rules,
        remediation,
    })
}

pub fn plan_deployment(request: &DeploymentRequest) -> Result<DeploymentRecord, String> {
    let packages = package_store().lock().unwrap();
    let package = packages
        .iter()
        .find(|p| p.id == request.package_id)
        .ok_or_else(|| format!("Package not found: {}", request.package_id))?;

    let id = format!(
        "dep-{}",
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );

    let plan = DeploymentPlan {
        pre_snapshot: format!(
            "DRY-RUN: Pre-install snapshot of {} (simulated, no Veeam calls)",
            request.server_name
        ),
        post_snapshot: format!(
            "DRY-RUN: Post-install snapshot of {} (simulated, no Veeam calls)",
            request.server_name
        ),
        install_steps: vec![
            format!(
                "DRY-RUN: Download {} v{} ({}) — simulated",
                package.name, request.target_version, package.package_type
            ),
            format!(
                "DRY-RUN: Install {} on {} — simulated",
                package.name, request.server_name
            ),
            format!(
                "DRY-RUN: Configure {} with site defaults — simulated",
                package.name
            ),
        ],
        rollback_steps: vec![
            "DRY-RUN: Uninstall package".into(),
            "DRY-RUN: Restore from pre-install snapshot".into(),
        ],
        estimated_duration_minutes: 15,
        reboot_required: false,
    };

    let record = DeploymentRecord {
        id,
        server_name: request.server_name.clone(),
        package_id: request.package_id.clone(),
        package_name: package.name.clone(),
        target_version: request.target_version.clone(),
        scheduled_time: if request.scheduled_time.is_empty() {
            chrono::Utc::now().to_rfc3339()
        } else {
            request.scheduled_time.clone()
        },
        requester: request.requester.clone(),
        status: DeploymentStatus::Planned,
        approved_by: None,
        plan: Some(plan),
        executed_at: None,
        verified_at: None,
        evidence: vec![],
    };

    deployment_store().lock().unwrap().push(record.clone());
    Ok(record)
}

pub fn approve_deployment(request_id: &str, approver: &str) -> Result<DeploymentRecord, String> {
    let mut store = deployment_store().lock().unwrap();
    let idx = store
        .iter()
        .position(|d| d.id == request_id)
        .ok_or_else(|| format!("Deployment not found: {}", request_id))?;

    let record = &store[idx];
    if record.status != DeploymentStatus::Planned {
        return Err(format!(
            "Cannot approve deployment in status {:?}. Must be Planned first.",
            record.status
        ));
    }

    let mut approved = record.clone();
    approved.status = DeploymentStatus::Approved;
    approved.approved_by = Some(approver.to_string());

    store[idx] = approved.clone();
    Ok(approved)
}

pub fn execute_deployment(request_id: &str) -> Result<Vec<EvidenceItem>, String> {
    let store = deployment_store().lock().unwrap();
    let record = store
        .iter()
        .find(|d| d.id == request_id)
        .ok_or_else(|| format!("Deployment not found: {}", request_id))?;

    if record.status != DeploymentStatus::Approved {
        return Err(format!(
            "Cannot execute deployment in status {:?}. Must be Approved first.",
            record.status
        ));
    }

    let mut evidence: Vec<EvidenceItem> = Vec::new();

    evidence.push(EvidenceItem {
        key: "pre-flight-check".into(),
        value: format!(
            "DRY-RUN: Pre-flight check passed for {} (simulated)",
            record.server_name
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::InventoryCheck,
    });

    evidence.push(EvidenceItem {
        key: format!(
            "install-{}",
            record.package_name.to_lowercase().replace(' ', "-")
        ),
        value: format!(
            "DRY-RUN: {} v{} installed on {} (simulated, no provider calls)",
            record.package_name, record.target_version, record.server_name
        ),
        redacted_value: Some("***DRY-RUN SIMULATION***".into()),
        redacted: true,
        evidence_type: EvidenceType::ExecutionLog,
    });

    evidence.push(EvidenceItem {
        key: "post-install-health-check".into(),
        value: format!(
            "DRY-RUN: Health check passed for {} (simulated)",
            record.server_name
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::Summary,
    });

    Ok(evidence)
}

pub fn verify_deployment(request_id: &str) -> Result<ValidationResult, String> {
    let store = deployment_store().lock().unwrap();
    let record = store
        .iter()
        .find(|d| d.id == request_id)
        .ok_or_else(|| format!("Deployment not found: {}", request_id))?;

    let mut warnings: Vec<String> = Vec::new();

    warnings.push(format!(
        "DRY-RUN: Version check passed — {} is running {} v{} (simulated)",
        record.server_name, record.package_name, record.target_version
    ));
    warnings.push(format!(
        "DRY-RUN: Service health verified for {} (simulated)",
        record.server_name
    ));
    warnings.push("DRY-RUN: Configuration drift check passed (simulated)".into());

    Ok(ValidationResult {
        passed: true,
        errors: vec![],
        warnings,
        failed_rules: vec![],
        remediation: vec![],
    })
}

pub fn get_deployment_history(server_name: &str) -> Vec<DeploymentRecord> {
    let store = deployment_store().lock().unwrap();
    store
        .iter()
        .filter(|d| d.server_name == server_name)
        .cloned()
        .collect()
}

pub fn get_package_compliance(site: &str) -> Result<Value, String> {
    if !VALID_SITES.contains(&site) {
        return Err(format!("Unknown site: {}", site));
    }

    let packages = package_store().lock().unwrap();
    let deployments = deployment_store().lock().unwrap();

    let servers = vec![
        format!("w-{}-srv-01", site.to_lowercase()),
        format!("w-{}-srv-02", site.to_lowercase()),
        format!("l-{}-srv-01", site.to_lowercase()),
    ];

    let mut package_status: Vec<Value> = Vec::new();
    for pkg in packages.iter().filter(|p| p.site_scope.covers(site)) {
        let mut outdated_servers: Vec<String> = Vec::new();
        let mut compliant_servers: Vec<String> = Vec::new();

        for server in &servers {
            let has_deployment = deployments.iter().any(|d| {
                d.server_name == *server
                    && d.package_id == pkg.id
                    && d.status == DeploymentStatus::Completed
            });
            if has_deployment {
                compliant_servers.push(server.clone());
            } else {
                outdated_servers.push(server.clone());
            }
        }

        package_status.push(json!({
            "package_id": pkg.id,
            "package_name": pkg.name,
            "required_version": pkg.version,
            "compliant_servers": compliant_servers,
            "outdated_servers": outdated_servers,
            "compliance_percentage": if servers.is_empty() { 100.0 } else { (compliant_servers.len() as f64 / servers.len() as f64) * 100.0 }
        }));
    }

    Ok(json!({
        "source": "dry-run",
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "site": site,
        "servers": servers,
        "packages": package_status,
        "dry_run": true
    }))
}

pub fn get_software_contract() -> Value {
    json!({
        "source": "static-seed",
        "providerCallsEnabled": false,
        "deploymentMode": "dry-run-orchestration",
        "dryRunRequired": true,
        "liveExecutionAllowed": false,
        "supportedWorkflows": ["get-packages", "validate", "plan", "approve", "execute", "verify", "history", "compliance"],
        "validPackageTypes": ["msi", "exe", "apt", "rpm", "script"],
        "validSites": ["DEFRA","GBLON","FRPAR","NLAMS","DEBER","DEFRA","FRPAR","GBLON","NLAMS","DEBER","GBLON","FRPAR","NLAMS"],
        "requiredInputs": ["serverName", "packageId", "targetVersion", "requester"],
        "requiredGuards": ["package-approved", "server-online", "no-conflicting-deployments", "approval-route-assigned", "evidence-redacted"],
        "blockedReasons": ["provider-calls-disabled", "live-execution-disabled", "package-not-approved", "server-offline", "conflicting-deployment", "approval-missing", "evidence-not-redacted"],
        "requiredEvidence": ["Deployment plan summary", "Validation result", "Approval decisions", "Redacted execution evidence", "Post-install verification report", "Evidence references"]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seed_packages_loaded() {
        let packages = get_approved_packages(None);
        assert_eq!(packages.len(), 5);
    }

    #[test]
    fn test_get_approved_packages_by_site() {
        let defra_packages = get_approved_packages(Some("DEFRA"));
        assert!(defra_packages.iter().any(|p| p.id == "pkg-zabbix-agent"));
        assert!(defra_packages.iter().any(|p| p.id == "pkg-veeam-agent"));
        assert!(defra_packages.iter().any(|p| p.id == "pkg-qualys-agent"));
        assert!(
            defra_packages
                .iter()
                .any(|p| p.id == "pkg-crowdstrike-sensor")
        );
        assert!(defra_packages.iter().any(|p| p.id == "pkg-ms-teams"));

        let frpar_packages = get_approved_packages(Some("FRPAR"));
        assert!(frpar_packages.iter().any(|p| p.id == "pkg-zabbix-agent"));
        assert!(!frpar_packages.iter().any(|p| p.id == "pkg-veeam-agent"));
    }

    #[test]
    fn test_validate_deployment_empty_fields() {
        let request = DeploymentRequest {
            server_name: "".into(),
            package_id: "".into(),
            target_version: "".into(),
            scheduled_time: "".into(),
            requester: "".into(),
        };
        let result = validate_deployment(&request).unwrap();
        assert!(!result.passed);
        assert!(result.errors.len() >= 4);
    }

    #[test]
    fn test_validate_deployment_unknown_package() {
        let request = DeploymentRequest {
            server_name: "w-defra-srv-01".into(),
            package_id: "pkg-unknown".into(),
            target_version: "1.0".into(),
            scheduled_time: "2026-06-15T22:00:00Z".into(),
            requester: "ops-team".into(),
        };
        let result = validate_deployment(&request).unwrap();
        assert!(!result.passed);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("not in the approved catalog"))
        );
    }

    #[test]
    fn test_validate_deployment_valid() {
        let request = DeploymentRequest {
            server_name: "w-defra-srv-01".into(),
            package_id: "pkg-zabbix-agent".into(),
            target_version: "7.0.4".into(),
            scheduled_time: "2026-06-15T22:00:00Z".into(),
            requester: "ops-team".into(),
        };
        let result = validate_deployment(&request).unwrap();
        assert!(result.passed);
    }

    #[test]
    fn test_plan_deployment_creates_record() {
        let request = DeploymentRequest {
            server_name: "w-defra-srv-02".into(),
            package_id: "pkg-zabbix-agent".into(),
            target_version: "7.0.4".into(),
            scheduled_time: "2026-06-15T22:00:00Z".into(),
            requester: "ops-team".into(),
        };
        let record = plan_deployment(&request).unwrap();
        assert!(record.id.starts_with("dep-"));
        assert_eq!(record.status, DeploymentStatus::Planned);
        assert_eq!(record.package_name, "Zabbix Agent 7.0");
        assert!(record.plan.is_some());
        assert!(record.plan.as_ref().unwrap().install_steps.len() >= 2);
    }

    #[test]
    fn test_plan_deployment_unknown_package_fails() {
        let request = DeploymentRequest {
            server_name: "w-defra-srv-02".into(),
            package_id: "pkg-unknown".into(),
            target_version: "1.0".into(),
            scheduled_time: "2026-06-15T22:00:00Z".into(),
            requester: "ops-team".into(),
        };
        assert!(plan_deployment(&request).is_err());
    }

    #[test]
    fn test_approve_deployment() {
        let request = DeploymentRequest {
            server_name: "w-defra-srv-03".into(),
            package_id: "pkg-qualys-agent".into(),
            target_version: "5.2.0".into(),
            scheduled_time: "2026-06-16T22:00:00Z".into(),
            requester: "compliance-team".into(),
        };
        let planned = plan_deployment(&request).unwrap();
        let approved = approve_deployment(&planned.id, "admin-user").unwrap();
        assert_eq!(approved.status, DeploymentStatus::Approved);
        assert_eq!(approved.approved_by, Some("admin-user".into()));
    }

    #[test]
    fn test_approve_deployment_not_found() {
        assert!(approve_deployment("dep-nonexistent", "admin").is_err());
    }

    #[test]
    fn test_execute_deployment() {
        let request = DeploymentRequest {
            server_name: "w-gblon-srv-01".into(),
            package_id: "pkg-crowdstrike-sensor".into(),
            target_version: "7.11.0".into(),
            scheduled_time: "2026-06-18T23:00:00Z".into(),
            requester: "security-team".into(),
        };
        let planned = plan_deployment(&request).unwrap();
        let approved = approve_deployment(&planned.id, "admin").unwrap();
        let evidence = execute_deployment(&approved.id).unwrap();
        assert!(evidence.len() >= 3);
        assert!(evidence.iter().any(|e| e.key == "pre-flight-check"));
        assert!(
            evidence
                .iter()
                .any(|e| e.key == "post-install-health-check")
        );
    }

    #[test]
    fn test_execute_deployment_not_approved_fails() {
        let request = DeploymentRequest {
            server_name: "w-gblon-srv-02".into(),
            package_id: "pkg-ms-teams".into(),
            target_version: "24091.214.2846.4154".into(),
            scheduled_time: "2026-06-17T22:00:00Z".into(),
            requester: "workplace-team".into(),
        };
        let planned = plan_deployment(&request).unwrap();
        assert!(execute_deployment(&planned.id).is_err());
    }

    #[test]
    fn test_execute_deployment_not_found() {
        assert!(execute_deployment("dep-nonexistent").is_err());
    }

    #[test]
    fn test_verify_deployment() {
        let request = DeploymentRequest {
            server_name: "w-nlams-srv-03".into(),
            package_id: "pkg-qualys-agent".into(),
            target_version: "5.2.0".into(),
            scheduled_time: "2026-06-19T22:00:00Z".into(),
            requester: "compliance-team".into(),
        };
        let planned = plan_deployment(&request).unwrap();
        let result = verify_deployment(&planned.id).unwrap();
        assert!(result.passed);
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn test_verify_deployment_not_found() {
        assert!(verify_deployment("dep-nonexistent").is_err());
    }

    #[test]
    fn test_get_deployment_history() {
        let history = get_deployment_history("w-defra-srv-01");
        assert!(!history.is_empty());
        assert!(history.iter().any(|d| d.id == "dep-001"));
    }

    #[test]
    fn test_get_deployment_history_empty() {
        let history = get_deployment_history("nonexistent-server");
        assert!(history.is_empty());
    }

    #[test]
    fn test_get_package_compliance() {
        let compliance = get_package_compliance("DEFRA").unwrap();
        assert_eq!(compliance["source"], "dry-run");
        assert_eq!(compliance["dry_run"], true);
        assert_eq!(compliance["site"], "DEFRA");
        assert!(compliance["packages"].as_array().unwrap().len() >= 4);
    }

    #[test]
    fn test_get_package_compliance_unknown_site() {
        assert!(get_package_compliance("UNKNOWN").is_err());
    }

    #[test]
    fn test_get_software_contract() {
        let contract = get_software_contract();
        assert_eq!(contract["source"], "static-seed");
        assert_eq!(contract["dryRunRequired"], true);
        assert_eq!(contract["liveExecutionAllowed"], false);
    }
}
