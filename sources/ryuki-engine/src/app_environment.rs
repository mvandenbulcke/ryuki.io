use crate::models::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

const VALID_SITES: &[&str] = &["DEBER", "DEFRA", "FRPAR", "GBLON", "NLAMS"];

const VALID_TIERS: &[TierType] = &[TierType::Front, TierType::Mid, TierType::Back];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppEnvironment {
    pub id: String,
    pub app_name: String,
    pub environment: EnvironmentType,
    pub tier: TierType,
    pub vm_count: u32,
    pub cpu_per_vm: u32,
    pub memory_per_vm: u32,
    pub disk_gb: u32,
    pub network_zone: String,
    pub requires_sql: bool,
    pub requires_redis: bool,
    pub site: String,
    pub status: EnvironmentStatus,
    pub networking_plan: String,
    pub dns_plan: String,
    pub certs_plan: String,
    pub monitoring_plan: String,
    pub backup_plan: String,
    pub created_at: String,
    pub updated_at: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EnvironmentType {
    Dev,
    Test,
    Staging,
    Prod,
}

impl std::fmt::Display for EnvironmentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvironmentType::Dev => write!(f, "dev"),
            EnvironmentType::Test => write!(f, "test"),
            EnvironmentType::Staging => write!(f, "staging"),
            EnvironmentType::Prod => write!(f, "prod"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TierType {
    Front,
    Mid,
    Back,
}

impl std::fmt::Display for TierType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TierType::Front => write!(f, "front"),
            TierType::Mid => write!(f, "mid"),
            TierType::Back => write!(f, "back"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EnvironmentStatus {
    Draft,
    Planned,
    Validated,
    Approved,
    Deploying,
    Deployed,
    Verified,
    Failed,
    Retired,
}

impl std::fmt::Display for EnvironmentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvironmentStatus::Draft => write!(f, "draft"),
            EnvironmentStatus::Planned => write!(f, "planned"),
            EnvironmentStatus::Validated => write!(f, "validated"),
            EnvironmentStatus::Approved => write!(f, "approved"),
            EnvironmentStatus::Deploying => write!(f, "deploying"),
            EnvironmentStatus::Deployed => write!(f, "deployed"),
            EnvironmentStatus::Verified => write!(f, "verified"),
            EnvironmentStatus::Failed => write!(f, "failed"),
            EnvironmentStatus::Retired => write!(f, "retired"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentVerification {
    pub id: String,
    pub environment_id: String,
    pub health_check_ok: bool,
    pub connectivity_ok: bool,
    pub backup_active: bool,
    pub monitoring_active: bool,
    pub dns_resolved: bool,
    pub certs_valid: bool,
    pub evidence: Vec<EvidenceItem>,
}

fn tier_id() -> String {
    format!(
        "aenv-{}",
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

fn networking_plan_for_zone(network_zone: &str, site: &str) -> String {
    format!(
        "DRY-RUN: Networking plan — VLAN assignment from zone '{}' at site '{}'. \
         Firewall rules: allow intra-tier communication, restrict cross-zone access. \
         Load balancer: front-tier receives external traffic on ports 443/80. \
         (Simulated — no network device calls)",
        network_zone, site
    )
}

fn dns_plan_for_app(app_name: &str, environment: &EnvironmentType, site: &str) -> String {
    format!(
        "DRY-RUN: DNS plan — A records for {}-{}.{}.corp.local. \
         CNAME: {}-{}.corp.local -> front-tier LB. \
         PTR records configured for reverse lookup. \
         (Simulated — no DNS/IPAM calls)",
        app_name, environment, site, app_name, environment
    )
}

fn certs_plan_for_app(app_name: &str, environment: &EnvironmentType) -> String {
    format!(
        "DRY-RUN: Certificate plan — TLS cert for {}-{}.corp.local (SAN: *.{}-{}.corp.local). \
         Issuer: internal CA. Expiry: 365 days. Auto-renewal enabled. \
         (Simulated — no PKI/CA calls)",
        app_name, environment, app_name, environment
    )
}

fn monitoring_plan_for_tier(
    app_name: &str,
    environment: &EnvironmentType,
    tier: &TierType,
    site: &str,
) -> String {
    format!(
        "DRY-RUN: Monitoring plan for {}-{}-{} at site {}. \
         Host groups: 'Application Servers', '{}-{}-{}'. \
         Templates: 'OS Linux by Zabbix agent', 'HTTP Service'. \
         Triggers: CPU > 90%, memory > 85%, disk > 80%, service down. \
         (Simulated — no Zabbix calls)",
        app_name, environment, tier, site, app_name, environment, tier
    )
}

fn backup_plan_for_app(app_name: &str, environment: &EnvironmentType, site: &str) -> String {
    format!(
        "DRY-RUN: Backup plan for {}-{} at site {}. \
         Policy: 'app-daily' — daily incremental, weekly full. \
         Retention: 30 daily, 12 monthly, 7 yearly. \
         Replication: DR site copy enabled. \
         (Simulated — no Veeam calls)",
        app_name, environment, site
    )
}

pub fn plan_environment(
    app_name: &str,
    environment: EnvironmentType,
    site: &str,
) -> Result<Vec<AppEnvironment>, String> {
    if app_name.is_empty() {
        return Err("app_name cannot be empty".into());
    }
    if site.is_empty() || !VALID_SITES.contains(&site) {
        return Err(format!("Unknown or empty site: {}", site));
    }

    let now = now_iso();
    let mut tiers = Vec::new();

    for tier_type in VALID_TIERS {
        let (vm_count, cpu, memory, disk, zone) = match tier_type {
            TierType::Front => (2, 4, 8, 50, "dmz"),
            TierType::Mid => (3, 8, 16, 100, "app"),
            TierType::Back => (2, 4, 32, 200, "data"),
        };

        let requires_sql = matches!(tier_type, TierType::Back);
        let requires_redis = matches!(tier_type, TierType::Mid);

        let env = AppEnvironment {
            id: tier_id(),
            app_name: app_name.to_string(),
            environment: environment.clone(),
            tier: tier_type.clone(),
            vm_count,
            cpu_per_vm: cpu,
            memory_per_vm: memory,
            disk_gb: disk,
            network_zone: zone.to_string(),
            requires_sql,
            requires_redis,
            site: site.to_string(),
            status: EnvironmentStatus::Planned,
            networking_plan: networking_plan_for_zone(zone, site),
            dns_plan: dns_plan_for_app(app_name, &environment, site),
            certs_plan: certs_plan_for_app(app_name, &environment),
            monitoring_plan: monitoring_plan_for_tier(app_name, &environment, tier_type, site),
            backup_plan: backup_plan_for_app(app_name, &environment, site),
            created_at: now.clone(),
            updated_at: now.clone(),
            metadata: HashMap::from([("dry_run".into(), "true".into())]),
        };

        tiers.push(env);
    }

    Ok(tiers)
}

pub fn validate_environment(env: &AppEnvironment) -> Result<ValidationResult, String> {
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut failed_rules: Vec<String> = Vec::new();
    let mut remediation: Vec<String> = Vec::new();

    if env.app_name.is_empty() {
        errors.push("Missing app_name".into());
        failed_rules.push("p0-app-name-required".into());
        remediation.push("Provide a valid application name.".into());
    }

    if env.site.is_empty() {
        errors.push("Missing site".into());
        failed_rules.push("p0-site-required".into());
        remediation.push("Provide a valid site code.".into());
    } else if !VALID_SITES.contains(&env.site.as_str()) {
        errors.push(format!("Unknown site: {}", env.site));
        failed_rules.push("p0-site-ou-catalog-match".into());
        remediation.push(format!("Select a known site from: {:?}", VALID_SITES));
    }

    if env.network_zone.is_empty() {
        errors.push("Missing network_zone".into());
        failed_rules.push("p0-network-zone-required".into());
        remediation.push("Provide a valid network zone (dmz, app, data).".into());
    }

    if env.vm_count == 0 {
        errors.push("VM count must be at least 1".into());
        failed_rules.push("p0-invalid-vm-count".into());
        remediation.push("Provide a valid VM count (min 1).".into());
    }

    if env.cpu_per_vm == 0 {
        errors.push("CPU per VM must be at least 1".into());
        failed_rules.push("p0-invalid-cpu".into());
        remediation.push("Provide a valid CPU count per VM (min 1).".into());
    }

    if env.memory_per_vm == 0 {
        errors.push("Memory per VM must be at least 1 GB".into());
        failed_rules.push("p0-invalid-memory".into());
        remediation.push("Provide a valid memory size in GB (min 1).".into());
    }

    if env.disk_gb == 0 {
        errors.push("Disk must be at least 1 GB".into());
        failed_rules.push("p0-invalid-disk".into());
        remediation.push("Provide a valid disk size in GB (min 1).".into());
    }

    if env.vm_count > 50 {
        warnings.push(format!(
            "Tier '{}' has {} VMs — large scale deployment, verify cluster capacity",
            env.tier, env.vm_count
        ));
    }

    if env.cpu_per_vm > 64 {
        warnings.push(format!(
            "Tier '{}' has {} CPUs per VM — high-spec, verify host capacity",
            env.tier, env.cpu_per_vm
        ));
    }

    if !matches!(env.status, EnvironmentStatus::Planned)
        && !matches!(env.status, EnvironmentStatus::Validated)
    {
        warnings.push(format!(
            "Validating environment in status '{}' — expected Planned or Validated",
            env.status
        ));
    }

    warnings.push("DRY-RUN: No live provider validation performed".into());
    warnings.push("DRY-RUN: Cluster capacity not checked against live inventory".into());
    warnings
        .push("DRY-RUN: Network zone assignment not verified against live switchport state".into());

    Ok(ValidationResult {
        passed: errors.is_empty(),
        errors,
        warnings,
        failed_rules,
        remediation,
    })
}

pub fn approve_environment(env: &AppEnvironment, approver: &str) -> Result<AppEnvironment, String> {
    if !matches!(env.status, EnvironmentStatus::Planned)
        && !matches!(env.status, EnvironmentStatus::Validated)
    {
        return Err(format!(
            "Cannot approve environment in status '{}'. Must be Planned or Validated first.",
            env.status
        ));
    }

    let mut approved = env.clone();
    approved.status = EnvironmentStatus::Approved;
    approved.updated_at = now_iso();
    // approved_by = the authenticated caller, never a hardcoded string — the
    // approval audit trail must name the real principal.
    approved
        .metadata
        .insert("approved_by".into(), approver.to_string());
    approved.metadata.insert("approved_at".into(), now_iso());

    Ok(approved)
}

pub fn deploy_environment(env: &AppEnvironment) -> Result<AppEnvironment, String> {
    if matches!(env.status, EnvironmentStatus::Deployed)
        || matches!(env.status, EnvironmentStatus::Verified)
        || matches!(env.status, EnvironmentStatus::Failed)
        || matches!(env.status, EnvironmentStatus::Retired)
    {
        return Err(format!(
            "Cannot deploy environment in terminal status: '{}'",
            env.status
        ));
    }

    if !matches!(env.status, EnvironmentStatus::Approved) {
        return Err(format!(
            "Cannot deploy environment in status '{}'. Must be Approved first.",
            env.status
        ));
    }

    let mut deployed = env.clone();
    deployed.status = EnvironmentStatus::Deployed;
    deployed.updated_at = now_iso();
    deployed.metadata.insert(
        "deployment_log".into(),
        format!(
            "DRY-RUN: Deployed {}-{}-{} tier at site {}. \
             {} VMs with {} CPU/{} GB RAM/{} GB disk on zone '{}'. \
             Networking, DNS, certs, monitoring, and backup configured. \
             (Simulated — no hypervisor, network, DNS, PKI, Zabbix, or Veeam calls)",
            env.app_name,
            env.environment,
            env.tier,
            env.site,
            env.vm_count,
            env.cpu_per_vm,
            env.memory_per_vm,
            env.disk_gb,
            env.network_zone
        ),
    );

    Ok(deployed)
}

pub fn verify_environment(env: &AppEnvironment) -> Result<EnvironmentVerification, String> {
    if !matches!(env.status, EnvironmentStatus::Deployed)
        && !matches!(env.status, EnvironmentStatus::Verified)
    {
        return Err(format!(
            "Cannot verify environment in status '{}'. Must be Deployed first.",
            env.status
        ));
    }

    let mut evidence: Vec<EvidenceItem> = Vec::new();

    evidence.push(EvidenceItem {
        key: "health-check".into(),
        value: format!(
            "DRY-RUN: Health check passed for {}-{}-{} at site {} (simulated)",
            env.app_name, env.environment, env.tier, env.site
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::Summary,
    });

    evidence.push(EvidenceItem {
        key: "connectivity-check".into(),
        value: format!(
            "DRY-RUN: Connectivity verified for {}-{}-{} — all VMs reachable (simulated)",
            env.app_name, env.environment, env.tier
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::InventoryCheck,
    });

    evidence.push(EvidenceItem {
        key: "backup-status".into(),
        value: format!(
            "DRY-RUN: Backup policy active for {}-{} at site {} (simulated, no Veeam calls)",
            env.app_name, env.environment, env.site
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::PolicyAssignment,
    });

    evidence.push(EvidenceItem {
        key: "monitoring-status".into(),
        value: format!(
            "DRY-RUN: Monitoring active for {}-{}-{} — agent running, host groups assigned (simulated)",
            env.app_name, env.environment, env.tier
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::PolicyAssignment,
    });

    evidence.push(EvidenceItem {
        key: "dns-resolution".into(),
        value: format!(
            "DRY-RUN: DNS resolution verified for {}-{}.corp.local (simulated)",
            env.app_name, env.environment
        ),
        redacted_value: Some("***DRY-RUN SIMULATION***".into()),
        redacted: true,
        evidence_type: EvidenceType::ExecutionLog,
    });

    evidence.push(EvidenceItem {
        key: "certs-valid".into(),
        value: format!(
            "DRY-RUN: TLS certificate valid for {}-{}.corp.local (simulated)",
            env.app_name, env.environment
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::PolicyAssignment,
    });

    Ok(EnvironmentVerification {
        id: format!(
            "aev-{}",
            Uuid::new_v4()
                .to_string()
                .split('-')
                .next()
                .unwrap_or("unknown")
        ),
        environment_id: env.id.clone(),
        health_check_ok: true,
        connectivity_ok: true,
        backup_active: true,
        monitoring_active: true,
        dns_resolved: true,
        certs_valid: true,
        evidence,
    })
}

pub fn retire_environment(env: &AppEnvironment) -> Result<AppEnvironment, String> {
    if matches!(env.status, EnvironmentStatus::Retired) {
        return Err("Environment is already retired".into());
    }

    if matches!(env.status, EnvironmentStatus::Draft)
        || matches!(env.status, EnvironmentStatus::Planned)
    {
        return Err(format!(
            "Cannot retire environment in status '{}'. Must be deployed or verified first.",
            env.status
        ));
    }

    let mut retired = env.clone();
    retired.status = EnvironmentStatus::Retired;
    retired.updated_at = now_iso();
    retired.metadata.insert(
        "retirement_log".into(),
        format!(
            "DRY-RUN: Retired {}-{}-{} at site {}. \
             VMs decommissioned ({} total), DNS records removed, monitoring disabled, \
             backup retained per policy. \
             (Simulated — no hypervisor, DNS, Zabbix, or Veeam calls)",
            env.app_name, env.environment, env.tier, env.site, env.vm_count
        ),
    );

    Ok(retired)
}

pub fn seed_examples() -> Vec<AppEnvironment> {
    let example1 = plan_environment("payment-service", EnvironmentType::Prod, "DEFRA").unwrap();
    let example2 = plan_environment("inventory-api", EnvironmentType::Staging, "GBLON").unwrap();

    let mut all = Vec::new();
    all.extend(example1);
    all.extend(example2);
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plan_environment_creates_three_tiers() {
        let tiers = plan_environment("myapp", EnvironmentType::Prod, "DEFRA").unwrap();
        assert_eq!(tiers.len(), 3);

        let tier_names: Vec<String> = tiers.iter().map(|t| t.tier.to_string()).collect();
        assert!(tier_names.contains(&"front".to_string()));
        assert!(tier_names.contains(&"mid".to_string()));
        assert!(tier_names.contains(&"back".to_string()));
    }

    #[test]
    fn test_plan_environment_all_tiers_have_ids() {
        let tiers = plan_environment("myapp", EnvironmentType::Dev, "GBLON").unwrap();
        for tier in &tiers {
            assert!(tier.id.starts_with("aenv-"));
            assert!(!tier.id.is_empty());
        }
    }

    #[test]
    fn test_plan_environment_tier_specs_are_set() {
        let tiers = plan_environment("myapp", EnvironmentType::Staging, "NLAMS").unwrap();
        let front = tiers.iter().find(|t| t.tier == TierType::Front).unwrap();
        let mid = tiers.iter().find(|t| t.tier == TierType::Mid).unwrap();
        let back = tiers.iter().find(|t| t.tier == TierType::Back).unwrap();

        assert_eq!(front.vm_count, 2);
        assert_eq!(front.network_zone, "dmz");
        assert!(!front.requires_sql);
        assert!(!front.requires_redis);

        assert_eq!(mid.vm_count, 3);
        assert_eq!(mid.network_zone, "app");
        assert!(!mid.requires_sql);
        assert!(mid.requires_redis);

        assert_eq!(back.vm_count, 2);
        assert_eq!(back.network_zone, "data");
        assert!(back.requires_sql);
        assert!(!back.requires_redis);
    }

    #[test]
    fn test_plan_environment_empty_app_name_fails() {
        let result = plan_environment("", EnvironmentType::Prod, "DEFRA");
        assert!(result.is_err());
    }

    #[test]
    fn test_plan_environment_unknown_site_fails() {
        let result = plan_environment("myapp", EnvironmentType::Prod, "UNKNOWN");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_environment_passes() {
        let tiers = plan_environment("myapp", EnvironmentType::Prod, "DEFRA").unwrap();
        let result = validate_environment(&tiers[0]).unwrap();
        assert!(result.passed);
    }

    #[test]
    fn test_validate_environment_detects_bad_site() {
        let mut env = plan_environment("myapp", EnvironmentType::Prod, "DEFRA")
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        env.site = "INVALID".into();
        let result = validate_environment(&env).unwrap();
        assert!(!result.passed);
        assert!(result.errors.iter().any(|e| e.contains("Unknown site")));
    }

    #[test]
    fn test_validate_environment_detects_missing_app_name() {
        let mut env = plan_environment("myapp", EnvironmentType::Dev, "GBLON")
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        env.app_name = "".into();
        let result = validate_environment(&env).unwrap();
        assert!(!result.passed);
        assert!(result.errors.iter().any(|e| e.contains("Missing app_name")));
    }

    #[test]
    fn test_approve_environment() {
        let env = plan_environment("myapp", EnvironmentType::Prod, "DEFRA")
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let approved = approve_environment(&env, "env-approver").unwrap();
        assert_eq!(approved.status, EnvironmentStatus::Approved);
        // approved_by records the passed-in principal, not a hardcoded string.
        assert_eq!(
            approved.metadata.get("approved_by").map(String::as_str),
            Some("env-approver")
        );
    }

    #[test]
    fn test_approve_environment_wrong_status_fails() {
        let mut env = plan_environment("myapp", EnvironmentType::Test, "GBLON")
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        env.status = EnvironmentStatus::Deployed;
        let result = approve_environment(&env, "env-approver");
        assert!(result.is_err());
    }

    #[test]
    fn test_deploy_environment() {
        let mut env = plan_environment("myapp", EnvironmentType::Staging, "NLAMS")
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        env.status = EnvironmentStatus::Approved;
        let deployed = deploy_environment(&env).unwrap();
        assert_eq!(deployed.status, EnvironmentStatus::Deployed);
        assert!(deployed.metadata.contains_key("deployment_log"));
    }

    #[test]
    fn test_deploy_environment_not_approved_fails() {
        let env = plan_environment("myapp", EnvironmentType::Prod, "DEFRA")
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let result = deploy_environment(&env);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_environment() {
        let mut env = plan_environment("myapp", EnvironmentType::Dev, "GBLON")
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        env.status = EnvironmentStatus::Deployed;
        let verification = verify_environment(&env).unwrap();
        assert!(verification.health_check_ok);
        assert!(verification.connectivity_ok);
        assert!(verification.backup_active);
        assert!(verification.monitoring_active);
        assert!(verification.dns_resolved);
        assert!(verification.certs_valid);
        assert_eq!(verification.evidence.len(), 6);
        assert!(
            verification
                .evidence
                .iter()
                .any(|e| e.key == "health-check")
        );
        assert!(
            verification
                .evidence
                .iter()
                .any(|e| e.key == "backup-status")
        );
    }

    #[test]
    fn test_verify_environment_not_deployed_fails() {
        let env = plan_environment("myapp", EnvironmentType::Dev, "DEFRA")
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let result = verify_environment(&env);
        assert!(result.is_err());
    }

    #[test]
    fn test_retire_environment() {
        let mut env = plan_environment("myapp", EnvironmentType::Staging, "GBLON")
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        env.status = EnvironmentStatus::Deployed;
        let retired = retire_environment(&env).unwrap();
        assert_eq!(retired.status, EnvironmentStatus::Retired);
        assert!(retired.metadata.contains_key("retirement_log"));
    }

    #[test]
    fn test_retire_environment_already_retired_fails() {
        let mut env = plan_environment("myapp", EnvironmentType::Prod, "DEFRA")
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        env.status = EnvironmentStatus::Retired;
        let result = retire_environment(&env);
        assert!(result.is_err());
    }

    #[test]
    fn test_seed_examples() {
        let examples = seed_examples();
        assert_eq!(examples.len(), 6);
        let sites: Vec<&str> = examples.iter().map(|e| e.site.as_str()).collect();
        assert!(sites.contains(&"DEFRA"));
        assert!(sites.contains(&"GBLON"));
    }

    #[test]
    fn test_environment_type_display() {
        assert_eq!(EnvironmentType::Dev.to_string(), "dev");
        assert_eq!(EnvironmentType::Test.to_string(), "test");
        assert_eq!(EnvironmentType::Staging.to_string(), "staging");
        assert_eq!(EnvironmentType::Prod.to_string(), "prod");
    }

    #[test]
    fn test_tier_type_display() {
        assert_eq!(TierType::Front.to_string(), "front");
        assert_eq!(TierType::Mid.to_string(), "mid");
        assert_eq!(TierType::Back.to_string(), "back");
    }

    #[test]
    fn test_environment_status_display() {
        assert_eq!(EnvironmentStatus::Draft.to_string(), "draft");
        assert_eq!(EnvironmentStatus::Planned.to_string(), "planned");
        assert_eq!(EnvironmentStatus::Deployed.to_string(), "deployed");
        assert_eq!(EnvironmentStatus::Retired.to_string(), "retired");
    }

    #[test]
    fn test_all_environments_work_at_all_sites() {
        for site in VALID_SITES {
            let result = plan_environment("testapp", EnvironmentType::Prod, site);
            assert!(result.is_ok(), "Failed at site: {}", site);
        }
    }

    #[test]
    fn test_plan_environment_has_plans_for_all_tiers() {
        let tiers = plan_environment("myapp", EnvironmentType::Prod, "DEFRA").unwrap();
        for tier in &tiers {
            assert!(!tier.networking_plan.is_empty());
            assert!(!tier.dns_plan.is_empty());
            assert!(!tier.certs_plan.is_empty());
            assert!(!tier.monitoring_plan.is_empty());
            assert!(!tier.backup_plan.is_empty());
            assert!(tier.networking_plan.contains("DRY-RUN"));
        }
    }

    #[test]
    fn test_validate_environment_generates_warnings_for_large_specs() {
        let mut env = plan_environment("bigapp", EnvironmentType::Prod, "DEFRA")
            .unwrap()
            .into_iter()
            .find(|t| t.tier == TierType::Front)
            .unwrap();
        env.vm_count = 100;
        env.cpu_per_vm = 128;
        let result = validate_environment(&env).unwrap();
        assert!(result.passed);
        assert!(!result.warnings.is_empty());
    }
}
