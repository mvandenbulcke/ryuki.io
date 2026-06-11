use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SQLDeployment {
    id: String,
    instance_name: String,
    sql_version: SQLVersion,
    edition: SQLEdition,
    cpu: u32,
    memory_gb: u32,
    data_disk_gb: u32,
    log_disk_gb: u32,
    tempdb_disk_gb: u32,
    collation: String,
    service_account: String,
    site: String,
    cluster_mode: ClusterMode,
    status: DeploymentStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum SQLVersion {
    Sql2019,
    Sql2022,
}

impl std::fmt::Display for SQLVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SQLVersion::Sql2019 => write!(f, "2019"),
            SQLVersion::Sql2022 => write!(f, "2022"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
enum SQLEdition {
    Standard,
    Enterprise,
    Developer,
}

impl std::fmt::Display for SQLEdition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SQLEdition::Standard => write!(f, "Standard"),
            SQLEdition::Enterprise => write!(f, "Enterprise"),
            SQLEdition::Developer => write!(f, "Developer"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
#[allow(clippy::upper_case_acronyms)]
enum ClusterMode {
    Standalone,
    FCI,
    AG,
}

impl std::fmt::Display for ClusterMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClusterMode::Standalone => write!(f, "Standalone"),
            ClusterMode::FCI => write!(f, "FCI"),
            ClusterMode::AG => write!(f, "AG"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum DeploymentStatus {
    Draft,
    Validated,
    Planned,
    Installing,
    Configuring,
    Verified,
    BackedUp,
    Monitored,
    Completed,
    Failed,
}

type DeploymentStore = Vec<SQLDeployment>;

static DEPLOYMENT_STORE: OnceLock<Mutex<DeploymentStore>> = OnceLock::new();

fn deployment_store() -> &'static Mutex<DeploymentStore> {
    DEPLOYMENT_STORE.get_or_init(|| Mutex::new(seed_data()))
}

fn seed_data() -> DeploymentStore {
    vec![
        SQLDeployment {
            id: "sql-001".into(),
            instance_name: "LOVE-SQL-PROD-01".into(),
            sql_version: SQLVersion::Sql2022,
            edition: SQLEdition::Enterprise,
            cpu: 8,
            memory_gb: 64,
            data_disk_gb: 500,
            log_disk_gb: 200,
            tempdb_disk_gb: 100,
            collation: "Latin1_General_CI_AS".into(),
            service_account: "svc-sql-love-prod@ryuki.local".into(),
            site: "LOVE".into(),
            cluster_mode: ClusterMode::AG,
            status: DeploymentStatus::Draft,
        },
        SQLDeployment {
            id: "sql-002".into(),
            instance_name: "BUR1-SQL-PROD-01".into(),
            sql_version: SQLVersion::Sql2019,
            edition: SQLEdition::Standard,
            cpu: 4,
            memory_gb: 32,
            data_disk_gb: 250,
            log_disk_gb: 100,
            tempdb_disk_gb: 50,
            collation: "SQL_Latin1_General_CP1_CI_AS".into(),
            service_account: "svc-sql-bur1-prod@ryuki.local".into(),
            site: "BUR1".into(),
            cluster_mode: ClusterMode::Standalone,
            status: DeploymentStatus::Draft,
        },
    ]
}

fn deployment_to_json(d: &SQLDeployment) -> Value {
    json!({
        "id": d.id,
        "instance_name": d.instance_name,
        "sql_version": d.sql_version.to_string(),
        "edition": d.edition.to_string(),
        "cpu": d.cpu,
        "memory_gb": d.memory_gb,
        "data_disk_gb": d.data_disk_gb,
        "log_disk_gb": d.log_disk_gb,
        "tempdb_disk_gb": d.tempdb_disk_gb,
        "collation": d.collation,
        "service_account": d.service_account,
        "site": d.site,
        "cluster_mode": d.cluster_mode.to_string(),
        "status": d.status
    })
}

fn make_id() -> String {
    let store = deployment_store().lock().unwrap();
    format!("sql-{:03}", store.len() + 1)
}

pub fn plan_deployment(req: Value) -> Result<Value, String> {
    let instance_name = req["instance_name"]
        .as_str()
        .ok_or("instance_name is required")?;
    let version_str = req["sql_version"].as_str().unwrap_or("2022");
    let edition_str = req["edition"].as_str().unwrap_or("Standard");
    let cpu = req["cpu"].as_u64().unwrap_or(4) as u32;
    let memory_gb = req["memory_gb"].as_u64().unwrap_or(16) as u32;
    let data_disk_gb = req["data_disk_gb"].as_u64().unwrap_or(100) as u32;
    let log_disk_gb = req["log_disk_gb"].as_u64().unwrap_or(50) as u32;
    let tempdb_disk_gb = req["tempdb_disk_gb"].as_u64().unwrap_or(30) as u32;
    let collation = req["collation"].as_str().unwrap_or("SQL_Latin1_General_CP1_CI_AS");
    let service_account = req["service_account"]
        .as_str()
        .ok_or("service_account is required")?;
    let site = req["site"].as_str().ok_or("site is required")?;
    let cluster_str = req["cluster_mode"].as_str().unwrap_or("Standalone");

    let sql_version = match version_str {
        "2019" => SQLVersion::Sql2019,
        "2022" => SQLVersion::Sql2022,
        v => return Err(format!("Unsupported SQL version '{}'. Must be 2019 or 2022", v)),
    };

    let edition: SQLEdition = match edition_str {
        "Standard" => SQLEdition::Standard,
        "Enterprise" => SQLEdition::Enterprise,
        "Developer" => SQLEdition::Developer,
        e => return Err(format!(
            "Unsupported edition '{}'. Must be Standard, Enterprise, or Developer",
            e
        )),
    };

    let cluster_mode: ClusterMode = match cluster_str {
        "Standalone" => ClusterMode::Standalone,
        "FCI" => ClusterMode::FCI,
        "AG" => ClusterMode::AG,
        m => return Err(format!(
            "Unsupported cluster mode '{}'. Must be Standalone, FCI, or AG",
            m
        )),
    };

    let total_disk = data_disk_gb + log_disk_gb + tempdb_disk_gb;
    let recommended_memory = if memory_gb < 4 {
        "Warning: minimum 4 GB recommended for SQL Server".to_string()
    } else {
        format!(
            "Memory allocation: {} GB total, recommended max server memory: {} GB",
            memory_gb,
            if memory_gb > 4 { memory_gb - 2 } else { memory_gb / 2 }
        )
    };

    let disk_layout = json!({
        "data": { "drive": "D:", "size_gb": data_disk_gb, "path": "D:\\SQLData" },
        "log": { "drive": "E:", "size_gb": log_disk_gb, "path": "E:\\SQLLogs" },
        "tempdb": { "drive": "T:", "size_gb": tempdb_disk_gb, "path": "T:\\TempDB" },
        "backup": { "drive": "B:", "size_gb": total_disk, "path": "B:\\SQLBackup" }
    });

    let tempdb_files = if cpu >= 8 {
        json!({ "file_count": (cpu / 2).min(8), "initial_size_mb": 1024, "autogrowth_mb": 512 })
    } else {
        json!({ "file_count": cpu, "initial_size_mb": 512, "autogrowth_mb": 256 })
    };

    let id = make_id();

    let mut store = deployment_store().lock().map_err(|e| e.to_string())?;
    store.push(SQLDeployment {
        id: id.clone(),
        instance_name: instance_name.to_string(),
        sql_version,
        edition,
        cpu,
        memory_gb,
        data_disk_gb,
        log_disk_gb,
        tempdb_disk_gb,
        collation: collation.to_string(),
        service_account: service_account.to_string(),
        site: site.to_string(),
        cluster_mode,
        status: DeploymentStatus::Planned,
    });

    Ok(json!({
        "source": "dry-run",
        "deployment_id": id,
        "instance_name": instance_name,
        "sql_version": version_str,
        "edition": edition_str,
        "cluster_mode": cluster_str,
        "cpu": cpu,
        "memory_gb": memory_gb,
        "total_disk_gb": total_disk,
        "memory_recommendation": recommended_memory,
        "disk_layout": disk_layout,
        "tempdb_config": tempdb_files,
        "collation": collation,
        "service_account": service_account,
        "site": site,
        "status": "planned"
    }))
}

pub fn validate_deployment(req: Value) -> Result<Value, String> {
    let instance_name = req["instance_name"].as_str().unwrap_or("");
    let version_str = req["sql_version"].as_str().unwrap_or("");
    let cpu = req["cpu"].as_u64().unwrap_or(0) as u32;
    let memory_gb = req["memory_gb"].as_u64().unwrap_or(0) as u32;
    let site = req["site"].as_str().unwrap_or("");
    let edition_str = req["edition"].as_str().unwrap_or("");
    let cluster_str = req["cluster_mode"].as_str().unwrap_or("Standalone");
    let service_account = req["service_account"].as_str().unwrap_or("");

    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut remediation: Vec<String> = Vec::new();

    if instance_name.is_empty() {
        errors.push("instance_name is required".into());
    } else if instance_name.len() > 15 {
        errors.push(format!(
            "instance_name '{}' exceeds 15-character NetBIOS limit",
            instance_name
        ));
    } else if !instance_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        errors.push("instance_name must contain only alphanumeric characters and hyphens".into());
    }

    if site.is_empty() {
        errors.push("site is required".into());
    }

    if !version_str.is_empty() && version_str != "2019" && version_str != "2022" {
        errors.push(format!("Unsupported SQL version '{}'. Must be 2019 or 2022", version_str));
    }

    if version_str == "2019" {
        warnings.push("SQL Server 2019 mainstream support ended 2025-01-07. Consider 2022 for new deployments.".into());
        remediation.push("Upgrade target version to 2022 unless legacy application requires 2019".into());
    }

    if !edition_str.is_empty()
        && edition_str != "Standard"
        && edition_str != "Enterprise"
        && edition_str != "Developer"
    {
        errors.push(format!(
            "Unsupported edition '{}'. Must be Standard, Enterprise, or Developer",
            edition_str
        ));
    }

    if edition_str == "Developer" {
        warnings.push("Developer Edition is not licensed for production workloads".into());
        remediation.push("Use Standard or Enterprise edition for production deployments".into());
    }

    if !cluster_str.is_empty()
        && cluster_str != "Standalone"
        && cluster_str != "FCI"
        && cluster_str != "AG"
    {
        errors.push(format!(
            "Unsupported cluster mode '{}'. Must be Standalone, FCI, or AG",
            cluster_str
        ));
    }

    if cluster_str == "FCI" {
        if cpu < 4 {
            warnings.push("FCI deployments benefit from at least 4 CPU cores".into());
        }
        warnings.push("FCI requires shared storage (SAN/FC) and Windows Server Failover Clustering pre-configured".into());
        remediation.push("Verify WSFC cluster exists and shared storage is available before deployment".into());
    }

    if cluster_str == "AG" {
        if edition_str == "Standard" {
            warnings.push("Standard Edition supports only basic availability groups (1 database, no read-only secondaries)".into());
        }
        if cpu < 4 {
            warnings.push("AG deployments benefit from at least 4 CPU cores per node".into());
        }
        warnings.push("AG requires Windows Server Failover Clustering and at least 2 nodes".into());
        remediation.push("Ensure 2+ nodes, WSFC, and AG listener DNS record are pre-provisioned".into());
    }

    if cpu == 0 {
        errors.push("cpu is required and must be >= 1".into());
    } else if cpu > 256 {
        errors.push(format!("cpu {} exceeds maximum 256 for SQL Server", cpu));
    }

    if memory_gb == 0 {
        errors.push("memory_gb is required and must be >= 1".into());
    } else if memory_gb > 24576 {
        errors.push(format!("memory_gb {} exceeds maximum 24 TB for SQL Server", memory_gb));
    } else if memory_gb < 2 {
        errors.push("minimum 2 GB memory required for SQL Server".into());
        remediation.push("Increase memory to at least 4 GB for production workloads".into());
    }

    if service_account.is_empty() {
        errors.push("service_account is required".into());
    }

    let passed = errors.is_empty();

    Ok(json!({
        "source": "dry-run",
        "passed": passed,
        "errors": errors,
        "warnings": warnings,
        "failed_rules": errors.clone(),
        "remediation": remediation,
        "instance_name": instance_name,
        "site": site,
        "sql_version": version_str,
        "edition": edition_str,
        "cluster_mode": cluster_str
    }))
}

pub fn install_sql(deployment_id: &str) -> Result<Value, String> {
    let mut store = deployment_store().lock().map_err(|e| e.to_string())?;
    let deployment = store
        .iter_mut()
        .find(|d| d.id == deployment_id)
        .ok_or_else(|| format!("Deployment '{}' not found", deployment_id))?;

    deployment.status = DeploymentStatus::Installing;

    Ok(json!({
        "source": "dry-run",
        "deployment_id": deployment.id,
        "instance_name": deployment.instance_name,
        "status": "installing",
        "action": "mock-install",
        "steps": [
            "Mount SQL Server ISO",
            "Run setup.exe with configuration file",
            "Install Database Engine",
            "Install SQL Server Management Objects",
            "Apply latest Cumulative Update"
        ],
        "estimated_duration_minutes": 45,
        "message": format!(
            "Mock installation of SQL Server {} {} on {} started (dry-run)",
            deployment.sql_version, deployment.edition, deployment.instance_name
        )
    }))
}

pub fn configure_sql(deployment_id: &str) -> Result<Value, String> {
    let mut store = deployment_store().lock().map_err(|e| e.to_string())?;
    let deployment = store
        .iter_mut()
        .find(|d| d.id == deployment_id)
        .ok_or_else(|| format!("Deployment '{}' not found", deployment_id))?;

    let maxdop = if deployment.cpu >= 8 { 8 } else { deployment.cpu };
    let max_memory_mb = if deployment.memory_gb > 4 {
        (deployment.memory_gb - 2) * 1024
    } else {
        deployment.memory_gb * 512
    };

    let tempdb_files = if deployment.cpu >= 8 {
        (deployment.cpu / 2).min(8)
    } else {
        deployment.cpu
    };

    deployment.status = DeploymentStatus::Configuring;

    Ok(json!({
        "source": "dry-run",
        "deployment_id": deployment.id,
        "instance_name": deployment.instance_name,
        "status": "configuring",
        "action": "mock-configure",
        "config_applied": {
            "max_degree_of_parallelism": maxdop,
            "max_server_memory_mb": max_memory_mb,
            "min_server_memory_mb": 1024,
            "tempdb_file_count": tempdb_files,
            "tempdb_initial_size_mb": 1024,
            "tempdb_autogrowth_mb": 512,
            "backup_compression_default": 1,
            "backup_checksum_default": 1,
            "optimize_for_ad_hoc_workloads": 1,
            "cost_threshold_for_parallelism": 50,
            "instant_file_initialization_enabled": true,
            "collation": deployment.collation,
            "service_account": deployment.service_account
        },
        "message": format!(
            "Mock post-install configuration applied to {} (dry-run)",
            deployment.instance_name
        )
    }))
}

pub fn verify_sql(deployment_id: &str) -> Result<Value, String> {
    let mut store = deployment_store().lock().map_err(|e| e.to_string())?;
    let deployment = store
        .iter_mut()
        .find(|d| d.id == deployment_id)
        .ok_or_else(|| format!("Deployment '{}' not found", deployment_id))?;

    deployment.status = DeploymentStatus::Verified;

    Ok(json!({
        "source": "dry-run",
        "deployment_id": deployment.id,
        "instance_name": deployment.instance_name,
        "status": "verified",
        "action": "mock-verify",
        "checks": {
            "connectivity": {
                "passed": true,
                "endpoint": format!("{}.ryuki.local,1433", deployment.instance_name.to_lowercase()),
                "latency_ms": 2
            },
            "version_check": {
                "passed": true,
                "expected": deployment.sql_version.to_string(),
                "actual": deployment.sql_version.to_string(),
                "build": "16.0.4125.3"
            },
            "configuration_validation": {
                "passed": true,
                "maxdop_configured": true,
                "memory_configured": true,
                "tempdb_configured": true,
                "backup_defaults_set": true,
                "instant_file_init": true
            },
            "service_status": {
                "passed": true,
                "sql_server": "Running",
                "sql_agent": "Running",
                "startup_type": "Automatic"
            }
        },
        "message": format!(
            "Mock verification of {} completed successfully (dry-run)",
            deployment.instance_name
        )
    }))
}

pub fn add_to_backup(deployment_id: &str) -> Result<Value, String> {
    let mut store = deployment_store().lock().map_err(|e| e.to_string())?;
    let deployment = store
        .iter_mut()
        .find(|d| d.id == deployment_id)
        .ok_or_else(|| format!("Deployment '{}' not found", deployment_id))?;

    deployment.status = DeploymentStatus::BackedUp;

    Ok(json!({
        "source": "dry-run",
        "deployment_id": deployment.id,
        "instance_name": deployment.instance_name,
        "status": "backed-up",
        "action": "mock-backup-registration",
        "veeam_config": {
            "application_aware_processing": true,
            "log_backup_interval_minutes": 15,
            "log_retention_days": 30,
            "full_backup_schedule": "Daily at 22:00",
            "guest_interaction_proxy": "auto",
            "truncate_logs_after_backup": true
        },
        "backup_policy": "SQL-Production-Gold",
        "retention": {
            "daily": 7,
            "weekly": 4,
            "monthly": 12,
            "yearly": 3
        },
        "message": format!(
            "Mock Veeam application-aware backup registered for {} (dry-run)",
            deployment.instance_name
        )
    }))
}

pub fn add_to_monitoring(deployment_id: &str) -> Result<Value, String> {
    let mut store = deployment_store().lock().map_err(|e| e.to_string())?;
    let deployment = store
        .iter_mut()
        .find(|d| d.id == deployment_id)
        .ok_or_else(|| format!("Deployment '{}' not found", deployment_id))?;

    deployment.status = DeploymentStatus::Monitored;

    Ok(json!({
        "source": "dry-run",
        "deployment_id": deployment.id,
        "instance_name": deployment.instance_name,
        "status": "monitored",
        "action": "mock-monitoring-onboarding",
        "zabbix_config": {
            "template_applied": "Template DB MS SQL by ODBC",
            "host_group": format!("SQL-Servers/{}", deployment.site),
            "macros": {
                "{$MSSQL.PORT}": "1433",
                "{$MSSQL.INSTANCE}": "MSSQLSERVER",
                "{$MSSQL.DATA_THRESHOLD_PCT}": "85",
                "{$MSSQL.LOG_THRESHOLD_PCT}": "80"
            },
            "items_monitored": [
                "SQL Server availability",
                "Database status",
                "Transaction log size",
                "Buffer cache hit ratio",
                "Page life expectancy",
                "Blocked processes",
                "Lock waits",
                "SQL Agent jobs"
            ],
            "triggers": [
                "SQL service down",
                "Database offline",
                "Transaction log > 80%",
                "Buffer cache hit ratio < 90%",
                "Blocked processes > 10"
            ],
            "discovery_rules": ["Database auto-discovery", "SQL Agent job discovery"]
        },
        "message": format!(
            "Mock Zabbix SQL monitoring template onboarded for {} (dry-run)",
            deployment.instance_name
        )
    }))
}

pub fn get_inventory(site: &str) -> Result<Value, String> {
    let store = deployment_store().lock().map_err(|e| e.to_string())?;

    let deployments: Vec<&SQLDeployment> = if site.is_empty() {
        store.iter().collect()
    } else {
        store.iter().filter(|d| d.site == site).collect()
    };

    let deployment_list: Vec<Value> = deployments.iter().map(|d| deployment_to_json(d)).collect();

    Ok(json!({
        "source": "dry-run",
        "site": if site.is_empty() { "all" } else { site },
        "deployment_count": deployment_list.len(),
        "deployments": deployment_list
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plan_deployment_basic() {
        let result = plan_deployment(json!({
            "instance_name": "LOVE-SQL-TEST-01",
            "sql_version": "2022",
            "edition": "Standard",
            "cpu": 4,
            "memory_gb": 16,
            "data_disk_gb": 200,
            "log_disk_gb": 100,
            "tempdb_disk_gb": 50,
            "collation": "Latin1_General_CI_AS",
            "service_account": "svc-sql-test@ryuki.local",
            "site": "LOVE",
            "cluster_mode": "Standalone"
        }))
        .unwrap();

        assert_eq!(result["instance_name"], "LOVE-SQL-TEST-01");
        assert_eq!(result["site"], "LOVE");
        assert_eq!(result["status"], "planned");
        assert!(result["deployment_id"].as_str().unwrap().starts_with("sql-"));
        assert!(result["disk_layout"]["data"]["size_gb"].as_u64().unwrap() == 200);
        assert!(result["total_disk_gb"].as_u64().unwrap() == 350);
    }

    #[test]
    fn test_plan_deployment_missing_required_fields() {
        let result = plan_deployment(json!({
            "sql_version": "2022"
        }));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("instance_name"));
    }

    #[test]
    fn test_validate_deployment_all_passing() {
        let result = validate_deployment(json!({
            "instance_name": "LOVE-SQL-01",
            "sql_version": "2022",
            "edition": "Enterprise",
            "cpu": 8,
            "memory_gb": 64,
            "site": "LOVE",
            "cluster_mode": "AG",
            "service_account": "svc-sql@ryuki.local"
        }))
        .unwrap();

        assert!(result["passed"].as_bool().unwrap());
        assert!(result["errors"].as_array().unwrap().is_empty());
        assert!(!result["warnings"].as_array().unwrap().is_empty()); // AG warnings
    }

    #[test]
    fn test_validate_deployment_failures() {
        let result = validate_deployment(json!({
            "instance_name": "",
            "sql_version": "2014",
            "cpu": 0,
            "memory_gb": 0,
            "site": "",
            "service_account": ""
        }))
        .unwrap();

        assert!(!result["passed"].as_bool().unwrap());
        let errors = result["errors"].as_array().unwrap();
        assert!(errors.len() >= 3);
    }

    #[test]
    fn test_validate_deployment_2019_warning() {
        let result = validate_deployment(json!({
            "instance_name": "OLD-SQL-01",
            "sql_version": "2019",
            "edition": "Standard",
            "cpu": 4,
            "memory_gb": 16,
            "site": "LOVE",
            "cluster_mode": "Standalone",
            "service_account": "svc@ryuki.local"
        }))
        .unwrap();

        assert!(result["passed"].as_bool().unwrap());
        let warnings: Vec<&str> = result["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w.as_str().unwrap())
            .collect();
        assert!(warnings.iter().any(|w| w.contains("2019")));
    }

    #[test]
    fn test_install_configure_verify_backup_monitoring_flow() {
        plan_deployment(json!({
            "instance_name": "BUR1-SQL-DEV-01",
            "sql_version": "2022",
            "edition": "Developer",
            "cpu": 2,
            "memory_gb": 8,
            "data_disk_gb": 100,
            "log_disk_gb": 50,
            "tempdb_disk_gb": 30,
            "collation": "SQL_Latin1_General_CP1_CI_AS",
            "service_account": "svc-dev@ryuki.local",
            "site": "BUR1",
            "cluster_mode": "Standalone"
        }))
        .unwrap();

        let store = deployment_store().lock().unwrap();
        let deployment_id = store
            .iter()
            .find(|d| d.instance_name == "BUR1-SQL-DEV-01")
            .map(|d| d.id.clone())
            .unwrap();
        drop(store);

        let install_result = install_sql(&deployment_id).unwrap();
        assert_eq!(install_result["status"], "installing");
        assert!(install_result["steps"].as_array().unwrap().len() >= 3);

        let config_result = configure_sql(&deployment_id).unwrap();
        assert_eq!(config_result["status"], "configuring");
        assert!(config_result["config_applied"]["backup_compression_default"].as_u64().unwrap() == 1);

        let verify_result = verify_sql(&deployment_id).unwrap();
        assert_eq!(verify_result["status"], "verified");
        assert!(verify_result["checks"]["connectivity"]["passed"].as_bool().unwrap());

        let backup_result = add_to_backup(&deployment_id).unwrap();
        assert_eq!(backup_result["status"], "backed-up");
        assert!(backup_result["veeam_config"]["application_aware_processing"].as_bool().unwrap());

        let monitoring_result = add_to_monitoring(&deployment_id).unwrap();
        assert_eq!(monitoring_result["status"], "monitored");
        assert!(monitoring_result["zabbix_config"]["items_monitored"]
            .as_array()
            .unwrap()
            .len()
            >= 5);
    }

    #[test]
    fn test_get_inventory_all() {
        let result = get_inventory("").unwrap();
        assert!(result["deployment_count"].as_u64().unwrap() >= 2);
        let deployments = result["deployments"].as_array().unwrap();
        assert!(deployments.iter().any(|d| d["site"] == "LOVE"));
        assert!(deployments.iter().any(|d| d["site"] == "BUR1"));
    }

    #[test]
    fn test_get_inventory_by_site() {
        let result = get_inventory("LOVE").unwrap();
        let deployments = result["deployments"].as_array().unwrap();
        for d in deployments {
            assert_eq!(d["site"], "LOVE");
        }
    }

    #[test]
    fn test_get_inventory_empty_site() {
        let result = get_inventory("NONEXISTENT").unwrap();
        assert_eq!(result["deployment_count"].as_u64().unwrap(), 0);
    }

    #[test]
    fn test_deployment_not_found() {
        assert!(install_sql("sql-999").is_err());
        assert!(configure_sql("sql-999").is_err());
        assert!(verify_sql("sql-999").is_err());
        assert!(add_to_backup("sql-999").is_err());
        assert!(add_to_monitoring("sql-999").is_err());
    }

    #[test]
    fn test_validate_developer_edition_warning() {
        let result = validate_deployment(json!({
            "instance_name": "DEV-SQL-01",
            "sql_version": "2022",
            "edition": "Developer",
            "cpu": 4,
            "memory_gb": 16,
            "site": "LOVE",
            "cluster_mode": "Standalone",
            "service_account": "svc@ryuki.local"
        }))
        .unwrap();

        assert!(result["passed"].as_bool().unwrap());
        let warnings: Vec<&str> = result["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w.as_str().unwrap())
            .collect();
        assert!(warnings.iter().any(|w| w.contains("Developer")));
    }

    #[test]
    fn test_validate_fci_cluster_mode() {
        let result = validate_deployment(json!({
            "instance_name": "FCI-SQL-01",
            "sql_version": "2022",
            "edition": "Enterprise",
            "cpu": 8,
            "memory_gb": 64,
            "site": "LOVE",
            "cluster_mode": "FCI",
            "service_account": "svc@ryuki.local"
        }))
        .unwrap();

        assert!(result["passed"].as_bool().unwrap());
        let remediation: Vec<&str> = result["remediation"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap())
            .collect();
        assert!(remediation.iter().any(|r| r.contains("WSFC")));
    }

    #[test]
    fn test_validate_name_length_limit() {
        let result = validate_deployment(json!({
            "instance_name": "VERY-LONG-INSTANCE-NAME-TOO-LONG",
            "sql_version": "2022",
            "edition": "Enterprise",
            "cpu": 4,
            "memory_gb": 16,
            "site": "LOVE",
            "cluster_mode": "Standalone",
            "service_account": "svc@ryuki.local"
        }))
        .unwrap();

        assert!(!result["passed"].as_bool().unwrap());
        let errors: Vec<&str> = result["errors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e.as_str().unwrap())
            .collect();
        assert!(errors.iter().any(|e| e.contains("NetBIOS")));
    }

    #[test]
    fn test_plan_deployment_unsupported_version() {
        let result = plan_deployment(json!({
            "instance_name": "BAD-SQL-01",
            "sql_version": "2017",
            "edition": "Standard",
            "cpu": 4,
            "memory_gb": 16,
            "data_disk_gb": 100,
            "log_disk_gb": 50,
            "tempdb_disk_gb": 30,
            "collation": "Latin1_General_CI_AS",
            "service_account": "svc@ryuki.local",
            "site": "LOVE",
            "cluster_mode": "Standalone"
        }));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported SQL version"));
    }
}
