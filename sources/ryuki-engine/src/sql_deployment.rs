use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

// ─── Domain types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SQLDeployment {
    pub id: String,
    pub instance_name: String,
    pub sql_version: SQLVersion,
    pub edition: SQLEdition,
    pub cpu: u32,
    pub memory_gb: u32,
    pub data_disk_gb: u32,
    pub log_disk_gb: u32,
    pub tempdb_disk_gb: u32,
    pub collation_name: String,
    pub service_account: String,
    pub site: String,
    pub cluster_mode: ClusterMode,
    pub status: DeploymentStatus,
    pub created_at: String,
    pub updated_at: String,
}

/// SQL Server version.
///
/// Serde uses `rename_all = "kebab-case"` ("sql-2019" / "sql-2022").
/// The DB CHECK stores '2019' / '2022'.
/// Use `Display` when writing to the DB; use `sql_version_from_db` when reading.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SQLVersion {
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

/// SQL Server edition.
///
/// Serde uses `rename_all = "PascalCase"` ("Standard" / "Enterprise" / "Developer").
/// The DB CHECK stores the same PascalCase values — serde decode works directly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum SQLEdition {
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

/// Cluster topology.
///
/// Serde uses `rename_all = "UPPERCASE"` → "STANDALONE" / "FCI" / "AG".
/// The DB CHECK stores 'Standalone' / 'FCI' / 'AG' (PascalCase for Standalone).
/// `Display` produces the DB form. Use `cluster_mode_from_db` when reading.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
#[allow(clippy::upper_case_acronyms)]
pub enum ClusterMode {
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

/// Deployment lifecycle status.
///
/// Serde uses `rename_all = "kebab-case"` → "draft", "backed-up", etc.
/// The DB CHECK stores the identical kebab-case values, so serde decode works.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum DeploymentStatus {
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

impl std::fmt::Display for DeploymentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Produces the kebab-case form that matches the DB CHECK values.
        let s = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| format!("{self:?}").to_lowercase());
        write!(f, "{s}")
    }
}

// ─── Pure plan helpers ────────────────────────────────────────────────────────

/// Parse and validate the plan request body, returning a built `SQLDeployment`
/// (with an empty id — the repo assigns a real UUID) and a plan summary `Value`.
/// Returns `Err` on invalid inputs (bad version / edition / cluster / missing fields).
/// Parse a JSON integer "dimension" (cpu / memory / disk size) as u32, rejecting
/// values that would not fit the DB INTEGER column (0..=i32::MAX) or fall below
/// `min`. This keeps an out-of-range request a 400 at the engine boundary rather
/// than letting a bare `as` cast wrap, a `total_disk` sum overflow/panic, or a
/// repo i32 Decode surface as a 500.
fn parse_dimension(req: &Value, key: &str, default: u64, min: u32) -> Result<u32, String> {
    // Default ONLY when the field is absent/null. A present-but-wrong-type value
    // ("8", -1, 3.5, {}) must fail loudly rather than silently fall back to the
    // default and hide a malformed request from a direct engine caller.
    let raw = match &req[key] {
        Value::Null => default,
        v => v
            .as_u64()
            .ok_or_else(|| format!("{key} must be a non-negative integer"))?,
    };
    if raw > i32::MAX as u64 {
        return Err(format!("{key} must be at most {}", i32::MAX));
    }
    let value = raw as u32; // safe: raw <= i32::MAX
    if value < min {
        return Err(format!("{key} must be at least {min}"));
    }
    Ok(value)
}

pub fn plan_deployment(req: Value) -> Result<(SQLDeployment, Value), String> {
    let instance_name = req["instance_name"]
        .as_str()
        .ok_or("instance_name is required")?;
    let version_str = req["sql_version"].as_str().unwrap_or("2022");
    let edition_str = req["edition"].as_str().unwrap_or("Standard");
    let cpu = parse_dimension(&req, "cpu", 4, 1)?;
    let memory_gb = parse_dimension(&req, "memory_gb", 16, 2)?;
    let data_disk_gb = parse_dimension(&req, "data_disk_gb", 100, 10)?;
    let log_disk_gb = parse_dimension(&req, "log_disk_gb", 50, 10)?;
    let tempdb_disk_gb = parse_dimension(&req, "tempdb_disk_gb", 30, 10)?;
    let collation = req["collation"]
        .as_str()
        .unwrap_or("SQL_Latin1_General_CP1_CI_AS");
    let service_account = req["service_account"]
        .as_str()
        .ok_or("service_account is required")?;
    let site = req["site"].as_str().ok_or("site is required")?;
    let cluster_str = req["cluster_mode"].as_str().unwrap_or("Standalone");

    let sql_version = match version_str {
        "2019" => SQLVersion::Sql2019,
        "2022" => SQLVersion::Sql2022,
        v => {
            return Err(format!(
                "Unsupported SQL version '{}'. Must be 2019 or 2022",
                v
            ));
        }
    };

    let edition: SQLEdition = match edition_str {
        "Standard" => SQLEdition::Standard,
        "Enterprise" => SQLEdition::Enterprise,
        "Developer" => SQLEdition::Developer,
        e => {
            return Err(format!(
                "Unsupported edition '{}'. Must be Standard, Enterprise, or Developer",
                e
            ));
        }
    };

    let cluster_mode: ClusterMode = match cluster_str {
        "Standalone" => ClusterMode::Standalone,
        "FCI" => ClusterMode::FCI,
        "AG" => ClusterMode::AG,
        m => {
            return Err(format!(
                "Unsupported cluster mode '{}'. Must be Standalone, FCI, or AG",
                m
            ));
        }
    };

    // Bounds are enforced by parse_dimension above (each value is in 10..=i32::MAX
    // for disks), so sum in u64 to avoid a u32 overflow when three near-i32::MAX
    // disk sizes are added.
    let total_disk = data_disk_gb as u64 + log_disk_gb as u64 + tempdb_disk_gb as u64;
    let recommended_memory = if memory_gb < 4 {
        "Warning: minimum 4 GB recommended for SQL Server".to_string()
    } else {
        format!(
            "Memory allocation: {} GB total, recommended max server memory: {} GB",
            memory_gb,
            if memory_gb > 4 {
                memory_gb - 2
            } else {
                memory_gb / 2
            }
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

    let deployment = SQLDeployment {
        id: String::new(), // assigned by repo
        instance_name: instance_name.to_string(),
        sql_version,
        edition,
        cpu,
        memory_gb,
        data_disk_gb,
        log_disk_gb,
        tempdb_disk_gb,
        collation_name: collation.to_string(),
        service_account: service_account.to_string(),
        site: site.to_string(),
        cluster_mode,
        status: DeploymentStatus::Planned,
        created_at: String::new(),
        updated_at: String::new(),
    };

    let plan = json!({
        "source": "dry-run",
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
    });

    Ok((deployment, plan))
}

/// Pure validation of a deployment request body — no side effects.
/// Returns a validation report (never Err; the report carries passed/errors).
pub fn validate_deployment(req: Value) -> Result<Value, String> {
    let instance_name = req["instance_name"].as_str().unwrap_or("");
    let version_str = req["sql_version"].as_str().unwrap_or("");
    // Keep these as u64 (no `as u32` wrap): the checks below are pure comparisons
    // and the upper-bound checks (cpu > 256, memory_gb > 24576) flag oversized
    // values accurately instead of letting them wrap to a small in-range number.
    let cpu = req["cpu"].as_u64().unwrap_or(0);
    let memory_gb = req["memory_gb"].as_u64().unwrap_or(0);
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
        errors.push(format!(
            "Unsupported SQL version '{}'. Must be 2019 or 2022",
            version_str
        ));
    }

    if version_str == "2019" {
        warnings.push("SQL Server 2019 mainstream support ended 2025-01-07. Consider 2022 for new deployments.".into());
        remediation
            .push("Upgrade target version to 2022 unless legacy application requires 2019".into());
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
        remediation.push(
            "Verify WSFC cluster exists and shared storage is available before deployment".into(),
        );
    }

    if cluster_str == "AG" {
        if edition_str == "Standard" {
            warnings.push("Standard Edition supports only basic availability groups (1 database, no read-only secondaries)".into());
        }
        if cpu < 4 {
            warnings.push("AG deployments benefit from at least 4 CPU cores per node".into());
        }
        warnings
            .push("AG requires Windows Server Failover Clustering and at least 2 nodes".into());
        remediation
            .push("Ensure 2+ nodes, WSFC, and AG listener DNS record are pre-provisioned".into());
    }

    if cpu == 0 {
        errors.push("cpu is required and must be >= 1".into());
    } else if cpu > 256 {
        errors.push(format!("cpu {} exceeds maximum 256 for SQL Server", cpu));
    }

    if memory_gb == 0 {
        errors.push("memory_gb is required and must be >= 1".into());
    } else if memory_gb > 24576 {
        errors.push(format!(
            "memory_gb {} exceeds maximum 24 TB for SQL Server",
            memory_gb
        ));
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

// ─── Pure lifecycle guards ────────────────────────────────────────────────────
//
// Each guard validates that the loaded deployment is in the expected status.
// Returns Ok(()) on success; Err(msg) on illegal transition.
// The repo performs the actual DB mutation; the handler owns the orchestration.

/// Guard: deployment must be in `Planned` status before installation.
pub fn guard_install(deployment: &SQLDeployment) -> Result<(), String> {
    require_status(deployment, &DeploymentStatus::Planned, "install")
}

/// Guard: deployment must be in `Installing` status before configuration.
pub fn guard_configure(deployment: &SQLDeployment) -> Result<(), String> {
    require_status(deployment, &DeploymentStatus::Installing, "configure")
}

/// Guard: deployment must be in `Configuring` status before verification.
pub fn guard_verify(deployment: &SQLDeployment) -> Result<(), String> {
    require_status(deployment, &DeploymentStatus::Configuring, "verify")
}

/// Guard: deployment must be in `Verified` status before backup registration.
pub fn guard_backup(deployment: &SQLDeployment) -> Result<(), String> {
    require_status(deployment, &DeploymentStatus::Verified, "register backup for")
}

/// Guard: deployment must be in `BackedUp` status before monitoring onboarding.
pub fn guard_monitoring(deployment: &SQLDeployment) -> Result<(), String> {
    require_status(
        deployment,
        &DeploymentStatus::BackedUp,
        "register monitoring for",
    )
}

fn require_status(
    deployment: &SQLDeployment,
    expected: &DeploymentStatus,
    action: &str,
) -> Result<(), String> {
    if &deployment.status != expected {
        return Err(format!(
            "Cannot {} SQL deployment in status {:?}. Must be {:?} first.",
            action, deployment.status, expected
        ));
    }
    Ok(())
}

// ─── Pure response builders ───────────────────────────────────────────────────
//
// These produce the JSON body that handlers return after the repo writes succeed.
// They read from the deployment so they reflect persisted state.

pub fn install_response(deployment: &SQLDeployment) -> Value {
    json!({
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
    })
}

pub fn configure_response(deployment: &SQLDeployment) -> Value {
    let maxdop = if deployment.cpu >= 8 {
        8
    } else {
        deployment.cpu
    };
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

    json!({
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
            "collation": deployment.collation_name,
            "service_account": deployment.service_account
        },
        "message": format!(
            "Mock post-install configuration applied to {} (dry-run)",
            deployment.instance_name
        )
    })
}

pub fn verify_response(deployment: &SQLDeployment) -> Value {
    json!({
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
    })
}

pub fn backup_response(deployment: &SQLDeployment) -> Value {
    json!({
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
    })
}

pub fn monitoring_response(deployment: &SQLDeployment) -> Value {
    json!({
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
    })
}

/// Returns a JSON inventory list from a slice of deployments (pure, no I/O).
/// Empty slice → empty result (no Err).
pub fn inventory_response(site: &str, deployments: &[SQLDeployment]) -> Value {
    let list: Vec<Value> = deployments.iter().map(deployment_to_json).collect();
    json!({
        "source": "live",
        "site": if site.is_empty() { "all" } else { site },
        "deployment_count": list.len(),
        "deployments": list
    })
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
        "collation_name": d.collation_name,
        "service_account": d.service_account,
        "site": d.site,
        "cluster_mode": d.cluster_mode.to_string(),
        "status": d.status
    })
}

// ─── Unit tests (pure surface only — no store, no I/O) ───────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_deployment(status: DeploymentStatus) -> SQLDeployment {
        SQLDeployment {
            id: "test-id".into(),
            instance_name: "DEFRA-SQL-TEST-01".into(),
            sql_version: SQLVersion::Sql2022,
            edition: SQLEdition::Enterprise,
            cpu: 8,
            memory_gb: 64,
            data_disk_gb: 500,
            log_disk_gb: 200,
            tempdb_disk_gb: 100,
            collation_name: "Latin1_General_CI_AS".into(),
            service_account: "svc-sql-test@ryuki.local".into(),
            site: "DEFRA".into(),
            cluster_mode: ClusterMode::AG,
            status,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    // ── plan_deployment ──

    #[test]
    fn test_plan_deployment_basic() {
        let (deployment, plan) = plan_deployment(json!({
            "instance_name": "DEFRA-SQL-TEST-01",
            "sql_version": "2022",
            "edition": "Standard",
            "cpu": 4,
            "memory_gb": 16,
            "data_disk_gb": 200,
            "log_disk_gb": 100,
            "tempdb_disk_gb": 50,
            "collation": "Latin1_General_CI_AS",
            "service_account": "svc-sql-test@ryuki.local",
            "site": "DEFRA",
            "cluster_mode": "Standalone"
        }))
        .unwrap();

        assert_eq!(deployment.instance_name, "DEFRA-SQL-TEST-01");
        assert_eq!(deployment.site, "DEFRA");
        assert_eq!(deployment.status, DeploymentStatus::Planned);
        assert_eq!(deployment.sql_version, SQLVersion::Sql2022);
        assert_eq!(deployment.cluster_mode, ClusterMode::Standalone);
        assert!(deployment.id.is_empty(), "id assigned by repo, not engine");

        assert_eq!(plan["instance_name"], "DEFRA-SQL-TEST-01");
        assert_eq!(plan["status"], "planned");
        assert_eq!(plan["total_disk_gb"], 350_u64);
        assert_eq!(plan["disk_layout"]["data"]["size_gb"], 200_u64);
    }

    #[test]
    fn test_plan_deployment_missing_instance_name() {
        let result = plan_deployment(json!({ "sql_version": "2022" }));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("instance_name"));
    }

    fn dim_req(field: &str, value: serde_json::Value) -> Value {
        let mut req = json!({
            "instance_name": "DEFRA-SQL-DIM",
            "sql_version": "2022",
            "edition": "Standard",
            "service_account": "svc@ryuki.local",
            "site": "DEFRA",
            "cluster_mode": "Standalone"
        });
        req[field] = value;
        req
    }

    #[test]
    fn test_plan_deployment_rejects_dimension_above_i32_max() {
        // > i32::MAX would wrap on a bare `as i32` repo bind and surface as a 500.
        let result = plan_deployment(dim_req("cpu", json!(3_000_000_000u64)));
        assert!(result.is_err(), "cpu above i32::MAX must be rejected");
        assert!(result.unwrap_err().contains("cpu"));
    }

    #[test]
    fn test_plan_deployment_rejects_below_minimum() {
        assert!(plan_deployment(dim_req("cpu", json!(0))).is_err());
        assert!(plan_deployment(dim_req("memory_gb", json!(1))).is_err());
        assert!(plan_deployment(dim_req("data_disk_gb", json!(5))).is_err());
    }

    #[test]
    fn test_plan_deployment_rejects_wrong_type_dimension() {
        // Present-but-wrong-type must error, not silently default.
        assert!(plan_deployment(dim_req("cpu", json!("8"))).is_err());
        assert!(plan_deployment(dim_req("memory_gb", json!(-1))).is_err());
        assert!(plan_deployment(dim_req("data_disk_gb", json!(10.5))).is_err());
        // Absent dimension still defaults (no cpu key -> default 4, valid).
        let req = json!({
            "instance_name": "DEFRA-SQL-DEF", "sql_version": "2022", "edition": "Standard",
            "service_account": "svc@ryuki.local", "site": "DEFRA", "cluster_mode": "Standalone"
        });
        assert!(plan_deployment(req).is_ok(), "absent dimensions use defaults");
    }

    #[test]
    fn test_plan_deployment_large_disks_do_not_overflow_total() {
        // Three near-i32::MAX disks: summing as u32 would overflow (panic in debug);
        // total_disk is computed in u64, so this plans cleanly.
        let mut req = dim_req("data_disk_gb", json!(2_000_000_000u64));
        req["log_disk_gb"] = json!(2_000_000_000u64);
        req["tempdb_disk_gb"] = json!(2_000_000_000u64);
        let (_, plan) = plan_deployment(req).expect("near-max disks within i32 must plan");
        assert_eq!(plan["total_disk_gb"].as_u64(), Some(6_000_000_000));
    }

    #[test]
    fn test_plan_deployment_missing_service_account() {
        let result = plan_deployment(json!({
            "instance_name": "DEFRA-SQL-01",
            "sql_version": "2022",
            "site": "DEFRA"
        }));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("service_account"));
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
            "site": "DEFRA",
            "cluster_mode": "Standalone"
        }));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported SQL version"));
    }

    #[test]
    fn test_plan_deployment_unsupported_cluster_mode() {
        let result = plan_deployment(json!({
            "instance_name": "BAD-SQL-01",
            "sql_version": "2022",
            "edition": "Standard",
            "cpu": 4,
            "memory_gb": 16,
            "data_disk_gb": 100,
            "log_disk_gb": 50,
            "tempdb_disk_gb": 30,
            "service_account": "svc@ryuki.local",
            "site": "DEFRA",
            "cluster_mode": "CLUSTER"
        }));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported cluster mode"));
    }

    #[test]
    fn test_plan_deployment_tempdb_config_cpu_lt_8() {
        let (deployment, plan) = plan_deployment(json!({
            "instance_name": "GBLON-SQL-01",
            "sql_version": "2022",
            "edition": "Standard",
            "cpu": 4,
            "memory_gb": 16,
            "data_disk_gb": 100,
            "log_disk_gb": 50,
            "tempdb_disk_gb": 30,
            "service_account": "svc@ryuki.local",
            "site": "GBLON",
            "cluster_mode": "Standalone"
        }))
        .unwrap();
        // cpu < 8: file_count = cpu, initial_size_mb = 512
        assert_eq!(plan["tempdb_config"]["file_count"], 4_u64);
        assert_eq!(plan["tempdb_config"]["initial_size_mb"], 512_u64);
        assert_eq!(deployment.cpu, 4);
    }

    #[test]
    fn test_plan_deployment_tempdb_config_cpu_ge_8() {
        let (_, plan) = plan_deployment(json!({
            "instance_name": "DEFRA-SQL-BIG",
            "sql_version": "2022",
            "edition": "Enterprise",
            "cpu": 16,
            "memory_gb": 128,
            "data_disk_gb": 1000,
            "log_disk_gb": 500,
            "tempdb_disk_gb": 200,
            "service_account": "svc@ryuki.local",
            "site": "DEFRA",
            "cluster_mode": "AG"
        }))
        .unwrap();
        // cpu >= 8: file_count = min(cpu/2, 8) = min(8, 8) = 8, initial_size_mb = 1024
        assert_eq!(plan["tempdb_config"]["file_count"], 8_u64);
        assert_eq!(plan["tempdb_config"]["initial_size_mb"], 1024_u64);
    }

    // ── validate_deployment ──

    #[test]
    fn test_validate_deployment_all_passing() {
        let result = validate_deployment(json!({
            "instance_name": "DEFRA-SQL-01",
            "sql_version": "2022",
            "edition": "Enterprise",
            "cpu": 8,
            "memory_gb": 64,
            "site": "DEFRA",
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
            "site": "DEFRA",
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
    fn test_validate_developer_edition_warning() {
        let result = validate_deployment(json!({
            "instance_name": "DEV-SQL-01",
            "sql_version": "2022",
            "edition": "Developer",
            "cpu": 4,
            "memory_gb": 16,
            "site": "DEFRA",
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
            "site": "DEFRA",
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
            "site": "DEFRA",
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

    // ── Lifecycle guards ──

    #[test]
    fn test_guard_install_requires_planned() {
        let planned = make_deployment(DeploymentStatus::Planned);
        assert!(guard_install(&planned).is_ok());

        let draft = make_deployment(DeploymentStatus::Draft);
        let err = guard_install(&draft).unwrap_err();
        assert!(err.contains("Must be Planned first") || err.contains("install"));
    }

    #[test]
    fn test_guard_configure_requires_installing() {
        let installing = make_deployment(DeploymentStatus::Installing);
        assert!(guard_configure(&installing).is_ok());

        let planned = make_deployment(DeploymentStatus::Planned);
        let err = guard_configure(&planned).unwrap_err();
        assert!(err.contains("Must be Installing first") || err.contains("configure"));
    }

    #[test]
    fn test_guard_verify_requires_configuring() {
        let configuring = make_deployment(DeploymentStatus::Configuring);
        assert!(guard_verify(&configuring).is_ok());

        let installing = make_deployment(DeploymentStatus::Installing);
        assert!(guard_verify(&installing).is_err());
    }

    #[test]
    fn test_guard_backup_requires_verified() {
        let verified = make_deployment(DeploymentStatus::Verified);
        assert!(guard_backup(&verified).is_ok());

        let configuring = make_deployment(DeploymentStatus::Configuring);
        assert!(guard_backup(&configuring).is_err());
    }

    #[test]
    fn test_guard_monitoring_requires_backed_up() {
        let backed_up = make_deployment(DeploymentStatus::BackedUp);
        assert!(guard_monitoring(&backed_up).is_ok());

        let verified = make_deployment(DeploymentStatus::Verified);
        assert!(guard_monitoring(&verified).is_err());
    }

    #[test]
    fn test_full_guard_sequence() {
        // Confirm every guard rejects a status that's one step ahead or behind.
        let draft = make_deployment(DeploymentStatus::Draft);
        assert!(guard_install(&draft).is_err());

        let planned = make_deployment(DeploymentStatus::Planned);
        assert!(guard_install(&planned).is_ok());
        assert!(guard_configure(&planned).is_err());
    }

    // ── Response builders ──

    #[test]
    fn test_install_response() {
        let d = make_deployment(DeploymentStatus::Installing);
        let r = install_response(&d);
        assert_eq!(r["status"], "installing");
        assert!(r["steps"].as_array().unwrap().len() >= 3);
    }

    #[test]
    fn test_configure_response() {
        let d = make_deployment(DeploymentStatus::Configuring);
        let r = configure_response(&d);
        assert_eq!(r["status"], "configuring");
        assert_eq!(r["config_applied"]["backup_compression_default"], 1_u64);
    }

    #[test]
    fn test_verify_response() {
        let d = make_deployment(DeploymentStatus::Verified);
        let r = verify_response(&d);
        assert_eq!(r["status"], "verified");
        assert!(r["checks"]["connectivity"]["passed"].as_bool().unwrap());
    }

    #[test]
    fn test_backup_response() {
        let d = make_deployment(DeploymentStatus::BackedUp);
        let r = backup_response(&d);
        assert_eq!(r["status"], "backed-up");
        assert!(
            r["veeam_config"]["application_aware_processing"]
                .as_bool()
                .unwrap()
        );
    }

    #[test]
    fn test_monitoring_response() {
        let d = make_deployment(DeploymentStatus::Monitored);
        let r = monitoring_response(&d);
        assert_eq!(r["status"], "monitored");
        assert!(
            r["zabbix_config"]["items_monitored"]
                .as_array()
                .unwrap()
                .len()
                >= 5
        );
    }

    #[test]
    fn test_inventory_response_empty() {
        let r = inventory_response("DEFRA", &[]);
        assert_eq!(r["deployment_count"], 0_u64);
        assert_eq!(r["site"], "DEFRA");
    }

    #[test]
    fn test_inventory_response_filters_by_site() {
        let deployments = [
            make_deployment(DeploymentStatus::Draft),
            {
                let mut d = make_deployment(DeploymentStatus::Planned);
                d.site = "GBLON".into();
                d
            },
        ];
        let defra_only: Vec<SQLDeployment> = deployments
            .iter()
            .filter(|d| d.site == "DEFRA")
            .cloned()
            .collect::<Vec<_>>();
        let r = inventory_response("DEFRA", &defra_only);
        assert_eq!(r["deployment_count"], 1_u64);
    }

    #[test]
    fn test_inventory_response_all_sites() {
        let d = make_deployment(DeploymentStatus::Draft);
        let r = inventory_response("", &[d]);
        assert_eq!(r["site"], "all");
        assert_eq!(r["deployment_count"], 1_u64);
    }

    // ── Enum display / serde round-trip ──

    #[test]
    fn test_cluster_mode_display_matches_db_form() {
        assert_eq!(ClusterMode::Standalone.to_string(), "Standalone");
        assert_eq!(ClusterMode::FCI.to_string(), "FCI");
        assert_eq!(ClusterMode::AG.to_string(), "AG");
    }

    #[test]
    fn test_sql_version_display_matches_db_form() {
        assert_eq!(SQLVersion::Sql2019.to_string(), "2019");
        assert_eq!(SQLVersion::Sql2022.to_string(), "2022");
    }

    #[test]
    fn test_deployment_status_display_matches_db_form() {
        assert_eq!(DeploymentStatus::Draft.to_string(), "draft");
        assert_eq!(DeploymentStatus::BackedUp.to_string(), "backed-up");
        assert_eq!(DeploymentStatus::Completed.to_string(), "completed");
    }
}
