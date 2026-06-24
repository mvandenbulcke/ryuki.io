use serde::Deserialize;
use std::fs;
use std::path::Path;

const RYUKI_ENGINE_CARGO_TOML_PATH: &str = "sources/ryuki-engine/Cargo.toml";
const RYUKI_ENGINE_LIB_RS_PATH: &str = "sources/ryuki-engine/src/lib.rs";
const RYUKI_ENGINE_ADAPTER_FRAMEWORK_RS_PATH: &str =
    "sources/ryuki-engine/src/adapter_framework.rs";

const DECLARED_MODULES: &[&str] = &[
    "access_recertification",
    "ad_computer_lifecycle",
    "adapter_framework",
    "aiops",
    "alert_routing_engine",
    "app_environment",
    "auth",
    "backup_engine",
    "certificate_lifecycle",
    "cluster_capacity_admission",
    "cmdb_engine",
    "cmdb_file_exchange",
    "cmdb_impact",
    "compliance_reporting",
    "container_namespace",
    "cost_capacity",
    "customization_spec_governance",
    "datacenter_readiness",
    "dc_readiness",
    "decommission_quarantine",
    "degradation_mode",
    "degradation_readiness",
    "delegation_boundary",
    "dns_ipam",
    "dr_testing",
    "emergency_change",
    "evidence_pipeline",
    "feature_flag",
    "file_share_ntfs",
    "firewall_rules",
    "firmware_lifecycle",
    "gmsa_lifecycle",
    "hardware_lifecycle",
    "hardware_readiness",
    "health_monitor",
    "image_factory",
    "immutability_compliance",
    "incident_context",
    "incident_readiness",
    "integration_connections",
    "inventory_sync",
    "knowledge_suggestion",
    "legal_hold",
    "linux_deployment",
    "load_balancer",
    "log_forwarder",
    "maintenance_calendar",
    "maintenance_comm",
    "models",
    "network_readiness",
    "network_vlan",
    "noise_remediation",
    "notifications",
    "object_placement",
    "oob_access",
    "os_baseline",
    "outage_comms",
    "patch_engine",
    "platform_health",
    "policy_engine",
    "repository_capacity",
    "request_lifecycle",
    "runbook_execution",
    "runners",
    "scheduler",
    "secrets_rotation",
    "server_decommission",
    "servicenow_api",
    "servicenow_future_api",
    "shift_queue",
    "shift_readiness",
    "site_registry",
    "snapshot_engine",
    "snapshot_governance",
    "software_deployment",
    "sql_deployment",
    "storage_provisioning",
    "synthetic_health",
    "vm_operations",
    "vsan_esxi_lifecycle",
    "zabbix_drift",
];

const REQUIRED_ADAPTER_TYPES: &[&str] = &[
    "VMwareAdapter",
    "HyperVAdapter",
    "ProxmoxAdapter",
    "VeeamAdapter",
    "ZabbixAdapter",
    "ServiceNowAdapter",
];

const PROHIBITED_IMPORTS: &[&str] = &[
    "reqwest",
    "sqlx",
    "PgPool",
    "SqlitePool",
    "diesel",
    "rusqlite",
    "hyper::Client",
];

const REQUIRED_TRAIT_METHODS: &[&str] = &[
    "fn connect",
    "fn health_check",
    "fn sync_inventory",
    "fn execute",
    "fn disconnect",
];

#[derive(Debug, Deserialize)]
struct Context {
    cargo_toml: String,
    lib_rs: String,
    adapter_framework_rs: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid ryuki-engine context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate(
        &context.cargo_toml,
        &context.lib_rs,
        &context.adapter_framework_rs,
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let context: Context = serde_json::from_str(input)
        .map_err(|error| format!("invalid ryuki-engine catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate(
        &context.cargo_toml,
        &context.lib_rs,
        &context.adapter_framework_rs,
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    validate_catalog_json(input)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    validate_catalog_json(input)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    validate_catalog_json(input)
}

fn validate(cargo_toml: &str, lib_rs: &str, adapter_framework_rs: &str, errors: &mut Vec<String>) {
    validate_cargo_toml(cargo_toml, errors);
    validate_lib_rs(lib_rs, errors);
    validate_adapter_framework(adapter_framework_rs, errors);
    validate_no_prohibited_imports(cargo_toml, errors);
    validate_no_prohibited_imports(lib_rs, errors);
    validate_no_prohibited_imports(adapter_framework_rs, errors);
}

fn validate_cargo_toml(cargo_toml: &str, errors: &mut Vec<String>) {
    expect(
        cargo_toml.contains(r#"name = "ryuki-engine""#),
        errors,
        "ryuki-engine Cargo.toml must name the crate ryuki-engine",
    );
    expect(
        cargo_toml.contains("serde"),
        errors,
        "ryuki-engine Cargo.toml must depend on serde",
    );
    expect(
        cargo_toml.contains("serde_json"),
        errors,
        "ryuki-engine Cargo.toml must depend on serde_json",
    );
    expect(
        cargo_toml.contains("serde_yaml"),
        errors,
        "ryuki-engine Cargo.toml must depend on serde_yaml",
    );
    expect(
        cargo_toml.contains("chrono"),
        errors,
        "ryuki-engine Cargo.toml must depend on chrono",
    );
    expect(
        cargo_toml.contains("uuid"),
        errors,
        "ryuki-engine Cargo.toml must depend on uuid",
    );
    expect(
        cargo_toml.contains("thiserror"),
        errors,
        "ryuki-engine Cargo.toml must depend on thiserror",
    );
}

fn validate_lib_rs(lib_rs: &str, errors: &mut Vec<String>) {
    for module in DECLARED_MODULES {
        expect(
            lib_rs.contains(&format!("pub mod {module};")),
            errors,
            format!("ryuki-engine lib.rs missing module declaration: pub mod {module};"),
        );
    }
    let declared: Vec<&str> = lib_rs
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            trimmed
                .strip_prefix("pub mod ")
                .and_then(|s| s.strip_suffix(';'))
        })
        .collect();
    for module in declared {
        expect(
            DECLARED_MODULES.contains(&module),
            errors,
            format!("ryuki-engine lib.rs declares unexpected module: {module}"),
        );
    }
}

fn validate_adapter_framework(adapter_framework_rs: &str, errors: &mut Vec<String>) {
    expect(
        adapter_framework_rs.contains("pub trait ProviderAdapter"),
        errors,
        "ryuki-engine adapter_framework.rs must define ProviderAdapter trait",
    );
    for method in REQUIRED_TRAIT_METHODS {
        expect(
            adapter_framework_rs.contains(method),
            errors,
            format!("ryuki-engine ProviderAdapter trait missing method: {method}"),
        );
    }
    for adapter_type in REQUIRED_ADAPTER_TYPES {
        expect(
            adapter_framework_rs.contains(&format!("pub struct {adapter_type}")),
            errors,
            format!("ryuki-engine missing adapter struct: {adapter_type}"),
        );
        expect(
            adapter_framework_rs.contains(&format!("impl ProviderAdapter for {adapter_type}")),
            errors,
            format!("ryuki-engine {adapter_type} must implement ProviderAdapter"),
        );
    }
    expect(
        adapter_framework_rs.contains("static_dry_run"),
        errors,
        "ryuki-engine adapters must expose static_dry_run constructors",
    );
    expect(
        adapter_framework_rs.contains("DRY-RUN"),
        errors,
        "ryuki-engine adapter execute methods must produce DRY-RUN output",
    );
    for adapter_type in REQUIRED_ADAPTER_TYPES {
        let static_dry_run_pattern = format!("impl {adapter_type} {{\n    pub fn static_dry_run");
        expect(
            adapter_framework_rs.contains(&static_dry_run_pattern),
            errors,
            format!("ryuki-engine {adapter_type} must have static_dry_run() constructor"),
        );
    }
    expect(
        !adapter_framework_rs.contains("password = \"")
            && !adapter_framework_rs.contains("secret = \""),
        errors,
        "ryuki-engine adapter_framework.rs must not contain hardcoded credential values",
    );
}

fn validate_no_prohibited_imports(source: &str, errors: &mut Vec<String>) {
    for token in PROHIBITED_IMPORTS {
        expect(
            !source.contains(token),
            errors,
            format!("ryuki-engine must not reference prohibited import: {token}"),
        );
    }
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sources_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn read_sources_file(path: &str) -> String {
        std::fs::read_to_string(sources_root().join(path)).unwrap_or_default()
    }

    #[test]
    fn ryuki_engine_cargo_toml_is_valid() {
        let cargo_toml = read_sources_file(RYUKI_ENGINE_CARGO_TOML_PATH);
        let mut errors = Vec::new();
        validate_cargo_toml(&cargo_toml, &mut errors);
        assert!(
            errors.is_empty(),
            "ryuki-engine Cargo.toml validation errors: {:?}",
            errors
        );
    }

    #[test]
    fn ryuki_engine_lib_rs_declares_all_modules() {
        let lib_rs = read_sources_file(RYUKI_ENGINE_LIB_RS_PATH);
        let mut errors = Vec::new();
        validate_lib_rs(&lib_rs, &mut errors);
        assert!(
            errors.is_empty(),
            "ryuki-engine lib.rs validation errors: {:?}",
            errors
        );
    }

    #[test]
    fn ryuki_engine_adapter_framework_implements_trait() {
        let adapter_framework_rs = read_sources_file(RYUKI_ENGINE_ADAPTER_FRAMEWORK_RS_PATH);
        let cargo_toml = read_sources_file(RYUKI_ENGINE_CARGO_TOML_PATH);
        let mut errors = Vec::new();
        validate_adapter_framework(&adapter_framework_rs, &mut errors);
        validate_no_prohibited_imports(&cargo_toml, &mut errors);
        validate_no_prohibited_imports(&adapter_framework_rs, &mut errors);
        assert!(
            errors.is_empty(),
            "ryuki-engine adapter validation errors: {:?}",
            errors
        );
    }

    #[test]
    fn ryuki_engine_no_prohibited_imports() {
        let cargo_toml = read_sources_file(RYUKI_ENGINE_CARGO_TOML_PATH);
        let lib_rs = read_sources_file(RYUKI_ENGINE_LIB_RS_PATH);
        let adapter_framework_rs = read_sources_file(RYUKI_ENGINE_ADAPTER_FRAMEWORK_RS_PATH);

        let mut errors = Vec::new();
        validate_no_prohibited_imports(&cargo_toml, &mut errors);
        validate_no_prohibited_imports(&lib_rs, &mut errors);
        validate_no_prohibited_imports(&adapter_framework_rs, &mut errors);
        assert!(
            errors.is_empty(),
            "ryuki-engine prohibited imports: {:?}",
            errors
        );
    }
}
