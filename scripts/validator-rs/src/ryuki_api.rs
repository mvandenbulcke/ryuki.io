use serde::Deserialize;
use std::fs;
use std::path::Path;

const RYUKI_API_CARGO_TOML_PATH: &str = "sources/ryuki-api/Cargo.toml";
const RYUKI_API_MAIN_RS_PATH: &str = "sources/ryuki-api/src/main.rs";
const RYUKI_API_CONTRACTS_RS_PATH: &str = "sources/ryuki-api/src/contracts.rs";
const RYUKI_API_BOUNDARY_RS_PATH: &str = "sources/ryuki-api/src/boundary.rs";

const REQUIRED_ENDPOINTS: &[&str] = &[
    "/api/platform/summary",
    "/api/dashboard/global-overview-contract",
    "/api/dashboard/risk-heatmap-contract",
    "/api/requests/lifecycle-contract",
    "/api/requests/execution-timeline-contract",
    "/api/requests/intake-support-contract",
    "/api/requests/preflight-contract",
    "/api/platform/security-baseline-contract",
    "/api/platform/portal-information-architecture-contract",
    "/api/platform/design-system-contract",
    "/api/platform/ui-mockup-acceptance-contract",
    "/api/platform/release-promotion-contract",
    "/api/platform/local-container-readiness-contract",
    "/api/platform/kubernetes-runtime-readiness-contract",
    "/api/platform/database-readiness-contract",
    "/api/platform/object-storage-readiness-contract",
    "/api/platform/registry-readiness-contract",
    "/api/platform/vault-deployment-readiness-contract",
    "/api/platform/vault-secret-delivery-contract",
    "/api/catalog/categories",
    "/api/catalog/offerings-contract",
    "/api/catalog/recommendations-contract",
    "/api/catalog/request-form-contract",
    "/api/catalog/site-catalog-contract",
    "/api/catalog/policy-guardrails-contract",
    "/api/catalog/access-control",
    "/api/catalog/approval-routes",
    "/api/catalog/evidence-manifest",
    "/api/catalog/evidence-redaction-contract",
    "/api/catalog/secret-references",
    "/api/approvals/decision-readiness-contract",
    "/api/identity/rbac-approval-model-contract",
    "/api/identity/entra-rbac-approval-readiness-contract",
    "/api/identity/access-review-recertification-contract",
    "/api/identity/ad-computer-lifecycle-contract",
    "/api/identity/gmsa-lifecycle-contract",
    "/api/identity/local-privilege-access-contract",
    "/api/identity/file-share-ntfs-recertification-contract",
    "/api/evidence/export-retention-contract",
    "/api/evidence/compliance-dashboard-contract",
    "/api/integrations/readiness",
    "/api/integrations/adapter-readiness-matrix-contract",
    "/api/integrations/adapter-contract-test-contract",
    "/api/integrations/vmware/readiness",
    "/api/integrations/vmware/cluster-capacity-admission-contract",
    "/api/integrations/vmware/customization-spec-governance-contract",
    "/api/integrations/vmware/object-placement-contract",
    "/api/integrations/vmware/vsan-esxi-lifecycle-contract",
    "/api/integrations/vmware/day2-change-contract",
    "/api/integrations/vmware/snapshot-governance-contract",
    "/api/integrations/vmware/decommission-quarantine-contract",
    "/api/integrations/hyperv/readiness",
    "/api/integrations/proxmox/readiness",
    "/api/integrations/veeam/readiness",
    "/api/integrations/zabbix/readiness",
    "/api/integrations/servicenow/readiness",
    "/api/integrations/servicenow/cmdb-file-contract",
    "/api/integrations/servicenow/future-api-contract",
    "/api/inventory/coverage-contract",
    "/api/inventory/resource-overview-contract",
    "/api/inventory/coverage/local/summary",
    "/api/inventory/ownership-risk-contract",
    "/api/inventory/os-baseline-compliance-contract",
    "/api/software/approved-deployment-contract",
    "/api/workflows/server-lifecycle/dry-run-contract",
    "/api/workflows/application-environment/deployment-contract",
    "/api/workflows/application-environment/retirement-contract",
    "/api/workflows/sql-server/deployment-contract",
    "/api/workflows/azure-landing-zone/validation-contract",
    "/api/workflows/preflight/local/decision",
    "/api/operations/certificate-lifecycle-contract",
    "/api/operations/runbook-launch-contract",
    "/api/operations/standard-task-contract",
    "/api/operations/emergency-change-contract",
    "/api/operations/shift-queue-contract",
    "/api/operations/dependency-replay-contract",
    "/api/operations/activity-queue-contract",
    "/api/operations/run-state-contract",
    "/api/operations/datacenter-readiness-contract",
    "/api/operations/out-of-band-access-validation-contract",
    "/api/operations/network-vlan-readiness-contract",
    "/api/operations/hardware-lifecycle-contract",
    "/api/operations/firmware-compliance-exception-contract",
    "/api/operations/platform-health-contract",
    "/api/operations/incident-context-contract",
    "/api/operations/maintenance-communications-contract",
    "/api/operations/degradation-mode-contract",
    "/api/operations/aiops-suggestion-contract",
    "/api/operations/knowledge-suggestion-contract",
    "/api/images/factory-contract",
    "/api/patching/maintenance-contract",
    "/api/patching/policy-import-contract",
    "/api/patching/reboot-orchestration-contract",
    "/api/patching/maintenance-calendar-contract",
    "/api/protect/controlled-restore-contract",
    "/api/protect/backup-coverage-gap-contract",
    "/api/protect/repository-capacity-contract",
    "/api/protect/immutability-air-gap-compliance-contract",
    "/api/protect/application-aware-backup-validation-contract",
    "/api/protect/backup-dr-assignment-contract",
    "/api/protect/restore-testing-contract",
    "/api/protect/legal-hold-retention-contract",
    "/api/observe/zabbix-onboarding-contract",
    "/api/observe/alert-routing-contract",
    "/api/observe/monitoring-coverage-gap-contract",
    "/api/observe/zabbix-drift-remediation-contract",
    "/api/observe/synthetic-health-check-contract",
    "/api/observe/noise-flapping-remediation-contract",
    "/api/observe/monitoring-review-queue-contract",
    "/api/observe/log-forwarder-onboarding-contract",
    "/api/cmdb/reconciliation-contract",
    "/api/cmdb/relationship-graph-contract",
    "/api/cmdb/impact-analysis-contract",
    "/api/admin/worker-capability-contract",
    "/api/admin/feature-flag-governance-contract",
    "/api/admin/approval-groups-contract",
    "/api/admin/delegation-boundary-contract",
    "/api/auth/local/roles",
    "/api/auth/local/me",
    "/api/auth/local/decision",
    "/api/analytics/cost-capacity-contract",
];

const BOUNDARY_REQUIRED_TOKENS: &[&str] = &["BoundaryStatus", "::default()", "boundary_status"];

#[derive(Debug, Deserialize)]
struct Context {
    cargo_toml: String,
    main_rs: String,
    contracts_rs: String,
    boundary_rs: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid ryuki-api context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate(
        &context.cargo_toml,
        &context.main_rs,
        &context.contracts_rs,
        &context.boundary_rs,
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let context: Context = serde_json::from_str(input)
        .map_err(|error| format!("invalid ryuki-api catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate(
        &context.cargo_toml,
        &context.main_rs,
        &context.contracts_rs,
        &context.boundary_rs,
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

fn validate(
    cargo_toml: &str,
    main_rs: &str,
    contracts_rs: &str,
    boundary_rs: &str,
    errors: &mut Vec<String>,
) {
    validate_cargo_toml(cargo_toml, errors);
    validate_main_rs(main_rs, errors);
    validate_contracts_rs(contracts_rs, errors);
    validate_boundary_rs(boundary_rs, errors);
}

fn validate_cargo_toml(cargo_toml: &str, errors: &mut Vec<String>) {
    expect(
        cargo_toml.contains(r#"name = "ryuki-api""#),
        errors,
        "ryuki-api Cargo.toml must name the crate ryuki-api",
    );
    expect(
        cargo_toml.contains("axum"),
        errors,
        "ryuki-api Cargo.toml must depend on axum",
    );
    expect(
        cargo_toml.contains("tokio"),
        errors,
        "ryuki-api Cargo.toml must depend on tokio",
    );
    expect(
        cargo_toml.contains("serde"),
        errors,
        "ryuki-api Cargo.toml must depend on serde",
    );
    expect(
        cargo_toml.contains("tower-http"),
        errors,
        "ryuki-api Cargo.toml must depend on tower-http",
    );
    expect(
        cargo_toml.contains("ryuki-core"),
        errors,
        "ryuki-api Cargo.toml must depend on ryuki-core",
    );
    expect(
        !cargo_toml.contains("reqwest") && !cargo_toml.contains("hyper::"),
        errors,
        "ryuki-api Cargo.toml must not depend on external HTTP clients",
    );
    expect(
        !cargo_toml.contains("diesel"),
        errors,
        "ryuki-api Cargo.toml must not depend on diesel",
    );
}

fn validate_main_rs(main_rs: &str, errors: &mut Vec<String>) {
    expect(
        main_rs.contains("mod boundary;") && main_rs.contains("mod contracts;"),
        errors,
        "ryuki-api main.rs must declare boundary and contracts modules",
    );
    expect(
        main_rs.contains("axum"),
        errors,
        "ryuki-api main.rs must use axum",
    );
    expect(
        main_rs.contains(r#"bind("0.0.0.0:8080")"#)
            || main_rs.contains("api_bind_addr")
            || main_rs.contains("TcpListener::bind(&app_config.server.bind_address)"),
        errors,
        "ryuki-api must bind to 0.0.0.0:8080 or use Rust server bind_address config",
    );
    expect(
        main_rs.contains("contracts::routes()"),
        errors,
        "ryuki-api must merge contracts::routes()",
    );
    expect(
        main_rs.contains("boundary::routes()"),
        errors,
        "ryuki-api must merge boundary::routes()",
    );
    expect(
        main_rs.contains("/health") && main_rs.contains("/ready"),
        errors,
        "ryuki-api must expose /health and /ready endpoints",
    );
    expect(
        !main_rs.contains("reqwest"),
        errors,
        "ryuki-api main.rs must not reference external HTTP clients",
    );
}

fn validate_contracts_rs(contracts_rs: &str, errors: &mut Vec<String>) {
    for endpoint in REQUIRED_ENDPOINTS {
        expect(
            contracts_rs.contains(&format!("\"{endpoint}\"")),
            errors,
            format!("ryuki-api contracts.rs missing endpoint {endpoint}"),
        );
    }
    expect(
        contracts_rs.contains("pub fn routes() -> Router"),
        errors,
        "ryuki-api contracts.rs must expose routes() -> Router",
    );
    expect(
        !contracts_rs.contains("reqwest"),
        errors,
        "ryuki-api contracts.rs must not reference external HTTP clients",
    );
}

fn validate_boundary_rs(boundary_rs: &str, errors: &mut Vec<String>) {
    for token in BOUNDARY_REQUIRED_TOKENS {
        expect(
            boundary_rs.contains(token),
            errors,
            format!("ryuki-api boundary.rs missing required token {token}"),
        );
    }
    expect(
        boundary_rs.contains("pub fn routes() -> Router"),
        errors,
        "ryuki-api boundary.rs must expose routes() -> Router",
    );
    expect(
        boundary_rs.contains("ryuki_core"),
        errors,
        "ryuki-api boundary.rs must use ryuki_core types",
    );
    expect(
        boundary_rs.contains("/api/boundary/status"),
        errors,
        "ryuki-api boundary.rs must expose /api/boundary/status",
    );
    expect(
        !boundary_rs.contains("reqwest") && !boundary_rs.contains("sqlx"),
        errors,
        "ryuki-api boundary.rs must not reference external clients or databases",
    );
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
    fn ryuki_api_cargo_toml_is_valid() {
        let cargo_toml = read_sources_file(RYUKI_API_CARGO_TOML_PATH);
        let main_rs = read_sources_file(RYUKI_API_MAIN_RS_PATH);
        let contracts_rs = read_sources_file(RYUKI_API_CONTRACTS_RS_PATH);
        let boundary_rs = read_sources_file(RYUKI_API_BOUNDARY_RS_PATH);

        let mut errors = Vec::new();
        validate(
            &cargo_toml,
            &main_rs,
            &contracts_rs,
            &boundary_rs,
            &mut errors,
        );
        assert!(
            errors.is_empty(),
            "ryuki-api validation errors: {:?}",
            errors
        );
    }

    #[test]
    fn ryuki_api_contracts_covers_all_endpoints() {
        let contracts_rs = read_sources_file(RYUKI_API_CONTRACTS_RS_PATH);
        let mut errors = Vec::new();
        for endpoint in REQUIRED_ENDPOINTS {
            expect(
                contracts_rs.contains(&format!("\"{endpoint}\"")),
                &mut errors,
                format!("missing endpoint {endpoint}"),
            );
        }
        assert!(errors.is_empty(), "missing endpoints: {:?}", errors);
    }
}
