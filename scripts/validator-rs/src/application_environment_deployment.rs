use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/application-environment-deployment-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/application-environment-deployment.md";
const ENDPOINT: &str = "/api/workflows/application-environment/deployment-contract";

const REQUIRED_PLANS: &[&str] = &[
    "tier-topology-plan",
    "vm-placement-plan",
    "dns-ipam-plan",
    "certificate-plan",
    "firewall-rule-plan",
    "monitoring-plan",
    "backup-plan",
    "cmdb-relationship-plan",
    "handover-plan",
];
const REQUIRED_TIERS: &[&str] = &[
    "front-tier",
    "mid-tier",
    "back-tier",
    "data-tier",
    "shared-service-tier",
];
const REQUIRED_INPUTS: &[&str] = &[
    "businessPurpose",
    "applicationProfile",
    "environmentProfile",
    "tierProfile",
    "site",
    "criticality",
    "owner",
    "supportGroup",
    "dnsIpamSummary",
    "certificateSummary",
    "networkFlowSummary",
    "monitoringProfile",
    "backupPolicy",
    "cmdbRelationshipSummary",
    "approvalRoute",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "request-preflight-ready",
    "tier-topology-reviewed",
    "placement-plan-reviewed",
    "dns-ipam-plan-reviewed",
    "certificate-plan-reviewed",
    "network-flow-reviewed",
    "monitoring-plan-reviewed",
    "backup-plan-reviewed",
    "cmdb-relationship-reviewed",
    "approval-route-assigned",
    "rollback-plan-ready",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "environmentSummary",
    "tierTopology",
    "placementPlan",
    "dnsIpamPlan",
    "certificatePlan",
    "networkFlowPlan",
    "monitoringPlan",
    "backupPlan",
    "cmdbRelationshipPlan",
    "rollbackPlan",
    "handoverPlan",
    "evidenceReferences",
];
const REQUIRED_HYPERVISORS: &[&str] = &["VMware", "Hyper-V", "Proxmox"];
const REQUIRED_HYPERVISOR_PARITY: &[(&str, &str)] = &[
    ("VMware", "vmware-placement-dry-run-summary"),
    ("Hyper-V", "hyperv-placement-dry-run-summary"),
    ("Proxmox", "proxmox-placement-dry-run-summary"),
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "worker-execution-disabled",
    "live-deployment-disabled",
    "live-vmware-change-disabled",
    "live-hyperv-change-disabled",
    "live-proxmox-change-disabled",
    "live-dns-ipam-change-disabled",
    "live-certificate-change-disabled",
    "live-firewall-change-disabled",
    "live-monitoring-change-disabled",
    "live-backup-change-disabled",
    "live-cmdb-change-disabled",
    "raw-network-data-disabled",
    "raw-dns-records-disabled",
    "raw-certificate-data-disabled",
    "raw-firewall-rules-disabled",
    "raw-cmdb-rows-disabled",
    "raw-provider-payloads-disabled",
    "app-env-host-identifiers-disabled",
    "fqdn-values-disabled",
    "ip-address-values-disabled",
    "credential-values-disabled",
    "raw-recipient-data-disabled",
    "tier-topology-missing",
    "dns-ipam-plan-missing",
    "certificate-plan-missing",
    "firewall-plan-missing",
    "monitoring-plan-missing",
    "backup-plan-missing",
    "cmdb-relationship-missing",
    "approval-missing",
    "rollback-plan-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Environment summary",
    "Tier topology",
    "Placement plan",
    "DNS and IPAM plan",
    "Certificate plan",
    "Network flow plan",
    "Monitoring plan",
    "Backup plan",
    "CMDB relationship plan",
    "Rollback plan",
    "Handover plan",
    "Evidence references",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "workerExecutionAllowed",
    "deploymentExecutionAllowed",
    "liveVmwareChangesAllowed",
    "liveHyperVChangesAllowed",
    "liveProxmoxChangesAllowed",
    "liveDnsIpamChangesAllowed",
    "liveCertificateChangesAllowed",
    "liveFirewallChangesAllowed",
    "liveMonitoringChangesAllowed",
    "liveBackupChangesAllowed",
    "liveCmdbChangesAllowed",
    "rawNetworkDataAllowed",
    "rawDnsRecordsAllowed",
    "rawCertificateDataAllowed",
    "rawFirewallRulesAllowed",
    "rawCmdbRowsAllowed",
    "rawProviderPayloadsAllowed",
    "hostIdentifiersAllowed",
    "fqdnValuesAllowed",
    "ipAddressValuesAllowed",
    "credentialValuesAllowed",
    "rawRecipientDataAllowed",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "deploymentMode",
    "dryRunRequired",
    "supportedPlans",
    "environmentTiers",
    "supportedHypervisors",
    "hypervisorParity",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "providerCallsEnabled",
    "workerExecutionAllowed",
    "deploymentExecutionAllowed",
    "liveVmwareChangesAllowed",
    "liveHyperVChangesAllowed",
    "liveProxmoxChangesAllowed",
    "liveDnsIpamChangesAllowed",
    "liveCertificateChangesAllowed",
    "liveFirewallChangesAllowed",
    "liveMonitoringChangesAllowed",
    "liveBackupChangesAllowed",
    "liveCmdbChangesAllowed",
    "rawNetworkDataAllowed",
    "rawDnsRecordsAllowed",
    "rawCertificateDataAllowed",
    "rawFirewallRulesAllowed",
    "rawCmdbRowsAllowed",
    "rawProviderPayloadsAllowed",
    "hostIdentifiersAllowed",
    "fqdnValuesAllowed",
    "ipAddressValuesAllowed",
    "credentialValuesAllowed",
    "rawRecipientDataAllowed",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("supportedPlans", "applicationEnvironmentDeploymentPlans"),
    ("environmentTiers", "applicationEnvironmentDeploymentTiers"),
    (
        "supportedHypervisors",
        "applicationEnvironmentDeploymentSupportedHypervisors",
    ),
    (
        "requiredGuards",
        "applicationEnvironmentDeploymentRequiredGuards",
    ),
    (
        "planSections",
        "applicationEnvironmentDeploymentPlanSections",
    ),
    (
        "blockedReasons",
        "applicationEnvironmentDeploymentBlockedReasons",
    ),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredInputs", "requiredEvidence"];
const ENDPOINT_BINDING_VARIABLES: &[&str] = &[
    "applicationEnvironmentDeploymentPlans",
    "applicationEnvironmentDeploymentTiers",
    "applicationEnvironmentDeploymentSupportedHypervisors",
    "applicationEnvironmentDeploymentRequiredGuards",
    "applicationEnvironmentDeploymentPlanSections",
    "applicationEnvironmentDeploymentBlockedReasons",
];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "deploymentMode",
    "dryRunRequired",
    "hypervisorParity",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
    "supportedPlans",
    "environmentTiers",
    "supportedHypervisors",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "providerCallsEnabled",
    "workerExecutionAllowed",
    "deploymentExecutionAllowed",
    "liveVmwareChangesAllowed",
    "liveHyperVChangesAllowed",
    "liveProxmoxChangesAllowed",
    "liveDnsIpamChangesAllowed",
    "liveCertificateChangesAllowed",
    "liveFirewallChangesAllowed",
    "liveMonitoringChangesAllowed",
    "liveBackupChangesAllowed",
    "liveCmdbChangesAllowed",
    "rawNetworkDataAllowed",
    "rawDnsRecordsAllowed",
    "rawCertificateDataAllowed",
    "rawFirewallRulesAllowed",
    "rawCmdbRowsAllowed",
    "rawProviderPayloadsAllowed",
    "hostIdentifiersAllowed",
    "fqdnValuesAllowed",
    "ipAddressValuesAllowed",
    "credentialValuesAllowed",
    "rawRecipientDataAllowed",
];
const PROHIBITED_FIELD_ALIASES: &[&str] = &[
    "credential",
    "password",
    "bearer",
    "token",
    "url",
    "endpoint",
];
const PROHIBITED_FIELD_TOKENS: &[&str] = &[
    "applicationname",
    "environmentname",
    "dnsrecord",
    "certificatesubject",
    "subjectalternativename",
    "subjectaltname",
    "firewallrule",
    "cmdbsysid",
    "ciidentifier",
    "rawnetwork",
    "networkdata",
    "rawdns",
    "dnsrecords",
    "rawcertificate",
    "certificatedata",
    "rawfirewall",
    "firewallrules",
    "cmdbrow",
    "hostname",
    "hostidentifier",
    "fqdn",
    "ipaddress",
    "privateip",
    "tenantid",
    "tenantidentifier",
    "objectid",
    "objectidentifier",
    "endpointurl",
    "providerpayload",
    "rawnetwork",
    "rawdns",
    "rawcertificate",
    "rawfirewall",
    "rawcmdb",
    "rawprovider",
    "rawrecipient",
    "recipientemail",
    "recipientdata",
    "credentialvalue",
    "secretvalue",
    "accesstoken",
    "credential",
    "secret",
    "token",
    "password",
];
const REQUIRED_RULES: &[RuleRef] = &[
    RuleRef {
        id: "no-live-environment-deployment",
        decision: "block",
        requirement: "Application environment deployment produces a dry-run plan only and never creates, updates, or deletes VMware, Hyper-V, or Proxmox workloads, DNS and IPAM records, certificate records, firewall rules, monitoring objects, backup policies, CMDB records, workers, or provider state.",
        evidence: "Environment summary",
    },
    RuleRef {
        id: "dependency-plans-required",
        decision: "block",
        requirement: "Tier topology, placement, DNS and IPAM, certificate, network flow, monitoring, backup, and CMDB relationship plans must be reviewed before application environment approval.",
        evidence: "Tier topology",
    },
    RuleRef {
        id: "approval-rollback-handover-required",
        decision: "block",
        requirement: "Owner, support group, approval route, rollback plan, handover plan, and evidence references must be present before application environment deployment can be accepted.",
        evidence: "Rollback plan",
    },
    RuleRef {
        id: "raw-application-environment-data-not-exposed",
        decision: "block",
        requirement: "Application environment deployment evidence must use safe summaries only and must not expose application names, environment names, hostnames, FQDNs, IP addresses, DNS records, certificate subjects, subject alternative names, firewall rules, CMDB rows, recipient data, credentials, secret values, access tokens, or provider payloads.",
        evidence: "Evidence references",
    },
];

#[derive(Deserialize)]
struct ApplicationEnvironmentDeploymentContext {
    catalog: Value,
    catalog_text: String,
    program: String,
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
}

#[derive(Deserialize)]
struct ProgramInput {
    program: String,
    catalog: Value,
}

#[derive(Deserialize)]
struct DocsInput {
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
}

#[derive(Deserialize)]
struct ProhibitedInput {
    value: Value,
    path: String,
}

#[derive(Clone, Copy)]
struct RuleRef {
    id: &'static str,
    decision: &'static str,
    requirement: &'static str,
    evidence: &'static str,
}

#[derive(Clone)]
struct Rule {
    id: String,
    decision: String,
    requirement: String,
    evidence: String,
}

#[derive(Clone)]
struct HypervisorParity {
    platform: String,
    dry_run_summary: String,
}

#[derive(Clone)]
struct MapRoute {
    start: usize,
    route: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: ApplicationEnvironmentDeploymentContext =
        serde_json::from_str(&payload).map_err(|error| {
            format!("invalid application environment deployment context JSON: {error}")
        })?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    scan_prohibited_value(
        &Value::String(context.catalog_text),
        CATALOG_PATH,
        &mut errors,
    );
    if context.catalog.is_object() {
        validate_program_text(&context.program, &context.catalog, &mut errors);
    }
    validate_docs_text(
        &context.api_readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.api_readme),
        API_README_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.catalog_readme),
        CATALOG_README_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.doc_readme),
        DOC_README_PATH,
        &mut errors,
    );
    scan_prohibited_value(&Value::String(context.doc), DOC_PATH, &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input).map_err(|error| {
        format!("invalid application environment deployment catalog JSON: {error}")
    })?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input).map_err(|error| {
        format!("invalid application environment deployment program JSON: {error}")
    })?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input).map_err(|error| {
        format!("invalid application environment deployment docs JSON: {error}")
    })?;
    let mut errors = Vec::new();
    validate_docs_text(
        &payload.api_readme,
        &payload.catalog_readme,
        &payload.doc_readme,
        &payload.doc,
        &mut errors,
    );
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input).map_err(|error| {
        format!("invalid application environment deployment prohibited JSON: {error}")
    })?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    let Some(object) = catalog.as_object() else {
        errors.push("application environment deployment catalog must be a mapping".to_string());
        return;
    };

    let actual_keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    let expected_keys: BTreeSet<&str> = REQUIRED_CATALOG_KEYS.iter().copied().collect();
    let unexpected: Vec<&str> = actual_keys.difference(&expected_keys).copied().collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "application environment deployment unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }

    expect(
        value_i64(catalog, "version") == Some(1),
        errors,
        "application environment deployment version must be 1",
    );
    expect(
        value_str(catalog, "status") == Some("draft"),
        errors,
        "application environment deployment status must be draft",
    );
    expect(
        value_str(catalog, "source") == Some("static-seed"),
        errors,
        "application environment deployment source must be static-seed",
    );
    expect(
        value_str(catalog, "deploymentMode") == Some("dry-run-plan"),
        errors,
        "application environment deployment mode must be dry-run-plan",
    );
    expect(
        value_bool(catalog, "dryRunRequired") == Some(true),
        errors,
        "application environment deployment must require dry-run",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            value_bool(catalog, field) == Some(false),
            errors,
            &format!("application environment deployment {field} must be disabled"),
        );
    }

    validate_required_array(catalog, "supportedPlans", REQUIRED_PLANS, errors);
    validate_required_array(catalog, "environmentTiers", REQUIRED_TIERS, errors);
    validate_required_array(
        catalog,
        "supportedHypervisors",
        REQUIRED_HYPERVISORS,
        errors,
    );
    validate_hypervisor_parity_shape(catalog.get("hypervisorParity"), "catalog", errors);
    validate_hypervisor_parity(catalog_hypervisor_parity(catalog), "catalog", errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);
    scan_prohibited_value(catalog, CATALOG_PATH, errors);
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let values = string_array(catalog.get(field));
    expect(
        !values.is_empty(),
        errors,
        &format!("{field} must be non-empty array"),
    );
    let required: BTreeSet<String> = required_values
        .iter()
        .map(|value| value.to_string())
        .collect();
    let actual: BTreeSet<String> = values.iter().cloned().collect();
    let missing: Vec<String> = required.difference(&actual).cloned().collect();
    let unexpected: Vec<String> = actual.difference(&required).cloned().collect();
    if !missing.is_empty() {
        errors.push(format!("{field} missing values: {}", missing.join(", ")));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "{field} unexpected values: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        values.len() == actual.len(),
        errors,
        &format!("{field} values must be unique"),
    );
    for value in values {
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "{field} contains prohibited application environment deployment value {value}"
            ));
        }
    }
}

fn catalog_hypervisor_parity(catalog: &Value) -> Option<Vec<HypervisorParity>> {
    let values = catalog.get("hypervisorParity")?.as_array()?;
    Some(
        values
            .iter()
            .filter_map(|entry| {
                Some(HypervisorParity {
                    platform: value_str_direct(entry, "platform")?.to_string(),
                    dry_run_summary: value_str_direct(entry, "dryRunSummary")?.to_string(),
                })
            })
            .collect(),
    )
}

fn validate_hypervisor_parity_shape(value: Option<&Value>, source: &str, errors: &mut Vec<String>) {
    let Some(values) = value.and_then(Value::as_array) else {
        return;
    };
    let expected_keys: BTreeSet<&str> = ["platform", "dryRunSummary"].into_iter().collect();
    for entry in values {
        let Some(object) = entry.as_object() else {
            errors.push(format!("{source} hypervisorParity entries must be objects"));
            continue;
        };
        let label = object
            .get("platform")
            .and_then(Value::as_str)
            .unwrap_or("(missing platform)");
        let actual_keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
        let unexpected: Vec<&str> = actual_keys.difference(&expected_keys).copied().collect();
        let missing: Vec<&str> = expected_keys.difference(&actual_keys).copied().collect();
        if !unexpected.is_empty() {
            errors.push(format!(
                "{source} hypervisorParity {label} unexpected keys: {}",
                unexpected.join(", ")
            ));
        }
        if !missing.is_empty() {
            errors.push(format!(
                "{source} hypervisorParity {label} missing keys: {}",
                missing.join(", ")
            ));
        }
    }
}

fn validate_hypervisor_parity(
    values: Option<Vec<HypervisorParity>>,
    source: &str,
    errors: &mut Vec<String>,
) {
    let Some(values) = values else {
        errors.push(format!("{source} hypervisorParity must be non-empty array"));
        return;
    };
    if values.is_empty() {
        errors.push(format!("{source} hypervisorParity must be non-empty array"));
        return;
    }

    let platforms: Vec<String> = values.iter().map(|entry| entry.platform.clone()).collect();
    let expected_platforms: BTreeSet<String> = REQUIRED_HYPERVISOR_PARITY
        .iter()
        .map(|(platform, _)| platform.to_string())
        .collect();
    let actual_platforms: BTreeSet<String> = platforms.iter().cloned().collect();
    let missing: Vec<String> = expected_platforms
        .difference(&actual_platforms)
        .cloned()
        .collect();
    let unexpected: Vec<String> = actual_platforms
        .difference(&expected_platforms)
        .cloned()
        .collect();
    if !missing.is_empty() {
        errors.push(format!(
            "{source} hypervisorParity missing platforms: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "{source} hypervisorParity unexpected platforms: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        platforms.len() == actual_platforms.len(),
        errors,
        &format!("{source} hypervisorParity platforms must be unique"),
    );

    for (expected_platform, expected_summary) in REQUIRED_HYPERVISOR_PARITY {
        let Some(entry) = values
            .iter()
            .find(|candidate| candidate.platform == *expected_platform)
        else {
            continue;
        };
        expect(
            entry.platform == *expected_platform,
            errors,
            &format!("{source} hypervisorParity {expected_platform} platform must match"),
        );
        expect(
            entry.dry_run_summary == *expected_summary,
            errors,
            &format!("{source} hypervisorParity {expected_platform} dryRunSummary must match"),
        );
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = catalog
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let rule_ids: Vec<String> = rules
        .iter()
        .filter_map(|rule| value_str_direct(rule, "id").map(str::to_string))
        .collect();
    let expected: BTreeSet<String> = REQUIRED_RULES
        .iter()
        .map(|rule| rule.id.to_string())
        .collect();
    let actual: BTreeSet<String> = rule_ids.iter().cloned().collect();
    let missing: Vec<String> = expected.difference(&actual).cloned().collect();
    let unexpected: Vec<String> = actual.difference(&expected).cloned().collect();
    if !missing.is_empty() {
        errors.push(format!(
            "application environment deployment missing rules: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "application environment deployment unexpected rules: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        rule_ids.len() == actual.len(),
        errors,
        "application environment deployment rule IDs must be unique",
    );
    validate_rule_detail_uniqueness(
        &catalog_rules(catalog),
        "application environment deployment rule details",
        errors,
    );

    let expected_rule_keys: BTreeSet<&str> = RULE_KEYS.iter().copied().collect();
    for rule in &rules {
        let label = value_str_direct(rule, "id").unwrap_or("(missing id)");
        let Some(object) = rule.as_object() else {
            errors.push(format!(
                "application environment deployment rule {label} must be a mapping"
            ));
            continue;
        };
        let actual_rule_keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
        let unexpected_rule_keys: Vec<&str> = actual_rule_keys
            .difference(&expected_rule_keys)
            .copied()
            .collect();
        let missing_rule_keys: Vec<&str> = expected_rule_keys
            .difference(&actual_rule_keys)
            .copied()
            .collect();
        if !unexpected_rule_keys.is_empty() {
            errors.push(format!(
                "application environment deployment rule {label} unexpected rule keys: {}",
                unexpected_rule_keys.join(", ")
            ));
        }
        if !missing_rule_keys.is_empty() {
            errors.push(format!(
                "application environment deployment rule {label} missing rule keys: {}",
                missing_rule_keys.join(", ")
            ));
        }
    }

    for expected_rule in REQUIRED_RULES {
        let Some(rule) = rules
            .iter()
            .find(|candidate| value_str_direct(candidate, "id") == Some(expected_rule.id))
        else {
            continue;
        };
        expect(
            value_str_direct(rule, "decision") == Some(expected_rule.decision),
            errors,
            &format!(
                "application environment deployment rule {} decision must match",
                expected_rule.id
            ),
        );
        expect(
            value_str_direct(rule, "requirement") == Some(expected_rule.requirement),
            errors,
            &format!(
                "application environment deployment rule {} requirement must match",
                expected_rule.id
            ),
        );
        expect(
            value_str_direct(rule, "evidence") == Some(expected_rule.evidence),
            errors,
            &format!(
                "application environment deployment rule {} evidence must match",
                expected_rule.id
            ),
        );
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = csharp_without_comments(program);
    let Some(block) = endpoint_block(&uncommented_program, errors) else {
        return;
    };

    validate_program_text_terms(&block, PROGRAM_PATH, errors);
    expect(
        exact_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static-seed source",
    );
    expect(
        exact_string_assignment(&block, "deploymentMode", "dry-run-plan"),
        errors,
        "API must keep dry-run-plan mode",
    );
    expect(
        exact_endpoint_assignment(&block, "dryRunRequired", "true"),
        errors,
        "API must require dry-run",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            exact_endpoint_assignment(&block, field, "false"),
            errors,
            &format!("API must keep {field} disabled"),
        );
    }
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_endpoint_assignment(&block, field, variable),
            errors,
            &format!("API must bind {field} to {variable}"),
        );
        validate_api_array(
            field,
            csharp_array_values(&uncommented_program, variable),
            string_array(catalog.get(*field)),
            errors,
        );
    }
    for field in ENDPOINT_INLINE_ARRAYS {
        if endpoint_assignment_count(&block, field) != 1 {
            errors.push(format!("API {field} must be declared once"));
        }
        validate_api_array(
            field,
            endpoint_inline_array_values(&block, field),
            string_array(catalog.get(*field)),
            errors,
        );
    }
    validate_hypervisor_parity(
        endpoint_object_array_values(&block, "hypervisorParity", "API", errors),
        "API",
        errors,
    );
    validate_api_rules(&block, catalog, errors);
    validate_endpoint_field_names(&block, errors);
    validate_no_unsafe_true_flags(&block, errors);
}

fn validate_api_array(
    field: &str,
    values: Option<Vec<String>>,
    catalog_values: Vec<String>,
    errors: &mut Vec<String>,
) {
    let Some(values) = values else {
        errors.push(format!("API missing {field} array"));
        return;
    };
    let catalog_set: BTreeSet<String> = catalog_values.iter().cloned().collect();
    let value_set: BTreeSet<String> = values.iter().cloned().collect();
    let missing: Vec<String> = catalog_set.difference(&value_set).cloned().collect();
    let unexpected: Vec<String> = value_set.difference(&catalog_set).cloned().collect();
    if !missing.is_empty() {
        errors.push(format!(
            "API {field} missing values: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "API {field} unexpected values: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        values.len() == value_set.len(),
        errors,
        &format!("API {field} values must be unique"),
    );
    for value in values {
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "API {field} contains prohibited application environment deployment value {value}"
            ));
        }
    }
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let catalog_rules = catalog_rules(catalog);
    let api_rules = api_rules(block);
    let catalog_ids: Vec<String> = catalog_rules.iter().map(|rule| rule.id.clone()).collect();
    let api_ids: Vec<String> = api_rules.iter().map(|rule| rule.id.clone()).collect();
    let catalog_set: BTreeSet<String> = catalog_ids.iter().cloned().collect();
    let api_set: BTreeSet<String> = api_ids.iter().cloned().collect();
    for id in catalog_set.difference(&api_set) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_set.difference(&catalog_set) {
        errors.push(format!("API has unexpected API rule {id}"));
    }
    expect(
        api_ids.len() == api_set.len(),
        errors,
        "API rule IDs must be unique",
    );
    validate_rule_detail_uniqueness(&api_rules, "API rule details", errors);
    for catalog_rule in catalog_rules {
        let Some(api_rule) = api_rules.iter().find(|rule| rule.id == catalog_rule.id) else {
            continue;
        };
        expect(
            api_rule.decision == catalog_rule.decision,
            errors,
            &format!("API rule {} decision must match catalog", catalog_rule.id),
        );
        expect(
            api_rule.requirement == catalog_rule.requirement,
            errors,
            &format!(
                "API rule {} requirement must match catalog",
                catalog_rule.id
            ),
        );
        expect(
            api_rule.evidence == catalog_rule.evidence,
            errors,
            &format!("API rule {} evidence must match catalog", catalog_rule.id),
        );
    }
}

fn validate_rule_detail_uniqueness(rules: &[Rule], label: &str, errors: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    for rule in rules {
        if !seen.insert(rule_detail_key(rule)) {
            errors.push(format!("{label} must be unique"));
            return;
        }
    }
}

fn rule_detail_key(rule: &Rule) -> String {
    format!(
        "{}\u{1f}{}\u{1f}{}",
        rule.decision, rule.requirement, rule.evidence
    )
}

fn validate_docs_text(
    api_readme: &str,
    catalog_readme: &str,
    doc_readme: &str,
    doc: &str,
    errors: &mut Vec<String>,
) {
    expect(
        api_readme.contains(ENDPOINT),
        errors,
        "API README missing application environment deployment endpoint",
    );
    expect(
        catalog_readme.contains("application-environment-deployment-contract.yaml"),
        errors,
        "catalog README missing application environment deployment catalog",
    );
    expect(
        doc_readme.contains("application-environment-deployment.md"),
        errors,
        "workflow README missing application environment deployment doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "application environment deployment doc missing endpoint",
    );
    expect(
        api_readme.contains(
            "/api/workflows/application-environment/deployment-contract` | Static application environment deployment contract with VMware, Hyper-V, and Proxmox dry-run parity",
        ),
        errors,
        "API README missing application environment deployment hypervisor parity row",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "application environment deployment doc must prohibit provider calls",
    );
    expect(
        doc.contains("No worker execution."),
        errors,
        "application environment deployment doc must prohibit worker execution",
    );
    expect(
        doc.contains("VMware, Hyper-V, and Proxmox parity is limited to static dry-run summaries."),
        errors,
        "application environment deployment doc missing hypervisor parity phrase",
    );
    expect(
        doc.contains("No live VMware, Hyper-V, Proxmox, DNS/IPAM, certificate, firewall, monitoring, backup, or CMDB changes."),
        errors,
        "application environment deployment doc must prohibit live changes",
    );
    expect(
        doc.contains("No raw DNS records, host identifiers, FQDNs, IP addresses, firewall rules, CMDB rows, recipient data, credentials, or provider payloads."),
        errors,
        "application environment deployment doc must prohibit raw environment data",
    );
    expect(
        doc.contains("static application environment deployment summaries only"),
        errors,
        "application environment deployment doc must require static summaries",
    );
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> Option<String> {
    let routes = mapget_routes(program);
    let matching: Vec<&MapRoute> = routes
        .iter()
        .filter(|route| route.route == ENDPOINT)
        .collect();
    if matching.is_empty() {
        errors.push("API missing application environment deployment endpoint".to_string());
        return None;
    }
    if matching.len() > 1 {
        errors.push(
            "API must expose exactly one application environment deployment endpoint".to_string(),
        );
    }
    let start = matching[0].start;
    let end = routes
        .iter()
        .find(|route| route.start > start)
        .map_or(program.len(), |route| route.start);
    Some(program[start..end].to_string())
}

fn mapget_routes(program: &str) -> Vec<MapRoute> {
    let mut routes = Vec::new();
    for start in line_start_indexes(program) {
        let line = program[start..].lines().next().unwrap_or_default();
        let compact = compact_whitespace(line);
        let prefix = "app.MapGet(\"";
        let Some(rest) = compact.strip_prefix(prefix) else {
            continue;
        };
        let Some(end) = rest.find('"') else {
            continue;
        };
        routes.push(MapRoute {
            start,
            route: rest[..end].to_string(),
        });
    }
    routes
}

fn exact_endpoint_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = {value},");
    endpoint_assignment_count(block, field) == 1
        && block.lines().any(|line| line.trim() == expected)
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = \"{value}\",");
    endpoint_assignment_count(block, field) == 1
        && block.lines().any(|line| line.trim() == expected)
}

fn endpoint_assignment_count(block: &str, field: &str) -> usize {
    let marker = format!("{field} =");
    block
        .lines()
        .filter(|line| line.trim_start().starts_with(&marker))
        .count()
}

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    let marker = format!("var {variable} = new[]");
    let start = program.find(&marker)?;
    let open = program[start..].find('{').map(|index| start + index)?;
    let close = program[open..].find("};").map(|index| open + index)?;
    Some(csharp_literal_terms(&program[open + 1..close]))
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    if endpoint_assignment_count(block, field) != 1 {
        return None;
    }
    let marker = format!("{field} = new[]");
    let start = block.find(&marker)?;
    let open = block[start..].find('{').map(|index| start + index)?;
    let close = block[open..].find('}').map(|index| open + index)?;
    Some(csharp_literal_terms(&block[open + 1..close]))
}

fn endpoint_object_array_values(
    block: &str,
    field: &str,
    source: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<HypervisorParity>> {
    if endpoint_assignment_count(block, field) != 1 {
        errors.push(format!("{source} {field} must be declared once"));
        return None;
    }
    let (_, body) = object_array_span(block, field)?;
    let mut entries = Vec::new();
    let expected_keys: BTreeSet<&str> = ["platform", "dryRunSummary"].into_iter().collect();
    let mut offset = 0;
    while let Some(relative) = body[offset..].find("new") {
        let start = offset + relative;
        let open = skip_ascii_whitespace(body, start + "new".len());
        if !body[open..].starts_with('{') {
            offset = start + "new".len();
            continue;
        }
        let close = matching_brace(body, open)?;
        let item = &body[open + 1..close];
        let actual_keys: BTreeSet<String> = endpoint_assignment_fields(item).into_iter().collect();
        let actual_key_refs: BTreeSet<&str> = actual_keys.iter().map(String::as_str).collect();
        let label =
            quoted_assignment(item, "platform").unwrap_or_else(|| "(missing platform)".to_string());
        let unexpected: Vec<&str> = actual_key_refs
            .difference(&expected_keys)
            .copied()
            .collect();
        let missing: Vec<&str> = expected_keys
            .difference(&actual_key_refs)
            .copied()
            .collect();
        if !unexpected.is_empty() {
            errors.push(format!(
                "{source} hypervisorParity {label} unexpected keys: {}",
                unexpected.join(", ")
            ));
        }
        if !missing.is_empty() {
            errors.push(format!(
                "{source} hypervisorParity {label} missing keys: {}",
                missing.join(", ")
            ));
        }
        if let (Some(platform), Some(dry_run_summary)) = (
            quoted_assignment(item, "platform"),
            quoted_assignment(item, "dryRunSummary"),
        ) {
            entries.push(HypervisorParity {
                platform,
                dry_run_summary,
            });
        }
        offset = close + 1;
    }
    Some(entries)
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut offset = 0;
    while let Some(relative) = text[offset..].find('"') {
        let start = offset + relative;
        let Some((value, end)) = quoted_string_at(text, start) else {
            break;
        };
        values.push(value);
        offset = end;
    }
    values
}

fn csharp_literal_terms(text: &str) -> Vec<String> {
    let mut values = csharp_string_literals(text);
    values.extend(csharp_concatenated_string_literals(text));
    values.sort();
    values.dedup();
    values
}

fn csharp_concatenated_string_literals(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut index = 0;
    while let Some(relative) = text[index..].find('"') {
        let quote = index + relative;
        let Some((literal, next_index)) = quoted_string_at(text, quote) else {
            break;
        };
        let mut parts = vec![literal];
        let mut cursor = next_index;
        loop {
            cursor = skip_ascii_whitespace(text, cursor);
            if cursor >= text.len() || !text[cursor..].starts_with('+') {
                break;
            }
            cursor = skip_ascii_whitespace(text, cursor + 1);
            let Some((next_literal, next_cursor)) = quoted_string_at(text, cursor) else {
                break;
            };
            parts.push(next_literal);
            cursor = next_cursor;
        }
        if parts.len() > 1 {
            values.push(parts.join(""));
        }
        index = next_index;
    }
    values
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let field_scan_block = strip_endpoint_object_array(block, "hypervisorParity");
    for field in endpoint_assignment_fields(&field_scan_block) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has unexpected application environment deployment field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited application environment deployment field {field}"
            ));
        }
    }
}

fn endpoint_assignment_fields(block: &str) -> Vec<String> {
    let bytes = block.as_bytes();
    let mut fields = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_alphabetic() || bytes[index] == b'_' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            let end = index;
            let next = skip_ascii_whitespace(block, index);
            if next < bytes.len() && bytes[next] == b'=' {
                fields.push(block[start..end].to_string());
            }
        } else {
            index += 1;
        }
    }
    fields
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for line in block.lines() {
        let trimmed = line.trim();
        let Some((field, value)) = trimmed.split_once('=') else {
            continue;
        };
        if value.trim() != "true," {
            continue;
        }
        let field = field.trim();
        if field == "dryRunRequired" {
            continue;
        }
        if contains_any_case(
            field,
            &[
                "live",
                "provider",
                "worker",
                "raw",
                "payload",
                "identifier",
                "credential",
                "recipient",
                "deployment",
                "access",
                "deletion",
                "private",
            ],
        ) {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn catalog_rules(catalog: &Value) -> Vec<Rule> {
    catalog
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|rule| {
            Some(Rule {
                id: value_str_direct(rule, "id")?.to_string(),
                decision: value_str_direct(rule, "decision")?.to_string(),
                requirement: value_str_direct(rule, "requirement")?.to_string(),
                evidence: value_str_direct(rule, "evidence")?.to_string(),
            })
        })
        .collect()
}

fn api_rules(block: &str) -> Vec<Rule> {
    let mut rules = Vec::new();
    let mut offset = 0;
    while let Some(relative) = block[offset..].find("new") {
        let start = offset + relative;
        let open = skip_ascii_whitespace(block, start + "new".len());
        if !block[open..].starts_with('{') {
            offset = start + "new".len();
            continue;
        }
        let first_field = skip_ascii_whitespace(block, open + 1);
        if !block[first_field..].starts_with("id") {
            offset = open + 1;
            continue;
        }
        let Some(close) = matching_brace(block, open) else {
            break;
        };
        let body = &block[open + 1..close];
        if let (Some(id), Some(decision), Some(requirement), Some(evidence)) = (
            quoted_assignment(body, "id"),
            quoted_assignment(body, "decision"),
            quoted_assignment(body, "requirement"),
            quoted_assignment(body, "evidence"),
        ) {
            rules.push(Rule {
                id,
                decision,
                requirement,
                evidence,
            });
        }
        offset = close + 1;
    }
    rules
}

fn quoted_assignment(body: &str, field: &str) -> Option<String> {
    let marker = format!("{field} = ");
    let start = body.find(&marker)? + marker.len();
    let quote = skip_ascii_whitespace(body, start);
    let (value, _) = quoted_string_at(body, quote)?;
    Some(value)
}

fn object_array_span<'a>(block: &'a str, field: &str) -> Option<((usize, usize), &'a str)> {
    let marker = format!("{field} = new[]");
    let start = block.find(&marker)?;
    let open = block[start..].find('{').map(|index| start + index)?;
    let close = matching_brace(block, open)?;
    Some(((start, close + 1), &block[open + 1..close]))
}

fn strip_endpoint_object_array(block: &str, field: &str) -> String {
    let Some(((start, end), _)) = object_array_span(block, field) else {
        return block.to_string();
    };
    let mut stripped = String::with_capacity(block.len());
    stripped.push_str(&block[..start]);
    stripped.push_str(field);
    stripped.push_str(" = new[] { }");
    stripped.push_str(&block[end..]);
    stripped
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let child_path = format!("{path}.{key}");
                if prohibited_field(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited application environment deployment field"
                    ));
                }
                scan_prohibited_value(child, &child_path, errors);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                scan_prohibited_value(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => {
            if whole_file_text(path, text) {
                if path.ends_with(PROGRAM_PATH) {
                    let uncommented = csharp_without_comments(text);
                    if let Some(block) = endpoint_block(&uncommented, &mut Vec::new()) {
                        validate_program_text_terms(&block, path, errors);
                    }
                    return;
                }
                if application_environment_text_path(path) {
                    validate_text_terms(text, path, errors);
                    return;
                }
                if contains_prohibited_value(text) {
                    errors.push(format!("{path} contains prohibited value"));
                }
                return;
            }
            if safe_text_value(text) {
                return;
            }
            if contains_prohibited_value(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
            if prohibited_field(text) {
                errors.push(format!(
                    "{path} contains prohibited application environment deployment value {text}"
                ));
            }
        }
        _ => {}
    }
}

fn validate_text_terms(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        if !application_environment_text_line(path, line) || safe_text_line(line) {
            continue;
        }
        scan_plain_text_line(line, &format!("{path}:{}", index + 1), errors);
    }
}

fn validate_program_text_terms(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        let label = format!("{path}:{}", index + 1);
        for literal in csharp_literal_terms(line) {
            if safe_text_value(&literal) {
                continue;
            }
            scan_plain_text_line(&literal, &label, errors);
        }
        for term in identifier_terms(&csharp_without_string_literals(line)) {
            if prohibited_field(&term) {
                errors.push(format!(
                    "{label} contains prohibited application environment deployment field {term}"
                ));
            }
        }
    }
}

fn scan_plain_text_line(text: &str, path: &str, errors: &mut Vec<String>) {
    if contains_prohibited_value(text) {
        errors.push(format!("{path} contains prohibited value"));
    }
    for term in identifier_terms(text) {
        if prohibited_field(&term) {
            errors.push(format!(
                "{path} contains prohibited application environment deployment field {term}"
            ));
        }
    }
}

fn identifier_terms(text: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_alphabetic() {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric()
                    || bytes[index] == b'_'
                    || bytes[index] == b'-')
            {
                index += 1;
            }
            terms.push(text[start..index].to_string());
        } else {
            index += 1;
        }
    }
    terms
}

fn safe_text_line(line: &str) -> bool {
    let stripped = line.trim();
    let bullet_value = stripped.strip_prefix("- ").unwrap_or(stripped);
    let id_value = stripped.strip_prefix("- id: ").unwrap_or(stripped);
    let requirement_value = stripped.strip_prefix("requirement: ").unwrap_or(stripped);
    stripped.starts_with("# Application environment deployment seed data only.")
        || (stripped.starts_with("Endpoint:") && stripped.contains(ENDPOINT))
        || stripped.starts_with("- No ")
        || stripped.starts_with("| `/api/workflows/application-environment/deployment-contract` | Static application environment deployment contract with VMware, Hyper-V, and Proxmox dry-run parity")
        || safe_text_value(bullet_value)
        || safe_text_value(id_value)
        || safe_text_value(requirement_value)
        || (!csharp_string_literals(stripped).is_empty()
            && csharp_string_literals(stripped)
                .iter()
                .all(|value| safe_text_value(value)))
}

fn application_environment_text_path(path: &str) -> bool {
    [
        CATALOG_PATH,
        PROGRAM_PATH,
        DOC_PATH,
        API_README_PATH,
        CATALOG_README_PATH,
        DOC_README_PATH,
    ]
    .iter()
    .any(|text_path| path.ends_with(text_path))
}

fn application_environment_text_line(path: &str, line: &str) -> bool {
    path.ends_with(PROGRAM_PATH)
        || path.ends_with(CATALOG_PATH)
        || path.ends_with(DOC_PATH)
        || ((path.ends_with(API_README_PATH)
            || path.ends_with(CATALOG_README_PATH)
            || path.ends_with(DOC_README_PATH))
            && (line.contains(ENDPOINT)
                || contains_any_case(line, &["application environment deployment"])))
}

fn safe_text_value(value: &str) -> bool {
    [
        REQUIRED_PLANS,
        REQUIRED_TIERS,
        REQUIRED_INPUTS,
        REQUIRED_GUARDS,
        REQUIRED_PLAN_SECTIONS,
        REQUIRED_HYPERVISORS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        REQUIRED_DISABLED_FIELDS,
        REQUIRED_CATALOG_KEYS,
        ENDPOINT_BINDING_VARIABLES,
        &[
            "draft",
            "static-seed",
            "dry-run-plan",
            "block",
            "true",
            "false",
        ],
    ]
    .into_iter()
    .flatten()
    .any(|safe| *safe == value)
        || REQUIRED_HYPERVISOR_PARITY
            .iter()
            .any(|(platform, summary)| *platform == value || *summary == value)
        || REQUIRED_RULES.iter().any(|rule| {
            rule.id == value
                || rule.decision == value
                || rule.requirement == value
                || rule.evidence == value
        })
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize(value);
    if safe_normalized_value(&normalized) {
        return false;
    }
    PROHIBITED_FIELD_ALIASES.contains(&normalized.as_str())
        || PROHIBITED_FIELD_TOKENS
            .iter()
            .any(|token| normalized.contains(token))
}

fn safe_normalized_value(normalized: &str) -> bool {
    [
        REQUIRED_PLANS,
        REQUIRED_TIERS,
        REQUIRED_INPUTS,
        REQUIRED_GUARDS,
        REQUIRED_PLAN_SECTIONS,
        REQUIRED_HYPERVISORS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        REQUIRED_DISABLED_FIELDS,
        REQUIRED_CATALOG_KEYS,
        ENDPOINT_BINDING_VARIABLES,
        &[
            "draft",
            "static-seed",
            "dry-run-plan",
            "block",
            "true",
            "false",
        ],
    ]
    .into_iter()
    .flatten()
    .any(|safe| normalize(safe) == normalized)
        || REQUIRED_HYPERVISOR_PARITY
            .iter()
            .any(|(platform, summary)| {
                normalize(platform) == normalized || normalize(summary) == normalized
            })
        || REQUIRED_RULES.iter().any(|rule| {
            normalize(rule.id) == normalized
                || normalize(rule.decision) == normalized
                || normalize(rule.requirement) == normalized
                || normalize(rule.evidence) == normalized
        })
}

fn contains_prohibited_value(value: &str) -> bool {
    contains_aws_access_key(value)
        || contains_private_key_marker(value)
        || contains_url(value)
        || contains_ipv4(value)
        || contains_ipv6_like(value)
        || contains_uuid(value)
        || contains_email(value)
        || contains_fqdn_like(value)
        || contains_jwt_like(value)
        || contains_vault_token_like(value)
        || contains_sensitive_assignment(value)
}

fn contains_aws_access_key(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.windows(4).enumerate().any(|(index, window)| {
        window.eq_ignore_ascii_case(b"AKIA")
            && bytes
                .get(index + 4..index + 20)
                .is_some_and(|tail| tail.iter().all(u8::is_ascii_alphanumeric))
    })
}

fn contains_private_key_marker(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    upper.contains("-----BEGIN ") && upper.contains("PRIVATE KEY-----")
}

fn contains_url(value: &str) -> bool {
    value.find("://").is_some_and(|index| {
        index > 0
            && value[..index]
                .chars()
                .rev()
                .take_while(|character| {
                    character.is_ascii_alphanumeric() || "+.-".contains(*character)
                })
                .count()
                > 0
    })
}

fn contains_ipv4(value: &str) -> bool {
    value
        .split(|character: char| !character.is_ascii_digit() && character != '.')
        .filter(|candidate| candidate.matches('.').count() == 3)
        .any(|candidate| {
            let octets = candidate
                .split('.')
                .filter_map(|part| part.parse::<u8>().ok())
                .collect::<Vec<u8>>();
            octets.len() == 4
        })
}

fn contains_ipv6_like(value: &str) -> bool {
    value
        .split(|character: char| {
            !(character.is_ascii_hexdigit() || character == ':' || character == '.')
        })
        .any(|candidate| {
            candidate.contains(':')
                && candidate.matches(':').count() >= 2
                && candidate.chars().all(|character| {
                    character.is_ascii_hexdigit() || character == ':' || character == '.'
                })
        })
}

fn contains_uuid(value: &str) -> bool {
    value
        .split(|character: char| !character.is_ascii_hexdigit() && character != '-')
        .any(|candidate| {
            let parts = candidate.split('-').collect::<Vec<&str>>();
            parts.len() == 5
                && [8, 4, 4, 4, 12]
                    .iter()
                    .zip(parts.iter())
                    .all(|(length, part)| {
                        part.len() == *length
                            && part.chars().all(|character| character.is_ascii_hexdigit())
                    })
        })
}

fn contains_email(value: &str) -> bool {
    value.split_whitespace().any(|candidate| {
        let candidate = candidate.trim_matches(|character: char| {
            !(character.is_ascii_alphanumeric()
                || matches!(character, '@' | '.' | '_' | '%' | '+' | '-'))
        });
        let Some((local, domain)) = candidate.split_once('@') else {
            return false;
        };
        !local.is_empty()
            && domain.contains('.')
            && domain.chars().all(|character| {
                character.is_ascii_alphanumeric() || character == '.' || character == '-'
            })
    })
}

fn contains_fqdn_like(value: &str) -> bool {
    value.split_whitespace().any(|candidate| {
        let candidate = candidate.trim_matches(|character: char| {
            !(character.is_ascii_alphanumeric() || character == '.' || character == '-')
        });
        if candidate.ends_with(".md")
            || candidate.ends_with(".yaml")
            || candidate.ends_with(".yml")
            || candidate.ends_with(".cs")
            || candidate.ends_with(".json")
            || candidate.ends_with(".sh")
            || candidate.ends_with(".txt")
        {
            return false;
        }
        let labels: Vec<&str> = candidate.split('.').collect();
        labels.len() >= 2
            && labels.iter().all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric() || character == '-')
            })
            && labels.last().is_some_and(|suffix| {
                suffix.len() >= 2 && suffix.chars().all(|ch| ch.is_ascii_alphabetic())
            })
    })
}

fn contains_jwt_like(value: &str) -> bool {
    value.split_whitespace().any(|candidate| {
        let parts = candidate.split('.').collect::<Vec<&str>>();
        parts.len() == 3
            && parts.iter().all(|part| {
                part.len() >= 12
                    && part.chars().all(|character| {
                        character.is_ascii_alphanumeric() || character == '_' || character == '-'
                    })
            })
    })
}

fn contains_vault_token_like(value: &str) -> bool {
    value.split_whitespace().any(|candidate| {
        ["hvs.", "hvb.", "s."].iter().any(|prefix| {
            candidate.to_ascii_lowercase().starts_with(prefix)
                && candidate.len() >= prefix.len() + 16
        })
    })
}

fn contains_sensitive_assignment(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
        "token",
    ]
    .iter()
    .any(|key| {
        lower.find(key).is_some_and(|index| {
            lower[index + key.len()..]
                .trim_start()
                .chars()
                .next()
                .is_some_and(|character| character == ':' || character == '=')
        })
    })
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn csharp_without_comments(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut in_block = false;
    let mut in_line = false;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        if in_string {
            output.push(bytes[index] as char);
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if in_block {
            if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                output.push(' ');
                output.push(' ');
                index += 2;
                in_block = false;
            } else {
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
            continue;
        }
        if in_line {
            output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
            if bytes[index] == b'\n' {
                in_line = false;
            }
            index += 1;
            continue;
        }
        if bytes[index] == b'"' {
            in_string = true;
            output.push('"');
            index += 1;
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            output.push(' ');
            output.push(' ');
            index += 2;
            in_block = true;
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            output.push(' ');
            output.push(' ');
            index += 2;
            in_line = true;
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    output
}

fn csharp_without_string_literals(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            output.push(' ');
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
            output.push(' ');
        } else {
            output.push(byte as char);
        }
        index += 1;
    }
    output
}

fn matching_brace(text: &str, open: usize) -> Option<usize> {
    if !text[open..].starts_with('{') {
        return None;
    }
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut index = open;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
        } else if byte == b'{' {
            depth += 1;
        } else if byte == b'}' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(index);
            }
        }
        index += 1;
    }
    None
}

fn value_i64(value: &Value, key: &str) -> Option<i64> {
    value.get(key).and_then(Value::as_i64)
}

fn value_bool(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn value_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn value_str_direct<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.as_object()?.get(key)?.as_str()
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn quoted_string_at(text: &str, quote: usize) -> Option<(String, usize)> {
    if quote >= text.len() || !text[quote..].starts_with('"') {
        return None;
    }
    let bytes = text.as_bytes();
    let mut value = String::new();
    let mut index = quote + 1;
    while index < text.len() {
        let byte = bytes[index];
        if byte == b'"' {
            return Some((value, index + 1));
        }
        if byte == b'\\' {
            index += 1;
            if index >= text.len() {
                return None;
            }
            match bytes[index] as char {
                'u' => {
                    let end = index + 5;
                    let codepoint = parse_hex_char(text.get(index + 1..end)?)?;
                    value.push(codepoint);
                    index = end;
                }
                'U' => {
                    let end = index + 9;
                    let codepoint = parse_hex_char(text.get(index + 1..end)?)?;
                    value.push(codepoint);
                    index = end;
                }
                'x' => {
                    let mut end = index + 1;
                    while end < text.len()
                        && end < index + 5
                        && text.as_bytes()[end].is_ascii_hexdigit()
                    {
                        end += 1;
                    }
                    if end == index + 1 {
                        value.push('x');
                        index += 1;
                    } else {
                        let codepoint = parse_hex_char(text.get(index + 1..end)?)?;
                        value.push(codepoint);
                        index = end;
                    }
                }
                '"' => {
                    value.push('"');
                    index += 1;
                }
                '\'' => {
                    value.push('\'');
                    index += 1;
                }
                '\\' => {
                    value.push('\\');
                    index += 1;
                }
                '0' => {
                    value.push('\0');
                    index += 1;
                }
                'a' => {
                    value.push('\u{0007}');
                    index += 1;
                }
                'b' => {
                    value.push('\u{0008}');
                    index += 1;
                }
                'f' => {
                    value.push('\u{000c}');
                    index += 1;
                }
                'n' => {
                    value.push('\n');
                    index += 1;
                }
                'r' => {
                    value.push('\r');
                    index += 1;
                }
                't' => {
                    value.push('\t');
                    index += 1;
                }
                'v' => {
                    value.push('\u{000b}');
                    index += 1;
                }
                other => {
                    value.push(other);
                    index += 1;
                }
            }
            continue;
        }
        let character = text[index..].chars().next()?;
        value.push(character);
        index += character.len_utf8();
    }
    None
}

fn parse_hex_char(text: &str) -> Option<char> {
    let codepoint = u32::from_str_radix(text, 16).ok()?;
    char::from_u32(codepoint)
}

fn skip_ascii_whitespace(text: &str, mut index: usize) -> usize {
    while index < text.len() && text.as_bytes()[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn line_start_indexes(text: &str) -> Vec<usize> {
    let mut indexes = vec![0];
    indexes.extend(
        text.match_indices('\n')
            .map(|(index, _)| index + 1)
            .filter(|index| *index < text.len()),
    );
    indexes
}

fn compact_whitespace(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn normalize(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn contains_any_case(value: &str, needles: &[&str]) -> bool {
    let lower = value.to_ascii_lowercase();
    needles.iter().any(|needle| lower.contains(needle))
}

fn expect(condition: bool, errors: &mut Vec<String>, message: &str) {
    if !condition {
        errors.push(message.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapget_routes_allow_whitespace_and_detect_duplicates() {
        let program = format!(
            "app . MapGet (\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        let mut errors = Vec::new();

        let _ = endpoint_block(&program, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("exactly one") && error.contains("endpoint")));
    }

    #[test]
    fn prohibited_value_scan_rejects_embedded_url() {
        let mut errors = Vec::new();

        scan_prohibited_value(
            &Value::String("safe text with https://deployment.invalid/workflow".to_string()),
            "synthetic",
            &mut errors,
        );

        assert!(errors
            .iter()
            .any(|error| error.contains("prohibited value")));
    }

    #[test]
    fn comment_stripper_preserves_url_inside_string_literal() {
        let text = r#"operatorNote = "https://deployment.invalid/workflow", // comment"#;
        let stripped = csharp_without_comments(text);

        assert!(stripped.contains("https://deployment.invalid/workflow"));
        assert!(!stripped.contains("comment"));
    }

    #[test]
    fn commented_endpoint_decoy_is_ignored() {
        let program = format!(
            "// app . MapGet (\"{ENDPOINT}\", () => Results.Json(new {{ source = \"runtime-seed\" }}));\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        let uncommented = csharp_without_comments(&program);
        let mut errors = Vec::new();

        let block = endpoint_block(&uncommented, &mut errors);

        assert!(block.is_some());
        assert!(errors.is_empty());
    }

    #[test]
    fn source_assignment_spoof_is_not_exact_assignment() {
        let block = "source = \"static-seed\",\nsource = \"runtime-seed\",\n";

        assert_eq!(endpoint_assignment_count(block, "source"), 2);
        assert!(!exact_string_assignment(block, "source", "static-seed"));
    }

    #[test]
    fn quoted_scanning_reconstructs_escaped_and_fragmented_literals() {
        let terms = csharp_literal_terms(r#""access\u0054oken", "access" + "Token""#);

        assert!(terms.iter().any(|term| term == "accessToken"));
    }

    #[test]
    fn endpoint_property_identifier_is_rejected() {
        let mut errors = Vec::new();

        validate_endpoint_field_names("dnsRecord = \"redacted\",", &mut errors);

        assert!(errors.iter().any(|error| error.contains("dnsRecord")));
    }

    #[test]
    fn unsafe_provider_true_flag_is_rejected_without_blocking_dry_run() {
        let mut errors = Vec::new();

        validate_no_unsafe_true_flags(
            "providerCallsEnabled = true,\ndryRunRequired = true,",
            &mut errors,
        );

        assert!(errors
            .iter()
            .any(|error| error.contains("providerCallsEnabled")));
        assert!(!errors.iter().any(|error| error.contains("dryRunRequired")));
    }

    #[test]
    fn unsafe_provider_identifying_literal_is_rejected() {
        let mut errors = Vec::new();

        validate_program_text_terms(
            "operatorNote = \"providerPayload\",",
            PROGRAM_PATH,
            &mut errors,
        );

        assert!(errors.iter().any(|error| error.contains("providerPayload")));
    }

    #[test]
    fn catalog_rule_details_must_be_unique() {
        let mut catalog = catalog_with_required_rules();
        let rules = catalog
            .get_mut("rules")
            .and_then(Value::as_array_mut)
            .expect("rules array");
        let decision = rules[0]["decision"].clone();
        let requirement = rules[0]["requirement"].clone();
        let evidence = rules[0]["evidence"].clone();
        rules[1]["decision"] = decision;
        rules[1]["requirement"] = requirement;
        rules[1]["evidence"] = evidence;
        let mut errors = Vec::new();

        validate_required_rules(&catalog, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("rule details") && error.contains("unique")));
    }

    #[test]
    fn api_rule_details_must_be_unique() {
        let catalog = catalog_with_required_rules();
        let mut api_rules = REQUIRED_RULES
            .iter()
            .map(|rule| (rule.id, rule.decision, rule.requirement, rule.evidence))
            .collect::<Vec<_>>();
        api_rules[1].1 = api_rules[0].1;
        api_rules[1].2 = api_rules[0].2;
        api_rules[1].3 = api_rules[0].3;
        let block = format!(
            "rules = new[] {{\n{}\n}}",
            api_rules
                .iter()
                .map(|(id, decision, requirement, evidence)| format!(
                    "new {{ id = \"{id}\", decision = \"{decision}\", requirement = \"{requirement}\", evidence = \"{evidence}\" }}"
                ))
                .collect::<Vec<_>>()
                .join(",\n")
        );
        let mut errors = Vec::new();

        validate_api_rules(&block, &catalog, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("API rule details") && error.contains("unique")));
    }

    fn catalog_with_required_rules() -> Value {
        let rules = REQUIRED_RULES
            .iter()
            .map(|rule| {
                serde_json::json!({
                    "id": rule.id,
                    "decision": rule.decision,
                    "requirement": rule.requirement,
                    "evidence": rule.evidence,
                })
            })
            .collect::<Vec<_>>();
        serde_json::json!({ "rules": rules })
    }
}
