use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const ENDPOINT: &str = "/api/workflows/server-lifecycle/dry-run-contract";
const REQUIRED_WORKFLOWS: &[&str] = &["windows-server-deployment", "linux-server-deployment"];
const REQUIRED_HYPERVISORS: &[&str] = &["VMware", "Hyper-V", "Proxmox"];
const REQUIRED_LINUX_DISTRIBUTIONS: &[&str] = &[
    "sles",
    "rhel",
    "rocky-linux",
    "alma-linux",
    "ubuntu",
    "debian",
];
const REQUIRED_INPUTS: &[&str] = &[
    "businessPurpose",
    "requester",
    "owner",
    "site",
    "environment",
    "criticality",
    "hypervisorPlatform",
    "imageVersion",
    "vmSizing",
    "network",
    "backupPolicy",
    "monitoringProfile",
    "cmdbContext",
];
const REQUIRED_WINDOWS_INPUTS: &[&str] = &["ouPlacement", "customizationSpec", "domainJoinMode"];
const REQUIRED_LINUX_INPUTS: &[&str] = &["distribution", "baselineProfile", "cloudInitProfile"];
const REQUIRED_GUARDS: &[&str] = &[
    "request-preflight-ready",
    "capacity-admission-ready",
    "inventory-coverage-current",
    "approval-route-assigned",
    "evidence-redacted",
    "secret-reference-configured",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "placementPlan",
    "osCustomizationPlan",
    "backupPlan",
    "monitoringPlan",
    "cmdbUpdatePlan",
    "riskNotes",
    "rollbackNotes",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "missing-required-input",
    "stale-inventory",
    "capacity-not-approved",
    "backup-policy-missing",
    "monitoring-profile-missing",
    "cmdb-context-ambiguous",
    "unsupported-hypervisor",
    "live-hypervisor-execution-disabled",
    "live-execution-disabled",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Request payload summary",
    "Validation result",
    "Provider-safe plan",
    "Capacity check summary",
    "Policy assignments",
    "CMDB export package",
    "Evidence references",
];
const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-provider-execution",
        decision: "block",
        requirement: "The contract produces plans only and never executes VMware, Hyper-V, Proxmox, OS, backup, monitoring, or CMDB changes.",
        evidence: "Provider-safe plan",
    },
    RuleDetail {
        id: "dry-run-before-approval",
        decision: "block",
        requirement: "Approval cannot proceed until the dry-run plan has placement, OS, backup, monitoring, CMDB, risk, and rollback sections.",
        evidence: "Provider-safe plan",
    },
    RuleDetail {
        id: "current-inventory-required",
        decision: "block",
        requirement: "Stale or unknown inventory coverage blocks server lifecycle approval.",
        evidence: "Inventory snapshot",
    },
    RuleDetail {
        id: "protect-observe-publish-required",
        decision: "block",
        requirement: "Build plans must include backup, monitoring, and CMDB publication intent before approval.",
        evidence: "Policy assignments",
    },
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("supportedWorkflows", "serverLifecycleWorkflows"),
    (
        "supportedHypervisors",
        "serverLifecycleSupportedHypervisors",
    ),
    (
        "supportedLinuxDistributions",
        "serverLifecycleSupportedLinuxDistributions",
    ),
    ("requiredInputs", "serverLifecycleRequiredInputs"),
    ("requiredGuards", "serverLifecycleRequiredGuards"),
    ("planSections", "serverLifecyclePlanSections"),
    ("blockedReasons", "serverLifecycleBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("windowsAdditionalInputs", REQUIRED_WINDOWS_INPUTS),
    ("linuxAdditionalInputs", REQUIRED_LINUX_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveExecutionAllowed",
    "supportedWorkflows",
    "supportedHypervisors",
    "supportedLinuxDistributions",
    "requiredInputs",
    "windowsAdditionalInputs",
    "linuxAdditionalInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
];

#[derive(Debug, Deserialize)]
struct ServerLifecycleContext {
    catalog: Value,
    program: String,
    readme: String,
    doc: String,
}

#[derive(Debug, Deserialize)]
struct ProgramInput {
    program: String,
    catalog: Value,
}

#[derive(Debug, Deserialize)]
struct DocsInput {
    readme: String,
    doc: String,
}

#[derive(Debug, Deserialize)]
struct ProhibitedInput {
    value: Value,
    path: String,
}

struct RuleDetail {
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

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: ServerLifecycleContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid server lifecycle context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(&context.readme, &context.doc, &mut errors);
    scan_prohibited_value(
        &context.catalog,
        "catalog/server-lifecycle-dry-run-contract.yaml",
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.program),
        "api/Ryuki.Platform.Api/Program.cs",
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.readme),
        "api/Ryuki.Platform.Api/README.md",
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.doc),
        "docs/workflows/server-lifecycle-dry-run.md",
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid server lifecycle catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid server lifecycle program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid server lifecycle docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.readme, &payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid server lifecycle prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "server lifecycle dry-run version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "server lifecycle dry-run status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "server lifecycle dry-run source must be static-seed",
    );
    expect(
        bool_value(catalog, "dryRunRequired") == Some(true),
        errors,
        "server lifecycle dry-run must require dry-run",
    );
    expect(
        bool_value(catalog, "providerCallsEnabled") == Some(false),
        errors,
        "server lifecycle provider calls must be disabled",
    );
    expect(
        bool_value(catalog, "liveExecutionAllowed") == Some(false),
        errors,
        "server lifecycle live execution must be disabled",
    );
    validate_required_array(catalog, "supportedWorkflows", REQUIRED_WORKFLOWS, errors);
    validate_required_array(
        catalog,
        "supportedHypervisors",
        REQUIRED_HYPERVISORS,
        errors,
    );
    validate_required_array(
        catalog,
        "supportedLinuxDistributions",
        REQUIRED_LINUX_DISTRIBUTIONS,
        errors,
    );
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(
        catalog,
        "windowsAdditionalInputs",
        REQUIRED_WINDOWS_INPUTS,
        errors,
    );
    validate_required_array(
        catalog,
        "linuxAdditionalInputs",
        REQUIRED_LINUX_INPUTS,
        errors,
    );
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_rules(catalog_rules(catalog), "server lifecycle dry-run", errors);
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required: &[&str],
    errors: &mut Vec<String>,
) {
    let values = string_array(catalog, field);
    expect(
        !values.is_empty(),
        errors,
        format!("{field} must be non-empty array"),
    );
    let required_set: BTreeSet<&str> = required.iter().copied().collect();
    let value_set: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|item| !value_set.contains(item))
        .collect();
    let unexpected: Vec<&str> = values
        .iter()
        .map(String::as_str)
        .filter(|item| !required_set.contains(item))
        .collect();
    expect(
        missing.is_empty(),
        errors,
        format!("{field} missing values: {}", missing.join(", ")),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!("{field} unexpected values: {}", unexpected.join(", ")),
    );
    expect(
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        errors,
        format!("{field} values must be unique"),
    );
}

fn validate_rules(rules: Vec<Rule>, label: &str, errors: &mut Vec<String>) {
    let rule_ids: Vec<&str> = rules.iter().map(|rule| rule.id.as_str()).collect();
    let rule_details: Vec<(&str, &str, &str)> = rules
        .iter()
        .map(|rule| {
            (
                rule.decision.as_str(),
                rule.requirement.as_str(),
                rule.evidence.as_str(),
            )
        })
        .collect();
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        format!("{label} rule IDs must be unique"),
    );
    expect(
        rule_details.iter().collect::<BTreeSet<_>>().len() == rule_details.len(),
        errors,
        format!("{label} rule details must be unique"),
    );

    let expected_ids: BTreeSet<&str> = REQUIRED_RULES.iter().map(|rule| rule.id).collect();
    let actual_ids: BTreeSet<&str> = rule_ids.iter().copied().collect();
    let missing: Vec<&str> = REQUIRED_RULES
        .iter()
        .map(|rule| rule.id)
        .filter(|id| !actual_ids.contains(id))
        .collect();
    let unexpected: Vec<&str> = rule_ids
        .into_iter()
        .filter(|id| !expected_ids.contains(id))
        .collect();
    expect(
        missing.is_empty(),
        errors,
        format!("{label} missing rules: {}", missing.join(", ")),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!("{label} unexpected rules: {}", unexpected.join(", ")),
    );

    for expected_rule in REQUIRED_RULES {
        let Some(rule) = rules.iter().find(|rule| rule.id == expected_rule.id) else {
            continue;
        };
        expect(
            rule.decision == expected_rule.decision,
            errors,
            format!("{label} rule {} decision must match", expected_rule.id),
        );
        expect(
            rule.requirement == expected_rule.requirement,
            errors,
            format!("{label} rule {} requirement must match", expected_rule.id),
        );
        expect(
            rule.evidence == expected_rule.evidence,
            errors,
            format!("{label} rule {} evidence must match", expected_rule.id),
        );
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = strip_csharp_comments(program);
    let block = endpoint_block(program, errors);
    if block.is_empty() {
        return;
    }

    expect(
        exact_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static-seed source",
    );
    expect(
        exact_assignment(&block, "dryRunRequired", "true"),
        errors,
        "API must keep dryRunRequired true",
    );
    expect(
        exact_assignment(&block, "providerCallsEnabled", "false"),
        errors,
        "API must keep providerCallsEnabled disabled",
    );
    expect(
        exact_assignment(&block, "liveExecutionAllowed", "false"),
        errors,
        "API must keep liveExecutionAllowed disabled",
    );

    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_assignment(&block, field, variable),
            errors,
            format!("API must bind {field} to {variable}"),
        );
        let values = csharp_array_values(&uncommented_program, variable);
        validate_api_array(field, values, string_array(catalog, field), errors);
    }
    for (field, required) in ENDPOINT_INLINE_ARRAYS {
        let values = endpoint_inline_array_values(&block, field);
        validate_api_array(
            field,
            values,
            required.iter().map(|item| item.to_string()).collect(),
            errors,
        );
    }
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
    let catalog_set: BTreeSet<&str> = catalog_values.iter().map(String::as_str).collect();
    let value_set: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    let missing: Vec<&str> = catalog_values
        .iter()
        .map(String::as_str)
        .filter(|item| !value_set.contains(item))
        .collect();
    let unexpected: Vec<&str> = values
        .iter()
        .map(String::as_str)
        .filter(|item| !catalog_set.contains(item))
        .collect();
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
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        errors,
        format!("API {field} values must be unique"),
    );
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let api_rules = api_rules(block);
    let catalog_rules = catalog_rules(catalog);
    let catalog_ids: BTreeSet<&str> = catalog_rules.iter().map(|rule| rule.id.as_str()).collect();
    let api_ids: BTreeSet<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    for id in catalog_ids.difference(&api_ids) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_ids.difference(&catalog_ids) {
        errors.push(format!("API has unexpected rule {id}"));
    }
    validate_rules(api_rules.clone(), "API", errors);
    for catalog_rule in catalog_rules {
        let Some(api_rule) = api_rules.iter().find(|rule| rule.id == catalog_rule.id) else {
            continue;
        };
        expect(
            api_rule.decision == catalog_rule.decision,
            errors,
            format!("API rule {} decision must match catalog", catalog_rule.id),
        );
        expect(
            api_rule.requirement == catalog_rule.requirement,
            errors,
            format!(
                "API rule {} requirement must match catalog",
                catalog_rule.id
            ),
        );
        expect(
            api_rule.evidence == catalog_rule.evidence,
            errors,
            format!("API rule {} evidence must match catalog", catalog_rule.id),
        );
    }
}

fn validate_docs_text(readme: &str, doc: &str, errors: &mut Vec<String>) {
    expect(
        readme.contains(ENDPOINT),
        errors,
        "API README missing server lifecycle dry-run endpoint",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "server lifecycle dry-run doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "server lifecycle doc must prohibit provider calls",
    );
    expect(
        doc.contains("never enables live execution"),
        errors,
        "server lifecycle doc must prohibit live execution",
    );
    expect(
        doc.contains("provider-safe plan"),
        errors,
        "server lifecycle doc must require provider-safe plan",
    );
    for hypervisor in REQUIRED_HYPERVISORS {
        expect(
            doc.contains(hypervisor),
            errors,
            format!("server lifecycle doc missing supported hypervisor {hypervisor}"),
        );
    }
    expect(
        doc.contains("live hypervisor execution disabled"),
        errors,
        "server lifecycle doc must block live hypervisor execution",
    );
    for distribution in REQUIRED_LINUX_DISTRIBUTIONS {
        expect(
            doc.contains(distribution),
            errors,
            format!("server lifecycle doc missing supported Linux distribution {distribution}"),
        );
    }
    for summary in ["baseline", "patch", "monitoring", "backup", "CMDB"] {
        expect(
            doc.contains(&format!("{summary} plan")),
            errors,
            format!("server lifecycle doc must require distro-specific {summary} plan summaries"),
        );
    }
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let uncommented = strip_csharp_comments(program);
    let endpoint_count = uncommented.matches(ENDPOINT).count();
    if endpoint_count > 1 {
        errors.push(format!(
            "API has duplicate endpoint registration for {ENDPOINT}"
        ));
    }
    let marker = format!("app.MapGet(\"{ENDPOINT}\",");
    let Some(start_index) = uncommented.find(&marker) else {
        errors.push("API missing server lifecycle dry-run endpoint".to_string());
        return String::new();
    };
    let next_index = uncommented[start_index + marker.len()..]
        .find("\napp.MapGet(")
        .map(|index| start_index + marker.len() + index)
        .unwrap_or(uncommented.len());
    uncommented[start_index..next_index].to_string()
}

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    let marker = format!("var {variable} = new[] {{");
    let start = program.find(&marker)? + marker.len();
    let end = program[start..].find("};")? + start;
    Some(csharp_string_literals(&program[start..end]))
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    let marker = format!("{field} = new[] {{");
    let start = block.find(&marker)? + marker.len();
    let end = block[start..].find('}')? + start;
    Some(csharp_string_literals(&block[start..end]))
}

fn api_rules(block: &str) -> Vec<Rule> {
    let mut result = Vec::new();
    let mut offset = 0;
    while let Some(start) = block[offset..].find("new {") {
        let start = offset + start;
        let Some(end) = block[start..].find('}') else {
            break;
        };
        let segment = &block[start..start + end];
        if let (Some(id), Some(decision), Some(requirement), Some(evidence)) = (
            string_field(segment, "id"),
            string_field(segment, "decision"),
            string_field(segment, "requirement"),
            string_field(segment, "evidence"),
        ) {
            result.push(Rule {
                id,
                decision,
                requirement,
                evidence,
            });
        }
        offset = start + end + 1;
    }
    result
}

fn catalog_rules(catalog: &Value) -> Vec<Rule> {
    catalog
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|rule| {
            Some(Rule {
                id: rule.get("id")?.as_str()?.to_string(),
                decision: rule.get("decision")?.as_str()?.to_string(),
                requirement: rule.get("requirement")?.as_str()?.to_string(),
                evidence: rule.get("evidence")?.as_str()?.to_string(),
            })
        })
        .collect()
}

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let lines = assignment_lines(block, field);
    lines.len() == 1 && lines[0] == format!("{field} = {value},")
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let lines = assignment_lines(block, field);
    lines.len() == 1 && lines[0] == format!("{field} = \"{value}\",")
}

fn assignment_lines(block: &str, field: &str) -> Vec<String> {
    block
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with(&format!("{field} =")))
        .map(str::to_string)
        .collect()
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    for field in assignment_fields(&stripped) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            if prohibited_endpoint_field(&field) {
                errors.push(format!(
                    "API endpoint has prohibited server lifecycle field {field}"
                ));
            } else {
                errors.push(format!(
                    "API endpoint has unexpected server lifecycle field {field}"
                ));
            }
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    for (field, value) in assignment_values(&stripped) {
        if value == "true" && field != "dryRunRequired" && unsafe_true_field(&field) {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_endpoint_field(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited server lifecycle field"
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
        Value::String(text) if prohibited_value(text) => {
            errors.push(format!("{path} contains prohibited value"));
        }
        _ => {}
    }
}

fn prohibited_endpoint_field(field: &str) -> bool {
    let normalized = normalize(field);
    [
        "password",
        "credential",
        "secret",
        "token",
        "bearer",
        "tenantid",
        "tenantidentifier",
        "subscriptionid",
        "subscriptionidentifier",
        "objectid",
        "objectidentifier",
        "principalid",
        "principalidentifier",
        "privateip",
        "privatenetwork",
        "serialnumber",
        "providerpayload",
        "rawprovider",
        "rawevidence",
        "rawlog",
        "rawinventory",
        "rawcmdb",
        "recipientemail",
        "recipientaddress",
        "recipientdata",
        "customerid",
        "customeridentifier",
        "hostname",
        "fqdn",
        "username",
        "endpointurl",
        "url",
    ]
    .iter()
    .any(|term| normalized.contains(term))
}

fn unsafe_true_field(field: &str) -> bool {
    let lower = field.to_ascii_lowercase();
    [
        "live",
        "provider",
        "raw",
        "credential",
        "secret",
        "token",
        "tenant",
        "object",
        "principal",
        "private",
        "cmdb",
        "backup",
        "monitoring",
        "mutation",
        "execution",
    ]
    .iter()
    .any(|term| lower.contains(term))
}

fn prohibited_value(text: &str) -> bool {
    text.contains("://")
        || text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----")
        || text.contains("AKIA")
        || contains_secret_assignment(text)
        || contains_private_ip(text)
        || contains_uuid_like(text)
}

fn contains_secret_assignment(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
    ]
    .iter()
    .any(|term| contains_term_assignment(&lower, term))
}

fn contains_term_assignment(text: &str, term: &str) -> bool {
    let mut offset = 0;
    while let Some(found) = text[offset..].find(term) {
        let start = offset + found;
        let end = start + term.len();
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        let term_boundary = !before.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            && !after.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if term_boundary {
            let tail = text[end..].trim_start();
            let mut chars = tail.chars();
            if matches!(chars.next(), Some(':') | Some('='))
                && chars.as_str().chars().any(|ch| !ch.is_whitespace())
            {
                return true;
            }
        }
        offset = end;
    }
    false
}

fn contains_private_ip(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .any(|candidate| {
            let octets: Vec<u16> = candidate
                .split('.')
                .filter_map(|part| part.parse::<u16>().ok())
                .collect();
            if octets.len() != 4 || octets.iter().any(|octet| *octet > 255) {
                return false;
            }
            octets[0] == 10
                || (octets[0] == 192 && octets[1] == 168)
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        })
}

fn contains_uuid_like(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_hexdigit() || ch == '-'))
        .any(|candidate| {
            let parts: Vec<&str> = candidate.split('-').collect();
            parts.len() == 5
                && [8, 4, 4, 4, 12]
                    .iter()
                    .zip(parts.iter())
                    .all(|(len, part)| {
                        part.len() == *len && part.chars().all(|ch| ch.is_ascii_hexdigit())
                    })
        })
}

fn string_value<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn bool_value(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn string_array(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '"' {
            continue;
        }
        let mut value = String::new();
        let mut escaped = false;
        for inner in chars.by_ref() {
            if escaped {
                value.push(inner);
                escaped = false;
            } else if inner == '\\' {
                escaped = true;
            } else if inner == '"' {
                break;
            } else {
                value.push(inner);
            }
        }
        values.push(value);
    }
    values
}

fn string_field(segment: &str, field: &str) -> Option<String> {
    let marker = format!("{field} = \"");
    let start = segment.find(&marker)? + marker.len();
    let end = segment[start..].find('"')? + start;
    Some(segment[start..end].to_string())
}

fn strip_csharp_comments(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        if in_line_comment {
            if ch == '\n' {
                in_line_comment = false;
                output.push(ch);
            }
            continue;
        }
        if in_block_comment {
            if ch == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block_comment = false;
            } else if ch == '\n' {
                output.push(ch);
            }
            continue;
        }
        if in_string {
            output.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
            output.push(ch);
        } else if ch == '/' && chars.peek() == Some(&'/') {
            chars.next();
            in_line_comment = true;
        } else if ch == '/' && chars.peek() == Some(&'*') {
            chars.next();
            in_block_comment = true;
        } else {
            output.push(ch);
        }
    }
    output
}

fn strip_csharp_string_literals(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let chars = source.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    for ch in chars {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
                output.push_str("\"\"");
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
        } else {
            output.push(ch);
        }
    }
    output
}

fn assignment_fields(source: &str) -> Vec<String> {
    assignment_values(source)
        .into_iter()
        .map(|(field, _)| field)
        .collect()
}

fn assignment_values(source: &str) -> Vec<(String, String)> {
    let bytes = source.as_bytes();
    let mut result = Vec::new();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'=' {
            continue;
        }
        let mut left = index;
        while left > 0 && bytes[left - 1].is_ascii_whitespace() {
            left -= 1;
        }
        let end = left;
        while left > 0 && (bytes[left - 1].is_ascii_alphanumeric() || bytes[left - 1] == b'_') {
            left -= 1;
        }
        if left == end {
            continue;
        }
        let mut right = index + 1;
        while right < bytes.len() && bytes[right].is_ascii_whitespace() {
            right += 1;
        }
        let start_value = right;
        while right < bytes.len() && (bytes[right].is_ascii_alphanumeric() || bytes[right] == b'_')
        {
            right += 1;
        }
        result.push((
            source[left..end].to_string(),
            source[start_value..right].to_string(),
        ));
    }
    result
}

fn normalize(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_block_ignores_commented_decoys() {
        let mut errors = Vec::new();
        let block = endpoint_block(
            &format!(
                "// app.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ dryRunRequired = true }}));\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ dryRunRequired = false }}));"
            ),
            &mut errors,
        );

        assert!(errors.is_empty());
        assert!(block.contains("dryRunRequired = false"));
    }

    #[test]
    fn endpoint_block_rejects_duplicate_active_registrations() {
        let mut errors = Vec::new();
        let block = endpoint_block(
            &format!(
                "app.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ dryRunRequired = true }}));\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ dryRunRequired = true }}));"
            ),
            &mut errors,
        );

        assert!(block.contains(ENDPOINT));
        assert!(errors
            .iter()
            .any(|error| error.contains("duplicate endpoint registration")));
    }

    #[test]
    fn prohibited_keys_are_normalized() {
        assert!(prohibited_endpoint_field("tenant/id"));
        assert!(prohibited_endpoint_field("object id"));
        assert!(prohibited_endpoint_field("provider-payload"));
        assert!(prohibited_endpoint_field("customer identifier"));
        assert!(prohibited_endpoint_field("host name"));
    }
}
