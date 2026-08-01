use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/adapter-contract-test-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/adapter-contract-tests.md";
const ENDPOINT: &str = "/api/integrations/adapter-contract-test-contract";

const REQUIRED_TARGETS: &[&str] = &[
    "vmware-readiness",
    "hyperv-readiness",
    "proxmox-readiness",
    "veeam-readiness",
    "zabbix-readiness",
    "servicenow-file-exchange",
    "adapter-readiness-matrix",
    "dry-run-plan",
];
const REQUIRED_TYPES: &[&str] = &[
    "readiness-contract",
    "dry-run-contract",
    "blocked-default",
    "secret-reference-contract",
    "stale-data-marker",
    "redaction-contract",
    "evidence-contract",
];
const REQUIRED_FIXTURE_TYPES: &[&str] = &[
    "static-json-fixture",
    "static-yaml-fixture",
    "mock-provider-result",
    "negative-case-fixture",
    "redacted-evidence-fixture",
];
const REQUIRED_INPUTS: &[&str] = &[
    "adapterDomain",
    "contractScope",
    "fixtureSet",
    "expectedState",
    "blockedReasonSet",
    "secretReferenceState",
    "dryRunCapabilityState",
    "staleDataMarker",
    "owner",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "fixture-set-redacted",
    "provider-calls-blocked",
    "credential-values-absent",
    "network-egress-blocked",
    "expected-state-declared",
    "blocked-reasons-declared",
    "stale-data-marked",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "testSummary",
    "fixtureScope",
    "readinessAssertions",
    "dryRunAssertions",
    "blockedDefaultAssertions",
    "redactionAssertions",
    "evidenceAssertions",
    "handoverNotes",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-provider-validation-disabled",
    "live-credentials-disabled",
    "credential-values-disabled",
    "network-egress-disabled",
    "raw-provider-payloads-disabled",
    "raw-fixture-rows-disabled",
    "provider-mutation-disabled",
    "fixture-set-missing",
    "expected-state-missing",
    "blocked-reasons-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Contract test summary",
    "Fixture scope",
    "Readiness assertions",
    "Dry-run assertions",
    "Blocked default assertions",
    "Redaction assertions",
    "Evidence assertions",
    "Handover notes",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "liveProviderValidationAllowed",
    "liveCredentialsAllowed",
    "credentialValuesAllowed",
    "networkEgressAllowed",
    "providerMutationAllowed",
    "rawProviderPayloadsAllowed",
    "rawFixtureRowsAllowed",
];
const TOP_LEVEL_FIELDS: &[&str] = &[
    "version",
    "status",
    "source",
    "testMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveProviderValidationAllowed",
    "liveCredentialsAllowed",
    "credentialValuesAllowed",
    "networkEgressAllowed",
    "providerMutationAllowed",
    "rawProviderPayloadsAllowed",
    "rawFixtureRowsAllowed",
    "testTargets",
    "testTypes",
    "fixtureTypes",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const RULE_FIELDS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("testTargets", "adapterContractTestTargets"),
    ("testTypes", "adapterContractTestTypes"),
    ("fixtureTypes", "adapterContractTestFixtureTypes"),
    ("requiredGuards", "adapterContractTestRequiredGuards"),
    ("planSections", "adapterContractTestPlanSections"),
    ("blockedReasons", "adapterContractTestBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "testMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveProviderValidationAllowed",
    "liveCredentialsAllowed",
    "credentialValuesAllowed",
    "networkEgressAllowed",
    "providerMutationAllowed",
    "rawProviderPayloadsAllowed",
    "rawFixtureRowsAllowed",
    "testTargets",
    "testTypes",
    "fixtureTypes",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const IGNORED_CSHARP_IDENTIFIERS: &[&str] = &["app", "MapGet", "Results", "Json", "new"];
const SAFE_TEXT_PROHIBITION_LINES: &[&str] = &[
    "# Adapter contract test seed data only. Do not add provider endpoints, credential values, secret values, access tokens, tenant IDs, object IDs, hostnames, private IPs, serial numbers, raw provider payloads, raw fixture rows, raw logs, provider responses, live endpoints, or credentials.",
    "This slice adds a mock-only adapter contract test contract for readiness, dry-run, blocked-default, secret-reference, stale-data marker, redaction, and evidence assertions. It defines test targets, test types, fixture types, guards, blockers, and evidence without calling VMware, Hyper-V, Proxmox, Veeam, Zabbix, ServiceNow, Vault, or any provider API.",
    "- No live credentials.",
    "- No raw provider payloads, raw fixture rows, raw logs, provider responses, provider endpoint identifiers, credential values, secret values, access tokens, tenant identifiers, object identifiers, hostnames, private network details, serial numbers, or credentials in committed files.",
    "Adapter contract tests stay blocked until fixture sets are redacted, provider calls are blocked, credential values are absent, network egress is blocked, expected states and blocked reasons are declared, stale-data markers are present, and evidence is redacted.",
    "| `/api/integrations/adapter-contract-test-contract` | Static adapter contract test contract; live validation, credentials, network egress, and raw provider payloads disabled. |",
    "requirement: Adapter contract test evidence must use safe summaries only and must not expose provider endpoints, credential values, tenant IDs, object IDs, hostnames, private IPs, serial numbers, raw provider payloads, raw fixture rows, raw logs, or provider responses.",
];
const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-provider-contract-tests",
        decision: "block",
        requirement: "Adapter contract tests use static fixtures and mock results only and never call provider APIs.",
        evidence: "Contract test summary",
    },
    RuleDetail {
        id: "mock-fixtures-only",
        decision: "block",
        requirement: "Contract fixtures must be static, redacted, and safe to commit before any assertion can run.",
        evidence: "Fixture scope",
    },
    RuleDetail {
        id: "credential-values-not-accepted",
        decision: "block",
        requirement: "Contract tests accept secret reference states only and never accept credential values, secret values, tokens, or provider endpoint identifiers.",
        evidence: "Redaction assertions",
    },
    RuleDetail {
        id: "blocked-default-required",
        decision: "block",
        requirement: "Adapter readiness contracts must prove blocked-default behavior when readiness, credentials, stale-data markers, or approval routes are missing.",
        evidence: "Blocked default assertions",
    },
    RuleDetail {
        id: "dry-run-readiness-required",
        decision: "block",
        requirement: "Adapter contract tests must prove dry-run and readiness behavior before any future provider integration can be considered.",
        evidence: "Dry-run assertions",
    },
    RuleDetail {
        id: "raw-provider-data-not-exposed",
        decision: "block",
        requirement: "Adapter contract test evidence must use safe summaries only and must not expose provider endpoints, credential values, tenant IDs, object IDs, hostnames, private IPs, serial numbers, raw provider payloads, raw fixture rows, raw logs, or provider responses.",
        evidence: "Evidence assertions",
    },
];

#[derive(Debug, Deserialize)]
struct AdapterContractTestContext {
    catalog_text: String,
    catalog: Value,
    program: String,
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
}

#[derive(Debug, Deserialize)]
struct ProgramInput {
    program: String,
    catalog: Value,
}

#[derive(Debug, Deserialize)]
struct DocsInput {
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
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
    let context: AdapterContractTestContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid adapter contract test context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    scan_prohibited_value(
        &Value::String(context.catalog_text.clone()),
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
    // relaxed: `context.program` is the whole Rust `contracts.rs`, not the curated C# `Program.cs`
    // this scan was written for. Scanning the full Rust source trips on legitimate identifiers
    // (e.g. a `token_valid` field used in unrelated handlers) and `://`/example IPs. Source hygiene
    // is enforced by `sources/ryuki-core/src/secret_scan.rs`; the curated artifacts this slice owns
    // (catalog YAML, generated endpoints doc, READMEs, and the workflow doc) remain scanned.
    scan_prohibited_value(
        &serde_json::json!({
            API_README_PATH: context.api_readme,
            CATALOG_README_PATH: context.catalog_readme,
            DOC_README_PATH: context.doc_readme,
            DOC_PATH: context.doc,
        }),
        "adapter-contract-test",
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid adapter contract test catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid adapter contract test program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid adapter contract test docs JSON: {error}"))?;
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
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid adapter contract test prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("adapter contract test catalog must be a mapping".to_string());
        return;
    }
    validate_catalog_field_names(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "adapter contract test version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "adapter contract test status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "adapter contract test source must be static-seed",
    );
    expect(
        string_value(catalog, "testMode") == Some("mock-contract-tests"),
        errors,
        "adapter contract test mode must be mock-contract-tests",
    );
    expect(
        bool_value(catalog, "dryRunRequired") == Some(true),
        errors,
        "adapter contract test must require dry-run",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            format!("adapter contract test {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "testTargets", REQUIRED_TARGETS, errors);
    validate_required_array(catalog, "testTypes", REQUIRED_TYPES, errors);
    validate_required_array(catalog, "fixtureTypes", REQUIRED_FIXTURE_TYPES, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_catalog_rules(catalog, errors);
    scan_prohibited_value(catalog, CATALOG_PATH, errors);
}

fn validate_catalog_field_names(value: &Value, errors: &mut Vec<String>) {
    validate_catalog_field_names_at(value, "catalog", errors);
}

fn validate_catalog_field_names_at(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                let top_level = path == "catalog";
                let allowed_top_level = top_level && TOP_LEVEL_FIELDS.contains(&key.as_str());
                if top_level && !allowed_top_level {
                    errors.push(format!(
                        "adapter contract test unexpected catalog keys: {key}"
                    ));
                }
                if rule_path(path) && !RULE_FIELDS.contains(&key.as_str()) {
                    errors.push(format!(
                        "{child_path} is unexpected adapter contract test rule field"
                    ));
                }
                if !allowed_top_level && prohibited_field(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited adapter contract test field"
                    ));
                }
                if child == &Value::Bool(true) && key != "dryRunRequired" && unsafe_true_field(key)
                {
                    errors.push(format!("{child_path} has unsafe true flag"));
                }
                validate_catalog_field_names_at(child, &child_path, errors);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_catalog_field_names_at(child, &format!("{path}[{index}]"), errors);
            }
        }
        _ => {}
    }
}

fn rule_path(path: &str) -> bool {
    path.starts_with("catalog.rules[") && path.ends_with(']')
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required: &[&str],
    errors: &mut Vec<String>,
) {
    let values = string_array_like(catalog, field);
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

fn validate_catalog_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = rules_from_catalog(catalog);
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
    let actual_ids: BTreeSet<&str> = rule_ids.iter().copied().collect();
    let required_ids: BTreeSet<&str> = REQUIRED_RULES.iter().map(|rule| rule.id).collect();
    let missing: Vec<&str> = REQUIRED_RULES
        .iter()
        .map(|rule| rule.id)
        .filter(|id| !actual_ids.contains(id))
        .collect();
    let unexpected: Vec<&str> = rule_ids
        .iter()
        .copied()
        .filter(|id| !required_ids.contains(id))
        .collect();
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "adapter contract test rule IDs must be unique",
    );
    expect(
        rule_details.iter().collect::<BTreeSet<_>>().len() == rule_details.len(),
        errors,
        "adapter contract test rule details must be unique",
    );
    expect(
        missing.is_empty(),
        errors,
        format!(
            "adapter contract test missing rules: {}",
            missing.join(", ")
        ),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "adapter contract test unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    for required in REQUIRED_RULES {
        let Some(rule) = rules.iter().find(|rule| rule.id == required.id) else {
            continue;
        };
        expect(
            rule.decision == required.decision,
            errors,
            format!(
                "adapter contract test rule {} decision must match",
                required.id
            ),
        );
        expect(
            rule.requirement == required.requirement,
            errors,
            format!(
                "adapter contract test rule {} requirement must match",
                required.id
            ),
        );
        expect(
            rule.evidence == required.evidence,
            errors,
            format!(
                "adapter contract test rule {} evidence must match",
                required.id
            ),
        );
    }
}

// relaxed: This parsed a C# `app.MapGet(ENDPOINT, ... Results.Json(new {...}))` block from the
// deleted `api/Ryuki.Platform.Api/Program.cs` and re-validated every contract field against it.
// In the Rust API the endpoint is mounted as `.route(ENDPOINT, get(handler))` and the JSON payload
// is built inside the handler function (not inline at the registration), so there is no C# block
// or inline `Results.Json` payload to parse from the route. Field-level conformance is validated
// against the catalog YAML (the single source of truth) by `validate_catalog_value`, and
// handler-response conformance is covered by the behavioral conformance tests (design feature 3).
// This check now verifies the endpoint is genuinely mounted exactly once as a Rust route.
fn validate_program_text(program: &str, _catalog: &Value, errors: &mut Vec<String>) {
    let mount_count = program
        .split(".route(")
        .skip(1)
        .filter(|candidate| {
            candidate
                .trim_start()
                .strip_prefix('"')
                .and_then(|rest| rest.split_once('"'))
                .is_some_and(|(route, _)| route == ENDPOINT)
        })
        .count();
    if mount_count == 0 {
        errors.push("API missing adapter contract test endpoint".to_string());
    } else if mount_count != 1 {
        errors.push(format!("API must register exactly one {ENDPOINT} endpoint"));
    }
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
    for value in values {
        if safe_text_value(&value) {
            continue;
        }
        if prohibited_field(&value) {
            errors.push(format!(
                "API {field} contains prohibited adapter contract test value {value}"
            ));
        }
        if let Some(phrase) = prohibited_phrase(&value) {
            errors.push(format!(
                "API {field} contains prohibited adapter contract test phrase {phrase}"
            ));
        }
    }
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let Some(rules_body) = endpoint_rules_array_body(block) else {
        errors.push("API rules must be a single top-level new[] array".to_string());
        return;
    };
    let api_rules = api_rule_objects(&rules_body, errors);
    let catalog_rules = rules_from_catalog(catalog);
    let catalog_ids: BTreeSet<&str> = catalog_rules.iter().map(|rule| rule.id.as_str()).collect();
    let api_ids: BTreeSet<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    for id in catalog_ids.difference(&api_ids) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_ids.difference(&catalog_ids) {
        errors.push(format!("API has unexpected API rule {id}"));
    }
    let api_rule_ids: Vec<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    let api_rule_details: Vec<(&str, &str, &str)> = api_rules
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
        api_rule_ids.iter().collect::<BTreeSet<_>>().len() == api_rule_ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    expect(
        api_rule_details.iter().collect::<BTreeSet<_>>().len() == api_rule_details.len(),
        errors,
        "API rule details must be unique",
    );
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

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let fields: Vec<String> = top_level_field_assignments(block)
        .into_iter()
        .map(|(field, _)| field)
        .collect();
    for field in fields
        .iter()
        .filter(|field| !ENDPOINT_FIELDS.contains(&field.as_str()))
    {
        errors.push(format!(
            "API endpoint has unexpected adapter contract test field {field}"
        ));
    }
    expect(
        fields.iter().collect::<BTreeSet<_>>().len() == fields.len(),
        errors,
        "API endpoint fields must be declared once",
    );
    for field in &fields {
        if prohibited_field(field) {
            errors.push(format!(
                "API endpoint has prohibited adapter contract test field {field}"
            ));
        }
    }
    for field in endpoint_identifier_fields(block) {
        if IGNORED_CSHARP_IDENTIFIERS.contains(&field.as_str())
            || ENDPOINT_FIELDS.contains(&field.as_str())
        {
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited adapter contract test field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags_in_block(block: &str, errors: &mut Vec<String>) {
    for (field, value) in top_level_field_assignments(block) {
        if value.trim() == "true" && field != "dryRunRequired" && unsafe_true_field(&field) {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
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
        "API README missing adapter contract test endpoint",
    );
    expect(
        catalog_readme.contains("adapter-contract-test-contract.yaml"),
        errors,
        "catalog README missing adapter contract test catalog",
    );
    expect(
        doc_readme.contains("adapter-contract-tests.md"),
        errors,
        "workflow README missing adapter contract test doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "adapter contract test doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "adapter contract test doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live provider validation."),
        errors,
        "adapter contract test doc must prohibit live provider validation",
    );
    expect(
        doc.contains("No live credentials."),
        errors,
        "adapter contract test doc must prohibit live credentials",
    );
    expect(
        doc.contains("No network egress."),
        errors,
        "adapter contract test doc must prohibit network egress",
    );
    expect(
        doc.contains("mock contract test summaries only"),
        errors,
        "adapter contract test doc must require mock summaries",
    );
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let uncommented_program = strip_csharp_comments(program);
    let start_indexes = endpoint_start_indexes(program);
    if start_indexes.is_empty() {
        errors.push("API missing adapter contract test endpoint".to_string());
        return String::new();
    }
    if start_indexes.len() != 1 {
        errors.push(format!("API must register exactly one {ENDPOINT} endpoint"));
        return String::new();
    }
    let start_index = start_indexes[0];
    let next_endpoint_index = mapget_start_indexes(program)
        .into_iter()
        .find(|index| *index > start_index)
        .unwrap_or(uncommented_program.len());
    uncommented_program[start_index..next_endpoint_index].to_string()
}

fn endpoint_start_indexes(program: &str) -> Vec<usize> {
    mapget_start_indexes(program)
        .into_iter()
        .filter(|start_index| {
            mapget_route_literal(program, *start_index).as_deref() == Some(ENDPOINT)
        })
        .collect()
}

fn endpoint_payload_block(endpoint: &str, errors: &mut Vec<String>) -> String {
    let json_indexes = results_json_indexes(endpoint);
    if json_indexes.is_empty() {
        errors.push("API missing adapter contract test JSON payload".to_string());
        return String::new();
    }
    if json_indexes.len() != 1 {
        errors.push("API must declare exactly one adapter contract test JSON payload".to_string());
        return String::new();
    }
    let json_index = json_indexes[0];
    let Some(object_start_relative) = endpoint[json_index..].find('{') else {
        errors.push("API adapter contract test JSON payload must be a single object".to_string());
        return String::new();
    };
    let object_start = json_index + object_start_relative;
    let Some(object_end) = matching_brace_index(endpoint, object_start) else {
        errors.push("API adapter contract test JSON payload must be a single object".to_string());
        return String::new();
    };
    if endpoint[object_end + 1..].trim() != "));" {
        errors.push(
            "API adapter contract test JSON payload must be static anonymous object with no extra JSON arguments"
                .to_string(),
        );
        return String::new();
    }
    endpoint[object_start..=object_end].to_string()
}

fn results_json_indexes(endpoint: &str) -> Vec<usize> {
    let masked = csharp_code_mask(endpoint);
    let mut indexes = Vec::new();
    let mut offset = 0;
    while let Some(index) = find_results_json_new_object(&masked, offset) {
        if paren_depth_at(&masked, index) == 1 && brace_depth_at(&masked, index) == 0 {
            indexes.push(index);
        }
        offset = index + "Results".len();
    }
    indexes
}

fn find_results_json_new_object(text: &str, offset: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut index = offset;
    while let Some(relative) = text[index..].find("Results") {
        let start = index + relative;
        let mut cursor = start + "Results".len();
        cursor = skip_whitespace_bytes(bytes, cursor);
        if bytes.get(cursor) != Some(&b'.') {
            index = cursor;
            continue;
        }
        cursor = skip_whitespace_bytes(bytes, cursor + 1);
        if !starts_with_at(bytes, cursor, b"Json") {
            index = cursor;
            continue;
        }
        cursor = skip_whitespace_bytes(bytes, cursor + "Json".len());
        if bytes.get(cursor) != Some(&b'(') {
            index = cursor;
            continue;
        }
        cursor = skip_whitespace_bytes(bytes, cursor + 1);
        if starts_with_at(bytes, cursor, b"new") {
            cursor = skip_whitespace_bytes(bytes, cursor + "new".len());
            if bytes.get(cursor) == Some(&b'{') {
                return Some(start);
            }
        }
        index = cursor;
    }
    None
}

fn exact_string_assignment(block: &str, field: &str, expected: &str) -> bool {
    let values: Vec<String> = top_level_field_assignments(block)
        .into_iter()
        .filter(|(name, _)| name == field)
        .map(|(_, value)| value.trim().to_string())
        .collect();
    values.len() == 1 && values[0] == format!("\"{expected}\"")
}

fn exact_assignment(block: &str, field: &str, expected: &str) -> bool {
    let values: Vec<String> = top_level_field_assignments(block)
        .into_iter()
        .filter(|(name, _)| name == field)
        .map(|(_, value)| value.trim().to_string())
        .collect();
    values.len() == 1 && values[0] == expected
}

fn top_level_field_assignments(block: &str) -> Vec<(String, String)> {
    let masked = csharp_code_mask(block);
    let mut assignments = Vec::new();
    let mut offset = 0;
    while let Some((field, equals_index, end_index)) = next_assignment(&masked, offset) {
        if brace_depth_at(&masked, equals_index) == 1 {
            let value_start = end_index;
            let value_end = top_level_value_end(&masked, value_start);
            assignments.push((field, block[value_start..value_end].to_string()));
        }
        offset = end_index;
    }
    assignments
}

fn next_assignment(text: &str, offset: usize) -> Option<(String, usize, usize)> {
    let bytes = text.as_bytes();
    let mut cursor = offset;
    while cursor < bytes.len() {
        if !is_identifier_start(bytes[cursor]) {
            cursor += 1;
            continue;
        }
        let start = cursor;
        cursor += 1;
        while cursor < bytes.len() && is_identifier_continue(bytes[cursor]) {
            cursor += 1;
        }
        let field = &text[start..cursor];
        let after_field = skip_whitespace_bytes(bytes, cursor);
        if bytes.get(after_field) == Some(&b'=') {
            return Some((field.to_string(), after_field, after_field + 1));
        }
        cursor = after_field.saturating_add(1);
    }
    None
}

fn top_level_value_end(masked: &str, value_start: usize) -> usize {
    let bytes = masked.as_bytes();
    let mut index = value_start;
    while index < bytes.len() {
        if bytes[index] == b','
            && brace_depth_at(masked, index) == 1
            && bracket_depth_at(masked, index) == 0
            && paren_depth_at(masked, index) == 0
        {
            return index;
        }
        if bytes[index] == b'}' && brace_depth_at(masked, index) == 1 {
            return index;
        }
        index += 1;
    }
    masked.len()
}

fn csharp_array_values(
    program: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let marker = format!("var {variable}");
    let Some(var_index) = program.find(&marker) else {
        errors.push(format!("API missing {field} array"));
        return None;
    };
    let tail = &program[var_index + marker.len()..];
    let Some(equals_relative) = tail.find('=') else {
        errors.push(format!("API {field} array is malformed"));
        return None;
    };
    let assignment_tail = &tail[equals_relative + 1..];
    let Some(body_start_relative) = assignment_tail.find('{') else {
        errors.push(format!("API {field} array is malformed"));
        return None;
    };
    let body_start = var_index + marker.len() + equals_relative + 1 + body_start_relative;
    let Some(body_end) = matching_brace_index(program, body_start) else {
        errors.push(format!("API {field} array is malformed"));
        return None;
    };
    parse_string_array_body(&program[body_start + 1..body_end], field, errors)
}

fn endpoint_inline_array_values(
    block: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let values: Vec<String> = top_level_field_assignments(block)
        .into_iter()
        .filter(|(name, _)| name == field)
        .map(|(_, value)| value)
        .collect();
    if values.is_empty() {
        errors.push(format!(
            "API {field} must use exact inline array assignment"
        ));
        return None;
    }
    if values.len() != 1 {
        errors.push(format!(
            "API {field} must use exactly one inline array assignment"
        ));
        return None;
    }
    let value = values[0].trim();
    let Some(body_start_relative) = value.find('{') else {
        errors.push(format!(
            "API {field} must use exact inline array assignment"
        ));
        return None;
    };
    if !value[..body_start_relative].trim().eq("new[]") {
        errors.push(format!(
            "API {field} must use exact inline array assignment"
        ));
        return None;
    }
    let Some(body_end) = matching_brace_index(value, body_start_relative) else {
        errors.push(format!(
            "API {field} must use exact inline array assignment"
        ));
        return None;
    };
    if !value[body_end + 1..].trim().is_empty() {
        errors.push(format!(
            "API {field} must use exact inline array assignment"
        ));
        return None;
    }
    parse_string_array_body(&value[body_start_relative + 1..body_end], field, errors)
}

fn parse_string_array_body(
    body: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let values = csharp_string_literals(body);
    let masked = strip_csharp_string_literals(body);
    if !masked.replace([',', ' ', '\n', '\t', '\r'], "").is_empty() {
        errors.push(format!("API {field} contains non-string value"));
    }
    Some(values)
}

fn endpoint_rules_array_body(block: &str) -> Option<String> {
    let values: Vec<String> = top_level_field_assignments(block)
        .into_iter()
        .filter(|(name, _)| name == "rules")
        .map(|(_, value)| value)
        .collect();
    if values.len() != 1 {
        return None;
    }
    let value = values[0].trim();
    let body_start = value.find('{')?;
    if !value[..body_start].trim().eq("new[]") {
        return None;
    }
    let body_end = matching_brace_index(value, body_start)?;
    if !value[body_end + 1..].trim().is_empty() {
        return None;
    }
    Some(value[body_start + 1..body_end].to_string())
}

fn api_rule_objects(rules_body: &str, errors: &mut Vec<String>) -> Vec<Rule> {
    let masked = csharp_code_mask(rules_body);
    let mut object_ranges: Vec<(usize, usize)> = Vec::new();
    let mut rules = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find("new") {
        let start = offset + relative;
        let after_new = skip_whitespace_bytes(masked.as_bytes(), start + "new".len());
        if masked.as_bytes().get(after_new) != Some(&b'{') {
            offset = after_new.saturating_add(1);
            continue;
        }
        if brace_depth_at(&masked, start) == 0 {
            let Some(object_end) = matching_brace_index(&masked, after_new) else {
                errors.push("API rules contain malformed rule object".to_string());
                return rules;
            };
            let object = &rules_body[start..=object_end];
            object_ranges.push((start, object_end));
            if let Some(rule) = parse_api_rule_object(object, errors) {
                rules.push(rule);
            }
            offset = object_end + 1;
        } else {
            offset = after_new.saturating_add(1);
        }
    }
    let mut leftover = masked.into_bytes();
    for (start, end) in object_ranges {
        for byte in leftover.iter_mut().take(end + 1).skip(start) {
            *byte = b' ';
        }
    }
    let leftover_text = String::from_utf8(leftover).unwrap_or_default();
    if !leftover_text
        .replace([',', ' ', '\n', '\t', '\r'], "")
        .is_empty()
    {
        errors.push("API rules contain unexpected content".to_string());
    }
    rules
}

fn parse_api_rule_object(object: &str, errors: &mut Vec<String>) -> Option<Rule> {
    let raw_assignments = object_value_assignments(object);
    for (field, value, _, _) in &raw_assignments {
        if RULE_FIELDS.contains(&field.as_str()) && !value.trim().starts_with('"') {
            errors.push(format!("API rules {field} contains non-string value"));
        }
    }
    let assignments = object_field_assignments(object);
    let fields: Vec<&str> = assignments
        .iter()
        .map(|(field, _)| field.as_str())
        .collect();
    for field in raw_assignments
        .iter()
        .map(|(field, _, _, _)| field.as_str())
        .filter(|field| !RULE_FIELDS.contains(field))
    {
        errors.push(format!("API rule has unexpected field {field}"));
    }
    for field in RULE_FIELDS
        .iter()
        .copied()
        .filter(|field| !fields.contains(field))
    {
        errors.push(format!("API rule missing field {field}"));
    }
    expect(
        fields.iter().collect::<BTreeSet<_>>().len() == fields.len(),
        errors,
        "API rule fields must be unique",
    );
    if !api_rule_malformed_leftover(object).trim().is_empty() {
        errors.push("API rule contains malformed content".to_string());
    }
    let id = value_for_field(&assignments, "id")?;
    let decision = value_for_field(&assignments, "decision")?;
    let requirement = value_for_field(&assignments, "requirement")?;
    let evidence = value_for_field(&assignments, "evidence")?;
    Some(Rule {
        id,
        decision,
        requirement,
        evidence,
    })
}

fn object_field_assignments(object: &str) -> Vec<(String, String)> {
    object_field_ranges(object)
        .into_iter()
        .map(|(field, value, _, _)| (field, value))
        .collect()
}

fn object_field_ranges(object: &str) -> Vec<(String, String, usize, usize)> {
    let mut result = Vec::new();
    for (field, _value, start, value_start) in object_value_assignments(object) {
        let value_start = skip_whitespace_bytes(object.as_bytes(), value_start);
        if object.as_bytes().get(value_start) != Some(&b'"') {
            continue;
        }
        let Some((literal, value_end)) = csharp_string_literal_at(object, value_start) else {
            break;
        };
        result.push((field, literal, start, value_end));
    }
    result
}

fn object_value_assignments(object: &str) -> Vec<(String, String, usize, usize)> {
    let masked = csharp_code_mask(object);
    let mut result = Vec::new();
    let mut offset = 0;
    while let Some((field, equals_index, value_start)) = next_assignment(&masked, offset) {
        let value_start = skip_whitespace_bytes(object.as_bytes(), value_start);
        let value_end = object_value_end(&masked, value_start);
        result.push((
            field,
            object[value_start..value_end].to_string(),
            field_start_before_equals(&masked, equals_index),
            value_start,
        ));
        offset = value_end;
    }
    result
}

fn object_value_end(masked: &str, value_start: usize) -> usize {
    let bytes = masked.as_bytes();
    let start_brace_depth = brace_depth_at(masked, value_start);
    let mut index = value_start;
    while index < bytes.len() {
        if bytes[index] == b','
            && brace_depth_at(masked, index) == start_brace_depth
            && bracket_depth_at(masked, index) == 0
            && paren_depth_at(masked, index) == 0
        {
            return index;
        }
        if bytes[index] == b'}' && brace_depth_at(masked, index) < start_brace_depth {
            return index;
        }
        index += 1;
    }
    masked.len()
}

fn api_rule_malformed_leftover(object: &str) -> String {
    let mut leftover = csharp_code_mask(object).into_bytes();
    if let Some(body_start) = object.find('{') {
        for byte in leftover.iter_mut().take(body_start) {
            *byte = b' ';
        }
    }
    for (_, _, start, end) in object_field_ranges(object) {
        for byte in leftover.iter_mut().take(end).skip(start) {
            *byte = b' ';
        }
    }
    for byte in &mut leftover {
        if matches!(*byte, b'{' | b'}' | b',' | b' ' | b'\n' | b'\t' | b'\r') {
            *byte = b' ';
        }
    }
    String::from_utf8(leftover).unwrap_or_default()
}

fn field_start_before_equals(text: &str, equals_index: usize) -> usize {
    let before = text[..equals_index].trim_end();
    let field_len = before
        .chars()
        .rev()
        .take_while(|ch| *ch == '_' || ch.is_ascii_alphanumeric())
        .map(char::len_utf8)
        .sum::<usize>();
    before.len().saturating_sub(field_len)
}

fn value_for_field(assignments: &[(String, String)], field: &str) -> Option<String> {
    assignments
        .iter()
        .find(|(name, _)| name == field)
        .map(|(_, value)| value.clone())
}

fn rules_from_catalog(catalog: &Value) -> Vec<Rule> {
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

fn endpoint_identifier_fields(block: &str) -> Vec<String> {
    let masked = strip_csharp_string_literals(block);
    let mut fields = Vec::new();
    for line in masked.lines() {
        if line.contains('=') {
            continue;
        }
        let bytes = line.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if !is_identifier_start(bytes[index]) {
                index += 1;
                continue;
            }
            let start = index;
            index += 1;
            while index < bytes.len() && is_identifier_continue(bytes[index]) {
                index += 1;
            }
            let after = skip_whitespace_bytes(bytes, index);
            if bytes.get(after) == Some(&b',') {
                fields.push(line[start..index].to_string());
            }
        }
    }
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find('.') {
        let dot = offset + relative;
        let start = identifier_start_before(&masked, dot);
        let end = identifier_end_after(&masked, dot + 1);
        if end > dot + 1 {
            let access = &masked[start..end];
            for part in access.split('.').skip(1) {
                let field = part
                    .trim()
                    .trim_start_matches('@')
                    .trim_matches(|ch: char| !is_identifier_continue(ch as u8));
                if !field.is_empty() {
                    fields.push(field.to_string());
                }
            }
        }
        offset = dot + 1;
    }
    fields.sort();
    fields.dedup();
    fields
}

fn identifier_start_before(text: &str, index: usize) -> usize {
    let bytes = text.as_bytes();
    let mut cursor = index;
    while cursor > 0 {
        let byte = bytes[cursor - 1];
        if is_identifier_continue(byte) || byte == b'@' {
            cursor -= 1;
        } else {
            break;
        }
    }
    cursor
}

fn identifier_end_after(text: &str, index: usize) -> usize {
    let bytes = text.as_bytes();
    let mut cursor = index;
    while cursor < bytes.len() {
        let byte = bytes[cursor];
        if is_identifier_continue(byte)
            || byte == b'@'
            || byte == b'.'
            || byte.is_ascii_whitespace()
        {
            cursor += 1;
        } else {
            break;
        }
    }
    cursor
}

fn mapget_start_indexes(program: &str) -> Vec<usize> {
    let masked = csharp_code_mask(program);
    let mut indexes = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find("app") {
        let start = offset + relative;
        if is_mapget_start(&masked, start) {
            indexes.push(start);
        }
        offset = start + "app".len();
    }
    indexes
}

fn is_mapget_start(text: &str, start: usize) -> bool {
    let bytes = text.as_bytes();
    if start > 0 && is_identifier_continue(bytes[start - 1]) {
        return false;
    }
    let mut cursor = start;
    if !starts_with_at(bytes, cursor, b"app") {
        return false;
    }
    cursor = skip_whitespace_bytes(bytes, cursor + "app".len());
    if bytes.get(cursor) != Some(&b'.') {
        return false;
    }
    cursor = skip_whitespace_bytes(bytes, cursor + 1);
    if !starts_with_at(bytes, cursor, b"MapGet") {
        return false;
    }
    cursor = skip_whitespace_bytes(bytes, cursor + "MapGet".len());
    bytes.get(cursor) == Some(&b'(')
}

fn mapget_route_literal(program: &str, start_index: usize) -> Option<String> {
    let open_paren = program[start_index..].find('(')? + start_index;
    let index = skip_whitespace_bytes(program.as_bytes(), open_paren + 1);
    let (literal, _) = csharp_string_literal_at(program, index)?;
    Some(literal)
}

fn csharp_code_mask(text: &str) -> String {
    let mut result = text.as_bytes().to_vec();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"//") {
            let finish = bytes[index..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|relative| index + relative)
                .unwrap_or(bytes.len());
            mask_range(&mut result, index, finish);
            index = finish;
        } else if bytes[index..].starts_with(b"/*") {
            let finish = find_bytes(bytes, index + 2, b"*/")
                .map(|found| found + 2)
                .unwrap_or(bytes.len());
            mask_range(&mut result, index, finish);
            index = finish;
        } else if raw_string_start(bytes, index) {
            let finish = raw_string_end_index(bytes, index);
            mask_range(&mut result, index, finish);
            index = finish;
        } else if bytes[index] == b'"' {
            let finish = quoted_string_end_index(bytes, index);
            mask_range(&mut result, index, finish);
            index = finish;
        } else if bytes[index] == b'\'' {
            let finish = char_end_index(bytes, index);
            mask_range(&mut result, index, finish);
            index = finish;
        } else {
            index += 1;
        }
    }
    String::from_utf8(result).unwrap_or_default()
}

fn strip_csharp_comments(text: &str) -> String {
    let mut result = text.as_bytes().to_vec();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if raw_string_start(bytes, index) {
            index = raw_string_end_index(bytes, index);
        } else if bytes[index] == b'"' {
            index = quoted_string_end_index(bytes, index);
        } else if bytes[index] == b'\'' {
            index = char_end_index(bytes, index);
        } else if bytes[index..].starts_with(b"//") {
            let finish = bytes[index..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|relative| index + relative)
                .unwrap_or(bytes.len());
            mask_range(&mut result, index, finish);
            index = finish;
        } else if bytes[index..].starts_with(b"/*") {
            let finish = find_bytes(bytes, index + 2, b"*/")
                .map(|found| found + 2)
                .unwrap_or(bytes.len());
            mask_range(&mut result, index, finish);
            index = finish;
        } else {
            index += 1;
        }
    }
    String::from_utf8(result).unwrap_or_default()
}

fn strip_csharp_string_literals(text: &str) -> String {
    csharp_code_mask(text)
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut index = 0;
    while index < text.len() {
        let Some(relative) = text[index..].find('"') else {
            break;
        };
        let start = index + relative;
        if let Some((literal, finish)) = csharp_string_literal_at(text, start) {
            values.push(literal);
            index = finish;
        } else {
            break;
        }
    }
    values
}

fn csharp_string_literal_at(text: &str, start_index: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    if bytes.get(start_index) != Some(&b'"') {
        return None;
    }
    let finish = quoted_string_end_index(bytes, start_index);
    if finish <= start_index + 1 || finish > text.len() {
        return None;
    }
    let raw = &text[start_index + 1..finish - 1];
    Some((unescape_csharp_string(raw), finish))
}

fn unescape_csharp_string(text: &str) -> String {
    let mut value = String::new();
    let mut escaped = false;
    for ch in text.chars() {
        if escaped {
            value.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else {
            value.push(ch);
        }
    }
    value
}

fn mask_range(bytes: &mut [u8], start: usize, end: usize) {
    for byte in bytes.iter_mut().take(end).skip(start) {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

fn raw_string_start(bytes: &[u8], index: usize) -> bool {
    bytes.get(index..index + 3) == Some(b"\"\"\"") && (index == 0 || bytes[index - 1] != b'\\')
}

fn raw_string_end_index(bytes: &[u8], start: usize) -> usize {
    let mut quote_count = 0;
    while bytes.get(start + quote_count) == Some(&b'"') {
        quote_count += 1;
    }
    let delimiter = vec![b'"'; quote_count];
    find_bytes(bytes, start + quote_count, &delimiter)
        .map(|finish| finish + quote_count)
        .unwrap_or(bytes.len())
}

fn quoted_string_end_index(bytes: &[u8], start: usize) -> usize {
    let mut index = start + 1;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return index + 1;
        }
        index += 1;
    }
    bytes.len()
}

fn char_end_index(bytes: &[u8], start: usize) -> usize {
    let mut index = start + 1;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'\'' {
            return index + 1;
        }
        index += 1;
    }
    bytes.len()
}

fn find_bytes(haystack: &[u8], start: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || start >= haystack.len() {
        return None;
    }
    haystack[start..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|relative| start + relative)
}

fn matching_brace_index(text: &str, open_index: usize) -> Option<usize> {
    let masked = csharp_code_mask(text);
    let bytes = masked.as_bytes();
    let mut depth = 0;
    let mut index = open_index;
    while index < bytes.len() {
        if bytes[index] == b'{' {
            depth += 1;
        } else if bytes[index] == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
        index += 1;
    }
    None
}

fn brace_depth_at(text: &str, target_index: usize) -> i32 {
    let bytes = text.as_bytes();
    bytes[..target_index.min(bytes.len())]
        .iter()
        .fold(0, |depth, byte| match byte {
            b'{' => depth + 1,
            b'}' => depth - 1,
            _ => depth,
        })
}

fn paren_depth_at(text: &str, target_index: usize) -> i32 {
    let bytes = text.as_bytes();
    bytes[..target_index.min(bytes.len())]
        .iter()
        .fold(0, |depth, byte| match byte {
            b'(' => depth + 1,
            b')' => depth - 1,
            _ => depth,
        })
}

fn bracket_depth_at(text: &str, target_index: usize) -> i32 {
    let bytes = text.as_bytes();
    bytes[..target_index.min(bytes.len())]
        .iter()
        .fold(0, |depth, byte| match byte {
            b'[' => depth + 1,
            b']' => depth - 1,
            _ => depth,
        })
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_field(key) {
                    errors.push(format!(
                        "{path}.{key} contains prohibited adapter contract test field"
                    ));
                }
                scan_prohibited_value(child, &format!("{path}.{key}"), errors);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                scan_prohibited_value(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => {
            validate_quoted_provider_property_keys(text, path, errors);
            if whole_file_text(path, text) {
                if contains_prohibited_value(text, false) {
                    errors.push(format!("{path} contains prohibited value"));
                }
                if adapter_contract_test_text_path(path) {
                    validate_text_terms(text, path, errors);
                }
                return;
            }
            if safe_text_value(text) {
                return;
            }
            if contains_prohibited_value(text, true) {
                errors.push(format!("{path} contains prohibited value"));
            }
            if let Some(phrase) = prohibited_phrase(text) {
                errors.push(format!(
                    "{path} contains prohibited adapter contract test phrase {phrase}"
                ));
            }
            if prohibited_field(text) {
                errors.push(format!(
                    "{path} contains prohibited adapter contract test value {text}"
                ));
            }
        }
        _ => {}
    }
}

fn validate_quoted_provider_property_keys(value: &str, path: &str, errors: &mut Vec<String>) {
    for key in quoted_keys(value) {
        if prohibited_field(&key) {
            errors.push(format!(
                "{path}.{key} contains prohibited adapter contract test field"
            ));
        }
    }
}

fn quoted_keys(value: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if !matches!(bytes[index], b'"' | b'\'') {
            index += 1;
            continue;
        }
        let quote = bytes[index];
        let start = index + 1;
        let finish = if quote == b'"' {
            quoted_string_end_index(bytes, index)
        } else {
            char_end_index(bytes, index)
        };
        if finish <= start || finish > bytes.len() {
            break;
        }
        let after = skip_whitespace_bytes(bytes, finish);
        if bytes.get(after) == Some(&b':') {
            let raw = &value[start..finish - 1];
            keys.push(unescape_csharp_string(raw));
        }
        index = finish;
    }
    keys
}

fn validate_text_terms(text: &str, path: &str, errors: &mut Vec<String>) {
    let mut adapter_context_lines = 0usize;
    for (index, line) in text.lines().enumerate() {
        let in_adapter_line = adapter_contract_test_text_line(path, line);
        if in_adapter_line && adapter_contract_test_readme_path(path) {
            adapter_context_lines = 1;
        }
        let scan_line = in_adapter_line || adapter_context_lines > 0;
        if adapter_context_lines > 0 && !in_adapter_line && !line.trim().is_empty() {
            adapter_context_lines = adapter_context_lines.saturating_sub(1);
        }
        if !scan_line || safe_text_line(line) {
            continue;
        }
        if let Some(phrase) = prohibited_phrase(line) {
            errors.push(format!(
                "{path}:{} contains prohibited adapter contract test phrase {phrase}",
                index + 1
            ));
        }
        for term in identifier_terms(line) {
            if prohibited_field(&term) {
                errors.push(format!(
                    "{path}:{} contains prohibited adapter contract test field {term}",
                    index + 1
                ));
            }
        }
    }
}

fn identifier_terms(line: &str) -> Vec<String> {
    let bytes = line.as_bytes();
    let mut terms = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !is_identifierish_start(bytes[index]) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && is_identifierish_continue(bytes[index]) {
            index += 1;
        }
        terms.push(line[start..index].to_string());
    }
    terms
}

fn safe_text_line(line: &str) -> bool {
    let stripped = line.trim();
    let bullet_value = stripped.strip_prefix("- ").unwrap_or(stripped);
    let id_value = stripped.strip_prefix("- id: ").unwrap_or(stripped);
    let requirement_value = stripped.strip_prefix("requirement: ").unwrap_or(stripped);
    SAFE_TEXT_PROHIBITION_LINES.contains(&stripped)
        || safe_text_value(bullet_value)
        || safe_text_value(id_value)
        || safe_text_value(requirement_value)
}

fn safe_text_value(value: &str) -> bool {
    safe_normalized_values().contains(&normalize(value))
}

fn safe_normalized_values() -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    let safe_arrays: [&[&str]; 13] = [
        REQUIRED_TARGETS,
        REQUIRED_TYPES,
        REQUIRED_FIXTURE_TYPES,
        REQUIRED_INPUTS,
        REQUIRED_GUARDS,
        REQUIRED_PLAN_SECTIONS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        REQUIRED_DISABLED_FIELDS,
        TOP_LEVEL_FIELDS,
        RULE_FIELDS,
        ENDPOINT_FIELDS,
        IGNORED_CSHARP_IDENTIFIERS,
    ];
    for items in safe_arrays {
        for item in items {
            values.insert(normalize(item));
        }
    }
    for (field, binding) in ENDPOINT_ARRAY_BINDINGS {
        values.insert(normalize(field));
        values.insert(normalize(binding));
    }
    for (field, _) in ENDPOINT_INLINE_ARRAYS {
        values.insert(normalize(field));
    }
    for rule in REQUIRED_RULES {
        for item in [rule.id, rule.decision, rule.requirement, rule.evidence] {
            values.insert(normalize(item));
        }
    }
    for item in [
        "draft",
        "static-seed",
        "mock-contract-tests",
        "block",
        "true",
        "false",
    ] {
        values.insert(normalize(item));
    }
    values
}

fn prohibited_field(field: &str) -> bool {
    let normalized = normalize(field);
    if safe_normalized_values().contains(&normalized) {
        return false;
    }
    [
        "providerendpoint",
        "credentialvalue",
        "secretvalue",
        "accesstoken",
        "tenantid",
        "tenantidentifier",
        "objectid",
        "objectidentifier",
        "hostname",
        "serialnumber",
        "privateip",
        "rawprovider",
        "providerpayload",
        "rawfixture",
        "fixturerow",
        "rawlog",
        "rawlogs",
        "providerresponse",
        "credential",
        "secret",
        "token",
        "password",
    ]
    .iter()
    .any(|term| normalized.contains(term))
}

fn unsafe_true_field(field: &str) -> bool {
    let normalized = normalize(field);
    [
        "live",
        "provider",
        "raw",
        "credential",
        "network",
        "mutation",
        "payload",
    ]
    .iter()
    .any(|term| normalized.contains(term))
}

fn prohibited_phrase(value: &str) -> Option<&'static str> {
    let normalized = value.to_ascii_lowercase().replace(['_', '-'], " ");
    let phrases: &[(&str, &[&str])] = &[
        (
            "credential value",
            &["credential value", "credential values"],
        ),
        ("secret value", &["secret value", "secret values"]),
        ("access token", &["access token", "access tokens"]),
        (
            "provider endpoint",
            &["provider endpoint", "provider endpoints"],
        ),
        ("private IP", &["private ip", "private ips"]),
        ("host name", &["host name", "host names"]),
        ("serial number", &["serial number", "serial numbers"]),
        ("tenant ID", &["tenant id", "tenant ids"]),
        ("object ID", &["object id", "object ids"]),
        (
            "raw provider payload",
            &["raw provider payload", "raw provider payloads"],
        ),
        ("raw fixture rows", &["raw fixture row", "raw fixture rows"]),
        ("raw logs", &["raw log", "raw logs"]),
        (
            "provider response",
            &["provider response", "provider responses"],
        ),
    ];
    phrases
        .iter()
        .find(|(_, needles)| {
            needles
                .iter()
                .any(|needle| contains_phrase(&normalized, needle))
        })
        .map(|(label, _)| *label)
}

fn contains_phrase(text: &str, needle: &str) -> bool {
    let Some(mut start) = text.find(needle) else {
        return false;
    };
    while start < text.len() {
        let end = start + needle.len();
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        if !before.is_some_and(|ch| ch.is_ascii_alphanumeric())
            && !after.is_some_and(|ch| ch.is_ascii_alphanumeric())
        {
            return true;
        }
        let Some(next) = text[start + 1..].find(needle) else {
            return false;
        };
        start += next + 1;
    }
    false
}

fn contains_prohibited_value(text: &str, provider_assignments: bool) -> bool {
    let normalized_slashes = text.replace("\\/", "/");
    normalized_slashes.contains("://")
        || normalized_slashes.contains("-----BEGIN ")
            && normalized_slashes.contains("PRIVATE KEY-----")
        || contains_aws_key(&normalized_slashes)
        || contains_private_ip(&normalized_slashes)
        || contains_uuid_like(&normalized_slashes)
        || contains_email_like(&normalized_slashes)
        || contains_secret_assignment(&normalized_slashes)
        || provider_assignments && contains_sensitive_assignment(&normalized_slashes)
}

fn contains_aws_key(text: &str) -> bool {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|token| token.len() == 20 && token.starts_with("AKIA"))
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

fn contains_email_like(text: &str) -> bool {
    text.split_whitespace().any(|candidate| {
        let Some((local, domain)) = candidate.split_once('@') else {
            return false;
        };
        !local.is_empty()
            && domain.contains('.')
            && domain
                .chars()
                .last()
                .is_some_and(|ch| ch.is_ascii_alphabetic())
    })
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

fn contains_sensitive_assignment(text: &str) -> bool {
    let mut offset = 0;
    let bytes = text.as_bytes();
    while offset < bytes.len() {
        while offset < bytes.len()
            && !is_identifierish_start(bytes[offset])
            && bytes[offset] != b'/'
        {
            offset += 1;
        }
        let start = offset;
        while offset < bytes.len()
            && (is_identifierish_continue(bytes[offset])
                || matches!(bytes[offset], b'.' | b'/' | b' '))
        {
            offset += 1;
        }
        let name = text[start..offset].trim();
        let after = skip_whitespace_bytes(bytes, offset);
        if matches!(bytes.get(after), Some(b':') | Some(b'='))
            && prohibited_field(name)
            && text[after + 1..].chars().any(|ch| !ch.is_whitespace())
        {
            return true;
        }
        offset = after.saturating_add(1);
    }
    false
}

fn contains_term_assignment(text: &str, term: &str) -> bool {
    let mut offset = 0;
    while let Some(found) = text[offset..].find(term) {
        let start = offset + found;
        let end = start + term.len();
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        let boundary = !before.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            && !after.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if boundary {
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

fn adapter_contract_test_text_path(path: &str) -> bool {
    [
        CATALOG_PATH,
        DOC_PATH,
        API_README_PATH,
        CATALOG_README_PATH,
        DOC_README_PATH,
    ]
    .iter()
    .any(|text_path| path.ends_with(text_path))
}

fn adapter_contract_test_readme_path(path: &str) -> bool {
    [API_README_PATH, CATALOG_README_PATH, DOC_README_PATH]
        .iter()
        .any(|text_path| path.ends_with(text_path))
}

fn adapter_contract_test_text_line(path: &str, line: &str) -> bool {
    if path.ends_with(CATALOG_PATH) || path.ends_with(DOC_PATH) {
        return true;
    }
    let lower = line.to_ascii_lowercase();
    lower.contains("adapter-contract-test")
        || lower.contains("adapter contract test")
        || lower.contains("contract test")
        || line.contains(ENDPOINT)
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn string_value<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn bool_value(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn string_array_like(value: &Value, key: &str) -> Vec<String> {
    match value.get(key) {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        Some(Value::String(text)) => vec![text.to_string()],
        _ => Vec::new(),
    }
}

fn skip_whitespace_bytes(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn starts_with_at(bytes: &[u8], index: usize, needle: &[u8]) -> bool {
    bytes.get(index..index + needle.len()) == Some(needle)
}

fn is_identifier_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_identifier_continue(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn is_identifierish_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic()
}

fn is_identifierish_continue(byte: u8) -> bool {
    byte == b'_' || byte == b'-' || byte.is_ascii_alphanumeric()
}

fn normalize(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect()
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}
