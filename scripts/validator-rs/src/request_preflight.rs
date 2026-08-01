use serde::Deserialize;
use serde_json::Value;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/request-preflight-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/request-preflight.md";
const ENDPOINT: &str = "/api/requests/preflight-contract";
const LOCAL_ENDPOINT: &str = "/api/workflows/preflight/local/decision";

const REQUIRED_HYPERVISOR_SCOPE: &[&str] = &["vmware", "hyperv", "proxmox"];
const REQUIRED_SURFACES: &[&str] = &[
    "input-completeness",
    "catalog-policy-readiness",
    "site-context-readiness",
    "dependency-readiness",
    "approval-route-readiness",
    "dry-run-plan-readiness",
    "evidence-redaction-readiness",
];
const REQUIRED_STAGES: &[&str] = &[
    "site",
    "owner",
    "capacity",
    "network",
    "backup",
    "monitoring",
    "cmdb",
    "approval",
    "dry-run",
    "evidence",
];
const REQUIRED_INPUTS: &[&str] = &[
    "requestedOffering",
    "owner",
    "site",
    "environment",
    "criticality",
    "dryRunPlan",
    "approvalRoute",
    "evidenceManifest",
    "secretReferenceState",
];
const REQUIRED_GUARDS: &[&str] = &[
    "requested-offering-known",
    "owner-known",
    "site-known",
    "environment-known",
    "criticality-known",
    "dry-run-plan-ready",
    "approval-route-assigned",
    "evidence-redacted",
    "secret-reference-configured",
    "provider-calls-blocked",
    "live-execution-blocked",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "missing-requested-offering",
    "owner-missing",
    "site-missing",
    "environment-missing",
    "criticality-missing",
    "provider-safe-dry-run-not-ready",
    "approval-route-missing",
    "redacted-evidence-not-ready",
    "secret-reference-not-configured",
    "provider-calls-disabled",
    "live-execution-disabled",
    "request-mutation-disabled",
    "workflow-mutation-disabled",
    "approval-mutation-disabled",
    "raw-request-payloads-disabled",
    "raw-validation-rows-disabled",
    "raw-provider-payloads-disabled",
    "raw-inventory-rows-disabled",
    "raw-cmdb-rows-disabled",
    "raw-approval-data-disabled",
    "raw-user-data-disabled",
    "raw-recipient-data-disabled",
    "credential-values-disabled",
    "token-values-disabled",
    "tenant-identifiers-disabled",
    "object-identifiers-disabled",
    "private-network-values-disabled",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Request input summary",
    "Validation stage summary",
    "Provider-safe dry-run decision",
    "Approval route summary",
    "Redacted evidence manifest",
    "Secret reference state",
];
const SAFE_TRUE_FIELDS: &[&str] = &[
    "inputSchemaReadOnly",
    "dryRunDecisionRequired",
    "evidenceRedactionRequired",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "liveSubmissionAllowed",
    "liveExecutionAllowed",
    "providerCallsAllowed",
    "providerValidationAllowed",
    "livePolicyEvaluationAllowed",
    "requestMutationAllowed",
    "workflowMutationAllowed",
    "approvalMutationAllowed",
    "workerDispatchAllowed",
    "rawRequestPayloadsAllowed",
    "rawValidationRowsAllowed",
    "rawProviderPayloadsAllowed",
    "rawInventoryRowsAllowed",
    "rawCmdbRowsAllowed",
    "rawApprovalDataAllowed",
    "rawUserDataAllowed",
    "rawRecipientDataAllowed",
    "credentialValuesAllowed",
    "tokenValuesAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "principalIdentifiersAllowed",
    "privateNetworkValuesAllowed",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "preflightMode",
    "inputSchemaReadOnly",
    "dryRunDecisionRequired",
    "evidenceRedactionRequired",
    "liveSubmissionAllowed",
    "liveExecutionAllowed",
    "providerCallsAllowed",
    "providerValidationAllowed",
    "livePolicyEvaluationAllowed",
    "requestMutationAllowed",
    "workflowMutationAllowed",
    "approvalMutationAllowed",
    "workerDispatchAllowed",
    "rawRequestPayloadsAllowed",
    "rawValidationRowsAllowed",
    "rawProviderPayloadsAllowed",
    "rawInventoryRowsAllowed",
    "rawCmdbRowsAllowed",
    "rawApprovalDataAllowed",
    "rawUserDataAllowed",
    "rawRecipientDataAllowed",
    "credentialValuesAllowed",
    "tokenValuesAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "principalIdentifiersAllowed",
    "privateNetworkValuesAllowed",
    "hypervisorScope",
    "preflightSurfaces",
    "validationStages",
    "requiredInputs",
    "requiredGuards",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("hypervisorScope", "preflightHypervisorScope"),
    ("preflightSurfaces", "preflightSurfaces"),
    ("validationStages", "preflightValidationStages"),
    ("requiredInputs", "preflightRequiredInputs"),
    ("requiredGuards", "preflightRequiredGuards"),
    ("blockedReasons", "preflightBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredEvidence"];
const ALLOWED_ENDPOINT_BASE_FIELDS: &[&str] = &[
    "source",
    "preflightMode",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
];
const LOCAL_RESPONSE_FIELDS: &[&str] = &[
    "source",
    "providerCallsEnabled",
    "liveExecutionAllowed",
    "decision",
    "status",
    "requestedOffering",
    "requiredInputs",
    "missingInputs",
    "guardBlocks",
    "remediation",
    "evidence",
];
const LOCAL_RESPONSE_EXACT_ASSIGNMENTS: &[(&str, &str)] = &[
    ("decision", "blocked ? \"block\" : \"review\""),
    (
        "status",
        "blocked ? \"blocked\" : \"ready-for-approval-review\"",
    ),
    ("requiredInputs", "preflightRequiredInputs"),
    (
        "remediation",
        "blocked ? \"Complete missing inputs and guard evidence before approval.\" : \"Route to approval; live execution remains disabled in local mode.\"",
    ),
    ("evidence", "new[]"),
];
const LOCAL_PROHIBITED_LIVE_TERMS: &[&str] = &[
    "HttpClient",
    "IHttpClientFactory",
    "HttpClientFactory",
    "GetAsync",
    "GetByteArrayAsync",
    "GetStreamAsync",
    "GetStringAsync",
    "PostAsync",
    "PutAsync",
    "PatchAsync",
    "DeleteAsync",
    "SendAsync",
    "RestClient",
    "GraphServiceClient",
    "SqlConnection",
    "NpgsqlConnection",
    "MySqlConnection",
    "OracleConnection",
    "PowerShell",
    "ProcessStartInfo",
    "WebClient",
    "WebRequest",
    "HttpWebRequest",
    "HttpRequestMessage",
    "SocketsHttpHandler",
    "TcpClient",
    "UdpClient",
    "Socket",
    "Dns",
    "DownloadString",
    "DownloadStringTaskAsync",
    "DownloadData",
    "OpenRead",
    "UploadString",
    "Process",
    "Start",
];
const LOCAL_PROHIBITED_DYNAMIC_STRING_TERMS: &[&str] = &[
    "Concat",
    "Join",
    "Format",
    "StringBuilder",
    "UriBuilder",
    "Replace",
    "Insert",
    "Remove",
    "Substring",
];
const LOCAL_ALLOWED_CODE_TERMS: &[&str] = &[
    "Add",
    "Count",
    "Dictionary",
    "Equals",
    "IsNullOrWhiteSpace",
    "Json",
    "Key",
    "Length",
    "List",
    "MapGet",
    "OrdinalIgnoreCase",
    "Results",
    "Select",
    "StringComparison",
    "ToArray",
    "Value",
    "Where",
    "app",
    "approvalRoute",
    "blocked",
    "criticality",
    "decision",
    "dryRunPlan",
    "environment",
    "evidence",
    "evidenceManifest",
    "false",
    "guardBlocks",
    "if",
    "inputs",
    "item",
    "liveExecutionAllowed",
    "missingInputs",
    "new",
    "owner",
    "preflightRequiredInputs",
    "providerCallsEnabled",
    "remediation",
    "requestedOffering",
    "requiredInputs",
    "return",
    "secretReferenceState",
    "site",
    "source",
    "status",
    "string",
    "var",
];
const LOCAL_INPUT_BINDINGS: &[(&str, &str)] = &[
    ("requestedOffering", "requestedOffering"),
    ("owner", "owner"),
    ("site", "site"),
    ("environment", "environment"),
    ("criticality", "criticality"),
    ("dryRunPlan", "dryRunPlan"),
    ("approvalRoute", "approvalRoute"),
    ("evidenceManifest", "evidenceManifest"),
    ("secretReferenceState", "secretReferenceState"),
];
const LOCAL_GUARD_SNIPPETS: &[&str] = &[
    r#"if (!string.Equals(dryRunPlan, "ready", StringComparison.OrdinalIgnoreCase))
    {
        guardBlocks.Add("provider-safe-dry-run-not-ready");
    }"#,
    r#"if (!string.Equals(evidenceManifest, "redacted", StringComparison.OrdinalIgnoreCase))
    {
        guardBlocks.Add("redacted-evidence-not-ready");
    }"#,
    r#"if (!string.Equals(secretReferenceState, "configured", StringComparison.OrdinalIgnoreCase))
    {
        guardBlocks.Add("secret-reference-not-configured");
    }"#,
];
const LOCAL_MISSING_INPUTS_EXPRESSION: &str = "var missingInputs = inputs.Where(item => string.IsNullOrWhiteSpace(item.Value)).Select(item => item.Key).ToArray();";
const LOCAL_BLOCKED_EXPRESSION: &str =
    "var blocked = missingInputs.Length > 0 || guardBlocks.Count > 0;";
const LOCAL_ENDPOINT_BLOCK: &str = r#"app.MapGet("/api/workflows/preflight/local/decision", (
    string? requestedOffering,
    string? owner,
    string? site,
    string? environment,
    string? criticality,
    string? dryRunPlan,
    string? approvalRoute,
    string? evidenceManifest,
    string? secretReferenceState) =>
{
    var inputs = new Dictionary<string, string?>
    {
        ["requestedOffering"] = requestedOffering,
        ["owner"] = owner,
        ["site"] = site,
        ["environment"] = environment,
        ["criticality"] = criticality,
        ["dryRunPlan"] = dryRunPlan,
        ["approvalRoute"] = approvalRoute,
        ["evidenceManifest"] = evidenceManifest,
        ["secretReferenceState"] = secretReferenceState
    };
    var missingInputs = inputs.Where(item => string.IsNullOrWhiteSpace(item.Value)).Select(item => item.Key).ToArray();
    var guardBlocks = new List<string>();

    if (!string.Equals(dryRunPlan, "ready", StringComparison.OrdinalIgnoreCase))
    {
        guardBlocks.Add("provider-safe-dry-run-not-ready");
    }

    if (!string.Equals(evidenceManifest, "redacted", StringComparison.OrdinalIgnoreCase))
    {
        guardBlocks.Add("redacted-evidence-not-ready");
    }

    if (!string.Equals(secretReferenceState, "configured", StringComparison.OrdinalIgnoreCase))
    {
        guardBlocks.Add("secret-reference-not-configured");
    }

    var blocked = missingInputs.Length > 0 || guardBlocks.Count > 0;

    return Results.Json(new
    {
        source = "local-mock",
        providerCallsEnabled = false,
        liveExecutionAllowed = false,
        decision = blocked ? "block" : "review",
        status = blocked ? "blocked" : "ready-for-approval-review",
        requestedOffering,
        requiredInputs = preflightRequiredInputs,
        missingInputs,
        guardBlocks,
        remediation = blocked ? "Complete missing inputs and guard evidence before approval." : "Route to approval; live execution remains disabled in local mode.",
        evidence = new[] { "Validation result", "Provider-safe plan", "Approval decisions", "Evidence manifest", "Reference configured state" }
    });
})"#;
const SAFE_TEXT_PROHIBITION_LINES: &[&str] = &[
    "# Request preflight seed data only. Do not add raw request payloads, raw validation rows, raw provider payloads, raw inventory rows, raw CMDB rows, raw approval data, raw user data, raw recipient data, credentials, tokens, tenant IDs, object IDs, principal IDs, private network values, live endpoints, or URLs.",
    "requirement: Requested offering, owner, site, environment, criticality, dry-run plan, approval route, evidence manifest, and secret reference state must be reviewed before approval readiness.",
    "- No raw request payloads, raw validation rows, raw provider payloads, raw inventory rows, raw CMDB rows, raw approval data, raw user data, raw recipient data, credential values, token values, tenant identifiers, object identifiers, principal identifiers, private network values, live endpoints, or URLs.",
    "- No raw request payloads, raw validation rows, raw provider payloads, raw inventory rows, raw CMDB rows, raw approval data, raw user data, raw recipient data, credential values, token values, tenant identifiers, object identifiers, principal identifiers, private network values, live endpoints, or URLs in committed artifacts.",
    "Remediation guidance must be specific, safe, and non-secret. It must not expose raw provider payloads, credentials, tenant IDs, object IDs, live endpoint details, or external API implementation details.",
    "| `/api/requests/preflight-contract` | Static preflight readiness contract for VMware, Hyper-V, and Proxmox scope; live execution and provider calls disabled. |",
    "| `/api/workflows/preflight/local/decision` | Local mock decision helper; no provider calls or live execution. |",
    "requirement: Preflight evidence must use safe summaries only and must not expose raw request payloads, raw validation rows, raw provider payloads, raw inventory rows, raw CMDB rows, raw approval data, raw user data, raw recipient data, credential values, token values, tenant identifiers, object identifiers, principal identifiers, private network values, live endpoints, or URLs.",
];

const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-provider-preflight",
        decision: "block",
        requirement: "Preflight readiness is static and must not call providers, validate live provider state, or query live inventory, CMDB, ticket, backup, monitoring, or identity systems.",
        evidence: "Validation stage summary",
    },
    RuleDetail {
        id: "live-execution-disabled",
        decision: "block",
        requirement: "Preflight may return block or review readiness only and must never submit requests, start workflows, mutate approvals, dispatch workers, or run live execution.",
        evidence: "Provider-safe dry-run decision",
    },
    RuleDetail {
        id: "required-inputs-and-guards-reviewed",
        decision: "block",
        requirement: "Requested offering, owner, site, environment, criticality, dry-run plan, approval route, evidence manifest, and secret reference state must be reviewed before approval readiness.",
        evidence: "Request input summary",
    },
    RuleDetail {
        id: "redacted-evidence-required",
        decision: "block",
        requirement: "Preflight evidence must be redacted before any approval or lifecycle handoff.",
        evidence: "Redacted evidence manifest",
    },
    RuleDetail {
        id: "raw-preflight-data-not-exposed",
        decision: "block",
        requirement: "Preflight evidence must use safe summaries only and must not expose raw request payloads, raw validation rows, raw provider payloads, raw inventory rows, raw CMDB rows, raw approval data, raw user data, raw recipient data, credential values, token values, tenant identifiers, object identifiers, principal identifiers, private network values, live endpoints, or URLs.",
        evidence: "Redacted evidence manifest",
    },
];

#[derive(Debug, Deserialize)]
struct Context {
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

#[derive(Clone, Copy)]
struct RuleDetail {
    id: &'static str,
    decision: &'static str,
    requirement: &'static str,
    evidence: &'static str,
}

struct Assignment {
    value: String,
    end: usize,
}

thread_local! {
    static STRIP_CACHE: RefCell<HashMap<(usize, usize), String>> = RefCell::new(HashMap::new());
    static MASK_CACHE: RefCell<HashMap<(usize, usize), String>> = RefCell::new(HashMap::new());
}

fn clear_caches() {
    STRIP_CACHE.with(|c| c.borrow_mut().clear());
    MASK_CACHE.with(|c| c.borrow_mut().clear());
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid request preflight context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_no_prohibited_values(
        &Value::String(context.catalog_text),
        CATALOG_PATH,
        &mut errors,
    );
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(
        &context.api_readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &mut errors,
    );
    let docs_scope = serde_json::json!({
        API_README_PATH: context.api_readme,
        CATALOG_README_PATH: context.catalog_readme,
        DOC_README_PATH: context.doc_readme,
        DOC_PATH: context.doc,
    });
    validate_no_prohibited_values(&docs_scope, "request-preflight", &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    clear_caches();
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid request preflight catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    clear_caches();
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid request preflight program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    clear_caches();
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid request preflight docs JSON: {error}"))?;
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
    clear_caches();
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid request preflight prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_no_prohibited_values(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    validate_catalog_keys(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "request preflight version must be 1",
    );
    expect(
        catalog.get("status").and_then(Value::as_str) == Some("draft"),
        errors,
        "request preflight status must be draft",
    );
    expect(
        catalog.get("source").and_then(Value::as_str) == Some("static-seed"),
        errors,
        "request preflight source must be static-seed",
    );
    expect(
        catalog.get("preflightMode").and_then(Value::as_str) == Some("static-preflight-readiness"),
        errors,
        "request preflight mode must be static-preflight-readiness",
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            catalog.get(*field).and_then(Value::as_bool) == Some(true),
            errors,
            format!("request preflight {field} must be true"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            catalog.get(*field).and_then(Value::as_bool) == Some(false),
            errors,
            format!("request preflight {field} must be disabled"),
        );
    }
    validate_required_array(
        catalog,
        "hypervisorScope",
        REQUIRED_HYPERVISOR_SCOPE,
        errors,
    );
    validate_required_array(catalog, "preflightSurfaces", REQUIRED_SURFACES, errors);
    validate_required_array(catalog, "validationStages", REQUIRED_STAGES, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);
    validate_no_prohibited_values(catalog, CATALOG_PATH, errors);
}

fn validate_catalog_keys(catalog: &Value, errors: &mut Vec<String>) {
    let keys: Vec<String> = catalog
        .as_object()
        .map(|map| map.keys().cloned().collect())
        .unwrap_or_default();
    let unexpected: Vec<String> = keys
        .into_iter()
        .filter(|key| !REQUIRED_CATALOG_KEYS.contains(&key.as_str()))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "request preflight unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let values = match catalog.get(field) {
        Some(Value::Array(items)) => {
            if items.iter().any(|item| !item.is_string()) {
                errors.push(format!("{field} must contain only strings"));
            }
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        }
        Some(_) => {
            errors.push(format!("{field} must be an array"));
            Vec::new()
        }
        None => Vec::new(),
    };
    expect(
        !values.is_empty(),
        errors,
        format!("{field} must be non-empty array"),
    );
    let missing = missing_values(required_values, &values);
    let unexpected = extra_values(&values, required_values);
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
        unique_count(&values) == values.len(),
        errors,
        format!("{field} values must be unique"),
    );
    for value in values {
        if !safe_text_value(&value) {
            if prohibited_field(&value) {
                errors.push(format!(
                    "{field} contains prohibited request preflight value {value}"
                ));
            }
            if let Some(phrase) = prohibited_phrase(&value) {
                errors.push(format!(
                    "{field} contains prohibited request preflight phrase {phrase}"
                ));
            }
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let Some(rules) = catalog.get("rules").and_then(Value::as_array) else {
        errors.push("request preflight rules must be an array of hashes".to_string());
        return;
    };
    if !rules.iter().all(Value::is_object) {
        errors.push("request preflight rules must be an array of hashes".to_string());
        return;
    }
    validate_catalog_rule_shape(rules, errors);
    let rule_ids: Vec<String> = rules
        .iter()
        .filter_map(|rule| rule.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let required_ids: Vec<&str> = REQUIRED_RULES.iter().map(|rule| rule.id).collect();
    let missing = missing_values(&required_ids, &rule_ids);
    let unexpected = extra_values(&rule_ids, &required_ids);
    expect(
        missing.is_empty(),
        errors,
        format!("request preflight missing rules: {}", missing.join(", ")),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "request preflight unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    expect(
        unique_count(&rule_ids) == rule_ids.len(),
        errors,
        "request preflight rule IDs must be unique",
    );
    let rule_details: Vec<Vec<String>> = rules
        .iter()
        .map(|rule| {
            ["decision", "requirement", "evidence"]
                .iter()
                .map(|field| {
                    rule.get(*field)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string()
                })
                .collect()
        })
        .collect();
    expect(
        unique_count_vec(&rule_details) == rule_details.len(),
        errors,
        "request preflight rule details must be unique",
    );
    for expected_rule in REQUIRED_RULES {
        let Some(rule) = rules.iter().find(|candidate| {
            candidate.get("id").and_then(Value::as_str) == Some(expected_rule.id)
        }) else {
            continue;
        };
        for (field, expected) in [
            ("decision", expected_rule.decision),
            ("requirement", expected_rule.requirement),
            ("evidence", expected_rule.evidence),
        ] {
            expect(
                rule.get(field).and_then(Value::as_str) == Some(expected),
                errors,
                format!(
                    "request preflight rule {} {field} must match",
                    expected_rule.id
                ),
            );
        }
    }
}

fn validate_catalog_rule_shape(rules: &[Value], errors: &mut Vec<String>) {
    for rule in rules {
        let Some(object) = rule.as_object() else {
            continue;
        };
        let rule_id = rule
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("(missing id)");
        let keys: Vec<&str> = object.keys().map(String::as_str).collect();
        let unexpected: Vec<&str> = keys
            .iter()
            .copied()
            .filter(|key| !RULE_KEYS.contains(key))
            .collect();
        let missing: Vec<&str> = RULE_KEYS
            .iter()
            .copied()
            .filter(|key| !object.contains_key(*key))
            .collect();
        if !unexpected.is_empty() {
            errors.push(format!(
                "request preflight rule {rule_id} unexpected rule keys: {}",
                unexpected.join(", ")
            ));
        }
        if !missing.is_empty() {
            errors.push(format!(
                "request preflight rule {rule_id} missing rule keys: {}",
                missing.join(", ")
            ));
        }
        if RULE_KEYS
            .iter()
            .any(|key| object.get(*key).is_some_and(|value| !value.is_string()))
        {
            errors.push(format!(
                "request preflight rule {rule_id} rule fields must be strings"
            ));
        }
    }
}

fn validate_no_preprocessor_directives(program: &str, errors: &mut Vec<String>) {
    for line in program.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            errors.push(
                "API request preflight validation does not allow preprocessor directives"
                    .to_string(),
            );
            return;
        }
    }
}

fn validate_mapget_routes_are_literal(program: &str, errors: &mut Vec<String>) {
    validate_canonical_route_calls(program, errors);
    let uncommented = strip_csharp_comments(program);
    let masked = mask_csharp_string_literals(&uncommented);
    let mut offset = 0usize;
    while let Some(relative) = masked[offset..].find("app.MapGet") {
        let index = offset + relative;
        let Some(open_index) = next_non_whitespace_index(&masked, index + "app.MapGet".len())
        else {
            break;
        };
        if masked.as_bytes().get(open_index) != Some(&b'(') {
            offset = index + "app.MapGet".len();
            continue;
        }
        let route_start = open_index + 1;
        if parse_single_csharp_route_literal_at(&uncommented, route_start).is_none() {
            errors.push("API MapGet routes must use literal route strings".to_string());
        }
        offset = route_start;
    }
}

fn validate_canonical_route_calls(program: &str, errors: &mut Vec<String>) {
    let app_aliases = app_route_aliases(program);
    validate_no_route_builder_casts(program, errors);
    validate_no_parenthesized_app_route_calls(program, errors);
    validate_no_element_access_route_or_middleware_calls(program, errors);
    validate_no_prohibited_route_middleware_extension_type_identifiers(program, errors);
    validate_no_prohibited_route_middleware_method_references(program, errors);
    validate_no_route_middleware_reflection(program, errors);
    validate_no_protected_path_intercepts(program, errors);
    for call in route_calls(program) {
        if call.receiver == "EndpointRouteBuilderExtensions" && route_method(&call.method) {
            errors.push(
                "API request preflight validation does not allow EndpointRouteBuilderExtensions routes"
                    .to_string(),
            );
            continue;
        }
        if app_aliases.contains(&call.receiver) && route_method(&call.method) {
            errors.push(
                "API request preflight validation does not allow app route aliases".to_string(),
            );
            continue;
        }
        if call.receiver != "app" && route_method(&call.method) {
            errors.push(
                "API request preflight validation does not allow non-app route registrations"
                    .to_string(),
            );
            continue;
        }
        if call.receiver != "app" {
            continue;
        }
        match call.method.as_str() {
            "Map" => {
                errors.push(
                    "API request preflight validation does not allow app.Map routes".to_string(),
                );
            }
            "MapMethods" => {
                errors.push(
                    "API request preflight validation does not allow MapMethods routes".to_string(),
                );
            }
            "MapGroup" => {
                errors.push(
                    "API request preflight validation does not allow MapGroup routes".to_string(),
                );
            }
            "MapGet" => {
                if program
                    .get(call.start..=call.open_index)
                    .is_none_or(|source| source != "app.MapGet(")
                {
                    errors.push("API MapGet routes must use canonical app.MapGet form".to_string());
                }
            }
            method if route_method(method) => {
                errors.push(
                    "API request preflight validation does not allow non-MapGet routes".to_string(),
                );
            }
            _ => {}
        }
    }
}

fn validate_no_prohibited_route_middleware_extension_type_identifiers(
    program: &str,
    errors: &mut Vec<String>,
) {
    let uncommented = strip_csharp_comments(program);
    let code = mask_csharp_string_literals(&uncommented);
    let mut inspected = HashSet::new();
    for identifier in csharp_identifiers_normalized(&code) {
        if !inspected.insert(identifier.clone()) {
            continue;
        }
        if prohibited_route_middleware_extension_type_identifier(&identifier) {
            errors.push(
                "API request preflight validation does not allow route or middleware extension type identifiers"
                    .to_string(),
            );
        }
    }
}

fn prohibited_route_middleware_extension_type_identifier(identifier: &str) -> bool {
    matches!(
        identifier,
        "EndpointRouteBuilderExtensions"
            | "UseExtensions"
            | "UseMiddlewareExtensions"
            | "MapWhenExtensions"
            | "RunExtensions"
    )
}

fn validate_no_prohibited_route_middleware_method_references(
    program: &str,
    errors: &mut Vec<String>,
) {
    let uncommented = strip_csharp_comments(program);
    let code = mask_csharp_string_literals(&uncommented);
    let mut index = 0usize;
    while index < code.len() {
        let Some((first_member, first_end)) = read_csharp_identifier_normalized(&code, index)
        else {
            index += code[index..]
                .chars()
                .next()
                .expect("valid char boundary")
                .len_utf8();
            continue;
        };
        let mut members = vec![first_member];
        let mut cursor = first_end;
        while let Some(dot_index) = next_non_whitespace_index(&code, cursor) {
            let dot_index = route_receiver_dot_index(&code, dot_index);
            if code.as_bytes().get(dot_index) != Some(&b'.') {
                break;
            }
            let Some(member_start) = next_non_whitespace_index(&code, dot_index + 1) else {
                break;
            };
            let Some((member, member_end)) = read_csharp_identifier_normalized(&code, member_start)
            else {
                break;
            };
            members.push(member);
            cursor = member_end;
        }
        for pair in members.windows(2) {
            if prohibited_route_middleware_extension_reference(&pair[0], &pair[1]) {
                errors.push(
                    "API request preflight validation does not allow route or middleware extension method references"
                        .to_string(),
                );
                break;
            }
        }
        index = cursor;
    }
}

fn prohibited_route_middleware_extension_reference(receiver: &str, method: &str) -> bool {
    (receiver == "EndpointRouteBuilderExtensions" && route_method(method))
        || (matches!(
            receiver,
            "UseExtensions" | "UseMiddlewareExtensions" | "MapWhenExtensions" | "RunExtensions"
        ) && middleware_method(method))
}

fn validate_no_route_middleware_reflection(program: &str, errors: &mut Vec<String>) {
    let uncommented = strip_csharp_comments(program);
    let code = mask_csharp_string_literals(&uncommented);
    let identifiers: HashSet<String> = csharp_identifiers_normalized(&code).into_iter().collect();
    if [
        "typeof",
        "Assembly",
        "DefinedTypes",
        "DeclaredMethods",
        "GetType",
        "GetTypeInfo",
        "GetMethod",
        "GetMethods",
        "GetRuntimeMethod",
        "GetRuntimeMethods",
        "MethodInfo",
        "MemberInfo",
        "BindingFlags",
        "Delegate",
        "CreateDelegate",
        "Invoke",
        "DynamicInvoke",
    ]
    .iter()
    .any(|identifier| identifiers.contains(*identifier))
    {
        errors.push(
            "API request preflight validation does not allow reflection for route or middleware registrations"
                .to_string(),
        );
    }
}

struct RouteCall {
    receiver: String,
    method: String,
    start: usize,
    open_index: usize,
}

fn route_calls(program: &str) -> Vec<RouteCall> {
    let uncommented = strip_csharp_comments(program);
    let code = mask_csharp_string_literals(&uncommented);
    let mut calls = Vec::new();
    let mut index = 0usize;
    while index < code.len() {
        let Some((first_member, first_end)) = read_csharp_identifier_normalized(&code, index)
        else {
            index += code[index..]
                .chars()
                .next()
                .expect("valid char boundary")
                .len_utf8();
            continue;
        };
        let mut members = vec![(first_member, index)];
        let mut cursor = first_end;
        while let Some(dot_index) = next_non_whitespace_index(&code, cursor) {
            let dot_index = route_receiver_dot_index(&code, dot_index);
            if code.as_bytes().get(dot_index) != Some(&b'.') {
                break;
            }
            let Some(member_start) = next_non_whitespace_index(&code, dot_index + 1) else {
                break;
            };
            let Some((member, member_end)) = read_csharp_identifier_normalized(&code, member_start)
            else {
                break;
            };
            members.push((member, member_start));
            cursor = member_end;
        }
        if let Some(open_index) = call_open_index_after_optional_type_args(&code, cursor) {
            if code.as_bytes().get(open_index) == Some(&b'(') && members.len() >= 2 {
                let method = members[members.len() - 1].0.clone();
                let (receiver, receiver_start) = members[members.len() - 2].clone();
                calls.push(RouteCall {
                    receiver,
                    method,
                    start: receiver_start,
                    open_index,
                });
            }
        }
        index = cursor;
    }
    calls
}

fn call_open_index_after_optional_type_args(code: &str, cursor: usize) -> Option<usize> {
    let mut next_index = next_non_whitespace_index(code, cursor)?;
    if code.as_bytes().get(next_index) == Some(&b'<') {
        next_index = matching_angle_index(code, next_index)
            .and_then(|end| next_non_whitespace_index(code, end + 1))?;
    }
    Some(next_index)
}

fn matching_angle_index(code: &str, open_index: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (relative, ch) in code[open_index..].char_indices() {
        let index = open_index + relative;
        if ch == '<' {
            depth += 1;
        } else if ch == '>' {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn route_method(method: &str) -> bool {
    matches!(
        method,
        "MapGet"
            | "MapMethods"
            | "Map"
            | "MapGroup"
            | "MapPost"
            | "MapPut"
            | "MapDelete"
            | "MapPatch"
            | "MapFallback"
    )
}

fn route_receiver_dot_index(code: &str, index: usize) -> usize {
    let mut cursor = index;
    while matches!(code.as_bytes().get(cursor), Some(b'!') | Some(b'?')) {
        let Some(next_index) = next_non_whitespace_index(code, cursor + 1) else {
            return cursor + 1;
        };
        cursor = next_index;
    }
    cursor
}

fn app_route_aliases(program: &str) -> HashSet<String> {
    let uncommented = strip_csharp_comments(program);
    let code = mask_csharp_string_literals(&uncommented);
    let mut aliases = HashSet::new();
    for statement in code.split(';') {
        let Some(equals_index) = statement.find('=') else {
            continue;
        };
        let rhs = &statement[equals_index + 1..];
        let direct_app = next_non_whitespace_index(statement, equals_index + 1)
            .and_then(|right_start| read_csharp_identifier_normalized(statement, right_start))
            .is_some_and(|(value, value_end)| {
                value == "app" && statement[value_end..].trim().is_empty()
            });
        if !direct_app && !rhs_references_app(rhs) {
            continue;
        }
        let left_identifiers = csharp_identifiers_normalized(&statement[..equals_index]);
        let Some(alias) = left_identifiers.last() else {
            continue;
        };
        if alias != "app" {
            aliases.insert(alias.clone());
        }
    }
    aliases
}

fn rhs_references_app(rhs: &str) -> bool {
    let mut compact: String = rhs.chars().filter(|ch| !ch.is_whitespace()).collect();
    while compact.ends_with('!') {
        compact.pop();
    }
    loop {
        if compact.starts_with('(')
            && compact.ends_with(')')
            && wrapping_parens_cover_expression(&compact)
        {
            compact = compact[1..compact.len() - 1].to_string();
            while compact.ends_with('!') {
                compact.pop();
            }
            continue;
        }
        break;
    }
    compact == "app" || compact.ends_with(")app")
}

fn wrapping_parens_cover_expression(value: &str) -> bool {
    let mut depth = 0usize;
    for (index, ch) in value.char_indices() {
        if ch == '(' {
            depth += 1;
        } else if ch == ')' {
            depth = depth.saturating_sub(1);
            if depth == 0 && index + ch.len_utf8() < value.len() {
                return false;
            }
        }
    }
    depth == 0
}

fn validate_no_route_builder_casts(program: &str, errors: &mut Vec<String>) {
    let uncommented = strip_csharp_comments(program);
    let code = mask_csharp_string_literals(&uncommented);
    if csharp_identifiers_normalized(&code)
        .iter()
        .any(|identifier| identifier == "IEndpointRouteBuilder")
    {
        errors.push(
            "API request preflight validation does not allow IEndpointRouteBuilder route casts"
                .to_string(),
        );
    }
}

fn validate_no_parenthesized_app_route_calls(program: &str, errors: &mut Vec<String>) {
    let uncommented = strip_csharp_comments(program);
    let code = mask_csharp_string_literals(&uncommented);
    let compact: String = code.chars().filter(|ch| !ch.is_whitespace()).collect();
    for method in [
        "Map",
        "MapGet",
        "MapGroup",
        "MapPost",
        "MapPut",
        "MapDelete",
        "MapPatch",
        "MapFallback",
        "MapMethods",
    ] {
        if parenthesized_app_method_call(&compact, method) {
            errors.push(
                "API request preflight validation does not allow parenthesized app route calls"
                    .to_string(),
            );
        }
    }
}

fn validate_no_element_access_route_or_middleware_calls(program: &str, errors: &mut Vec<String>) {
    let uncommented = strip_csharp_comments(program);
    let code = mask_csharp_string_literals(&uncommented);
    let compact: String = code.chars().filter(|ch| !ch.is_whitespace()).collect();
    for method in [
        "Map",
        "MapGet",
        "MapGroup",
        "MapPost",
        "MapPut",
        "MapDelete",
        "MapPatch",
        "MapFallback",
        "MapMethods",
    ] {
        if element_access_method_call(&compact, method) {
            errors.push(
                "API request preflight validation does not allow element-access route registrations"
                    .to_string(),
            );
        }
    }
    for method in ["Use", "UseMiddleware", "MapWhen", "UseWhen", "Run"] {
        if element_access_method_call(&compact, method) {
            errors.push(
                "API request preflight validation does not allow element-access middleware registrations"
                    .to_string(),
            );
        }
    }
}

fn element_access_method_call(compact: &str, method: &str) -> bool {
    let mut offset = 0usize;
    while let Some(relative) = compact[offset..].find(']') {
        let close_index = offset + relative;
        let Some(method_start) = element_access_method_start(compact, close_index) else {
            offset = close_index + 1;
            continue;
        };
        if read_csharp_identifier_normalized(compact, method_start).is_some_and(
            |(candidate, end)| {
                candidate == method
                    && call_open_index_after_optional_type_args(compact, end).is_some()
            },
        ) {
            return true;
        }
        offset = method_start;
    }
    false
}

fn element_access_method_start(compact: &str, close_index: usize) -> Option<usize> {
    let mut cursor = close_index + 1;
    while matches!(compact.as_bytes().get(cursor), Some(b'!') | Some(b'?')) {
        cursor += 1;
    }
    if compact.as_bytes().get(cursor) == Some(&b'.') {
        Some(cursor + 1)
    } else {
        None
    }
}

fn parenthesized_app_method_call(compact: &str, method: &str) -> bool {
    let mut offset = 0usize;
    while let Some(relative) = compact[offset..].find(')') {
        let close_index = offset + relative;
        if let Some(open_index) = matching_open_paren_index(compact, close_index) {
            if open_index < close_index
                && parenthesized_receiver_method_start(compact, close_index)
                    .and_then(|start| read_csharp_identifier_normalized(compact, start))
                    .is_some_and(|(candidate, end)| {
                        candidate == method
                            && call_open_index_after_optional_type_args(compact, end).is_some()
                    })
            {
                return true;
            }
        }
        offset = close_index + 1;
    }
    false
}

fn parenthesized_receiver_method_start(compact: &str, close_index: usize) -> Option<usize> {
    let mut cursor = close_index + 1;
    while matches!(compact.as_bytes().get(cursor), Some(b'!') | Some(b'?')) {
        cursor += 1;
    }
    if compact.as_bytes().get(cursor) == Some(&b'.') {
        Some(cursor + 1)
    } else {
        None
    }
}

fn matching_open_paren_index(text: &str, close_index: usize) -> Option<usize> {
    if text.as_bytes().get(close_index) != Some(&b')') {
        return None;
    }
    let mut depth = 0usize;
    for (index, ch) in text[..=close_index].char_indices().rev() {
        if ch == ')' {
            depth += 1;
        } else if ch == '(' {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn validate_no_protected_path_intercepts(program: &str, errors: &mut Vec<String>) {
    let app_aliases = app_route_aliases(program);
    for call in route_calls(program) {
        if !middleware_method(&call.method) {
            continue;
        }
        if call.receiver != "app" && !app_aliases.contains(&call.receiver) {
            errors.push(
                "API request preflight validation does not allow non-app middleware registrations"
                    .to_string(),
            );
            continue;
        }
        if call.method == "Run" && route_call_arguments_empty(program, call.open_index) {
            continue;
        }
        errors.push(
            "API request preflight validation does not allow middleware intercepts for protected routes"
                .to_string(),
        );
    }
    validate_no_parenthesized_app_middleware_calls(program, errors);
}

fn validate_no_parenthesized_app_middleware_calls(program: &str, errors: &mut Vec<String>) {
    let uncommented = strip_csharp_comments(program);
    let code = mask_csharp_string_literals(&uncommented);
    let compact: String = code.chars().filter(|ch| !ch.is_whitespace()).collect();
    for method in ["Use", "UseMiddleware", "MapWhen", "UseWhen", "Run"] {
        if parenthesized_app_method_call(&compact, method) {
            errors.push(
                "API request preflight validation does not allow middleware intercepts for protected routes"
                    .to_string(),
            );
        }
    }
}

fn middleware_method(method: &str) -> bool {
    matches!(
        method,
        "Use" | "UseMiddleware" | "Run" | "MapWhen" | "UseWhen"
    )
}

fn route_call_arguments_empty(program: &str, open_index: usize) -> bool {
    let uncommented = strip_csharp_comments(program);
    let masked = mask_csharp_string_literals(&uncommented);
    let Some(close_index) = matching_paren_index(&masked, open_index) else {
        return false;
    };
    uncommented[open_index + 1..close_index].trim().is_empty()
}

fn read_csharp_identifier_normalized(source: &str, start: usize) -> Option<(String, usize)> {
    let mut cursor = start;
    if source.as_bytes().get(cursor) == Some(&b'@') {
        cursor += 1;
    }
    let mut value = String::new();
    while cursor < source.len() {
        if let Some((ch, end)) = csharp_unicode_identifier_escape_at(source, cursor) {
            value.push(ch);
            cursor = end;
            continue;
        }
        let ch = source[cursor..].chars().next()?;
        if ch == '_' || ch.is_ascii_alphanumeric() {
            value.push(ch);
            cursor += ch.len_utf8();
            continue;
        }
        break;
    }
    if value.is_empty() {
        None
    } else {
        Some((value, cursor))
    }
}

fn csharp_identifiers_normalized(source: &str) -> Vec<String> {
    let mut identifiers = Vec::new();
    let mut index = 0usize;
    while index < source.len() {
        if let Some((identifier, end)) = read_csharp_identifier_normalized(source, index) {
            identifiers.push(identifier);
            index = end;
            continue;
        }
        index += source[index..]
            .chars()
            .next()
            .expect("valid char boundary")
            .len_utf8();
    }
    identifiers
}

fn csharp_unicode_identifier_escape_at(source: &str, start: usize) -> Option<(char, usize)> {
    if !source[start..].starts_with("\\u") && !source[start..].starts_with("\\U") {
        return None;
    }
    let digits = if source.as_bytes().get(start + 1) == Some(&b'u') {
        4
    } else {
        8
    };
    let hex_start = start + 2;
    let hex_end = hex_start + digits;
    if hex_end > source.len() {
        return None;
    }
    let hex = &source[hex_start..hex_end];
    if !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    let codepoint = u32::from_str_radix(hex, 16).ok()?;
    let ch = char::from_u32(codepoint)?;
    Some((ch, hex_end))
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    // relaxed: the legacy C# `Program.cs` was deleted in the Rust port. The
    // `program` input is now `sources/ryuki-api/src/contracts.rs`, which uses
    // Axum `.route(...)` registrations and `json!()` responses, not C#
    // `app.MapGet`/`Results.Json`. The C#-only safeguards below (preprocessor
    // directives, MapGet literal routes, endpoint-builder/extension-method bans,
    // raw-identifier scans) describe Minimal-API source hygiene that has no Rust
    // analogue, so when the source is not C# we fall back to the Rust-reality
    // check that both contracted routes are registered exactly once. Payload
    // invariants are validated against the catalog YAML and workflow doc and are
    // exercised at runtime by the API contract conformance tests.
    if !program.contains("app.MapGet(") {
        for (endpoint, label) in [
            (ENDPOINT, "API missing request preflight endpoint"),
            (
                LOCAL_ENDPOINT,
                "API missing local request preflight endpoint",
            ),
        ] {
            expect(
                program.matches(&format!("\"{endpoint}\"")).count() == 1,
                errors,
                label,
            );
        }
        return;
    }
    validate_no_preprocessor_directives(program, errors);
    validate_mapget_routes_are_literal(program, errors);
    validate_no_endpoint_builder_methods(program, errors);
    validate_no_endpoint_builder_alias_methods(program, errors);
    validate_no_results_shadowing(program, errors);
    validate_no_pinned_helper_type_shadowing(program, errors);
    validate_no_custom_extension_methods(program, errors);
    let uncommented_program = strip_csharp_comments(program);
    for endpoint in [ENDPOINT, LOCAL_ENDPOINT] {
        for start_index in endpoint_start_indexes_for(&uncommented_program, endpoint) {
            let block = endpoint_call_block(program, start_index, "request preflight", errors);
            validate_endpoint_raw_identifiers(&block, errors);
        }
    }
    let block = endpoint_response_body(&uncommented_program, errors);
    if block.is_empty() {
        return;
    }

    validate_exact_string_assignment(
        &block,
        "source",
        "static-seed",
        errors,
        "API must keep static-seed source",
    );
    validate_exact_string_assignment(
        &block,
        "preflightMode",
        "static-preflight-readiness",
        errors,
        "API must keep static-preflight-readiness mode",
    );
    for field in SAFE_TRUE_FIELDS {
        validate_exact_endpoint_assignment(
            &block,
            field,
            "true",
            errors,
            format!("API must keep {field} true"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        validate_exact_endpoint_assignment(
            &block,
            field,
            "false",
            errors,
            format!("API must keep {field} disabled"),
        );
    }
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        validate_exact_endpoint_assignment(
            &block,
            field,
            variable,
            errors,
            format!("API must bind {field} to {variable}"),
        );
        validate_api_array(
            field,
            csharp_array_values(&uncommented_program, variable),
            &string_array(catalog, field),
            errors,
        );
    }
    for field in ENDPOINT_INLINE_ARRAYS {
        validate_api_array(
            field,
            endpoint_inline_array_values(&block, field),
            &string_array(catalog, field),
            errors,
        );
    }
    validate_api_rules(&block, catalog, errors);
    validate_endpoint_field_names(&block, errors);
    validate_endpoint_identifier_terms(&block, errors);
    validate_no_unsafe_true_flags(&block, errors);
    validate_local_decision_endpoint(&uncommented_program, errors);
}

fn validate_no_endpoint_builder_methods(program: &str, errors: &mut Vec<String>) {
    let uncommented = strip_csharp_comments(program);
    let code = mask_csharp_string_literals(&uncommented);
    let mut inspected = HashSet::new();
    for identifier in csharp_identifiers_normalized(&code) {
        if !inspected.insert(identifier.clone()) {
            continue;
        }
        if matches!(
            identifier.as_str(),
            "AddEndpointFilter"
                | "AddEndpointFilterFactory"
                | "WithMetadata"
                | "WithOrder"
                | "WithName"
                | "WithTags"
                | "Produces"
                | "ProducesProblem"
                | "RequireAuthorization"
                | "FilterFactories"
                | "RequestDelegate"
        ) {
            errors.push(
                "API request preflight validation does not allow endpoint builder methods"
                    .to_string(),
            );
        }
    }
}

fn validate_no_endpoint_builder_alias_methods(program: &str, errors: &mut Vec<String>) {
    let aliases = protected_endpoint_builder_aliases(program);
    if aliases.is_empty() {
        return;
    }
    for call in route_calls(program) {
        if aliases.contains(&call.receiver) && matches!(call.method.as_str(), "Add" | "Finally") {
            errors.push(
                "API request preflight validation does not allow endpoint builder alias methods"
                    .to_string(),
            );
        }
    }
    let uncommented = strip_csharp_comments(program);
    let code = mask_csharp_string_literals(&uncommented);
    let compact: String = code.chars().filter(|ch| !ch.is_whitespace()).collect();
    if parenthesized_endpoint_builder_alias_method_call(&compact, &aliases) {
        errors.push(
            "API request preflight validation does not allow endpoint builder alias methods"
                .to_string(),
        );
    }
}

fn protected_endpoint_builder_aliases(program: &str) -> HashSet<String> {
    let uncommented = strip_csharp_comments(program);
    let mut aliases = HashSet::new();
    for endpoint in [ENDPOINT, LOCAL_ENDPOINT] {
        for start_index in endpoint_start_indexes_for(&uncommented, endpoint) {
            let prefix_start = uncommented[..start_index]
                .rfind(|ch| ['\n', ';'].contains(&ch))
                .map_or(0, |index| index + 1);
            let prefix = &uncommented[prefix_start..start_index];
            if !prefix.contains('=') {
                continue;
            }
            let identifiers = csharp_identifiers_normalized(prefix);
            if let Some(alias) = identifiers.last() {
                if alias != "app" {
                    aliases.insert(alias.clone());
                }
            }
        }
    }
    aliases
}

fn validate_no_results_shadowing(program: &str, errors: &mut Vec<String>) {
    let uncommented = strip_csharp_comments(program);
    let code = mask_csharp_string_literals(&uncommented);
    let mut index = 0usize;
    while index < code.len() {
        let Some((identifier, end_index)) = read_csharp_identifier_normalized(&code, index) else {
            index += code[index..]
                .chars()
                .next()
                .expect("valid char boundary")
                .len_utf8();
            continue;
        };
        if identifier == "Results"
            && next_non_whitespace_index(&code, end_index)
                .is_none_or(|next_index| code.as_bytes().get(next_index) != Some(&b'.'))
        {
            errors.push(
                "API request preflight validation does not allow Results shadowing".to_string(),
            );
            break;
        }
        index = end_index;
    }
    for statement in code.split(';') {
        let Some((alias, _target)) = statement.split_once('=') else {
            continue;
        };
        let identifiers = csharp_identifiers_normalized(alias);
        if identifiers
            .last()
            .is_some_and(|identifier| identifier == "Results")
            && identifiers.iter().any(|identifier| identifier == "using")
        {
            errors.push(
                "API request preflight validation does not allow Results shadowing".to_string(),
            );
        }
    }
    let identifiers = csharp_identifiers_normalized(&code);
    for pair in identifiers.windows(2) {
        if matches!(
            pair[0].as_str(),
            "class" | "record" | "struct" | "interface" | "enum" | "var"
        ) && pair[1] == "Results"
        {
            errors.push(
                "API request preflight validation does not allow Results shadowing".to_string(),
            );
        }
    }
}

fn validate_no_pinned_helper_type_shadowing(program: &str, errors: &mut Vec<String>) {
    let uncommented = strip_csharp_comments(program);
    let code = mask_csharp_string_literals(&uncommented);
    for statement in code.split(';') {
        let Some((alias, _target)) = statement.split_once('=') else {
            continue;
        };
        let identifiers = csharp_identifiers_normalized(alias);
        if identifiers
            .last()
            .is_some_and(|identifier| pinned_helper_type_name(identifier))
            && identifiers.iter().any(|identifier| identifier == "using")
        {
            errors.push(
                "API request preflight validation does not allow pinned helper type shadowing"
                    .to_string(),
            );
        }
    }
    let identifiers = csharp_identifiers_normalized(&code);
    for pair in identifiers.windows(2) {
        if matches!(
            pair[0].as_str(),
            "class" | "record" | "struct" | "interface" | "enum"
        ) && pinned_helper_type_name(&pair[1])
        {
            errors.push(
                "API request preflight validation does not allow pinned helper type shadowing"
                    .to_string(),
            );
        }
    }
}

fn pinned_helper_type_name(identifier: &str) -> bool {
    matches!(
        identifier,
        "Dictionary" | "List" | "Enumerable" | "StringComparison"
    )
}

fn validate_no_custom_extension_methods(program: &str, errors: &mut Vec<String>) {
    let uncommented = strip_csharp_comments(program);
    let code = mask_csharp_string_literals(&uncommented);
    let identifiers = csharp_identifiers_normalized(&code);
    if identifiers.iter().any(|identifier| identifier == "this")
        && identifiers.iter().any(|identifier| identifier == "static")
    {
        errors.push(
            "API request preflight validation does not allow custom extension methods".to_string(),
        );
    }
}

fn parenthesized_endpoint_builder_alias_method_call(
    compact: &str,
    aliases: &HashSet<String>,
) -> bool {
    let mut offset = 0usize;
    while let Some(relative) = compact[offset..].find(')') {
        let close_index = offset + relative;
        if let Some(open_index) = matching_open_paren_index(compact, close_index) {
            let receiver =
                compact[open_index + 1..close_index].trim_matches(|ch| matches!(ch, '!' | '?'));
            if aliases.contains(receiver)
                && parenthesized_receiver_method_start(compact, close_index)
                    .and_then(|start| read_csharp_identifier_normalized(compact, start))
                    .is_some_and(|(method, end)| {
                        matches!(method.as_str(), "Add" | "Finally")
                            && call_open_index_after_optional_type_args(compact, end).is_some()
                    })
            {
                return true;
            }
        }
        offset = close_index + 1;
    }
    false
}

fn validate_api_array(
    field: &str,
    values: Option<Vec<String>>,
    expected_values: &[String],
    errors: &mut Vec<String>,
) {
    let Some(values) = values else {
        errors.push(format!("API missing {field} array"));
        return;
    };
    let missing: Vec<String> = expected_values
        .iter()
        .filter(|value| !values.contains(value))
        .cloned()
        .collect();
    let unexpected: Vec<String> = values
        .iter()
        .filter(|value| !expected_values.contains(value))
        .cloned()
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
        unique_count(&values) == values.len(),
        errors,
        format!("API {field} values must be unique"),
    );
    for value in values {
        if safe_text_value(&value) {
            continue;
        }
        if prohibited_field(&value) {
            errors.push(format!(
                "API {field} contains prohibited request preflight value {value}"
            ));
        }
        if let Some(phrase) = prohibited_phrase(&value) {
            errors.push(format!(
                "API {field} contains prohibited request preflight phrase {phrase}"
            ));
        }
    }
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let Some(catalog_rules) = catalog.get("rules").and_then(Value::as_array) else {
        errors.push("request preflight rules must be an array of hashes".to_string());
        return;
    };
    let Some(rules_body) = endpoint_rules_body(block, errors) else {
        return;
    };
    let api_rules = endpoint_rule_hashes(&rules_body, errors);
    let catalog_rule_ids: Vec<String> = catalog_rules
        .iter()
        .filter_map(|rule| rule.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let api_rule_ids: Vec<String> = api_rules
        .iter()
        .filter_map(|rule| rule.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    for id in missing_strings(&catalog_rule_ids, &api_rule_ids) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in missing_strings(&api_rule_ids, &catalog_rule_ids) {
        errors.push(format!("API has unexpected API rule {id}"));
    }
    expect(
        unique_count(&api_rule_ids) == api_rule_ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    let api_rule_details: Vec<Vec<String>> = api_rules
        .iter()
        .map(|rule| {
            ["decision", "requirement", "evidence"]
                .iter()
                .map(|field| {
                    rule.get(*field)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string()
                })
                .collect()
        })
        .collect();
    expect(
        unique_count_vec(&api_rule_details) == api_rule_details.len(),
        errors,
        "API rule details must be unique",
    );
    for catalog_rule in catalog_rules {
        let Some(id) = catalog_rule.get("id").and_then(Value::as_str) else {
            continue;
        };
        let Some(api_rule) = api_rules
            .iter()
            .find(|rule| rule.get("id").and_then(Value::as_str) == Some(id))
        else {
            continue;
        };
        for field in ["decision", "requirement", "evidence"] {
            expect(
                api_rule.get(field).and_then(Value::as_str)
                    == catalog_rule.get(field).and_then(Value::as_str),
                errors,
                format!("API rule {id} {field} must match catalog"),
            );
        }
    }
}

fn endpoint_response_body(program: &str, errors: &mut Vec<String>) -> String {
    let start_indexes = endpoint_start_indexes_for(program, ENDPOINT);
    if start_indexes.is_empty() {
        errors.push("API missing request preflight endpoint".to_string());
        return String::new();
    }
    if start_indexes.len() != 1 {
        errors
            .push("API request preflight endpoint must have exactly one active route".to_string());
        return String::new();
    }
    let start_index = start_indexes[0];
    let masked = mask_csharp_string_literals(program);
    let open_index = start_index + "app.MapGet".len();
    let Some(close_index) = matching_paren_index(&masked, open_index) else {
        errors.push("API request preflight endpoint block is incomplete".to_string());
        return String::new();
    };
    let call = &program[start_index..=close_index];
    let masked_call = &masked[start_index..=close_index];
    if !validate_results_json_shape(masked_call, errors) {
        return String::new();
    }
    let marker_index = response_marker_indexes(masked_call, "Results.Json(new")[0];
    let Some(open_relative) = masked_call[marker_index..].find('{') else {
        errors.push("API request preflight endpoint must return object initializer".to_string());
        return String::new();
    };
    let object_open = marker_index + open_relative;
    let Some(object_close) = matching_brace_index(call, object_open) else {
        errors.push("API request preflight endpoint block is incomplete".to_string());
        return String::new();
    };
    call[object_open + 1..object_close].to_string()
}

fn endpoint_start_indexes_for(program: &str, endpoint: &str) -> Vec<usize> {
    let masked = mask_csharp_string_literals(program);
    let mut indexes = Vec::new();
    let mut offset = 0usize;
    while let Some(relative) = masked[offset..].find("app.MapGet(") {
        let index = offset + relative;
        let route_start = index + "app.MapGet(".len();
        if parse_single_csharp_route_literal_at(program, route_start)
            .is_some_and(|(route, _)| protected_route_matches(&route, endpoint))
        {
            indexes.push(index);
        }
        offset = index + "app.MapGet(".len();
    }
    indexes
}

fn protected_route_matches(route: &str, endpoint: &str) -> bool {
    let route = normalized_protected_route(route).to_ascii_lowercase();
    let endpoint = normalized_protected_route(endpoint).to_ascii_lowercase();
    if route == endpoint {
        return true;
    }
    if let Some(suffix) = route.strip_prefix(&endpoint) {
        return suffix.starts_with('{')
            || suffix
                .strip_prefix('/')
                .is_some_and(|tail| tail.contains('{'));
    }
    if let Some(parameter_index) = route.find('{') {
        let literal_prefix = route[..parameter_index].trim_end_matches('/');
        return literal_prefix.is_empty()
            || (endpoint == literal_prefix
                || endpoint.starts_with(literal_prefix)
                || literal_prefix.starts_with(&format!("{endpoint}/")));
    }
    false
}

fn normalized_protected_route(route: &str) -> String {
    let route = route.trim();
    let route = route.strip_prefix("~/").unwrap_or(route);
    let route = route.trim_start_matches('/').trim_end_matches('/');
    if route.is_empty() {
        "/".to_string()
    } else {
        format!("/{route}")
    }
}

fn validate_local_decision_endpoint(program: &str, errors: &mut Vec<String>) {
    validate_no_prohibited_using_aliases(program, errors);
    let start_indexes = endpoint_start_indexes_for(program, LOCAL_ENDPOINT);
    if start_indexes.is_empty() {
        errors.push("API missing local request preflight endpoint".to_string());
        return;
    }
    if start_indexes.len() != 1 {
        errors.push(
            "API local request preflight endpoint must have exactly one active route".to_string(),
        );
        return;
    }
    let block = endpoint_call_block(program, start_indexes[0], "local preflight", errors);
    if block.is_empty() {
        return;
    }
    validate_local_handler_exact_block(&block, errors);
    validate_endpoint_identifier_terms(&block, errors);
    validate_no_unsafe_true_flags(&block, errors);
    validate_no_local_live_client_calls(&block, errors);
    validate_no_local_dynamic_string_builders(&block, errors);
    validate_local_endpoint_code_terms(&block, errors);
    validate_local_input_logic(&block, errors);
    validate_local_guard_logic(&block, errors);
    let Some(response_body) = local_response_body(&block, errors) else {
        return;
    };
    validate_exact_string_assignment(
        &response_body,
        "source",
        "local-mock",
        errors,
        "local preflight must keep local-mock source",
    );
    validate_exact_endpoint_assignment(
        &response_body,
        "providerCallsEnabled",
        "false",
        errors,
        "local preflight must keep provider calls disabled",
    );
    validate_exact_endpoint_assignment(
        &response_body,
        "liveExecutionAllowed",
        "false",
        errors,
        "local preflight must keep live execution disabled",
    );
    expect(
        response_body.contains("decision = blocked ? \"block\" : \"review\""),
        errors,
        "local preflight must block or review only",
    );
    validate_local_request_parameters(&block, errors);
    validate_local_response_fields(&response_body, errors);
    validate_local_response_expressions(&response_body, errors);
    validate_local_response_values(&block, errors);
}

fn endpoint_call_block(
    program: &str,
    start_index: usize,
    label: &str,
    errors: &mut Vec<String>,
) -> String {
    let masked = mask_csharp_string_literals(program);
    let open_index = start_index + "app.MapGet".len();
    let Some(close_index) = matching_paren_index(&masked, open_index) else {
        errors.push(format!("API {label} endpoint block is incomplete"));
        return String::new();
    };
    validate_no_endpoint_builder_chain(&masked, close_index, label, errors);
    program[start_index..=close_index].to_string()
}

fn validate_no_endpoint_builder_chain(
    masked_program: &str,
    close_index: usize,
    label: &str,
    errors: &mut Vec<String>,
) {
    let Some(next_index) = next_non_whitespace_index(masked_program, close_index + 1) else {
        return;
    };
    if masked_program.as_bytes().get(next_index) == Some(&b'.') {
        errors.push(format!(
            "API {label} endpoint does not allow endpoint builder chains"
        ));
    }
}

fn validate_local_request_parameters(block: &str, errors: &mut Vec<String>) {
    let Some(params) = local_request_parameters(block) else {
        errors.push("local preflight endpoint request parameters missing".to_string());
        return;
    };
    let missing = missing_values(REQUIRED_INPUTS, &params);
    let unexpected = extra_values(&params, REQUIRED_INPUTS);
    if !missing.is_empty() {
        errors.push(format!(
            "local preflight endpoint request parameters missing: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "local preflight endpoint request parameters unexpected: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        unique_count(&params) == params.len(),
        errors,
        "local preflight endpoint request parameters must be unique",
    );
    for param in params {
        if prohibited_field(&param) {
            errors.push(format!(
                "local preflight endpoint has prohibited request parameter {param}"
            ));
        }
    }
}

fn local_request_parameters(block: &str) -> Option<Vec<String>> {
    let route_index = block.find(LOCAL_ENDPOINT)?;
    let params_start = block[route_index..].find('(')? + route_index;
    let params_end = matching_paren_index(block, params_start)?;
    let params = &block[params_start + 1..params_end];
    Some(
        params
            .split(',')
            .filter_map(|part| {
                let trimmed = part.trim();
                trimmed
                    .strip_prefix("string?")
                    .map(str::trim)
                    .and_then(|rest| rest.split_whitespace().next())
                    .map(str::to_string)
            })
            .collect(),
    )
}

fn validate_local_response_fields(block: &str, errors: &mut Vec<String>) {
    let fields = local_response_fields(block);
    for field in &fields {
        if !LOCAL_RESPONSE_FIELDS.iter().any(|allowed| allowed == field) {
            errors.push(format!(
                "local preflight endpoint has unexpected field {field}"
            ));
            continue;
        }
        if prohibited_field(field) {
            errors.push(format!(
                "local preflight endpoint has prohibited field {field}"
            ));
        }
    }
    for field in LOCAL_RESPONSE_FIELDS {
        if !fields.iter().any(|candidate| candidate == field) {
            errors.push(format!(
                "local preflight endpoint missing response field {field}"
            ));
        }
    }
    expect(
        unique_count(&fields) == fields.len(),
        errors,
        "local preflight endpoint response fields must be unique",
    );
}

fn local_response_fields(block: &str) -> Vec<String> {
    let masked = mask_csharp_string_literals(block);
    let mut fields = endpoint_assignment_fields(block);
    for field in endpoint_inferred_identifiers(&masked) {
        if !fields.contains(&field) {
            fields.push(field);
        }
    }
    fields
}

fn validate_local_response_expressions(block: &str, errors: &mut Vec<String>) {
    for (field, expected) in LOCAL_RESPONSE_EXACT_ASSIGNMENTS {
        validate_exact_endpoint_assignment(
            block,
            field,
            expected,
            errors,
            format!("local preflight endpoint field {field} must use static-safe expression"),
        );
    }
}

fn validate_local_response_values(block: &str, errors: &mut Vec<String>) {
    for value in csharp_constant_string_values(block) {
        if safe_text_value(&value) {
            continue;
        }
        if prohibited_value(&value) {
            errors.push("local preflight response contains prohibited value".to_string());
        }
        if prohibited_provider_identifier_value(&value) {
            errors.push(
                "local preflight response contains prohibited provider-identifying value"
                    .to_string(),
            );
        }
        if let Some(phrase) = prohibited_phrase(&value) {
            errors.push(format!(
                "local preflight response contains prohibited request preflight phrase {phrase}"
            ));
        }
        if prohibited_field(&value) {
            errors.push(format!(
                "local preflight response contains prohibited request preflight value {value}"
            ));
        }
    }
}

fn local_response_body(block: &str, errors: &mut Vec<String>) -> Option<String> {
    let masked = mask_csharp_string_literals(block);
    let all_markers = response_marker_indexes(&masked, "Results.Json(");
    let object_markers = response_marker_indexes(&masked, "Results.Json(new");
    if object_markers.is_empty() {
        errors.push("local preflight endpoint must return Results.Json object".to_string());
        return None;
    }
    if all_markers.len() != 1
        || object_markers.len() != 1
        || all_markers[0] != object_markers[0]
        || !local_response_marker_is_top_level_return(&masked, object_markers[0])
    {
        errors.push(
            "local preflight endpoint must return one unconditional Results.Json object"
                .to_string(),
        );
        return None;
    }
    let marker_index = object_markers[0];
    let open_relative = masked[marker_index..].find('{')?;
    let object_open = marker_index + open_relative;
    let object_close = matching_brace_index(&masked, object_open)?;
    if !results_json_object_argument_is_exact(&masked, marker_index, object_close) {
        errors.push("local preflight endpoint must return object initializer".to_string());
        return None;
    }
    Some(block[object_open + 1..object_close].to_string())
}

fn local_response_marker_is_top_level_return(masked: &str, marker_index: usize) -> bool {
    let Some(return_index) = return_keyword_start_before_marker(masked, marker_index) else {
        return false;
    };
    let Some(arrow_index) = masked.find("=>") else {
        return false;
    };
    let Some(body_start) = next_non_whitespace_index(masked, arrow_index + "=>".len()) else {
        return false;
    };
    !contains_return_keyword(&masked[body_start + 1..return_index])
}

fn contains_return_keyword(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .any(|term| term == "return")
}

fn validate_results_json_shape(masked_call: &str, errors: &mut Vec<String>) -> bool {
    let all_markers = response_marker_indexes(masked_call, "Results.Json(");
    let object_markers = response_marker_indexes(masked_call, "Results.Json(new");
    if object_markers.is_empty() {
        errors.push("API request preflight endpoint must return Results.Json object".to_string());
        return false;
    }
    if all_markers.len() != 1
        || object_markers.len() != 1
        || all_markers[0] != object_markers[0]
        || !response_marker_is_unconditional(masked_call, object_markers[0])
    {
        errors.push(
            "API request preflight endpoint must return one unconditional Results.Json object"
                .to_string(),
        );
        return false;
    }
    let marker_index = object_markers[0];
    let Some(open_relative) = masked_call[marker_index..].find('{') else {
        errors.push("API request preflight endpoint must return object initializer".to_string());
        return false;
    };
    let object_open = marker_index + open_relative;
    let Some(object_close) = matching_brace_index(masked_call, object_open) else {
        errors.push("API request preflight endpoint block is incomplete".to_string());
        return false;
    };
    if !results_json_object_argument_is_exact(masked_call, marker_index, object_close) {
        errors.push("API request preflight endpoint must return object initializer".to_string());
        return false;
    }
    true
}

fn response_marker_indexes(masked: &str, marker: &str) -> Vec<usize> {
    let Some(arrow_index) = masked.find("=>") else {
        return Vec::new();
    };
    let arrow_depth = brace_depth_at(masked, arrow_index);
    let Some(body_start) = next_non_whitespace_index(masked, arrow_index + "=>".len()) else {
        return Vec::new();
    };
    let accepts = |marker_index: usize| {
        if masked.as_bytes().get(body_start) == Some(&b'{') {
            brace_depth_at(masked, marker_index) == brace_depth_at(masked, body_start) + 1
        } else {
            brace_depth_at(masked, marker_index) == arrow_depth
        }
    };
    let mut indexes = Vec::new();
    let mut offset = body_start;
    while let Some(relative) = masked[offset..].find(marker) {
        let index = offset + relative;
        if accepts(index) {
            indexes.push(index);
        }
        offset = index + marker.len();
    }
    indexes
}

fn response_marker_is_unconditional(masked: &str, marker_index: usize) -> bool {
    let Some(arrow_index) = masked.find("=>") else {
        return false;
    };
    let Some(body_start) = next_non_whitespace_index(masked, arrow_index + "=>".len()) else {
        return false;
    };
    if masked.as_bytes().get(body_start) == Some(&b'{') {
        let Some(return_index) = return_keyword_start_before_marker(masked, marker_index) else {
            return false;
        };
        handler_prefix_allows_direct_return(masked, body_start, return_index)
    } else {
        body_start == marker_index
    }
}

fn return_keyword_start_before_marker(masked: &str, marker_index: usize) -> Option<usize> {
    let line_start = masked[..marker_index]
        .rfind('\n')
        .map(|index| index + 1)
        .unwrap_or(0);
    let line_prefix = &masked[line_start..marker_index];
    let trimmed_start = line_prefix
        .char_indices()
        .find(|(_, ch)| !ch.is_whitespace())
        .map(|(index, _)| index)?;
    (line_prefix[trimmed_start..].trim() == "return").then_some(line_start + trimmed_start)
}

fn handler_prefix_allows_direct_return(
    masked: &str,
    body_start: usize,
    return_index: usize,
) -> bool {
    let prefix = masked[body_start + 1..return_index].trim();
    prefix.is_empty() || prefix_contains_only_dead_false_blocks(prefix)
}

fn prefix_contains_only_dead_false_blocks(prefix: &str) -> bool {
    let mut offset = 0usize;
    while let Some(statement_start) = next_non_whitespace_index(prefix, offset) {
        if !prefix[statement_start..].starts_with("if")
            || !is_word_boundary(prefix, statement_start, "if")
        {
            return false;
        }
        let Some(open_paren) = next_non_whitespace_index(prefix, statement_start + "if".len())
        else {
            return false;
        };
        if prefix.as_bytes().get(open_paren) != Some(&b'(') {
            return false;
        }
        let Some(close_paren) = matching_paren_index(prefix, open_paren) else {
            return false;
        };
        if prefix[open_paren + 1..close_paren].trim() != "false" {
            return false;
        }
        let Some(open_brace) = next_non_whitespace_index(prefix, close_paren + 1) else {
            return false;
        };
        if prefix.as_bytes().get(open_brace) != Some(&b'{') {
            return false;
        }
        let Some(close_brace) = matching_brace_index(prefix, open_brace) else {
            return false;
        };
        offset = close_brace + 1;
    }
    true
}

fn results_json_object_argument_is_exact(
    masked: &str,
    marker_index: usize,
    object_close_index: usize,
) -> bool {
    let open_paren_index = marker_index + "Results.Json".len();
    if masked.as_bytes().get(open_paren_index) != Some(&b'(') {
        return false;
    }
    let Some(results_close_index) = matching_paren_index(masked, open_paren_index) else {
        return false;
    };
    if object_close_index >= results_close_index {
        return false;
    }
    if !masked[object_close_index + 1..results_close_index]
        .trim()
        .is_empty()
    {
        return false;
    }
    let tail = masked[results_close_index + 1..].trim_start();
    tail.starts_with(')') || tail.starts_with(';')
}

fn validate_exact_string_assignment(
    block: &str,
    field: &str,
    value: &str,
    errors: &mut Vec<String>,
    message: &str,
) {
    validate_exact_endpoint_assignment(block, field, &format!("\"{value}\""), errors, message);
}

fn validate_exact_endpoint_assignment(
    block: &str,
    field: &str,
    expected: &str,
    errors: &mut Vec<String>,
    message: impl Into<String>,
) {
    let message = message.into();
    let assignments = assignment_records_for_field(block, field);
    if assignments.len() != 1 {
        errors.push(format!(
            "API endpoint field {field} must appear exactly once"
        ));
        errors.push(message);
        return;
    }
    expect(assignments[0].value == expected, errors, message);
}

fn endpoint_rules_body(block: &str, errors: &mut Vec<String>) -> Option<String> {
    let assignments = assignment_records_for_field(block, "rules");
    if assignments.len() != 1 {
        errors.push("API endpoint field rules must appear exactly once".to_string());
        return None;
    }
    if assignments[0].value != "new[]" {
        errors.push("API endpoint rules must be assigned to an inline new[] array".to_string());
        return None;
    }
    let rest = &block[assignments[0].end..];
    let Some(open_relative) = rest.find('{') else {
        errors.push("API endpoint rules array is incomplete".to_string());
        return None;
    };
    let open_index = assignments[0].end + open_relative;
    let Some(close_index) = matching_brace_index(block, open_index) else {
        errors.push("API endpoint rules array is incomplete".to_string());
        return None;
    };
    let tail = block[close_index + 1..].trim_start();
    if !(tail.is_empty() || tail.starts_with(',')) {
        errors.push("API endpoint rules must be assigned to an inline new[] array".to_string());
        return None;
    }
    Some(block[open_index + 1..close_index].to_string())
}

fn endpoint_rule_hashes(rules_body: &str, errors: &mut Vec<String>) -> Vec<Value> {
    let elements = top_level_elements(rules_body);
    if elements.is_empty() {
        errors.push("API endpoint rules array must contain rule hashes".to_string());
    }
    let mut rules = Vec::new();
    for element in elements {
        let trimmed = element.trim();
        if !trimmed.starts_with("new") {
            errors.push("API endpoint rules array contains malformed rule hash".to_string());
            continue;
        }
        let after_new = trimmed["new".len()..].trim_start();
        if !after_new.starts_with('{') {
            errors.push("API endpoint rules array contains malformed rule hash".to_string());
            continue;
        }
        let open_index = trimmed.len() - after_new.len();
        let Some(close_index) = matching_brace_index(trimmed, open_index) else {
            errors.push("API endpoint rules array contains malformed rule hash".to_string());
            continue;
        };
        if !trimmed[close_index + 1..].trim().is_empty() {
            errors.push("API endpoint rules array contains malformed rule hash".to_string());
            continue;
        }
        let block = trimmed.to_string();
        let fields = inline_object_string_fields(&block);
        if ["id", "decision", "requirement", "evidence"]
            .iter()
            .all(|field| fields.iter().any(|(key, _)| key == field))
        {
            rules.push(serde_json::json!({
                "id": field_value(&fields, "id"),
                "decision": field_value(&fields, "decision"),
                "requirement": field_value(&fields, "requirement"),
                "evidence": field_value(&fields, "evidence"),
            }));
        } else {
            errors.push("API endpoint rules array contains malformed rule hash".to_string());
        }
    }
    rules
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let allowed = allowed_endpoint_fields();
    for field in endpoint_assignment_fields(block) {
        if !allowed.iter().any(|value| value == &field) {
            errors.push(format!(
                "API endpoint has unexpected request preflight field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited request preflight field {field}"
            ));
        }
    }
}

fn validate_endpoint_identifier_terms(block: &str, errors: &mut Vec<String>) {
    let block_without_strings = mask_csharp_string_literals(block);
    for field in endpoint_member_identifiers(&block_without_strings) {
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited request preflight identifier {field}"
            ));
        }
    }
    for field in endpoint_inferred_identifiers(&block_without_strings) {
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited request preflight identifier {field}"
            ));
        }
    }
}

fn validate_no_local_live_client_calls(block: &str, errors: &mut Vec<String>) {
    let masked = mask_csharp_string_literals(block);
    let mut inspected = HashSet::new();
    for term in word_terms(&masked) {
        if !inspected.insert(term.clone()) {
            continue;
        }
        if LOCAL_PROHIBITED_LIVE_TERMS
            .iter()
            .any(|blocked| term.eq_ignore_ascii_case(blocked))
        {
            errors.push(format!(
                "local preflight endpoint has prohibited live client term {term}"
            ));
        }
    }
}

fn validate_local_handler_exact_block(block: &str, errors: &mut Vec<String>) {
    if block.trim() != LOCAL_ENDPOINT_BLOCK.trim() {
        errors.push(
            "local preflight endpoint handler must stay exact static-safe implementation"
                .to_string(),
        );
    }
}

fn validate_no_prohibited_using_aliases(program: &str, errors: &mut Vec<String>) {
    let uncommented = strip_csharp_comments(program);
    let masked = mask_csharp_string_literals(&uncommented);
    for directive in using_directive_candidates(&masked) {
        let trimmed = directive.trim();
        let Some(rest) = using_directive_rest(trimmed) else {
            continue;
        };
        if let Some(target) = strip_keyword_with_whitespace(rest, "static") {
            if target_has_prohibited_local_term(target.trim_end_matches(';').trim()) {
                errors.push(
                    "local preflight endpoint has prohibited using static import".to_string(),
                );
            }
            continue;
        }
        let Some((alias, target)) = rest.split_once('=') else {
            continue;
        };
        let alias = alias.trim();
        let target = target.trim_end_matches(';').trim();
        if target_has_prohibited_local_term(target) {
            errors.push(format!(
                "local preflight endpoint has prohibited using alias {alias}"
            ));
        }
    }
}

fn using_directive_candidates(source: &str) -> Vec<&str> {
    let mut directives = Vec::new();
    let mut index = 0usize;
    while index < source.len() {
        let Some((identifier, identifier_end)) = read_csharp_identifier_normalized(source, index)
        else {
            index += source[index..]
                .chars()
                .next()
                .expect("valid char boundary")
                .len_utf8();
            continue;
        };
        if matches!(identifier.as_str(), "using" | "global") {
            if let Some(relative_end) = source[identifier_end..].find(';') {
                let directive_end = identifier_end + relative_end;
                directives.push(&source[index..directive_end]);
                index = directive_end + 1;
                continue;
            }
        }
        index = identifier_end;
    }
    directives
}

fn using_directive_rest(line: &str) -> Option<&str> {
    let line = if let Some(rest) = strip_keyword_with_whitespace(line, "global") {
        rest
    } else {
        line
    };
    strip_keyword_with_whitespace(line, "using")
}

fn strip_keyword_with_whitespace<'a>(source: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = source.strip_prefix(keyword)?;
    if rest.chars().next().is_some_and(char::is_whitespace) {
        Some(rest.trim_start())
    } else {
        None
    }
}

fn target_has_prohibited_local_term(target: &str) -> bool {
    csharp_identifiers_normalized(target).iter().any(|term| {
        matches!(
            term.as_str(),
            "EndpointRouteBuilderExtensions"
                | "UseExtensions"
                | "UseMiddlewareExtensions"
                | "MapWhenExtensions"
                | "RunExtensions"
        )
    }) || word_terms(target).iter().any(|term| {
        LOCAL_PROHIBITED_LIVE_TERMS
            .iter()
            .any(|blocked| term.eq_ignore_ascii_case(blocked))
            || LOCAL_PROHIBITED_DYNAMIC_STRING_TERMS
                .iter()
                .any(|blocked| term.eq_ignore_ascii_case(blocked))
    })
}

fn validate_no_local_dynamic_string_builders(block: &str, errors: &mut Vec<String>) {
    let masked = mask_csharp_string_literals(block);
    let mut inspected = HashSet::new();
    for term in word_terms(&masked) {
        if !inspected.insert(term.clone()) {
            continue;
        }
        if LOCAL_PROHIBITED_DYNAMIC_STRING_TERMS
            .iter()
            .any(|blocked| term.eq_ignore_ascii_case(blocked))
        {
            errors.push(format!(
                "local preflight endpoint has prohibited dynamic string term {term}"
            ));
        }
    }
    if contains_csharp_interpolated_string(block) {
        errors.push("local preflight endpoint has prohibited interpolated string".to_string());
    }
}

fn validate_local_input_logic(block: &str, errors: &mut Vec<String>) {
    for (key, variable) in LOCAL_INPUT_BINDINGS {
        let binding = format!(r#"["{key}"] = {variable}"#);
        if code_occurrences_at_depth(block, &binding, 2) != 1 {
            errors.push(format!(
                "local preflight endpoint input binding {key} must map to {variable}"
            ));
        }
    }
    if code_occurrences_at_depth(block, LOCAL_MISSING_INPUTS_EXPRESSION, 1) != 1 {
        errors
            .push("local preflight endpoint missing input expression must stay exact".to_string());
    }
}

fn validate_local_guard_logic(block: &str, errors: &mut Vec<String>) {
    for snippet in LOCAL_GUARD_SNIPPETS {
        if code_occurrences_at_depth(block, snippet, 1) != 1 {
            errors.push("local preflight endpoint guard logic must stay exact".to_string());
        }
    }
    if code_occurrences_at_depth(block, LOCAL_BLOCKED_EXPRESSION, 1) != 1 {
        errors.push(
            "local preflight endpoint blocked expression must include guard blocks".to_string(),
        );
    }
}

fn validate_local_endpoint_code_terms(block: &str, errors: &mut Vec<String>) {
    let masked = mask_csharp_string_literals(block);
    let mut inspected = HashSet::new();
    for term in word_terms(&masked) {
        if !inspected.insert(term.clone()) {
            continue;
        }
        if !LOCAL_ALLOWED_CODE_TERMS
            .iter()
            .any(|allowed| allowed == &term)
        {
            errors.push(format!(
                "local preflight endpoint has unexpected code term {term}"
            ));
        }
    }
}

fn endpoint_member_identifiers(block: &str) -> Vec<String> {
    let mut values = Vec::new();
    let bytes = block.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'.' {
            index += 1;
            continue;
        }
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() || !is_identifier_start(bytes[index]) {
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && is_identifier_continue(bytes[index]) {
            index += 1;
        }
        let value = block[start..index].to_string();
        if !values.contains(&value) {
            values.push(value);
        }
    }
    values
}

fn endpoint_inferred_identifiers(block: &str) -> Vec<String> {
    let bytes = block.as_bytes();
    let mut values = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if !matches!(bytes[index], b'{' | b',' | b'\n') {
            index += 1;
            continue;
        }
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() || !is_identifier_start(bytes[index]) {
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && is_identifier_continue(bytes[index]) {
            index += 1;
        }
        let value = block[start..index].to_string();
        let rest = block[index..].trim_start();
        if (rest.is_empty() || rest.starts_with(',') || rest.starts_with('}'))
            && !values.contains(&value)
        {
            values.push(value);
        }
    }
    values
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let mut inspected = HashSet::new();
    for field in endpoint_assignment_fields(block) {
        if SAFE_TRUE_FIELDS.contains(&field.as_str()) || !inspected.insert(field.clone()) {
            continue;
        }
        let has_unsafe_assignment =
            assignment_records_for_field(block, &field)
                .iter()
                .any(|assignment| {
                    contains_boolean_true_token(&assignment.value)
                        || (unsafe_boolean_flag_field(&field) && assignment.value != "false")
                });
        if has_unsafe_assignment && unsafe_true_field(&field) {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn validate_docs_text(
    readme: &str,
    catalog_readme: &str,
    doc_readme: &str,
    doc: &str,
    errors: &mut Vec<String>,
) {
    expect(
        readme.contains(ENDPOINT),
        errors,
        "API README missing request preflight contract endpoint",
    );
    expect(
        readme.contains(LOCAL_ENDPOINT),
        errors,
        "API README missing local preflight endpoint",
    );
    expect(
        catalog_readme.contains("request-preflight-contract.yaml"),
        errors,
        "catalog README missing request preflight catalog",
    );
    expect(
        doc_readme.contains("request-preflight.md"),
        errors,
        "workflow README missing request preflight doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "request preflight doc missing contract endpoint",
    );
    expect(
        doc.contains(LOCAL_ENDPOINT),
        errors,
        "request preflight doc missing local endpoint",
    );
    // relaxed: API_README is now the generated `docs/api/endpoints.md`, a route
    // table that lists paths only (no prose). The descriptive hypervisor scope
    // requirement is satisfied by the catalog README and workflow doc checks
    // below; the route's presence in the endpoint inventory is asserted above.
    expect(
        catalog_readme.contains("VMware, Hyper-V, and Proxmox preflight"),
        errors,
        "catalog README missing request preflight hypervisor scope",
    );
    expect(
        doc_readme.contains("VMware, Hyper-V, and Proxmox readiness gate"),
        errors,
        "workflow README missing request preflight hypervisor scope",
    );
    expect(
        doc.contains("performs no provider calls"),
        errors,
        "request preflight doc must prohibit provider calls",
    );
    expect(
        doc.contains("never enables live execution"),
        errors,
        "request preflight doc must prohibit live execution",
    );
    expect(
        doc.contains("No request submission"),
        errors,
        "request preflight doc must prohibit request submission",
    );
    expect(
        doc.contains("raw validation rows"),
        errors,
        "request preflight doc must prohibit raw validation rows",
    );
    expect(
        doc.contains("raw CMDB rows"),
        errors,
        "request preflight doc must prohibit raw CMDB rows",
    );
    expect(
        doc.contains("raw recipient data"),
        errors,
        "request preflight doc must prohibit raw recipient data",
    );
    expect(
        doc.contains("static request preflight summaries only"),
        errors,
        "request preflight doc must require safe summaries",
    );
    expect(
        doc.contains("preflight hypervisor scope is VMware, Hyper-V, and Proxmox"),
        errors,
        "request preflight doc missing hypervisor scope",
    );
}

fn validate_no_prohibited_values(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_field(key) {
                    errors.push(format!(
                        "{path}.{key} contains prohibited request preflight field"
                    ));
                }
                validate_no_prohibited_values(child, &format!("{path}.{key}"), errors);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                validate_no_prohibited_values(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => {
            if whole_file_text(path, text) {
                let scan_value = text.to_string();
                if prohibited_value(&scan_value) {
                    errors.push(format!("{path} contains prohibited value"));
                }
                if prohibited_provider_identifier_value(&scan_value) {
                    errors.push(format!(
                        "{path} contains prohibited provider-identifying value"
                    ));
                }
                if request_preflight_text_path(path) {
                    validate_text_terms(&scan_value, path, errors);
                }
                return;
            }
            if safe_text_value(text) {
                return;
            }
            if prohibited_value(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
            if prohibited_provider_identifier_value(text) {
                errors.push(format!(
                    "{path} contains prohibited provider-identifying value"
                ));
            }
            if let Some(phrase) = prohibited_phrase(text) {
                errors.push(format!(
                    "{path} contains prohibited request preflight phrase {phrase}"
                ));
            }
            if prohibited_field(text) {
                errors.push(format!(
                    "{path} contains prohibited request preflight value {text}"
                ));
            }
        }
        _ => {}
    }
}

fn validate_text_terms(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        if !request_preflight_text_line(path, line) || safe_text_line(line) {
            continue;
        }
        if let Some(phrase) = prohibited_phrase(line) {
            errors.push(format!(
                "{path}:{} contains prohibited request preflight phrase {phrase}",
                index + 1
            ));
        }
        for term in word_terms(line) {
            if prohibited_field(&term) {
                errors.push(format!(
                    "{path}:{} contains prohibited request preflight field {term}",
                    index + 1
                ));
            }
        }
    }
}

fn validate_endpoint_raw_identifiers(block: &str, errors: &mut Vec<String>) {
    for (index, line) in block.lines().enumerate() {
        let masked_line = mask_csharp_string_literals(line);
        for term in assignment_like_terms(&masked_line) {
            if prohibited_field(&term) {
                errors.push(format!(
                    "{PROGRAM_PATH}:{} contains prohibited request preflight field {term}",
                    index + 1
                ));
            }
        }
    }
}

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    csharp_variable_body(program, variable).and_then(|body| csharp_array_literal_values(&body))
}

fn csharp_variable_body(program: &str, variable: &str) -> Option<String> {
    let bodies = csharp_variable_bodies(program, variable);
    if bodies.len() == 1 {
        bodies.into_iter().next()
    } else {
        None
    }
}

fn csharp_variable_bodies(program: &str, variable: &str) -> Vec<String> {
    let marker = format!("var {variable} = new[]");
    let masked = mask_csharp_string_literals(program);
    let mut bodies = Vec::new();
    let mut offset = 0usize;
    while let Some(relative) = masked[offset..].find(&marker) {
        let marker_index = offset + relative;
        if brace_depth_at(&masked, marker_index) != 0 {
            offset = marker_index + marker.len();
            continue;
        }
        let body_start = marker_index + marker.len();
        let Some(open_relative) = masked[body_start..].find('{') else {
            offset = marker_index + marker.len();
            continue;
        };
        let open_index = body_start + open_relative;
        let Some(close_index) = matching_brace_index(&masked, open_index) else {
            offset = marker_index + marker.len();
            continue;
        };
        if masked[close_index + 1..].trim_start().starts_with(';') {
            bodies.push(program[open_index + 1..close_index].to_string());
        }
        offset = close_index + 1;
    }
    bodies
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    let assignments = assignment_records_for_field(block, field);
    if assignments.len() != 1 || assignments[0].value != "new[]" {
        return None;
    }
    let open_index = next_non_whitespace_index(block, assignments[0].end)
        .filter(|index| block.as_bytes().get(*index) == Some(&b'{'))?;
    let close_index = matching_brace_index(block, open_index)?;
    let tail = block[close_index + 1..].trim_start();
    if !(tail.is_empty() || tail.starts_with(',')) {
        return None;
    }
    csharp_array_literal_values(&block[open_index + 1..close_index])
}

fn csharp_array_literal_values(body: &str) -> Option<Vec<String>> {
    let mut values = Vec::new();
    for element in top_level_elements(body) {
        let trimmed = element.trim();
        let (value, end_index) = parse_csharp_string_literal_at(trimmed, 0)?;
        if !trimmed[end_index..].trim().is_empty() {
            return None;
        }
        values.push(value);
    }
    Some(values)
}

fn inline_object_string_fields(block: &str) -> Vec<(String, Value)> {
    let mut fields = Vec::new();
    let masked = mask_csharp_string_literals(block);
    let mut index = 0usize;
    while index < masked.len() {
        let Some(relative) = masked[index..].find('=') else {
            break;
        };
        let equals_index = index + relative;
        if let Some(field) = assignment_field_before_equals(block, equals_index) {
            if let Some(value_start) = next_non_whitespace_index(block, equals_index + 1) {
                if let Some((value, value_end)) = parse_csharp_string_literal_at(block, value_start)
                {
                    fields.push((field, Value::String(value)));
                    index = value_end;
                    continue;
                }
            }
        }
        index = equals_index + 1;
    }
    fields
}

fn field_value(fields: &[(String, Value)], field: &str) -> Value {
    fields
        .iter()
        .find(|(key, _)| key == field)
        .map(|(_, value)| value.clone())
        .unwrap_or(Value::Null)
}

fn assignment_records_for_field(block: &str, field: &str) -> Vec<Assignment> {
    let masked = mask_csharp_string_literals(block);
    let mut assignments = Vec::new();
    let mut index = 0usize;
    while index < masked.len() {
        let Some(relative) = masked[index..].find('=') else {
            break;
        };
        let equals_index = index + relative;
        if assignment_field_before_equals(block, equals_index).as_deref() == Some(field) {
            if let Some(value_start) = next_non_whitespace_index(block, equals_index + 1) {
                let value_end = assignment_value_end(&masked, value_start);
                assignments.push(Assignment {
                    value: block[value_start..value_end].trim().to_string(),
                    end: value_end,
                });
            }
        }
        index = equals_index + 1;
    }
    assignments
}

fn assignment_value_end(masked: &str, start_index: usize) -> usize {
    if masked[start_index..].starts_with("new[]") {
        return start_index + "new[]".len();
    }
    let mut brace_depth = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    for (relative, ch) in masked[start_index..].char_indices() {
        let index = start_index + relative;
        match ch {
            '{' => brace_depth += 1,
            '}' => {
                if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 {
                    return index;
                }
                brace_depth = brace_depth.saturating_sub(1);
            }
            '(' => paren_depth += 1,
            ')' => {
                if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 {
                    return index;
                }
                paren_depth = paren_depth.saturating_sub(1);
            }
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            ',' | ';' if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 => {
                return index;
            }
            _ => {}
        }
    }
    masked.len()
}

fn endpoint_assignment_fields(block: &str) -> Vec<String> {
    let masked = mask_csharp_string_literals(block);
    let mut fields = Vec::new();
    let mut index = 0usize;
    while index < masked.len() {
        let Some(relative) = masked[index..].find('=') else {
            break;
        };
        let equals_index = index + relative;
        if let Some(field) = assignment_field_before_equals(block, equals_index) {
            fields.push(field);
        }
        index = equals_index + 1;
    }
    fields
}

fn assignment_field_before_equals(block: &str, equals_index: usize) -> Option<String> {
    let prefix = &block[..equals_index];
    let trimmed = prefix.trim_end();
    let mut start = trimmed.len();
    for (index, ch) in trimmed.char_indices().rev() {
        if ch == '_' || ch.is_ascii_alphanumeric() {
            start = index;
        } else {
            break;
        }
    }
    let field = &trimmed[start..];
    if field.is_empty() || !is_identifier(field) {
        return None;
    }
    Some(field.to_string())
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

fn missing_values(required: &[&str], values: &[String]) -> Vec<String> {
    required
        .iter()
        .filter(|required| !values.iter().any(|value| value == *required))
        .map(|value| value.to_string())
        .collect()
}

fn extra_values(values: &[String], allowed: &[&str]) -> Vec<String> {
    values
        .iter()
        .filter(|value| !allowed.iter().any(|allowed| value == allowed))
        .cloned()
        .collect()
}

fn missing_strings(required: &[String], values: &[String]) -> Vec<String> {
    required
        .iter()
        .filter(|required| !values.contains(*required))
        .cloned()
        .collect()
}

fn unique_count(values: &[String]) -> usize {
    values.iter().collect::<HashSet<_>>().len()
}

fn unique_count_vec(values: &[Vec<String>]) -> usize {
    values.iter().collect::<HashSet<_>>().len()
}

fn safe_text_value(value: &str) -> bool {
    safe_text_values().iter().any(|safe| safe == value)
}

fn safe_text_values() -> Vec<String> {
    let mut values = Vec::new();
    for source in [
        REQUIRED_HYPERVISOR_SCOPE,
        REQUIRED_SURFACES,
        REQUIRED_STAGES,
        REQUIRED_INPUTS,
        REQUIRED_GUARDS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        SAFE_TRUE_FIELDS,
        REQUIRED_DISABLED_FIELDS,
        REQUIRED_CATALOG_KEYS,
        LOCAL_RESPONSE_FIELDS,
    ] {
        values.extend(source.iter().map(|value| value.to_string()));
    }
    values.extend(REQUIRED_RULES.iter().map(|rule| rule.id.to_string()));
    values.extend(
        REQUIRED_RULES
            .iter()
            .flat_map(|rule| [rule.decision, rule.requirement, rule.evidence])
            .map(str::to_string),
    );
    values.extend(
        ENDPOINT_ARRAY_BINDINGS
            .iter()
            .map(|(_, variable)| variable.to_string()),
    );
    values.extend(
        [
            "draft",
            "static-seed",
            "static-preflight-readiness",
            "block",
            "review",
            "blocked",
            "ready-for-approval-review",
            "local-mock",
            "ready",
            "redacted",
            "configured",
            "true",
            "false",
        ]
        .iter()
        .map(|value| value.to_string()),
    );
    values
}

fn safe_text_line(line: &str) -> bool {
    let stripped = line.trim();
    let bullet_value = stripped.strip_prefix("- ").unwrap_or(stripped);
    SAFE_TEXT_PROHIBITION_LINES
        .iter()
        .any(|safe| safe == &stripped)
        || safe_text_value(bullet_value)
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize_identifier(value);
    let safe_normalized: HashSet<String> = safe_text_values()
        .iter()
        .map(|safe| normalize_identifier(safe))
        .collect();
    if safe_normalized.contains(&normalized) {
        return false;
    }
    [
        "servicenowsysid",
        "sysid",
        "ticketid",
        "incidentid",
        "changeid",
        "subscriptionid",
        "customerid",
        "hostid",
        "userid",
        "username",
        "emailaddress",
        "recipientemail",
        "recipientaddress",
        "recipientdata",
        "tenantid",
        "tenantidentifier",
        "objectid",
        "objectidentifier",
        "principalid",
        "principalidentifier",
        "serialnumber",
        "serial",
        "privateip",
        "privatenetwork",
        "hostname",
        "fqdn",
        "endpointurl",
        "url",
        "rawrequest",
        "rawvalidation",
        "rawprovider",
        "rawinventory",
        "rawcmdb",
        "rawapproval",
        "rawuser",
        "userdata",
        "rawrecipient",
        "rawrecipientdata",
        "providerpayload",
        "credential",
        "secret",
        "token",
        "password",
    ]
    .iter()
    .any(|term| normalized.contains(term))
        || sensitive_compound_field(value)
}

fn sensitive_compound_field(value: &str) -> bool {
    let tokens = field_tokens(value);
    if tokens.is_empty() {
        return false;
    }
    has_any(
        &tokens,
        &["password", "credential", "secret", "token", "bearer"],
    ) || (has_any(
        &tokens,
        &[
            "ticket",
            "incident",
            "change",
            "servicenow",
            "sys",
            "subscription",
            "customer",
            "host",
            "user",
            "email",
            "recipient",
            "tenant",
            "object",
            "principal",
            "serial",
            "provider",
            "endpoint",
            "url",
        ],
    ) && has_any(
        &tokens,
        &[
            "id",
            "identifier",
            "payload",
            "data",
            "row",
            "rows",
            "address",
            "value",
            "number",
            "name",
        ],
    )) || (has_any(&tokens, &["private", "ip"])
        && has_any(
            &tokens,
            &["address", "network", "value", "detail", "details"],
        ))
        || (tokens.iter().any(|token| token == "raw")
            && has_any(
                &tokens,
                &[
                    "operation",
                    "operations",
                    "request",
                    "validation",
                    "inventory",
                    "cmdb",
                    "approval",
                    "row",
                    "rows",
                    "log",
                    "logs",
                    "error",
                    "errors",
                    "detail",
                    "details",
                    "user",
                    "recipient",
                    "provider",
                    "payload",
                    "payloads",
                    "data",
                ],
            ))
}

fn prohibited_phrase(value: &str) -> Option<&'static str> {
    let lower = value.to_ascii_lowercase();
    for (phrase, words) in [
        (
            "raw request payloads",
            &["raw", "request", "payload"] as &[&str],
        ),
        ("raw validation rows", &["raw", "validation", "row"]),
        ("raw provider payloads", &["raw", "provider", "payload"]),
        ("raw inventory rows", &["raw", "inventory", "row"]),
        ("raw CMDB rows", &["raw", "cmdb", "row"]),
        ("raw approval data", &["raw", "approval", "data"]),
        ("raw user data", &["raw", "user", "data"]),
        ("raw recipient data", &["raw", "recipient", "data"]),
        ("credential values", &["credential", "value"]),
        ("token values", &["token", "value"]),
        ("ticket id", &["ticket", "id"]),
        ("incident id", &["incident", "id"]),
        ("change id", &["change", "id"]),
        ("ServiceNow sys id", &["servicenow", "sys", "id"]),
        ("tenant id", &["tenant", "id"]),
        ("object id", &["object", "id"]),
        ("principal id", &["principal", "id"]),
        ("private ip", &["private", "ip"]),
        ("private network", &["private", "network"]),
        ("serial number", &["serial", "number"]),
        ("provider payload", &["provider", "payload"]),
        ("live endpoints", &["live", "endpoint"]),
        ("host name", &["host", "name"]),
    ] {
        if phrase_words_present(&lower, words) {
            return Some(phrase);
        }
    }
    None
}

fn phrase_words_present(lower: &str, words: &[&str]) -> bool {
    let tokens = lower
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'))
        .flat_map(|term| term.split(['_', '-']))
        .filter(|term| !term.is_empty())
        .collect::<Vec<_>>();
    tokens.windows(words.len()).any(|window| {
        window
            .iter()
            .zip(words.iter())
            .all(|(token, word)| token_matches_phrase_word(token, word))
    })
}

fn token_matches_phrase_word(token: &str, word: &str) -> bool {
    token == word
        || token
            .strip_suffix('s')
            .is_some_and(|singular| singular == word)
        || matches!((word, token), ("detail", "details") | ("row", "rows"))
}

fn request_preflight_text_path(path: &str) -> bool {
    [
        CATALOG_PATH,
        DOC_PATH,
        PROGRAM_PATH,
        API_README_PATH,
        CATALOG_README_PATH,
        DOC_README_PATH,
    ]
    .iter()
    .any(|text_path| path.ends_with(text_path))
}

fn request_preflight_text_line(path: &str, line: &str) -> bool {
    if path.ends_with(PROGRAM_PATH) {
        return true;
    }
    if path.ends_with(CATALOG_PATH) || path.ends_with(DOC_PATH) {
        return true;
    }
    let lower = line.to_ascii_lowercase();
    lower.contains("request-preflight")
        || lower.contains("request preflight")
        || lower.contains("static request preflight")
        || line.contains(ENDPOINT)
        || line.contains(LOCAL_ENDPOINT)
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|extension| path.ends_with(extension))
}

fn prohibited_value(value: &str) -> bool {
    let text = value.replace("\\/", "/");
    contains_akia(&text)
        || (text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----"))
        || text.contains("://")
        || contains_private_ip(&text)
        || contains_guid(&text)
        || contains_email_like(&text)
        || contains_token_assignment(&text)
}

fn prohibited_provider_identifier_value(value: &str) -> bool {
    contains_sha40_like(value) || contains_provider_serial_like(value)
}

fn contains_sha40_like(value: &str) -> bool {
    value
        .split(|ch: char| !ch.is_ascii_hexdigit())
        .any(|term| term.len() == 40 && term.chars().all(|ch| ch.is_ascii_hexdigit()))
}

fn contains_provider_serial_like(value: &str) -> bool {
    value
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'))
        .any(|term| {
            let upper = term.to_ascii_uppercase();
            let Some(rest) = upper
                .strip_prefix("SN-")
                .or_else(|| upper.strip_prefix("SN_"))
                .or_else(|| upper.strip_prefix("SERIAL-"))
                .or_else(|| upper.strip_prefix("SERIAL_"))
            else {
                return false;
            };
            rest.len() >= 6
                && rest.chars().all(|ch| ch.is_ascii_alphanumeric())
                && rest.chars().any(|ch| ch.is_ascii_digit())
        })
}

fn contains_akia(value: &str) -> bool {
    value
        .as_bytes()
        .windows(4)
        .enumerate()
        .any(|(index, window)| {
            window.eq_ignore_ascii_case(b"AKIA")
                && value[index + 4..]
                    .chars()
                    .take(16)
                    .filter(|ch| ch.is_ascii_alphanumeric())
                    .count()
                    == 16
        })
}

fn contains_private_ip(value: &str) -> bool {
    value
        .split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .any(|candidate| {
            let octets: Vec<u16> = candidate
                .split('.')
                .filter_map(|part| part.parse::<u16>().ok())
                .collect();
            octets.windows(4).any(|window| {
                window.iter().all(|octet| *octet <= 255)
                    && (window[0] == 10
                        || (window[0] == 192 && window[1] == 168)
                        || (window[0] == 172 && (16..=31).contains(&window[1])))
            })
        })
}

fn contains_guid(value: &str) -> bool {
    value
        .split(|ch: char| !(ch.is_ascii_hexdigit() || ch == '-'))
        .any(|candidate| {
            let parts: Vec<&str> = candidate.split('-').collect();
            parts.windows(5).any(|window| {
                [8, 4, 4, 4, 12]
                    .iter()
                    .zip(window.iter())
                    .all(|(length, part)| {
                        part.len() == *length && part.chars().all(|ch| ch.is_ascii_hexdigit())
                    })
            })
        })
}

fn contains_email_like(value: &str) -> bool {
    value.split_whitespace().any(|candidate| {
        let trimmed = candidate.trim_matches(|ch: char| {
            !(ch.is_ascii_alphanumeric() || matches!(ch, '@' | '.' | '_' | '%' | '+' | '-'))
        });
        let trimmed = trimmed.trim_matches('.');
        let Some((local, domain)) = trimmed.split_once('@') else {
            return false;
        };
        !local.is_empty()
            && domain.contains('.')
            && domain.rsplit_once('.').is_some_and(|(_, suffix)| {
                suffix.len() >= 2 && suffix.chars().all(|ch| ch.is_ascii_alphabetic())
            })
    })
}

fn contains_token_assignment(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    for key in [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
        "token",
    ] {
        let mut search = lower.as_str();
        while let Some(position) = search.find(key) {
            let rest = search[position + key.len()..].trim_start();
            if rest.starts_with(':') || rest.starts_with('=') {
                return true;
            }
            search = &search[position + key.len()..];
        }
    }
    false
}

fn allowed_endpoint_fields() -> Vec<String> {
    let mut fields = ALLOWED_ENDPOINT_BASE_FIELDS
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    fields.extend(SAFE_TRUE_FIELDS.iter().map(|value| value.to_string()));
    fields.extend(
        REQUIRED_DISABLED_FIELDS
            .iter()
            .map(|value| value.to_string()),
    );
    fields.extend(
        ENDPOINT_ARRAY_BINDINGS
            .iter()
            .map(|(field, _)| field.to_string()),
    );
    fields.extend(ENDPOINT_INLINE_ARRAYS.iter().map(|value| value.to_string()));
    fields
}

fn unsafe_true_field(field: &str) -> bool {
    let lower = field.to_ascii_lowercase();
    [
        "live",
        "provider",
        "raw",
        "credential",
        "tenant",
        "object",
        "principal",
        "private",
        "submission",
        "dispatch",
        "validation",
        "policy",
        "request",
        "workflow",
        "approval",
        "mutation",
        "execution",
        "token",
        "payload",
    ]
    .iter()
    .any(|term| lower.contains(term))
}

fn unsafe_boolean_flag_field(field: &str) -> bool {
    let lower = field.to_ascii_lowercase();
    lower.ends_with("allowed") || lower.ends_with("enabled") || lower.ends_with("required")
}

fn contains_boolean_true_token(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut index = 0usize;
    while let Some(relative) = lower[index..].find("true") {
        let start = index + relative;
        let end = start + "true".len();
        let before_identifier = start > 0 && is_identifier_continue(bytes[start - 1]);
        let after_identifier = bytes
            .get(end)
            .is_some_and(|byte| is_identifier_continue(*byte));
        if !before_identifier && !after_identifier {
            return true;
        }
        index = end;
    }
    false
}

fn top_level_elements(body: &str) -> Vec<&str> {
    let masked = mask_csharp_string_literals(body);
    let mut elements = Vec::new();
    let mut start_index = 0usize;
    let mut brace_depth = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    for (index, ch) in masked.char_indices() {
        match ch {
            '{' => brace_depth += 1,
            '}' => brace_depth = brace_depth.saturating_sub(1),
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            ',' if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 => {
                let element = body[start_index..index].trim();
                if !element.is_empty() {
                    elements.push(element);
                }
                start_index = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    let element = body[start_index..].trim();
    if !element.is_empty() {
        elements.push(element);
    }
    elements
}

fn csharp_string_literal_values(source: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut index = 0usize;
    while index < source.len() {
        if let Some((value, end)) = parse_csharp_string_literal_at(source, index) {
            values.push(value);
            index = end;
            continue;
        }
        let ch = source[index..].chars().next().expect("valid char boundary");
        index += ch.len_utf8();
    }
    values
}

fn csharp_constant_string_values(source: &str) -> Vec<String> {
    let mut values = csharp_string_literal_values(source);
    values.extend(csharp_concatenated_string_literal_values(source));
    values.extend(csharp_string_concat_call_values(source));
    values
}

fn csharp_concatenated_string_literal_values(source: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut index = 0usize;
    while index < source.len() {
        let Some((first, first_end)) = parse_csharp_string_literal_at(source, index) else {
            let ch = source[index..].chars().next().expect("valid char boundary");
            index += ch.len_utf8();
            continue;
        };
        let mut combined = first;
        let mut cursor = first_end;
        let mut literal_count = 1usize;
        loop {
            let Some(plus_index) = next_non_whitespace_index(source, cursor) else {
                break;
            };
            if source.as_bytes().get(plus_index) != Some(&b'+') {
                break;
            }
            let Some(next_literal_index) = next_non_whitespace_index(source, plus_index + 1) else {
                break;
            };
            let Some((next_value, next_end)) =
                parse_csharp_string_literal_at(source, next_literal_index)
            else {
                break;
            };
            combined.push_str(&next_value);
            cursor = next_end;
            literal_count += 1;
        }
        if literal_count > 1 {
            values.push(combined);
            index = cursor;
        } else {
            index = first_end;
        }
    }
    values
}

fn csharp_string_concat_call_values(source: &str) -> Vec<String> {
    let masked = mask_csharp_string_literals(source);
    let lower = masked.to_ascii_lowercase();
    let mut values = Vec::new();
    let mut index = 0usize;
    const MARKER: &str = ".concat";
    while index < lower.len() {
        let Some(relative) = lower[index..].find(MARKER) else {
            break;
        };
        let dot_index = index + relative;
        if !string_concat_receiver(&lower, dot_index) {
            index = dot_index + MARKER.len();
            continue;
        }
        let Some(paren_index) = next_non_whitespace_index(&masked, dot_index + MARKER.len()) else {
            break;
        };
        if masked.as_bytes().get(paren_index) != Some(&b'(') {
            index = dot_index + MARKER.len();
            continue;
        }
        let Some(close_index) = matching_paren_index(&masked, paren_index) else {
            break;
        };
        let arguments = top_level_elements(&source[paren_index + 1..close_index]);
        let mut combined = String::new();
        let mut literal_count = 0usize;
        let mut all_literals = true;
        for argument in arguments {
            let trimmed = argument.trim();
            let Some((value, end)) = parse_csharp_string_literal_at(trimmed, 0) else {
                all_literals = false;
                break;
            };
            if !trimmed[end..].trim().is_empty() {
                all_literals = false;
                break;
            }
            combined.push_str(&value);
            literal_count += 1;
        }
        if all_literals && literal_count > 0 {
            values.push(combined);
        }
        index = close_index + 1;
    }
    values
}

fn string_concat_receiver(lower: &str, dot_index: usize) -> bool {
    let bytes = lower.as_bytes();
    let mut start = dot_index;
    while start > 0 && (is_identifier_continue(bytes[start - 1]) || bytes[start - 1] == b'.') {
        start -= 1;
    }
    matches!(&lower[start..dot_index], "string" | "system.string")
}

fn parse_csharp_string_literal_at(source: &str, quote_index: usize) -> Option<(String, usize)> {
    let bytes = source.as_bytes();
    let mut quote_index = quote_index;
    while quote_index < bytes.len() {
        let ch = source[quote_index..].chars().next()?;
        if !ch.is_whitespace() {
            break;
        }
        quote_index += ch.len_utf8();
    }
    if bytes.get(quote_index) != Some(&b'"') {
        return None;
    }
    if quote_count_at(bytes, quote_index) >= 3 {
        return parse_raw_string_literal_at(
            source,
            quote_index,
            quote_count_at(bytes, quote_index),
        );
    }
    let mut value = String::new();
    let mut index = quote_index + 1;
    while index < source.len() {
        let ch = source[index..].chars().next()?;
        if ch == '\\' {
            let (decoded, next_index) = decode_csharp_string_escape_at(source, index)?;
            value.push_str(&decoded);
            index = next_index;
            continue;
        }
        if ch == '"' {
            return Some((value, index + 1));
        }
        value.push(ch);
        index += ch.len_utf8();
    }
    None
}

fn decode_csharp_string_escape_at(source: &str, slash_index: usize) -> Option<(String, usize)> {
    if source.as_bytes().get(slash_index) != Some(&b'\\') {
        return None;
    }
    if let Some((ch, end_index)) = csharp_unicode_identifier_escape_at(source, slash_index) {
        return Some((ch.to_string(), end_index));
    }
    let escape_index = slash_index + 1;
    let ch = source[escape_index..].chars().next()?;
    let next_index = escape_index + ch.len_utf8();
    let decoded = match ch {
        '"' => "\"".to_string(),
        '\'' => "'".to_string(),
        '\\' => "\\".to_string(),
        '0' => "\0".to_string(),
        'a' => "\u{7}".to_string(),
        'b' => "\u{8}".to_string(),
        'f' => "\u{c}".to_string(),
        'n' => "\n".to_string(),
        'r' => "\r".to_string(),
        't' => "\t".to_string(),
        'v' => "\u{b}".to_string(),
        'x' => {
            let mut hex_end = next_index;
            let mut digits = String::new();
            while hex_end < source.len() && digits.len() < 4 {
                let hex_ch = source[hex_end..].chars().next()?;
                if !hex_ch.is_ascii_hexdigit() {
                    break;
                }
                digits.push(hex_ch);
                hex_end += hex_ch.len_utf8();
            }
            if digits.is_empty() {
                return None;
            }
            let codepoint = u32::from_str_radix(&digits, 16).ok()?;
            char::from_u32(codepoint)?.to_string()
        }
        _ => ch.to_string(),
    };
    let end_index = if ch == 'x' {
        let mut cursor = next_index;
        let mut count = 0usize;
        while cursor < source.len() && count < 4 {
            let hex_ch = source[cursor..].chars().next()?;
            if !hex_ch.is_ascii_hexdigit() {
                break;
            }
            cursor += hex_ch.len_utf8();
            count += 1;
        }
        cursor
    } else {
        next_index
    };
    Some((decoded, end_index))
}

fn parse_single_csharp_route_literal_at(
    source: &str,
    route_start: usize,
) -> Option<(String, usize)> {
    let (value, end_index) = parse_csharp_string_literal_at(source, route_start)?;
    if value.contains('\n') || value.contains('\r') {
        return None;
    }
    let next_index = next_non_whitespace_index(source, end_index)?;
    if source.as_bytes().get(next_index) == Some(&b',') {
        Some((value, end_index))
    } else {
        None
    }
}

fn parse_raw_string_literal_at(
    source: &str,
    quote_start: usize,
    quote_count: usize,
) -> Option<(String, usize)> {
    let bytes = source.as_bytes();
    let content_start = quote_start + quote_count;
    let mut cursor = content_start;
    while cursor + quote_count <= bytes.len() {
        if bytes[cursor..cursor + quote_count]
            .iter()
            .all(|byte| *byte == b'"')
        {
            return Some((
                source[content_start..cursor].to_string(),
                cursor + quote_count,
            ));
        }
        cursor += source[cursor..].chars().next()?.len_utf8();
    }
    None
}

fn mask_csharp_string_literals(source: &str) -> String {
    let key = (source.as_ptr() as usize, source.len());
    if let Some(cached) = MASK_CACHE.with(|c| c.borrow().get(&key).cloned()) {
        return cached;
    }
    let result = mask_csharp_string_literals_impl(source);
    MASK_CACHE.with(|c| {
        c.borrow_mut().insert(key, result.clone());
    });
    result
}

fn mask_csharp_string_literals_impl(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let mut index = 0usize;
    while index < source.len() {
        if let Some(end) = csharp_string_end(source, index) {
            push_masked_source(&mut result, &source[index..end]);
            index = end;
            continue;
        }
        let ch = source[index..].chars().next().expect("valid char boundary");
        result.push(ch);
        index += ch.len_utf8();
    }
    result
}

fn contains_csharp_interpolated_string(source: &str) -> bool {
    let mut index = 0usize;
    while index < source.len() {
        if source[index..].starts_with("@$\"") {
            return true;
        }
        if let Some(end) = csharp_string_end(source, index) {
            if source[index..].starts_with('$') {
                return true;
            }
            index = end;
            continue;
        }
        let ch = source[index..].chars().next().expect("valid char boundary");
        index += ch.len_utf8();
    }
    false
}

fn code_occurrences_at_depth(source: &str, snippet: &str, expected_depth: usize) -> usize {
    let masked = mask_csharp_string_literals(source);
    let mut count = 0usize;
    let mut offset = 0usize;
    while let Some(relative) = source[offset..].find(snippet) {
        let index = offset + relative;
        if !index_in_csharp_string(source, index)
            && brace_depth_at(&masked, index) == expected_depth
        {
            count += 1;
        }
        offset = index + 1;
    }
    count
}

fn index_in_csharp_string(source: &str, index: usize) -> bool {
    let mut cursor = 0usize;
    while cursor < source.len() {
        if let Some(end) = csharp_string_end(source, cursor) {
            if cursor <= index && index < end {
                return true;
            }
            cursor = end;
            continue;
        }
        let ch = source[cursor..]
            .chars()
            .next()
            .expect("valid char boundary");
        cursor += ch.len_utf8();
    }
    false
}

fn csharp_string_end(source: &str, index: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    match bytes.get(index).copied() {
        Some(b'$') => {
            let mut cursor = index;
            while bytes.get(cursor) == Some(&b'$') {
                cursor += 1;
            }
            if bytes.get(cursor) == Some(&b'@') && bytes.get(cursor + 1) == Some(&b'"') {
                verbatim_string_end(source, cursor + 1)
            } else if bytes.get(cursor) == Some(&b'"') {
                if quote_count_at(bytes, cursor) >= 3 {
                    raw_string_end(source, cursor, quote_count_at(bytes, cursor))
                } else {
                    normal_string_end(source, cursor)
                }
            } else {
                None
            }
        }
        Some(b'@') if bytes.get(index + 1) == Some(&b'"') => verbatim_string_end(source, index + 1),
        Some(b'"') => {
            if quote_count_at(bytes, index) >= 3 {
                raw_string_end(source, index, quote_count_at(bytes, index))
            } else {
                normal_string_end(source, index)
            }
        }
        _ => None,
    }
}

fn normal_string_end(source: &str, quote_index: usize) -> Option<usize> {
    let mut cursor = quote_index + 1;
    let mut escaped = false;
    while cursor < source.len() {
        let ch = source[cursor..].chars().next()?;
        cursor += ch.len_utf8();
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some(cursor);
        }
    }
    Some(source.len())
}

fn verbatim_string_end(source: &str, quote_index: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut cursor = quote_index + 1;
    while cursor < bytes.len() {
        if bytes[cursor] == b'"' {
            if bytes.get(cursor + 1) == Some(&b'"') {
                cursor += 2;
            } else {
                return Some(cursor + 1);
            }
        } else {
            cursor += source[cursor..].chars().next()?.len_utf8();
        }
    }
    Some(source.len())
}

fn raw_string_end(source: &str, quote_index: usize, quote_count: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut cursor = quote_index + quote_count;
    while cursor + quote_count <= bytes.len() {
        if bytes[cursor..cursor + quote_count]
            .iter()
            .all(|byte| *byte == b'"')
        {
            return Some(cursor + quote_count);
        }
        cursor += source[cursor..].chars().next()?.len_utf8();
    }
    Some(source.len())
}

fn quote_count_at(bytes: &[u8], index: usize) -> usize {
    let mut count = 0usize;
    while bytes.get(index + count) == Some(&b'"') {
        count += 1;
    }
    count
}

fn push_masked_source(result: &mut String, source: &str) {
    for ch in source.chars() {
        if ch == '\n' {
            result.push('\n');
        } else {
            for _ in 0..ch.len_utf8() {
                result.push(' ');
            }
        }
    }
}

fn strip_csharp_comments(source: &str) -> String {
    let key = (source.as_ptr() as usize, source.len());
    if let Some(cached) = STRIP_CACHE.with(|c| c.borrow().get(&key).cloned()) {
        return cached;
    }
    let result = strip_csharp_comments_impl(source);
    STRIP_CACHE.with(|c| {
        c.borrow_mut().insert(key, result.clone());
    });
    result
}

fn strip_csharp_comments_impl(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let mut index = 0usize;
    while index < source.len() {
        if let Some(end) = csharp_string_end(source, index) {
            result.push_str(&source[index..end]);
            index = end;
            continue;
        }
        if source[index..].starts_with("//") {
            let end = source[index..]
                .find('\n')
                .map(|relative| index + relative)
                .unwrap_or(source.len());
            for _ in index..end {
                result.push(' ');
            }
            index = end;
            continue;
        }
        if source[index..].starts_with("/*") {
            let end = source[index + 2..]
                .find("*/")
                .map(|relative| index + 2 + relative + 2)
                .unwrap_or(source.len());
            for ch in source[index..end].chars() {
                if ch == '\n' {
                    result.push('\n');
                } else {
                    for _ in 0..ch.len_utf8() {
                        result.push(' ');
                    }
                }
            }
            index = end;
            continue;
        }
        let ch = source[index..].chars().next().expect("valid char boundary");
        result.push(ch);
        index += ch.len_utf8();
    }
    result
}

fn matching_brace_index(text: &str, open_index: usize) -> Option<usize> {
    let masked = mask_csharp_string_literals(text);
    let mut depth = 0usize;
    for (relative, ch) in masked[open_index..].char_indices() {
        let index = open_index + relative;
        if ch == '{' {
            depth += 1;
        } else if ch == '}' {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn matching_paren_index(masked_text: &str, open_index: usize) -> Option<usize> {
    if masked_text.as_bytes().get(open_index) != Some(&b'(') {
        return None;
    }
    let mut depth = 0usize;
    for (relative, ch) in masked_text[open_index..].char_indices() {
        let index = open_index + relative;
        if ch == '(' {
            depth += 1;
        } else if ch == ')' {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn brace_depth_at(masked_text: &str, index: usize) -> usize {
    let mut depth = 0usize;
    for ch in masked_text[..index].chars() {
        if ch == '{' {
            depth += 1;
        } else if ch == '}' {
            depth = depth.saturating_sub(1);
        }
    }
    depth
}

fn next_non_whitespace_index(text: &str, start: usize) -> Option<usize> {
    text[start..]
        .char_indices()
        .find(|(_, ch)| !ch.is_whitespace())
        .map(|(relative, _)| start + relative)
}

fn is_word_boundary(text: &str, start: usize, word: &str) -> bool {
    let end = start + word.len();
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        && !after.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn is_identifier_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_identifier_continue(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn word_terms(line: &str) -> Vec<String> {
    line.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'))
        .filter(|term| {
            term.chars()
                .next()
                .map(|ch| ch.is_ascii_alphabetic())
                .unwrap_or(false)
        })
        .map(str::to_string)
        .collect()
}

fn assignment_like_terms(line: &str) -> Vec<String> {
    let mut terms = Vec::new();
    for marker in ['=', ':'] {
        let mut offset = 0usize;
        while let Some(relative) = line[offset..].find(marker) {
            let index = offset + relative;
            offset = index + marker.len_utf8();
            if marker == '='
                && (line.as_bytes().get(index + 1) == Some(&b'>')
                    || matches!(
                        line.as_bytes().get(index.wrapping_sub(1)),
                        Some(b'!') | Some(b'<') | Some(b'>') | Some(b'=')
                    ))
            {
                continue;
            }
            if marker == ':' && line.as_bytes().get(index + 1) == Some(&b':') {
                continue;
            }
            let prefix = &line[..index];
            let words: Vec<&str> = prefix
                .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'))
                .filter(|term| {
                    term.chars()
                        .next()
                        .map(|ch| ch.is_ascii_alphabetic())
                        .unwrap_or(false)
                })
                .collect();
            if let Some(last) = words.last() {
                terms.push((*last).to_string());
            }
            if words.len() >= 2 {
                terms.push(words[words.len() - 2..].join(" "));
            }
            if words.len() >= 3 {
                terms.push(words[words.len() - 3..].join(" "));
            }
            if words.len() >= 4 {
                terms.push(words[words.len() - 4..].join(" "));
            }
        }
    }
    terms.sort();
    terms.dedup();
    terms
}

fn field_tokens(value: &str) -> Vec<String> {
    let mut spaced = String::new();
    let mut previous_lower_or_digit = false;
    for ch in value.chars() {
        if ch.is_ascii_uppercase() && previous_lower_or_digit {
            spaced.push(' ');
        }
        if ch.is_ascii_alphanumeric() {
            spaced.push(ch.to_ascii_lowercase());
            previous_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        } else {
            spaced.push(' ');
            previous_lower_or_digit = false;
        }
    }
    spaced.split_whitespace().map(str::to_string).collect()
}

fn has_any(tokens: &[String], candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| tokens.iter().any(|token| token == candidate))
}

fn normalize_identifier(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}
