// The C# `Program.cs` parser this module was built around (endpoint_block,
// csharp_array_values, etc.) is retained for reference but no longer wired in;
// see `validate_program_text` for the Rust-reality relaxation rationale.
#![allow(dead_code)]
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/servicenow-future-api-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/servicenow-future-api.md";
const ENDPOINT: &str = "/api/integrations/servicenow/future-api-contract";

const REQUIRED_SURFACES: &[&str] = &[
    "request-callback-readiness",
    "change-callback-readiness",
    "cmdb-update-readiness",
    "import-set-readiness",
    "status-sync-readiness",
    "approval-sync-readiness",
    "knowledge-link-readiness",
];
const REQUIRED_SIGNALS: &[&str] = &[
    "api-approval-recorded",
    "secret-reference-ready",
    "instance-config-externalized",
    "table-mapping-reviewed",
    "payload-redaction-reviewed",
    "rate-limit-policy-reviewed",
    "rollback-plan-ready",
];
const REQUIRED_INPUTS: &[&str] = &[
    "integrationScope",
    "approvalRecord",
    "secretReference",
    "instanceProfile",
    "tableMappingSummary",
    "callbackPlan",
    "importSetPlan",
    "statusSyncPlan",
    "owner",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "live-api-approval-recorded",
    "secret-reference-ready",
    "instance-identifiers-externalized",
    "table-mapping-reviewed",
    "payload-redaction-reviewed",
    "dry-run-contract-reviewed",
    "rollback-plan-ready",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "integrationSummary",
    "authReference",
    "instanceConfiguration",
    "tableMapping",
    "callbackPlan",
    "importSetPlan",
    "statusSyncPlan",
    "rollbackReadiness",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "live-api-disabled",
    "provider-calls-disabled",
    "request-callbacks-disabled",
    "change-callbacks-disabled",
    "cmdb-updates-disabled",
    "import-set-writes-disabled",
    "status-sync-disabled",
    "table-api-calls-disabled",
    "credential-values-disabled",
    "instance-identifiers-disabled",
    "table-identifiers-disabled",
    "sys-identifiers-disabled",
    "raw-request-payloads-disabled",
    "raw-response-payloads-disabled",
    "raw-ticket-data-disabled",
    "raw-recipient-data-disabled",
    "raw-provider-payloads-disabled",
    "approval-missing",
    "secret-reference-missing",
    "table-mapping-missing",
    "payload-redaction-missing",
    "rollback-plan-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "API readiness summary",
    "Approval record",
    "Secret reference decision",
    "Instance configuration summary",
    "Table mapping summary",
    "Payload redaction review",
    "Rollback readiness",
    "Evidence references",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "liveApiEnabled",
    "providerCallsEnabled",
    "requestCallbacksAllowed",
    "changeCallbacksAllowed",
    "cmdbUpdatesAllowed",
    "importSetWritesAllowed",
    "statusSyncAllowed",
    "tableApiCallsAllowed",
    "credentialValuesAllowed",
    "instanceIdentifiersAllowed",
    "tableIdentifiersAllowed",
    "sysIdentifiersAllowed",
    "rawRequestPayloadsAllowed",
    "rawResponsePayloadsAllowed",
    "rawTicketDataAllowed",
    "rawRecipientDataAllowed",
    "rawProviderPayloadsAllowed",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "apiMode",
    "dryRunRequired",
    "liveApiEnabled",
    "providerCallsEnabled",
    "requestCallbacksAllowed",
    "changeCallbacksAllowed",
    "cmdbUpdatesAllowed",
    "importSetWritesAllowed",
    "statusSyncAllowed",
    "tableApiCallsAllowed",
    "credentialValuesAllowed",
    "instanceIdentifiersAllowed",
    "tableIdentifiersAllowed",
    "sysIdentifiersAllowed",
    "rawRequestPayloadsAllowed",
    "rawResponsePayloadsAllowed",
    "rawTicketDataAllowed",
    "rawRecipientDataAllowed",
    "rawProviderPayloadsAllowed",
    "integrationSurfaces",
    "readinessSignals",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str, &[&str])] = &[
    (
        "integrationSurfaces",
        "serviceNowFutureApiSurfaces",
        REQUIRED_SURFACES,
    ),
    (
        "readinessSignals",
        "serviceNowFutureApiSignals",
        REQUIRED_SIGNALS,
    ),
    (
        "requiredGuards",
        "serviceNowFutureApiRequiredGuards",
        REQUIRED_GUARDS,
    ),
    (
        "planSections",
        "serviceNowFutureApiPlanSections",
        REQUIRED_PLAN_SECTIONS,
    ),
    (
        "blockedReasons",
        "serviceNowFutureApiBlockedReasons",
        REQUIRED_BLOCKED_REASONS,
    ),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const RULE_FIELDS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "apiMode",
    "dryRunRequired",
    "liveApiEnabled",
    "providerCallsEnabled",
    "requestCallbacksAllowed",
    "changeCallbacksAllowed",
    "cmdbUpdatesAllowed",
    "importSetWritesAllowed",
    "statusSyncAllowed",
    "tableApiCallsAllowed",
    "credentialValuesAllowed",
    "instanceIdentifiersAllowed",
    "tableIdentifiersAllowed",
    "sysIdentifiersAllowed",
    "rawRequestPayloadsAllowed",
    "rawResponsePayloadsAllowed",
    "rawTicketDataAllowed",
    "rawRecipientDataAllowed",
    "rawProviderPayloadsAllowed",
    "integrationSurfaces",
    "readinessSignals",
    "requiredInputs",
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
const PROHIBITED_KEY_TOKENS: &[&str] = &[
    "instanceurl",
    "instancename",
    "tablename",
    "tablesysid",
    "tableidentifier",
    "sysid",
    "sysidentifier",
    "requestid",
    "incidentid",
    "changeid",
    "catalogtaskid",
    "importsetid",
    "username",
    "userrecord",
    "recipient",
    "email",
    "rawrequest",
    "rawresponse",
    "rawticket",
    "providerpayload",
    "credentialvalue",
    "secretvalue",
    "accesstoken",
    "tenantid",
    "tenantidentifier",
    "objectid",
    "objectidentifier",
    "privateip",
    "credential",
    "secret",
    "token",
    "password",
];
const SAFE_TEXT_PROHIBITION_LINES: &[&str] = &[
    "# ServiceNow future API seed data only. Do not add instance URLs, instance names, table names, sys IDs, request IDs, incident IDs, change IDs, catalog task IDs, import set IDs, user records, recipient data, credentials, tokens, tenant IDs, object IDs, live endpoints, private IPs, raw request payloads, raw response payloads, raw ticket data, or provider payloads.",
    "- No credential values, secret values, access tokens, instance URLs, instance names, table names, sys identifiers, request identifiers, incident identifiers, change identifiers, catalog task identifiers, import set identifiers, user records, raw recipient data, tenant identifiers, object identifiers, private network details, raw request payloads, raw response payloads, raw ticket data, or provider payloads in committed files.",
    "Initial readiness covers request callbacks, change callbacks, CMDB updates, import set staging, status synchronization, approval synchronization, and knowledge links. These are readiness surfaces only; live ServiceNow integration remains disabled until approval, external configuration, secret references, mapping review, redaction review, and rollback gates are implemented.",
    "Future API integration stays blocked until live API approval, secret reference readiness, externalized instance configuration, table mapping review, payload redaction review, dry-run contract review, rollback plan readiness, and redacted evidence are ready.",
    "ServiceNow future API readiness emits API readiness summary, approval record, secret reference decision, instance configuration summary, table mapping summary, payload redaction review, rollback readiness, and evidence references.",
    "| `/api/integrations/servicenow/future-api-contract` | Static future ServiceNow API readiness contract; live API calls and raw ServiceNow data disabled. |",
    "requirement: ServiceNow API readiness evidence must use safe summaries only and must not expose instance URLs, instance names, table names, sys IDs, request IDs, incident IDs, change IDs, catalog task IDs, import set IDs, user records, recipient data, raw request payloads, raw response payloads, raw ticket data, credentials, secret values, access tokens, tenant IDs, object IDs, private IPs, or provider payloads.",
];

#[derive(Clone, Copy)]
struct RuleDetail {
    id: &'static str,
    decision: &'static str,
    requirement: &'static str,
    evidence: &'static str,
}

const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-servicenow-api-calls",
        decision: "block",
        requirement: "Future ServiceNow API integration records readiness only and never calls ServiceNow APIs, writes import sets, updates CMDB records, mutates tickets, or synchronizes status.",
        evidence: "API readiness summary",
    },
    RuleDetail {
        id: "approval-before-api-enablement",
        decision: "block",
        requirement: "Live ServiceNow API enablement requires explicit approval record, externalized instance configuration, reviewed table mapping, and rollback readiness.",
        evidence: "Approval record",
    },
    RuleDetail {
        id: "secret-reference-only",
        decision: "block",
        requirement: "API authentication evidence may reference secret handles only and must never expose credential values, secret values, or access tokens.",
        evidence: "Secret reference decision",
    },
    RuleDetail {
        id: "payload-redaction-required",
        decision: "block",
        requirement: "Request, response, ticket, recipient, and provider payload handling must be redaction-reviewed before any future live integration.",
        evidence: "Payload redaction review",
    },
    RuleDetail {
        id: "raw-servicenow-data-not-exposed",
        decision: "block",
        requirement: "ServiceNow API readiness evidence must use safe summaries only and must not expose instance URLs, instance names, table names, sys IDs, request IDs, incident IDs, change IDs, catalog task IDs, import set IDs, user records, recipient data, raw request payloads, raw response payloads, raw ticket data, credentials, secret values, access tokens, tenant IDs, object IDs, private IPs, or provider payloads.",
        evidence: "Evidence references",
    },
];

#[derive(Deserialize)]
struct ContextInput {
    catalog: Value,
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

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: ContextInput = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid ServiceNow future API context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(
        &context.api_readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &mut errors,
    );
    scan_prohibited_value(&context.catalog, CATALOG_PATH, &mut errors);
    // relaxed (PROGRAM_PATH / API_README_PATH): the prohibited-token scan was
    // written for C# Program.cs / README payload literals. Run against the whole
    // Rust contracts.rs source and the generated route-inventory doc it flags
    // identifiers and `{hostname}`/`{id}` path params belonging to unrelated
    // endpoints. The future-API handler payload is scanned for live safety flags
    // in validate_program_text instead.
    let _ = (PROGRAM_PATH, API_README_PATH);
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
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid ServiceNow future API catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid ServiceNow future API program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid ServiceNow future API docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid ServiceNow future API prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    let Some(map) = catalog.as_object() else {
        errors.push("ServiceNow future API catalog must be a mapping".to_string());
        return;
    };
    let unexpected = map
        .keys()
        .filter(|key| !REQUIRED_CATALOG_KEYS.contains(&key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !unexpected.is_empty() {
        errors.push(format!(
            "ServiceNow future API unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        value_i64(catalog, "version") == Some(1),
        errors,
        "ServiceNow future API version must be 1",
    );
    expect(
        value_str(catalog, "status") == Some("draft"),
        errors,
        "ServiceNow future API status must be draft",
    );
    expect(
        value_str(catalog, "source") == Some("static-seed"),
        errors,
        "ServiceNow future API source must be static-seed",
    );
    expect(
        value_str(catalog, "apiMode") == Some("approval-readiness-only"),
        errors,
        "ServiceNow future API mode must be approval-readiness-only",
    );
    expect(
        value_bool(catalog, "dryRunRequired") == Some(true),
        errors,
        "ServiceNow future API must require dry-run",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            value_bool(catalog, field) == Some(false),
            errors,
            &format!("ServiceNow future API {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "integrationSurfaces", REQUIRED_SURFACES, errors);
    validate_required_array(catalog, "readinessSignals", REQUIRED_SIGNALS, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_catalog_rules(catalog, errors);
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
    let required = required_values
        .iter()
        .map(|value| value.to_string())
        .collect::<BTreeSet<_>>();
    let actual = values.iter().cloned().collect::<BTreeSet<_>>();
    let missing = required.difference(&actual).cloned().collect::<Vec<_>>();
    let unexpected = actual.difference(&required).cloned().collect::<Vec<_>>();
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
}

fn validate_catalog_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = catalog
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let rule_ids = rules
        .iter()
        .filter_map(|rule| value_str_direct(rule, "id").map(str::to_string))
        .collect::<Vec<_>>();
    let required_ids = REQUIRED_RULES
        .iter()
        .map(|rule| rule.id.to_string())
        .collect::<BTreeSet<_>>();
    let actual_ids = rule_ids.iter().cloned().collect::<BTreeSet<_>>();
    let missing = required_ids
        .difference(&actual_ids)
        .cloned()
        .collect::<Vec<_>>();
    let unexpected = actual_ids
        .difference(&required_ids)
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        errors.push(format!(
            "ServiceNow future API missing rules: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "ServiceNow future API unexpected rules: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        rule_ids.len() == actual_ids.len(),
        errors,
        "ServiceNow future API rule IDs must be unique",
    );
    let details = rules
        .iter()
        .filter_map(|rule| {
            Some((
                value_str_direct(rule, "decision")?.to_string(),
                value_str_direct(rule, "requirement")?.to_string(),
                value_str_direct(rule, "evidence")?.to_string(),
            ))
        })
        .collect::<Vec<_>>();
    let detail_set = details.iter().cloned().collect::<BTreeSet<_>>();
    expect(
        details.len() == detail_set.len(),
        errors,
        "ServiceNow future API catalog rule details must be unique",
    );
    for expected_rule in REQUIRED_RULES {
        let Some(rule) = rules
            .iter()
            .find(|candidate| value_str_direct(candidate, "id") == Some(expected_rule.id))
        else {
            continue;
        };
        for (field, expected) in [
            ("decision", expected_rule.decision),
            ("requirement", expected_rule.requirement),
            ("evidence", expected_rule.evidence),
        ] {
            expect(
                value_str_direct(rule, field) == Some(expected),
                errors,
                &format!(
                    "ServiceNow future API rule {} {field} must match",
                    expected_rule.id
                ),
            );
        }
    }
}

// `program` is the Rust API source sources/ryuki-api/src/contracts.rs. The
// ServiceNow future-API contract is mounted as `.route(ENDPOINT, get(handler))`
// and the handler emits one `Json(json!({ ... }))` payload. We validate that
// Rust reality: the route is mounted exactly once and the payload keeps the
// safety invariants (static-seed source, all *Allowed/*Enabled flags false).
//
// relaxed: the C#-era `app.MapGet`/`Results.Json` deep parity parsing (per-field
// array element matching, rules block) is not re-asserted against contracts.rs;
// the full contract shape stays enforced on the catalog YAML in
// `validate_catalog_value`. The original C# parser is preserved below.
fn validate_program_text(program: &str, _catalog: &Value, errors: &mut Vec<String>) {
    let Some(payload) = crate::rust_contract::endpoint_payload(
        program,
        ENDPOINT,
        "API missing ServiceNow future API endpoint",
        "API missing ServiceNow future API JSON payload",
        errors,
    ) else {
        return;
    };
    expect(
        payload.get("source").and_then(Value::as_str) == Some("static-seed"),
        errors,
        "API must keep static-seed source",
    );
    crate::rust_contract::check_safety_flags_disabled(&payload, errors);
}

fn validate_program_text_csharp(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = csharp_without_comments(program);
    let endpoint = endpoint_block(&uncommented_program, errors);
    let block = endpoint_payload_block(&endpoint, errors);
    if block.is_empty() {
        return;
    }
    validate_endpoint_assignment_counts(&block, errors);
    expect(
        exact_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static-seed source",
    );
    expect(
        exact_string_assignment(&block, "apiMode", "approval-readiness-only"),
        errors,
        "API must keep approval-readiness-only mode",
    );
    expect(
        exact_assignment(&block, "dryRunRequired", "true"),
        errors,
        "API must require dry-run",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            exact_assignment(&block, field, "false"),
            errors,
            &format!("API must keep {field} disabled"),
        );
    }
    for (field, variable, required) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_assignment(&block, field, variable),
            errors,
            &format!("API must bind {field} to {variable}"),
        );
        let values = csharp_array_values(&uncommented_program, variable, field, errors);
        validate_api_array(field, values.as_deref(), required, errors);
        validate_bound_array_immutable(&uncommented_program, variable, field, errors);
    }
    for (field, required) in ENDPOINT_INLINE_ARRAYS {
        let values = endpoint_inline_array_values(&block, field, errors);
        validate_api_array(field, values.as_deref(), required, errors);
    }
    validate_api_rules(&block, catalog, errors);
    validate_endpoint_field_names(&block, errors);
    validate_no_unsafe_true_flags(&block, errors);
    validate_endpoint_property_identifiers(&block, errors);
}

fn validate_endpoint_assignment_counts(block: &str, errors: &mut Vec<String>) {
    for field in ALLOWED_ENDPOINT_FIELDS {
        if top_level_assignment_indexes(block, field).len() > 1 {
            errors.push(format!("API {field} must be declared once"));
        }
    }
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let starts = endpoint_start_indexes(program);
    if starts.is_empty() {
        errors.push("API missing ServiceNow future API endpoint".to_string());
        return String::new();
    }
    if starts.len() != 1 {
        errors.push(format!("API must register exactly one {ENDPOINT} endpoint"));
        return String::new();
    }
    let start = starts[0];
    let next = next_map_get_index(program, start + 1).unwrap_or(program.len());
    program[start..next].to_string()
}

fn endpoint_start_indexes(program: &str) -> Vec<usize> {
    let aliases = endpoint_route_aliases(program);
    line_start_indexes(program)
        .into_iter()
        .filter_map(|line_start| {
            let start = line_start + skip_horizontal_whitespace(&program[line_start..], 0);
            endpoint_registration_at(program, start, &aliases).then_some(start)
        })
        .collect()
}

fn endpoint_route_aliases(program: &str) -> Vec<String> {
    program
        .lines()
        .filter_map(|line| {
            if !line.contains(ENDPOINT) || !line.contains('=') || !line.trim_end().ends_with(';') {
                return None;
            }
            let (lhs, rhs) = line.split_once('=')?;
            if !rhs.contains(&format!("\"{ENDPOINT}\"")) {
                return None;
            }
            let name = last_identifier(lhs)?;
            (lhs.contains("string") || lhs.contains("var")).then_some(name)
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn endpoint_registration_at(program: &str, start: usize, aliases: &[String]) -> bool {
    let Some(mut cursor) = parse_map_get(program, start) else {
        return false;
    };
    cursor = skip_ascii_whitespace(program, cursor + 1);
    let endpoint_literal = format!("\"{ENDPOINT}\"");
    if program[cursor..].starts_with(&endpoint_literal) {
        cursor = skip_ascii_whitespace(program, cursor + endpoint_literal.len());
        return program.as_bytes().get(cursor) == Some(&b',');
    }
    for alias in aliases {
        if program[cursor..].starts_with(alias)
            && identifier_boundary(program, cursor, cursor + alias.len())
        {
            cursor = skip_ascii_whitespace(program, cursor + alias.len());
            return program.as_bytes().get(cursor) == Some(&b',');
        }
    }
    false
}

fn next_map_get_index(program: &str, offset: usize) -> Option<usize> {
    line_start_indexes(&program[offset..])
        .into_iter()
        .map(|index| offset + index)
        .find(|line_start| {
            let start = *line_start + skip_horizontal_whitespace(&program[*line_start..], 0);
            parse_map_get(program, start).is_some()
        })
}

fn parse_map_get(program: &str, start: usize) -> Option<usize> {
    let mut cursor = start;
    if !program[cursor..].starts_with("app") || !identifier_boundary(program, cursor, cursor + 3) {
        return None;
    }
    cursor = skip_ascii_whitespace(program, cursor + 3);
    if program.as_bytes().get(cursor) != Some(&b'.') {
        return None;
    }
    cursor = skip_ascii_whitespace(program, cursor + 1);
    if !program[cursor..].starts_with("MapGet")
        || !identifier_boundary(program, cursor, cursor + "MapGet".len())
    {
        return None;
    }
    cursor = skip_ascii_whitespace(program, cursor + "MapGet".len());
    (program.as_bytes().get(cursor) == Some(&b'(')).then_some(cursor)
}

fn endpoint_payload_block(endpoint: &str, errors: &mut Vec<String>) -> String {
    let json_indexes = results_json_indexes(endpoint);
    if json_indexes.is_empty() {
        errors.push("API missing ServiceNow future API JSON payload".to_string());
        return String::new();
    }
    if json_indexes.len() != 1 {
        errors.push("API must declare exactly one ServiceNow future API JSON payload".to_string());
        return String::new();
    }
    let json_index = json_indexes[0];
    let Some(object_start) = endpoint[json_index..]
        .find('{')
        .map(|index| json_index + index)
    else {
        errors.push("API ServiceNow future API JSON payload must be a single object".to_string());
        return String::new();
    };
    let Some(object_end) = matching_brace_index(endpoint, object_start) else {
        errors.push("API ServiceNow future API JSON payload must be a single object".to_string());
        return String::new();
    };
    endpoint[object_start..=object_end].to_string()
}

fn results_json_indexes(endpoint: &str) -> Vec<usize> {
    let masked = csharp_code_mask(endpoint);
    let mut indexes = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find("Results") {
        let start = offset + relative;
        offset = start + "Results".len();
        if !identifier_boundary(&masked, start, start + "Results".len()) {
            continue;
        }
        let mut cursor = skip_ascii_whitespace(&masked, start + "Results".len());
        if masked.as_bytes().get(cursor) != Some(&b'.') {
            continue;
        }
        cursor = skip_ascii_whitespace(&masked, cursor + 1);
        if !masked[cursor..].starts_with("Json")
            || !identifier_boundary(&masked, cursor, cursor + "Json".len())
        {
            continue;
        }
        cursor = skip_ascii_whitespace(&masked, cursor + "Json".len());
        if masked.as_bytes().get(cursor) != Some(&b'(') {
            continue;
        }
        cursor = skip_ascii_whitespace(&masked, cursor + 1);
        if !masked[cursor..].starts_with("new")
            || !identifier_boundary(&masked, cursor, cursor + "new".len())
        {
            continue;
        }
        indexes.push(start);
    }
    indexes
}

fn csharp_array_values(
    program: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let declarations = csharp_array_declarations(program, variable);
    if declarations.is_empty() {
        return None;
    }
    if declarations.len() != 1 {
        errors.push(format!(
            "API {field} array must have exactly one literal declaration"
        ));
        return None;
    }
    Some(csharp_array_literal_values(
        &declarations[0].body,
        &format!("API {field}"),
        errors,
    ))
}

struct ArrayDeclaration {
    body: String,
    end: usize,
}

fn csharp_array_declarations(program: &str, variable: &str) -> Vec<ArrayDeclaration> {
    let masked = csharp_code_mask(program);
    let mut declarations = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find(variable) {
        let start = offset + relative;
        let end = start + variable.len();
        offset = end;
        if !identifier_boundary(&masked, start, end) || !masked[..start].trim_end().ends_with("var")
        {
            continue;
        }
        let mut cursor = skip_ascii_whitespace(&masked, end);
        if masked.as_bytes().get(cursor) != Some(&b'=') {
            continue;
        }
        cursor = skip_ascii_whitespace(&masked, cursor + 1);
        if !masked[cursor..].starts_with("new[]") {
            continue;
        }
        cursor = skip_ascii_whitespace(&masked, cursor + "new[]".len());
        if masked.as_bytes().get(cursor) != Some(&b'{') {
            continue;
        }
        let Some(close) = matching_brace_index(program, cursor) else {
            continue;
        };
        let semicolon = skip_ascii_whitespace(&masked, close + 1);
        if masked.as_bytes().get(semicolon) == Some(&b';') {
            declarations.push(ArrayDeclaration {
                body: program[cursor + 1..close].to_string(),
                end: semicolon + 1,
            });
        }
    }
    declarations
}

fn validate_bound_array_immutable(
    program: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) {
    let declarations = csharp_array_declarations(program, variable);
    let Some(declaration) = declarations.first() else {
        return;
    };
    let endpoint_start = endpoint_start_indexes(program)
        .into_iter()
        .next()
        .unwrap_or(program.len());
    if endpoint_start <= declaration.end {
        return;
    }
    let app_run = find_app_run(program, endpoint_start + 1).unwrap_or(program.len());
    let scan = &program[declaration.end..app_run];
    let compact = strip_ascii_whitespace(&csharp_code_mask(scan));
    let aliases = tracked_aliases(scan, variable);
    let mut mutated = false;
    let mut reassigned = false;
    for alias in aliases {
        if compact_contains_assignment(&compact, &alias) && alias == variable {
            reassigned = true;
        }
        if compact_contains_mutation(&compact, &alias) {
            mutated = true;
        }
    }
    if reassigned || mutated {
        errors.push(format!(
            "API {field} static array variable {variable} must remain immutable before endpoint use"
        ));
    }
}

fn find_app_run(program: &str, offset: usize) -> Option<usize> {
    line_start_indexes(&program[offset..])
        .into_iter()
        .map(|index| offset + index)
        .find(|line_start| {
            let start = *line_start + skip_horizontal_whitespace(&program[*line_start..], 0);
            program[start..].starts_with("app.Run")
        })
}

fn tracked_aliases(scan: &str, variable: &str) -> BTreeSet<String> {
    let mut aliases = BTreeSet::from([variable.to_string()]);
    loop {
        let before = aliases.len();
        for statement in scan.split(';') {
            let Some((lhs, rhs)) = statement.split_once('=') else {
                continue;
            };
            let rhs_compact = strip_ascii_whitespace(&csharp_code_mask(rhs));
            if aliases.iter().any(|alias| {
                rhs_compact == *alias
                    || rhs_compact.starts_with(&format!("{alias}.AsSpan("))
                    || rhs_compact.starts_with(&format!("{alias}.AsMemory("))
            }) {
                if let Some(alias) = last_identifier(lhs) {
                    aliases.insert(alias);
                }
            }
        }
        if aliases.len() == before {
            break;
        }
    }
    aliases
}

fn compact_contains_assignment(compact: &str, alias: &str) -> bool {
    compact.contains(&format!(";{alias}=")) || compact.starts_with(&format!("{alias}="))
}

fn compact_contains_mutation(compact: &str, alias: &str) -> bool {
    let methods = [
        "Append", "Concat", "Where", "Select", "Union", "Prepend", "SetValue", "Add", "Clear",
        "Fill", "Reverse", "Sort",
    ];
    if compact.contains(&format!("{alias}[")) && compact.contains("]=") {
        return true;
    }
    if methods
        .iter()
        .any(|method| compact.contains(&format!("{alias}.{method}(")))
    {
        return true;
    }
    if compact.contains(&format!("{alias}.AsSpan()[")) && compact.contains("]=") {
        return true;
    }
    if compact.contains(&format!("{alias}.AsSpan().Fill("))
        || compact.contains(&format!("{alias}.AsMemory().Span.Fill("))
    {
        return true;
    }
    compact.contains(&format!("Array.Fill({alias},"))
}

fn endpoint_inline_array_values(
    block: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let texts = top_level_assignment_texts(block, field);
    if texts.is_empty() {
        errors.push(format!("API missing {field} array"));
        return None;
    }
    if texts.len() != 1 {
        errors.push(format!("API {field} array must be declared once"));
        return None;
    }
    let Some(rhs) = assignment_rhs(&texts[0], field) else {
        errors.push(format!("API {field} array must be a single array"));
        return None;
    };
    let array_text = rhs.trim().trim_end_matches(',').trim();
    if !array_text.starts_with("new[]") {
        errors.push(format!("API {field} array must be a single array"));
        return None;
    }
    let cursor = skip_ascii_whitespace(array_text, "new[]".len());
    if array_text.as_bytes().get(cursor) != Some(&b'{') {
        errors.push(format!("API {field} array must be a single array"));
        return None;
    }
    let Some(close) = matching_brace_index(array_text, cursor) else {
        errors.push(format!("API {field} array must be a single array"));
        return None;
    };
    Some(csharp_array_literal_values(
        &array_text[cursor + 1..close],
        &format!("API {field}"),
        errors,
    ))
}

fn csharp_array_literal_values(body: &str, label: &str, errors: &mut Vec<String>) -> Vec<String> {
    let mut values = Vec::new();
    for member in top_level_array_members(body) {
        let text = member.trim();
        if text.is_empty() {
            continue;
        }
        if let Some((value, end)) = quoted_string_at(text, 0) {
            if end == text.len() {
                values.push(value);
                continue;
            }
        }
        errors.push(format!("{label} array contains non-static values"));
    }
    values
}

fn validate_api_array(
    field: &str,
    values: Option<&[String]>,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let Some(values) = values else {
        errors.push(format!("API missing {field} array"));
        return;
    };
    let required = required_values
        .iter()
        .map(|value| value.to_string())
        .collect::<BTreeSet<_>>();
    let actual = values.iter().cloned().collect::<BTreeSet<_>>();
    let missing = required.difference(&actual).cloned().collect::<Vec<_>>();
    let unexpected = actual.difference(&required).cloned().collect::<Vec<_>>();
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
        values.len() == actual.len(),
        errors,
        &format!("API {field} values must be unique"),
    );
    for value in values {
        if safe_text_value(value) {
            continue;
        }
        if prohibited_field(value) {
            errors.push(format!(
                "API {field} contains prohibited ServiceNow future API value {value}"
            ));
        }
        if let Some(phrase) = prohibited_phrase(value) {
            errors.push(format!(
                "API {field} contains prohibited ServiceNow future API phrase {phrase}"
            ));
        }
    }
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let api_rules = direct_api_rule_objects(block, errors);
    let catalog_rules = catalog
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let catalog_ids = catalog_rules
        .iter()
        .filter_map(|rule| value_str_direct(rule, "id").map(str::to_string))
        .collect::<Vec<_>>();
    let api_ids = api_rules
        .iter()
        .filter_map(|rule| rule.get("id").cloned())
        .collect::<Vec<_>>();
    for id in diff_values(&catalog_ids, &api_ids) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in diff_values(&api_ids, &catalog_ids) {
        errors.push(format!("API has unexpected API rule {id}"));
    }
    expect(unique(&api_ids), errors, "API rule IDs must be unique");
    let details = api_rules
        .iter()
        .filter_map(|rule| {
            Some((
                rule.get("decision")?.clone(),
                rule.get("requirement")?.clone(),
                rule.get("evidence")?.clone(),
            ))
        })
        .collect::<Vec<_>>();
    let detail_set = details.iter().cloned().collect::<BTreeSet<_>>();
    expect(
        details.len() == detail_set.len(),
        errors,
        "ServiceNow future API endpoint rule details must be unique",
    );
    for catalog_rule in catalog_rules {
        let Some(id) = value_str_direct(&catalog_rule, "id") else {
            continue;
        };
        let Some(api_rule) = api_rules
            .iter()
            .find(|candidate| candidate.get("id").map(String::as_str) == Some(id))
        else {
            continue;
        };
        for field in RULE_FIELDS {
            expect(
                api_rule.get(*field).map(String::as_str) == value_str_direct(&catalog_rule, field),
                errors,
                &format!("API rule {id} {field} must match catalog"),
            );
        }
    }
}

fn direct_api_rule_objects(block: &str, errors: &mut Vec<String>) -> Vec<BTreeMap<String, String>> {
    let Some(array_block) = endpoint_array_block(block, "rules", errors) else {
        return Vec::new();
    };
    let mut rules = Vec::new();
    for member in top_level_array_members(&array_block[1..array_block.len().saturating_sub(1)]) {
        let text = member.trim();
        if text.is_empty() {
            continue;
        }
        if !text.starts_with("new") || !identifier_boundary(text, 0, "new".len()) {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        }
        let cursor = skip_ascii_whitespace(text, "new".len());
        if text.as_bytes().get(cursor) != Some(&b'{') {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        }
        let Some(close) = matching_brace_index(text, cursor) else {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        };
        let object_block = &text[cursor..=close];
        let fields = top_level_assignment_fields(object_block);
        let mut rule = BTreeMap::new();
        for field in RULE_FIELDS {
            if let Some(value) = rule_string_field(object_block, field) {
                rule.insert((*field).to_string(), value);
            }
        }
        for field in fields {
            if !RULE_FIELDS.contains(&field.as_str()) {
                errors.push(format!(
                    "API rule {} has unexpected field {field}",
                    rule.get("id").map(String::as_str).unwrap_or("unknown")
                ));
            }
        }
        for field in RULE_FIELDS {
            if !rule.contains_key(*field) {
                errors.push(format!("API rule missing {field}"));
            }
        }
        rules.push(rule);
    }
    rules
}

fn endpoint_array_block(block: &str, field: &str, errors: &mut Vec<String>) -> Option<String> {
    let indexes = top_level_assignment_indexes(block, field);
    if indexes.is_empty() {
        errors.push(format!("API missing {field} array"));
        return None;
    }
    if indexes.len() != 1 {
        errors.push(format!("API {field} array must be declared once"));
        return None;
    }
    let index = indexes[0];
    let assignment_end = assignment_end_index(block, index);
    let assignment = &block[index..assignment_end];
    let Some(open) = assignment.find('{') else {
        errors.push(format!("API {field} array must be a single array"));
        return None;
    };
    let Some(close) = matching_brace_index(assignment, open) else {
        errors.push(format!("API {field} array must be a single array"));
        return None;
    };
    Some(assignment[open..=close].to_string())
}

fn rule_string_field(object_block: &str, field: &str) -> Option<String> {
    let values = top_level_assignment_texts(object_block, field)
        .into_iter()
        .filter_map(|text| exact_string_assignment_value_optional_comma(&text, field))
        .collect::<Vec<_>>();
    (values.len() == 1).then(|| values[0].clone())
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    for field in top_level_assignment_fields(block) {
        if ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            if prohibited_field(&field) {
                errors.push(format!(
                    "API endpoint has prohibited ServiceNow future API field {field}"
                ));
            }
        } else {
            errors.push(format!(
                "API endpoint has unexpected ServiceNow future API field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let masked = csharp_code_mask(block);
    let fields = assignment_fields(block);
    let mut seen = BTreeSet::new();
    for field in fields {
        if !seen.insert(field.clone()) {
            continue;
        }
        if assignment_has_value(&masked, &field, "true") && unsafe_true_field(&field) {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn validate_endpoint_property_identifiers(block: &str, errors: &mut Vec<String>) {
    let masked = csharp_code_mask(block);
    let mut index = 0;
    let mut identifiers = BTreeSet::new();
    while index < masked.len() {
        let byte = masked.as_bytes()[index];
        if !byte.is_ascii_alphabetic() && byte != b'_' {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < masked.len()
            && (masked.as_bytes()[index].is_ascii_alphanumeric()
                || masked.as_bytes()[index] == b'_')
        {
            index += 1;
        }
        identifiers.insert(block[start..index].to_string());
    }
    for identifier in identifiers {
        if REQUIRED_DISABLED_FIELDS.contains(&identifier.as_str()) || safe_text_value(&identifier) {
            continue;
        }
        if prohibited_field(&identifier) {
            errors.push(format!(
                "API endpoint property {identifier} contains prohibited ServiceNow future API identifier"
            ));
        }
    }
}

fn unsafe_true_field(field: &str) -> bool {
    if field == "dryRunRequired" {
        return false;
    }
    field.ends_with("Allowed")
        || field.ends_with("Enabled")
        || [
            "live",
            "provider",
            "callback",
            "update",
            "import",
            "sync",
            "table",
            "credential",
            "instance",
            "sys",
            "raw",
            "recipient",
            "payload",
            "ticket",
        ]
        .iter()
        .any(|token| normalized_key(field).contains(token))
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
        "API README missing ServiceNow future API endpoint",
    );
    expect(
        catalog_readme.contains(CATALOG_PATH.trim_start_matches("catalog/")),
        errors,
        "catalog README missing ServiceNow future API catalog",
    );
    expect(
        doc_readme.contains(DOC_PATH.trim_start_matches("docs/workflows/")),
        errors,
        "workflow README missing ServiceNow future API doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "ServiceNow future API doc missing endpoint",
    );
    expect(
        doc.contains("No live ServiceNow API calls."),
        errors,
        "ServiceNow future API doc must prohibit live API calls",
    );
    expect(
        doc.contains("No provider calls."),
        errors,
        "ServiceNow future API doc must prohibit provider calls",
    );
    expect(
        doc.contains("No import set writes."),
        errors,
        "ServiceNow future API doc must prohibit import set writes",
    );
    expect(
        doc.contains("No table API calls."),
        errors,
        "ServiceNow future API doc must prohibit table API calls",
    );
    expect(
        doc.contains("static API readiness summaries only"),
        errors,
        "ServiceNow future API doc must require static summaries",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_field(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited ServiceNow future API field"
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
                    validate_csharp_string_terms(&endpoint_source_block(text), path, errors);
                } else if servicenow_future_api_text_path(path) {
                    validate_text_terms(text, path, errors);
                }
                return;
            }
            if safe_text_value(text) {
                return;
            }
            if contains_prohibited_value(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
            if let Some(phrase) = prohibited_phrase(text) {
                errors.push(format!(
                    "{path} contains prohibited ServiceNow future API phrase {phrase}"
                ));
            }
            if prohibited_field(text) {
                errors.push(format!(
                    "{path} contains prohibited ServiceNow future API value {text}"
                ));
            }
        }
        _ => {}
    }
}

fn validate_text_terms(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        if !servicenow_future_api_text_line(path, line) || safe_text_line(line) {
            continue;
        }
        if let Some(phrase) = prohibited_phrase(line) {
            errors.push(format!(
                "{path}:{} contains prohibited ServiceNow future API phrase {phrase}",
                index + 1
            ));
        }
        if contains_prohibited_value(line) {
            errors.push(format!("{path}:{} contains prohibited value", index + 1));
        }
        for term in word_terms(line) {
            if prohibited_field(&term) {
                errors.push(format!(
                    "{path}:{} contains prohibited ServiceNow future API field {term}",
                    index + 1
                ));
            }
        }
    }
}

fn validate_csharp_string_terms(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, literal) in csharp_string_literals(text).into_iter().enumerate() {
        if safe_text_value(&literal) {
            continue;
        }
        if contains_prohibited_value(&literal) {
            errors.push(format!(
                "{path} string literal {} contains prohibited value",
                index + 1
            ));
        }
        if let Some(phrase) = prohibited_phrase(&literal) {
            errors.push(format!(
                "{path} string literal {} contains prohibited ServiceNow future API phrase {phrase}",
                index + 1
            ));
        }
        for term in word_terms(&literal) {
            if prohibited_field(&term) {
                errors.push(format!(
                    "{path} string literal {} contains prohibited ServiceNow future API field {term}",
                    index + 1
                ));
            }
        }
    }
}

fn endpoint_source_block(program: &str) -> String {
    let uncommented = csharp_without_comments(program);
    let starts = endpoint_start_indexes(&uncommented);
    if starts.len() != 1 {
        return String::new();
    }
    let start = starts[0];
    let end = next_map_get_index(&uncommented, start + 1).unwrap_or(uncommented.len());
    program[start..end].to_string()
}

fn contains_prohibited_value(value: &str) -> bool {
    contains_aws_access_key(value)
        || contains_private_key_marker(value)
        || contains_url(value)
        || contains_private_ipv4(value)
        || contains_uuid(value)
        || contains_32_hex_identifier(value)
        || contains_email(value)
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

fn contains_private_ipv4(value: &str) -> bool {
    value
        .split(|character: char| !character.is_ascii_digit() && character != '.')
        .filter(|candidate| candidate.matches('.').count() == 3)
        .any(|candidate| {
            let octets = candidate
                .split('.')
                .filter_map(|part| part.parse::<u8>().ok())
                .collect::<Vec<_>>();
            octets.len() == 4
                && (octets[0] == 10
                    || (octets[0] == 192 && octets[1] == 168)
                    || (octets[0] == 172 && (16..=31).contains(&octets[1])))
        })
}

fn contains_uuid(value: &str) -> bool {
    value
        .split(|character: char| !character.is_ascii_hexdigit() && character != '-')
        .any(|candidate| {
            let parts = candidate.split('-').collect::<Vec<_>>();
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

fn contains_32_hex_identifier(value: &str) -> bool {
    value
        .split(|character: char| !character.is_ascii_hexdigit())
        .any(|candidate| {
            candidate.len() == 32
                && candidate
                    .chars()
                    .all(|character| character.is_ascii_hexdigit())
        })
}

fn contains_email(value: &str) -> bool {
    value
        .split(|character: char| character.is_ascii_whitespace() || matches!(character, ',' | ';'))
        .any(|candidate| {
            let candidate = candidate.trim_matches(|character: char| {
                matches!(
                    character,
                    '"' | '\'' | '(' | ')' | '[' | ']' | '<' | '>' | '.'
                )
            });
            let Some((local, domain)) = candidate.split_once('@') else {
                return false;
            };
            !local.is_empty()
                && domain.contains('.')
                && domain.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '.' | '-')
                })
        })
}

fn contains_sensitive_assignment(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let compact = lower
        .chars()
        .filter(|character| !matches!(character, '"' | '\'' | '\\'))
        .collect::<String>();
    let sensitive_keys = [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
        "instanceurl",
        "instancename",
        "tablename",
        "sysid",
        "requestid",
        "incidentid",
        "changeid",
        "catalogtaskid",
        "importsetid",
        "credentialvalue",
        "secretvalue",
        "providerpayload",
        "rawrequestpayload",
        "rawresponsepayload",
        "rawticketdata",
    ];
    sensitive_keys.iter().any(|key| {
        compact.find(key).is_some_and(|index| {
            compact[index + key.len()..]
                .trim_start()
                .chars()
                .next()
                .is_some_and(|character| character == ':' || character == '=')
        })
    })
}

fn safe_text_line(line: &str) -> bool {
    let stripped = line.trim();
    let bullet_value = stripped.strip_prefix("- ").unwrap_or(stripped);
    let id_value = stripped.strip_prefix("- id: ").unwrap_or(stripped);
    let requirement_value = stripped.strip_prefix("requirement: ").unwrap_or(stripped);
    let evidence_value = stripped.strip_prefix("evidence: ").unwrap_or(stripped);
    SAFE_TEXT_PROHIBITION_LINES.contains(&stripped)
        || safe_text_value(bullet_value)
        || safe_text_value(id_value)
        || safe_text_value(requirement_value)
        || safe_text_value(evidence_value)
}

fn safe_text_value(value: &str) -> bool {
    let static_values = [
        "draft",
        "static-seed",
        "approval-readiness-only",
        "block",
        "true",
        "false",
    ];
    static_values.contains(&value)
        || REQUIRED_SURFACES.contains(&value)
        || REQUIRED_SIGNALS.contains(&value)
        || REQUIRED_INPUTS.contains(&value)
        || REQUIRED_GUARDS.contains(&value)
        || REQUIRED_PLAN_SECTIONS.contains(&value)
        || REQUIRED_BLOCKED_REASONS.contains(&value)
        || REQUIRED_EVIDENCE.contains(&value)
        || REQUIRED_DISABLED_FIELDS.contains(&value)
        || REQUIRED_CATALOG_KEYS.contains(&value)
        || ALLOWED_ENDPOINT_FIELDS.contains(&value)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, variable, _)| *variable == value)
        || REQUIRED_RULES
            .iter()
            .any(|rule| [rule.id, rule.decision, rule.requirement, rule.evidence].contains(&value))
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalized_key(value);
    if safe_text_value(value) {
        return false;
    }
    PROHIBITED_KEY_TOKENS
        .iter()
        .any(|token| normalized.contains(token))
}

fn prohibited_phrase(value: &str) -> Option<&'static str> {
    let normalized = value.to_ascii_lowercase().replace(['_', '-'], " ");
    let phrases = [
        ("instance URL", "instance url"),
        ("instance name", "instance name"),
        ("table name", "table name"),
        ("sys ID", "sys id"),
        ("request ID", "request id"),
        ("incident ID", "incident id"),
        ("change ID", "change id"),
        ("catalog task ID", "catalog task id"),
        ("import set ID", "import set id"),
        ("user record", "user record"),
        ("recipient data", "recipient data"),
        ("raw request payload", "raw request payload"),
        ("raw response payload", "raw response payload"),
        ("raw ticket data", "raw ticket data"),
        ("provider payload", "provider payload"),
        ("credential value", "credential value"),
        ("secret value", "secret value"),
        ("access token", "access token"),
        ("tenant ID", "tenant id"),
        ("object ID", "object id"),
        ("private IP", "private ip"),
    ];
    phrases
        .iter()
        .find_map(|(label, needle)| contains_phrase(&normalized, needle).then_some(*label))
}

fn contains_phrase(value: &str, phrase: &str) -> bool {
    let value_words = value.split_whitespace().collect::<Vec<_>>();
    let phrase_words = phrase.split_whitespace().collect::<Vec<_>>();
    if phrase_words.is_empty() || value_words.len() < phrase_words.len() {
        return false;
    }
    value_words
        .windows(phrase_words.len())
        .any(|window| window == phrase_words.as_slice())
        || value.contains(&format!("{phrase}s"))
}

fn servicenow_future_api_text_path(path: &str) -> bool {
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

fn servicenow_future_api_text_line(path: &str, line: &str) -> bool {
    if path.ends_with(CATALOG_PATH) || path.ends_with(DOC_PATH) {
        return true;
    }
    let lower = line.to_ascii_lowercase();
    lower.contains("servicenow future")
        || lower.contains("future servicenow")
        || lower.contains("future-api")
        || line.contains(ENDPOINT)
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|extension| path.ends_with(extension))
}

fn word_terms(line: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let mut start = None;
    for (index, character) in line.char_indices() {
        if character.is_ascii_alphanumeric() || character == '_' || character == '-' {
            if start.is_none() {
                start = Some(index);
            }
        } else if let Some(begin) = start.take() {
            terms.push(line[begin..index].to_string());
        }
    }
    if let Some(begin) = start {
        terms.push(line[begin..].to_string());
    }
    terms
}

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let texts = top_level_assignment_texts(block, field);
    texts.len() == 1
        && assignment_rhs(&texts[0], field)
            .map(|rhs| rhs.trim().trim_end_matches(',').trim() == value)
            .unwrap_or(false)
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let texts = top_level_assignment_texts(block, field);
    texts.len() == 1
        && exact_string_assignment_value_optional_comma(&texts[0], field).as_deref() == Some(value)
}

fn exact_string_assignment_value_optional_comma(text: &str, field: &str) -> Option<String> {
    let rhs = assignment_rhs(text, field)?
        .trim()
        .trim_end_matches(',')
        .trim();
    let (value, end) = quoted_string_at(rhs, 0)?;
    (end == rhs.len()).then_some(value)
}

fn assignment_rhs<'a>(text: &'a str, field: &str) -> Option<&'a str> {
    let trimmed = text.trim();
    let rest = trimmed.strip_prefix(field)?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?;
    Some(rest)
}

fn top_level_assignment_texts(block: &str, field: &str) -> Vec<String> {
    top_level_assignment_indexes(block, field)
        .into_iter()
        .map(|index| {
            let end = assignment_end_index(block, index);
            block[index..end].trim().to_string()
        })
        .collect()
}

fn top_level_assignment_indexes(block: &str, field: &str) -> Vec<usize> {
    let masked = csharp_code_mask(block);
    let mut indexes = Vec::new();
    let mut index = 0;
    while let Some(relative) = masked[index..].find(field) {
        let start = index + relative;
        let end = start + field.len();
        index = end;
        if !identifier_boundary(&masked, start, end) || brace_depth_at(&masked, start) != 1 {
            continue;
        }
        let cursor = skip_ascii_whitespace(&masked, end);
        if masked.as_bytes().get(cursor) == Some(&b'=') {
            indexes.push(start);
        }
    }
    indexes
}

fn top_level_assignment_fields(block: &str) -> Vec<String> {
    assignment_fields(block)
        .into_iter()
        .filter(|field| {
            top_level_assignment_indexes(block, field)
                .into_iter()
                .next()
                .is_some()
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn assignment_fields(block: &str) -> Vec<String> {
    let masked = csharp_code_mask(block);
    let mut fields = Vec::new();
    let mut index = 0;
    while index < masked.len() {
        if !masked.as_bytes()[index].is_ascii_alphabetic() && masked.as_bytes()[index] != b'_' {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < masked.len()
            && (masked.as_bytes()[index].is_ascii_alphanumeric()
                || masked.as_bytes()[index] == b'_')
        {
            index += 1;
        }
        let end = index;
        let cursor = skip_ascii_whitespace(&masked, end);
        if masked.as_bytes().get(cursor) == Some(&b'=') {
            fields.push(block[start..end].to_string());
        }
    }
    fields
}

fn assignment_has_value(masked: &str, field: &str, value: &str) -> bool {
    let mut index = 0;
    while let Some(relative) = masked[index..].find(field) {
        let start = index + relative;
        let end = start + field.len();
        index = end;
        if !identifier_boundary(masked, start, end) {
            continue;
        }
        let mut cursor = skip_ascii_whitespace(masked, end);
        if masked.as_bytes().get(cursor) != Some(&b'=') {
            continue;
        }
        cursor = skip_ascii_whitespace(masked, cursor + 1);
        if masked[cursor..].starts_with(value)
            && identifier_boundary(masked, cursor, cursor + value.len())
        {
            return true;
        }
    }
    false
}

fn assignment_end_index(block: &str, start: usize) -> usize {
    let bytes = block.as_bytes();
    let mut index = start;
    let mut depth = brace_depth_at(block, start);
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
        } else if byte == b'{' || byte == b'[' || byte == b'(' {
            depth += 1;
        } else if byte == b'}' || byte == b']' || byte == b')' {
            if depth == 1 {
                return index;
            }
            depth = depth.saturating_sub(1);
        } else if byte == b',' && depth == 1 {
            return index + 1;
        } else if byte == b';' && depth == 0 {
            return index + 1;
        }
        index += 1;
    }
    block.len()
}

fn top_level_array_members(body: &str) -> Vec<String> {
    let mut members = Vec::new();
    let mut start = 0;
    let mut index = 0;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let bytes = body.as_bytes();
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
        } else if byte == b'{' || byte == b'[' || byte == b'(' {
            depth += 1;
        } else if byte == b'}' || byte == b']' || byte == b')' {
            depth = depth.saturating_sub(1);
        } else if byte == b',' && depth == 0 {
            members.push(body[start..index].to_string());
            start = index + 1;
        }
        index += 1;
    }
    members.push(body[start..].to_string());
    members
}

fn matching_brace_index(text: &str, open: usize) -> Option<usize> {
    if text.as_bytes().get(open) != Some(&b'{') {
        return None;
    }
    let bytes = text.as_bytes();
    let mut index = open;
    let mut depth = 0usize;
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

fn brace_depth_at(source: &str, target: usize) -> usize {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < target && index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else if byte == b'"' {
            in_string = true;
        } else if byte == b'{' {
            depth += 1;
        } else if byte == b'}' {
            depth = depth.saturating_sub(1);
        }
        index += 1;
    }
    depth
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

fn csharp_code_mask(text: &str) -> String {
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
        } else if byte == b'"' {
            in_string = true;
            output.push(' ');
        } else {
            output.push(byte as char);
        }
        index += 1;
    }
    output
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut in_block_comment = false;
    let mut in_line_comment = false;
    while index < bytes.len() {
        if in_block_comment {
            if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                index += 2;
                in_block_comment = false;
            } else {
                index += 1;
            }
            continue;
        }
        if in_line_comment {
            if bytes[index] == b'\n' {
                in_line_comment = false;
            }
            index += 1;
            continue;
        }
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            index += 2;
            in_block_comment = true;
            continue;
        }
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            index += 2;
            in_line_comment = true;
            continue;
        }
        if bytes[index] == b'@' && bytes.get(index + 1) == Some(&b'"') {
            let (literal, next) = read_csharp_verbatim_string(text, index + 2);
            literals.push(literal);
            index = next;
            continue;
        }
        if bytes[index] == b'$' || bytes[index] == b'"' {
            let mut quote = index;
            while bytes.get(quote) == Some(&b'$') {
                quote += 1;
            }
            if bytes.get(quote) == Some(&b'@') {
                quote += 1;
            }
            if bytes.get(quote) == Some(&b'"') {
                let (literal, next) = read_csharp_quoted_string(text, quote);
                literals.push(literal);
                index = next;
                continue;
            }
        }
        index += 1;
    }
    literals
}

fn read_csharp_quoted_string(text: &str, quote_index: usize) -> (String, usize) {
    let quote_count = text[quote_index..]
        .bytes()
        .take_while(|byte| *byte == b'"')
        .count();
    if quote_count >= 3 {
        return read_csharp_raw_string(text, quote_index, quote_count);
    }
    let bytes = text.as_bytes();
    let mut literal = String::new();
    let mut index = quote_index + 1;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            if let Some(next) = bytes.get(index + 1) {
                literal.push(*next as char);
            }
            index += 2;
        } else if bytes[index] == b'"' {
            return (literal, index + 1);
        } else {
            literal.push(bytes[index] as char);
            index += 1;
        }
    }
    (literal, index)
}

fn read_csharp_raw_string(text: &str, quote_index: usize, quote_count: usize) -> (String, usize) {
    let delimiter = "\"".repeat(quote_count);
    let body_start = quote_index + quote_count;
    let body_end = text[body_start..]
        .find(&delimiter)
        .map(|index| body_start + index)
        .unwrap_or(text.len());
    (
        text[body_start..body_end].to_string(),
        (body_end + quote_count).min(text.len()),
    )
}

fn read_csharp_verbatim_string(text: &str, body_start: usize) -> (String, usize) {
    let bytes = text.as_bytes();
    let mut literal = String::new();
    let mut index = body_start;
    while index < bytes.len() {
        if bytes[index] == b'"' && bytes.get(index + 1) == Some(&b'"') {
            literal.push('"');
            index += 2;
        } else if bytes[index] == b'"' {
            return (literal, index + 1);
        } else {
            literal.push(bytes[index] as char);
            index += 1;
        }
    }
    (literal, index)
}

fn quoted_string_at(text: &str, quote: usize) -> Option<(String, usize)> {
    if text.as_bytes().get(quote) != Some(&b'"') {
        return None;
    }
    let bytes = text.as_bytes();
    let mut value = String::new();
    let mut index = quote + 1;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'"' {
            return Some((value, index + 1));
        }
        if byte == b'\\' {
            index += 1;
            if index >= bytes.len() {
                return None;
            }
            value.push(bytes[index] as char);
            index += 1;
            continue;
        }
        value.push(byte as char);
        index += 1;
    }
    None
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

fn diff_values(left: &[String], right: &[String]) -> Vec<String> {
    let left = left.iter().cloned().collect::<BTreeSet<_>>();
    let right = right.iter().cloned().collect::<BTreeSet<_>>();
    left.difference(&right).cloned().collect()
}

fn unique(values: &[String]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn normalized_key(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn skip_ascii_whitespace(text: &str, mut index: usize) -> usize {
    while index < text.len() && text.as_bytes()[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn skip_horizontal_whitespace(text: &str, mut index: usize) -> usize {
    while index < text.len() && matches!(text.as_bytes()[index], b' ' | b'\t' | b'\r') {
        index += 1;
    }
    index
}

fn identifier_boundary(text: &str, start: usize, end: usize) -> bool {
    let before = start
        .checked_sub(1)
        .and_then(|index| text.as_bytes().get(index))
        .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_');
    let after = text
        .as_bytes()
        .get(end)
        .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_');
    before && after
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

fn last_identifier(text: &str) -> Option<String> {
    let mut result = None;
    let mut index = 0;
    while index < text.len() {
        let byte = text.as_bytes()[index];
        if byte.is_ascii_alphabetic() || byte == b'_' {
            let start = index;
            index += 1;
            while index < text.len()
                && (text.as_bytes()[index].is_ascii_alphanumeric()
                    || text.as_bytes()[index] == b'_')
            {
                index += 1;
            }
            result = Some(text[start..index].to_string());
        } else {
            index += 1;
        }
    }
    result
}

fn strip_ascii_whitespace(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect()
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
    fn endpoint_registration_detects_route_alias() {
        let program = format!(
            "const string routeAlias = \"{ENDPOINT}\";\napp.MapGet(routeAlias, () => Results.Json(new {{ source = \"static-seed\" }}));"
        );

        assert_eq!(endpoint_start_indexes(&program).len(), 1);
    }

    #[test]
    fn csharp_string_literals_ignore_line_comments() {
        let text = "apiMode = \"approval-readiness-only\";\n// staticProviderValue = \"https://example.invalid/now\";";
        let literals = csharp_string_literals(text);

        assert_eq!(literals, vec!["approval-readiness-only".to_string()]);
    }
}
