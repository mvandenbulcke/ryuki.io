use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/dashboard-global-overview.md";
const ENDPOINT: &str = "/api/dashboard/global-overview-contract";
const REQUIRED_SUMMARY_DOMAINS: &[&str] = &[
    "global-health",
    "site-readiness",
    "open-requests",
    "failed-operations",
    "patch-risk",
    "backup-risk",
    "monitoring-gaps",
    "cmdb-risk",
    "evidence-readiness",
];
const REQUIRED_STATUS_BANDS: &[&str] = &[
    "healthy",
    "attention",
    "risk",
    "blocked",
    "stale",
    "unknown",
];
const REQUIRED_LENSES: &[&str] = &[
    "by-site",
    "by-environment",
    "by-owner-domain",
    "by-service-criticality",
    "by-time-window",
];
const REQUIRED_GUARDS: &[&str] = &[
    "aggregate-only",
    "stale-data-marked",
    "evidence-redacted",
    "owner-domain-safe",
    "scope-known",
    "live-query-blocked",
    "raw-detail-blocked",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "dashboard-live-query-disabled",
    "dashboard-mutation-disabled",
    "dashboard-provider-calls-disabled",
    "dashboard-notification-dispatch-disabled",
    "dashboard-raw-request-rows-disabled",
    "dashboard-raw-operation-rows-disabled",
    "dashboard-raw-inventory-rows-disabled",
    "dashboard-raw-cmdb-rows-disabled",
    "dashboard-raw-backup-rows-disabled",
    "dashboard-raw-monitoring-rows-disabled",
    "dashboard-raw-user-data-disabled",
    "dashboard-raw-recipient-data-disabled",
    "dashboard-credential-values-disabled",
    "dashboard-token-values-disabled",
    "dashboard-tenant-identifiers-disabled",
    "dashboard-object-identifiers-disabled",
    "dashboard-principal-identifiers-disabled",
    "dashboard-private-network-values-disabled",
    "scope-missing",
    "stale-data-unmarked",
    "evidence-not-redacted",
    "raw-detail-requested",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Dashboard summary",
    "Site readiness summary",
    "Request backlog summary",
    "Failed operation summary",
    "Patch risk summary",
    "Backup risk summary",
    "Monitoring gap summary",
    "CMDB risk summary",
    "Evidence references",
];
const REQUIRED_RULE_DETAILS: &[(&str, &str, &str, &str)] = &[
    (
        "global-dashboard-aggregate-only",
        "block",
        "Global dashboard summaries are aggregate-only and must not run live queries or expose raw request, operation, inventory, CMDB, backup, or monitoring rows.",
        "Dashboard summary",
    ),
    (
        "risk-signals-read-only",
        "block",
        "Patch, backup, monitoring, CMDB, and evidence risk signals are read-only and must not mutate dashboards, workflows, providers, or notification state.",
        "Patch risk summary",
    ),
    (
        "stale-data-explicit",
        "block",
        "Dashboard freshness and stale-data markers must be explicit so operators do not mistake cached aggregate state for live provider state.",
        "Site readiness summary",
    ),
    (
        "raw-dashboard-data-not-exposed",
        "block",
        "Dashboard evidence must not expose raw request rows, raw operation rows, raw inventory rows, raw CMDB rows, raw backup rows, raw monitoring rows, raw user data, raw recipient data, credential values, token values, tenant identifiers, object identifiers, principal identifiers, private network values, live endpoints, or URLs.",
        "Evidence references",
    ),
];
const REQUIRED_RULES: &[&str] = &[
    "global-dashboard-aggregate-only",
    "risk-signals-read-only",
    "stale-data-explicit",
    "raw-dashboard-data-not-exposed",
];
const SAFE_TRUE_FIELDS: &[&str] = &[
    "dashboardSummaryAggregateOnly",
    "siteReadinessAggregateOnly",
    "riskSignalsReadOnly",
    "evidenceReferencesOnly",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "liveQueryAllowed",
    "dashboardMutationAllowed",
    "providerCallsAllowed",
    "notificationDispatchAllowed",
    "rawRequestRowsAllowed",
    "rawOperationRowsAllowed",
    "rawInventoryRowsAllowed",
    "rawCmdbRowsAllowed",
    "rawBackupRowsAllowed",
    "rawMonitoringRowsAllowed",
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
    "dashboardGlobalOverviewMode",
    "dashboardSummaryAggregateOnly",
    "siteReadinessAggregateOnly",
    "riskSignalsReadOnly",
    "evidenceReferencesOnly",
    "liveQueryAllowed",
    "dashboardMutationAllowed",
    "providerCallsAllowed",
    "notificationDispatchAllowed",
    "rawRequestRowsAllowed",
    "rawOperationRowsAllowed",
    "rawInventoryRowsAllowed",
    "rawCmdbRowsAllowed",
    "rawBackupRowsAllowed",
    "rawMonitoringRowsAllowed",
    "rawUserDataAllowed",
    "rawRecipientDataAllowed",
    "credentialValuesAllowed",
    "tokenValuesAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "principalIdentifiersAllowed",
    "privateNetworkValuesAllowed",
    "summaryDomains",
    "statusBands",
    "lenses",
    "requiredGuards",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("summaryDomains", "dashboardGlobalOverviewDomains"),
    ("statusBands", "dashboardGlobalOverviewStatusBands"),
    ("lenses", "dashboardGlobalOverviewLenses"),
    ("requiredGuards", "dashboardGlobalOverviewRequiredGuards"),
    ("blockedReasons", "dashboardGlobalOverviewBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredEvidence"];
const BASE_ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "dashboardGlobalOverviewMode",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
    "requiredEvidence",
];
const PROHIBITED_FIELD_ALIASES: &[&str] = &[
    "credential",
    "password",
    "bearer",
    "token",
    "url",
    "endpoint",
    "user",
    "principal",
    "tenant",
    "object",
];
const PROHIBITED_FIELD_NEEDLES: &[&str] = &[
    "password",
    "credential",
    "tenantid",
    "tenantidentifier",
    "objectid",
    "objectidentifier",
    "principalid",
    "principalidentifier",
    "userid",
    "useridentifier",
    "useremail",
    "privateip",
    "privatenetwork",
    "rawrequest",
    "requestrow",
    "rawoperation",
    "operationrow",
    "rawinventory",
    "inventoryrow",
    "rawcmdb",
    "cmdbrow",
    "rawbackup",
    "backuprow",
    "rawmonitoring",
    "monitoringrow",
    "rawuser",
    "userdata",
    "rawrecipient",
    "recipientemail",
    "recipientaddress",
    "recipientdata",
    "endpointurl",
    "url",
    "token",
    "bearer",
    "secret",
    "dashboardmutation",
    "providercall",
    "notificationdispatch",
    "livequery",
];
const SECRET_ASSIGNMENT_KEYS: &[&str] = &[
    "password",
    "client_secret",
    "access_token",
    "refresh_token",
    "bearer",
    "token",
];

#[derive(Debug, Deserialize)]
struct Context {
    catalog: Value,
    catalog_text: String,
    program: String,
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
}

#[derive(Debug, Deserialize)]
struct CatalogInput {
    catalog: Value,
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
    path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    id: String,
    decision: String,
    requirement: String,
    evidence: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid dashboard global overview context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_no_prohibited_values(&context.catalog, "catalog", &mut errors);
    validate_no_prohibited_values(
        &Value::String(context.catalog_text),
        "catalog/dashboard-global-overview-contract.yaml",
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
    let mut docs_scope = Map::new();
    docs_scope.insert(
        API_README_PATH.to_string(),
        Value::String(context.api_readme),
    );
    docs_scope.insert(
        CATALOG_README_PATH.to_string(),
        Value::String(context.catalog_readme),
    );
    docs_scope.insert(
        DOC_README_PATH.to_string(),
        Value::String(context.doc_readme),
    );
    docs_scope.insert(DOC_PATH.to_string(), Value::String(context.doc));
    validate_no_prohibited_values(
        &Value::Object(docs_scope),
        "dashboard-global-overview",
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let payload: CatalogInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid dashboard global overview catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid dashboard global overview program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid dashboard global overview docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid dashboard global overview prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_no_prohibited_values(
        &payload.value,
        payload.path.as_deref().unwrap_or("value"),
        &mut errors,
    );
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    validate_catalog_keys(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "dashboard global overview version must be 1",
    );
    expect(
        catalog.get("status").and_then(Value::as_str) == Some("draft"),
        errors,
        "dashboard global overview status must be draft",
    );
    expect(
        catalog.get("source").and_then(Value::as_str) == Some("static-seed"),
        errors,
        "dashboard global overview source must be static-seed",
    );
    expect(
        catalog
            .get("dashboardGlobalOverviewMode")
            .and_then(Value::as_str)
            == Some("static-dashboard-global-overview"),
        errors,
        "dashboard global overview mode must be static-dashboard-global-overview",
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            catalog.get(*field).and_then(Value::as_bool) == Some(true),
            errors,
            format!("dashboard global overview {field} must be true"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            catalog.get(*field).and_then(Value::as_bool) == Some(false),
            errors,
            format!("dashboard global overview {field} must be false"),
        );
    }
    validate_required_array(catalog, "summaryDomains", REQUIRED_SUMMARY_DOMAINS, errors);
    validate_required_array(catalog, "statusBands", REQUIRED_STATUS_BANDS, errors);
    validate_required_array(catalog, "lenses", REQUIRED_LENSES, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);
    validate_no_prohibited_values(catalog, "catalog", errors);
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
            "dashboard global overview unexpected catalog keys: {}",
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
    let values = string_array(catalog, field, errors);
    expect(
        !values.is_empty(),
        errors,
        format!("{field} must be non-empty array"),
    );
    let missing: Vec<&str> = required_values
        .iter()
        .copied()
        .filter(|required| !values.iter().any(|value| value == required))
        .collect();
    let unexpected: Vec<String> = values
        .iter()
        .filter(|value| !required_values.contains(&value.as_str()))
        .cloned()
        .collect();
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
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        errors,
        format!("{field} values must be unique"),
    );
    for value in values {
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "{field} contains prohibited dashboard global overview value {value}"
            ));
        }
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
        .filter_map(|rule| rule.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let missing: Vec<&str> = REQUIRED_RULES
        .iter()
        .copied()
        .filter(|id| !rule_ids.iter().any(|rule_id| rule_id == id))
        .collect();
    let unexpected: Vec<String> = rule_ids
        .iter()
        .filter(|id| !REQUIRED_RULES.contains(&id.as_str()))
        .cloned()
        .collect();
    if !missing.is_empty() {
        errors.push(format!(
            "dashboard global overview missing rules: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "dashboard global overview unexpected rules: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "dashboard global overview rule IDs must be unique",
    );
    let rule_details: Vec<(String, String, String)> = rules
        .iter()
        .filter_map(|rule| {
            Some((
                rule.get("decision")?.as_str()?.to_string(),
                rule.get("requirement")?.as_str()?.to_string(),
                rule.get("evidence")?.as_str()?.to_string(),
            ))
        })
        .collect();
    expect(
        rule_details.iter().collect::<BTreeSet<_>>().len() == rule_details.len(),
        errors,
        "dashboard global overview rule details must be unique",
    );
    for rule in &rules {
        let keys: Vec<String> = rule
            .as_object()
            .map(|map| map.keys().cloned().collect())
            .unwrap_or_default();
        let unexpected_keys: Vec<String> = keys
            .iter()
            .filter(|key| !RULE_KEYS.contains(&key.as_str()))
            .cloned()
            .collect();
        let missing_keys: Vec<&str> = RULE_KEYS
            .iter()
            .copied()
            .filter(|key| !keys.iter().any(|candidate| candidate == key))
            .collect();
        let id = rule
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("(missing id)");
        if !unexpected_keys.is_empty() {
            errors.push(format!(
                "dashboard global overview rule {id} unexpected rule keys: {}",
                unexpected_keys.join(", ")
            ));
        }
        if !missing_keys.is_empty() {
            errors.push(format!(
                "dashboard global overview rule {id} missing rule keys: {}",
                missing_keys.join(", ")
            ));
        }
    }
    for (id, decision, requirement, evidence) in REQUIRED_RULE_DETAILS {
        let Some(rule) = rules
            .iter()
            .find(|candidate| candidate.get("id").and_then(Value::as_str) == Some(*id))
        else {
            continue;
        };
        expect(
            rule.get("decision").and_then(Value::as_str) == Some(*decision),
            errors,
            format!("dashboard global overview rule {id} decision must match"),
        );
        expect(
            rule.get("requirement").and_then(Value::as_str) == Some(*requirement),
            errors,
            format!("dashboard global overview rule {id} requirement must match"),
        );
        expect(
            rule.get("evidence").and_then(Value::as_str) == Some(*evidence),
            errors,
            format!("dashboard global overview rule {id} evidence must match"),
        );
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let block = endpoint_block(program, errors);
    if block.is_empty() {
        return;
    }
    expect_single_string_assignment(
        &block,
        "source",
        "static-seed",
        "API must keep static-seed source",
        errors,
    );
    expect_single_string_assignment(
        &block,
        "dashboardGlobalOverviewMode",
        "static-dashboard-global-overview",
        "API must keep static-dashboard-global-overview mode",
        errors,
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            exact_endpoint_assignment(&block, field, "true"),
            errors,
            format!("API must keep {field} true"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            exact_endpoint_assignment(&block, field, "false"),
            errors,
            format!("API must keep {field} disabled"),
        );
    }
    let uncommented_program = strip_csharp_comments(program);
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_endpoint_assignment(&block, field, variable),
            errors,
            format!("API must bind {field} to {variable}"),
        );
        validate_api_array(
            field,
            csharp_array_values(&uncommented_program, variable),
            string_array_silent(catalog, field),
            errors,
        );
    }
    for field in ENDPOINT_INLINE_ARRAYS {
        validate_api_array(
            field,
            endpoint_inline_array_values(&block, field),
            string_array_silent(catalog, field),
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
    let missing: Vec<String> = catalog_values
        .iter()
        .filter(|value| !values.contains(*value))
        .cloned()
        .collect();
    let unexpected: Vec<String> = values
        .iter()
        .filter(|value| !catalog_values.contains(*value))
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
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        errors,
        format!("API {field} values must be unique"),
    );
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let catalog_rules = catalog_rules(catalog);
    let api_rules = parse_api_rules(&strip_csharp_comments(block));
    let catalog_rule_ids: Vec<String> = catalog_rules.iter().map(|rule| rule.id.clone()).collect();
    let api_rule_ids: Vec<String> = api_rules.iter().map(|rule| rule.id.clone()).collect();
    for id in catalog_rule_ids
        .iter()
        .filter(|id| !api_rule_ids.contains(*id))
    {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_rule_ids
        .iter()
        .filter(|id| !catalog_rule_ids.contains(*id))
    {
        errors.push(format!("API has unexpected rule {id}"));
    }
    expect(
        api_rule_ids.iter().collect::<BTreeSet<_>>().len() == api_rule_ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    for catalog_rule in &catalog_rules {
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
        "API README missing dashboard global overview endpoint",
    );
    expect(
        catalog_readme.contains("dashboard-global-overview-contract.yaml"),
        errors,
        "catalog README missing dashboard global overview catalog",
    );
    expect(
        doc_readme.contains("dashboard-global-overview.md"),
        errors,
        "workflow README missing dashboard global overview doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "dashboard global overview doc missing endpoint",
    );
    expect(
        doc.contains("No live dashboard queries"),
        errors,
        "dashboard global overview doc must prohibit live dashboard queries",
    );
    expect(
        doc.contains("No dashboard, workflow, provider, or notification mutation"),
        errors,
        "dashboard global overview doc must prohibit mutation",
    );
    expect(
        doc.contains("No provider calls"),
        errors,
        "dashboard global overview doc must prohibit provider calls",
    );
    expect(
        doc.contains("raw request rows"),
        errors,
        "dashboard global overview doc must prohibit raw request rows",
    );
    expect(
        doc.contains("raw operation rows"),
        errors,
        "dashboard global overview doc must prohibit raw operation rows",
    );
    expect(
        doc.contains("raw inventory rows"),
        errors,
        "dashboard global overview doc must prohibit raw inventory rows",
    );
    expect(
        doc.contains("raw CMDB rows"),
        errors,
        "dashboard global overview doc must prohibit raw CMDB rows",
    );
    expect(
        doc.contains("raw monitoring rows"),
        errors,
        "dashboard global overview doc must prohibit raw monitoring rows",
    );
    expect(
        doc.contains("tenant identifiers"),
        errors,
        "dashboard global overview doc must prohibit tenant identifiers",
    );
    expect(
        doc.contains("static dashboard global overview summaries only"),
        errors,
        "dashboard global overview doc must require static summaries",
    );
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let uncommented = strip_csharp_comments(program);
    let Some(start) = find_endpoint_start(&uncommented, ENDPOINT) else {
        errors.push("API missing dashboard global overview endpoint".to_string());
        return String::new();
    };
    let end = find_next_endpoint_start(&uncommented, start + 1).unwrap_or(uncommented.len());
    uncommented[start..end].to_string()
}

fn find_endpoint_start(program: &str, endpoint: &str) -> Option<usize> {
    program
        .match_indices('\n')
        .map(|(index, _)| index + 1)
        .chain(std::iter::once(0))
        .filter(|index| {
            program[*index..].lines().next().is_some_and(|line| {
                line.trim_start()
                    .starts_with(&format!("app.MapGet(\"{endpoint}\","))
            })
        })
        .min()
}

fn find_next_endpoint_start(program: &str, start: usize) -> Option<usize> {
    program[start..]
        .match_indices('\n')
        .map(|(index, _)| start + index + 1)
        .find(|index| {
            program[*index..]
                .lines()
                .next()
                .is_some_and(|line| line.trim_start().starts_with("app.MapGet("))
        })
}

fn strip_csharp_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes.get(index..index + 2) == Some(b"//") {
            output.push_str("  ");
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(' ');
                index += 1;
            }
        } else if bytes.get(index..index + 2) == Some(b"/*") {
            output.push_str("  ");
            index += 2;
            while index < bytes.len() {
                if bytes.get(index..index + 2) == Some(b"*/") {
                    output.push_str("  ");
                    index += 2;
                    break;
                }
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    output
}

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    let needle = format!("var {variable}");
    let start = program.find(&needle)?;
    let body_start = program[start..].find('{')? + start + 1;
    let body_end = program[body_start..].find("};")? + body_start;
    Some(csharp_string_literals(&program[body_start..body_end]))
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    let needle = format!("{field} = new[]");
    let start = block.find(&needle)?;
    let body_start = block[start..].find('{')? + start + 1;
    let body_end = block[body_start..].find('}')? + body_start;
    Some(csharp_string_literals(&block[body_start..body_end]))
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }
        index += 1;
        let mut escaped = false;
        let mut value = String::new();
        while index < bytes.len() {
            let byte = bytes[index];
            if escaped {
                value.push(byte as char);
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                break;
            } else {
                value.push(byte as char);
            }
            index += 1;
        }
        values.push(value);
        index += 1;
    }
    values
}

fn exact_endpoint_assignment(block: &str, field: &str, value: &str) -> bool {
    block
        .lines()
        .any(|line| line.trim() == format!("{field} = {value},"))
}

fn expect_single_string_assignment(
    block: &str,
    field: &str,
    value: &str,
    message: &str,
    errors: &mut Vec<String>,
) {
    let values = string_assignment_values(block, field);
    expect(values == vec![value.to_string()], errors, message);
}

fn string_assignment_values(block: &str, field: &str) -> Vec<String> {
    block
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let prefix = format!("{field} = \"");
            let rest = trimmed.strip_prefix(&prefix)?;
            let value_end = rest.find('"')?;
            let trailing = rest[value_end + 1..].trim();
            (trailing == ",").then(|| rest[..value_end].to_string())
        })
        .collect()
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(&strip_csharp_comments(block));
    for field in assignment_fields(&stripped) {
        if !allowed_endpoint_field(&field) {
            errors.push(format!(
                "API endpoint has unexpected dashboard global overview field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited dashboard global overview field {field}"
            ));
        }
    }
}

fn strip_csharp_string_literals(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let bytes = source.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            output.push(bytes[index] as char);
            index += 1;
            continue;
        }
        output.push('"');
        index += 1;
        let mut escaped = false;
        while index < bytes.len() {
            let byte = bytes[index];
            output.push(if byte == b'\n' { '\n' } else { ' ' });
            index += 1;
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                break;
            }
        }
    }
    output
}

fn assignment_fields(source: &str) -> Vec<String> {
    let bytes = source.as_bytes();
    let mut fields = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_alphabetic() {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
        {
            index += 1;
        }
        let name = &source[start..index];
        let mut cursor = index;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if bytes.get(cursor) == Some(&b'=') {
            fields.push(name.to_string());
        }
    }
    fields
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(&strip_csharp_comments(block));
    for field in assignment_fields(&stripped) {
        if SAFE_TRUE_FIELDS.contains(&field.as_str()) {
            continue;
        }
        if stripped.contains(&format!("{field} = true,")) && unsafe_true_field(&field) {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn validate_no_prohibited_values(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_field(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited dashboard global overview field"
                    ));
                }
                validate_no_prohibited_values(child, &child_path, errors);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                validate_no_prohibited_values(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => {
            if whole_file_text(path, text) {
                if prohibited_value(text) {
                    errors.push(format!("{path} contains prohibited value"));
                }
                return;
            }
            if safe_text_value(text) {
                return;
            }
            if prohibited_value(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
            if prohibited_field(text) {
                errors.push(format!(
                    "{path} contains prohibited dashboard global overview value {text}"
                ));
            }
        }
        _ => {}
    }
}

fn whole_file_text(path: &str, text: &str) -> bool {
    text.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn string_array(value: &Value, field: &str, errors: &mut Vec<String>) -> Vec<String> {
    let Some(items) = value.get(field).and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut values = Vec::new();
    for item in items {
        if let Some(text) = item.as_str() {
            values.push(text.to_string());
        } else {
            errors.push(format!("{field} must contain only strings"));
        }
    }
    values
}

fn string_array_silent(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
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

fn parse_api_rules(block: &str) -> Vec<Rule> {
    let mut rules = Vec::new();
    let mut search_start = 0;
    while let Some(relative) = block[search_start..].find("new") {
        let start = search_start + relative;
        let Some(open_relative) = block[start..].find('{') else {
            break;
        };
        let open = start + open_relative;
        let Some(close_relative) = block[open..].find('}') else {
            break;
        };
        let close = open + close_relative;
        let object = &block[open + 1..close];
        if let (Some(id), Some(decision), Some(requirement), Some(evidence)) = (
            string_assignment_value(object, "id"),
            string_assignment_value(object, "decision"),
            string_assignment_value(object, "requirement"),
            string_assignment_value(object, "evidence"),
        ) {
            rules.push(Rule {
                id,
                decision,
                requirement,
                evidence,
            });
        }
        search_start = close + 1;
    }
    rules
}

fn string_assignment_value(object: &str, field: &str) -> Option<String> {
    let needle = format!("{field} = \"");
    let start = object.find(&needle)? + needle.len();
    let rest = &object[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn allowed_endpoint_field(field: &str) -> bool {
    BASE_ALLOWED_ENDPOINT_FIELDS.contains(&field)
        || SAFE_TRUE_FIELDS.contains(&field)
        || REQUIRED_DISABLED_FIELDS.contains(&field)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(catalog_field, _)| *catalog_field == field)
}

fn unsafe_true_field(field: &str) -> bool {
    [
        "live",
        "provider",
        "workflow",
        "raw",
        "credential",
        "token",
        "tenant",
        "object",
        "principal",
        "user",
        "mutation",
        "notification",
        "metric",
        "query",
        "dashboard",
    ]
    .iter()
    .any(|needle| field.to_ascii_lowercase().contains(needle))
}

fn prohibited_field(value: &str) -> bool {
    let normalized: String = value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    if safe_text_value(value) {
        return false;
    }
    PROHIBITED_FIELD_ALIASES.contains(&normalized.as_str())
        || PROHIBITED_FIELD_NEEDLES
            .iter()
            .any(|needle| normalized.contains(needle))
}

fn safe_text_value(value: &str) -> bool {
    let safe_sets: &[&[&str]] = &[
        REQUIRED_SUMMARY_DOMAINS,
        REQUIRED_STATUS_BANDS,
        REQUIRED_LENSES,
        REQUIRED_GUARDS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        REQUIRED_RULES,
        SAFE_TRUE_FIELDS,
        REQUIRED_DISABLED_FIELDS,
        REQUIRED_CATALOG_KEYS,
    ];
    [
        "draft",
        "static-seed",
        "static-dashboard-global-overview",
        "block",
        "true",
        "false",
    ]
    .contains(&value)
        || safe_sets.iter().any(|set| set.contains(&value))
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, binding)| *binding == value)
        || REQUIRED_RULE_DETAILS
            .iter()
            .any(|rule| rule.0 == value || rule.1 == value || rule.2 == value || rule.3 == value)
}

fn prohibited_value(text: &str) -> bool {
    contains_aws_access_key(text)
        || text.to_ascii_uppercase().contains("-----BEGIN ")
            && text.to_ascii_uppercase().contains("PRIVATE KEY-----")
        || contains_url(text)
        || contains_private_ip(text)
        || contains_uuid(text)
        || contains_email(text)
        || contains_sensitive_assignment(text)
}

fn contains_aws_access_key(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.windows(4).enumerate().any(|(index, window)| {
        window.eq_ignore_ascii_case(b"AKIA")
            && bytes
                .get(index + 4..index + 20)
                .is_some_and(|candidate| candidate.iter().all(|byte| byte.is_ascii_alphanumeric()))
    })
}

fn contains_url(text: &str) -> bool {
    for (index, _) in text.match_indices("://") {
        let scheme = text[..index]
            .rsplit(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-')))
            .next()
            .unwrap_or_default();
        if scheme
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-'))
        {
            return true;
        }
    }
    false
}

fn contains_private_ip(text: &str) -> bool {
    let bytes = text.as_bytes();
    for index in 0..bytes.len() {
        if !bytes[index].is_ascii_digit() || !word_boundary_before(bytes, index) {
            continue;
        }
        if private_ip_match_end(bytes, index).is_some_and(|end| word_boundary_after(bytes, end)) {
            return true;
        }
    }
    false
}

fn contains_uuid(text: &str) -> bool {
    let bytes = text.as_bytes();
    for index in 0..bytes.len() {
        if !bytes[index].is_ascii_hexdigit() || !word_boundary_before(bytes, index) {
            continue;
        }
        let end = index + 36;
        if end <= bytes.len() && uuid_at(bytes, index) && word_boundary_after(bytes, end) {
            return true;
        }
    }
    false
}

fn contains_email(text: &str) -> bool {
    text.split_whitespace().any(|word| {
        let candidate = word.trim_matches(|ch: char| {
            matches!(
                ch,
                ',' | ';' | ':' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | '"' | '\''
            )
        });
        let Some((local, domain)) = candidate.split_once('@') else {
            return false;
        };
        !local.is_empty()
            && local
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '%' | '+' | '-'))
            && domain.contains('.')
            && domain
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-'))
            && domain
                .rsplit('.')
                .next()
                .is_some_and(|tld| tld.len() >= 2 && tld.chars().all(|ch| ch.is_ascii_alphabetic()))
    })
}

fn private_ip_match_end(bytes: &[u8], start: usize) -> Option<usize> {
    let (first, mut index) = parse_octet(bytes, start)?;
    if bytes.get(index) != Some(&b'.') {
        return None;
    }
    index += 1;
    let (second, next) = parse_octet(bytes, index)?;
    index = next;
    if bytes.get(index) != Some(&b'.') {
        return None;
    }
    index += 1;
    let (_, next) = parse_octet(bytes, index)?;
    index = next;
    if bytes.get(index) != Some(&b'.') {
        return None;
    }
    index += 1;
    let (_, end) = parse_octet(bytes, index)?;
    if first == "10"
        || (first == "192" && second == "168")
        || (first == "172"
            && second.len() == 2
            && second
                .parse::<u8>()
                .is_ok_and(|value| (16..=31).contains(&value)))
    {
        Some(end)
    } else {
        None
    }
}

fn parse_octet(bytes: &[u8], start: usize) -> Option<(&str, usize)> {
    let mut end = start;
    while end < bytes.len() && bytes[end].is_ascii_digit() && end - start < 3 {
        end += 1;
    }
    if end == start {
        return None;
    }
    std::str::from_utf8(&bytes[start..end])
        .ok()
        .map(|octet| (octet, end))
}

fn uuid_at(bytes: &[u8], start: usize) -> bool {
    const HYPHENS: &[usize] = &[8, 13, 18, 23];
    for offset in 0..36 {
        let byte = bytes[start + offset];
        if HYPHENS.contains(&offset) {
            if byte != b'-' {
                return false;
            }
        } else if !byte.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn contains_sensitive_assignment(text: &str) -> bool {
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':').or_else(|| line.split_once('=')) else {
            continue;
        };
        if value.trim().is_empty() {
            continue;
        }
        let normalized = normalize_assignment_key(key);
        if SECRET_ASSIGNMENT_KEYS
            .iter()
            .any(|needle| normalized == *needle || normalized.ends_with(needle))
        {
            return true;
        }
    }
    false
}

fn normalize_assignment_key(key: &str) -> String {
    key.trim()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
        .map(|ch| {
            if matches!(ch, '-' | '.') {
                '_'
            } else {
                ch.to_ascii_lowercase()
            }
        })
        .collect()
}

fn word_boundary_before(bytes: &[u8], index: usize) -> bool {
    index == 0 || !is_word_byte(bytes[index - 1])
}

fn word_boundary_after(bytes: &[u8], index: usize) -> bool {
    index >= bytes.len() || !is_word_byte(bytes[index])
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}
