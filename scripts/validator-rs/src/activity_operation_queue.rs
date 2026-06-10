use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/activity-operation-queue-contract.yaml";
const ENDPOINT: &str = "/api/operations/activity-queue-contract";
const REQUIRED_QUEUE_ITEM_TYPES: &[&str] = &[
    "parent-operation",
    "child-operation",
    "lock",
    "retry",
    "blocked-reason",
    "handover-note",
    "evidence-reference",
];
const REQUIRED_QUEUE_STATES: &[&str] = &[
    "queued",
    "running",
    "blocked",
    "retrying",
    "waiting-approval",
    "completed",
    "failed",
    "canceled",
    "stale",
];
const REQUIRED_QUEUE_LENSES: &[&str] = &[
    "by-site",
    "by-workflow",
    "by-owner-domain",
    "by-priority",
    "by-risk",
    "by-staleness",
];
const REQUIRED_GUARDS: &[&str] = &[
    "operation-scope-known",
    "queue-state-known",
    "lock-state-known",
    "retry-policy-known",
    "blocked-reason-present",
    "stale-data-marked",
    "evidence-redacted",
    "live-query-blocked",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "activity-live-query-disabled",
    "activity-operation-mutation-disabled",
    "activity-workflow-mutation-disabled",
    "activity-worker-dispatch-disabled",
    "activity-provider-calls-disabled",
    "activity-notification-dispatch-disabled",
    "activity-raw-operation-rows-disabled",
    "activity-raw-child-operation-rows-disabled",
    "activity-raw-lock-rows-disabled",
    "activity-raw-retry-rows-disabled",
    "activity-raw-execution-logs-disabled",
    "activity-raw-provider-payloads-disabled",
    "activity-raw-user-data-disabled",
    "activity-raw-recipient-data-disabled",
    "activity-credential-values-disabled",
    "activity-token-values-disabled",
    "activity-tenant-identifiers-disabled",
    "activity-object-identifiers-disabled",
    "activity-principal-identifiers-disabled",
    "activity-private-network-values-disabled",
    "operation-scope-missing",
    "queue-state-unknown",
    "lock-state-unknown",
    "retry-policy-missing",
    "blocked-reason-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Activity queue summary",
    "Parent operation summary",
    "Child operation summary",
    "Lock state summary",
    "Retry state summary",
    "Blocked reason summary",
    "Handover notes",
    "Evidence references",
];
const SAFE_TRUE_FIELDS: &[&str] = &[
    "queueSummaryReadOnly",
    "childOperationSummaryReadOnly",
    "lockStateReadOnly",
    "retryStateReadOnly",
    "blockedReasonSummaryOnly",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "liveQueueQueryAllowed",
    "operationMutationAllowed",
    "workflowMutationAllowed",
    "workerDispatchAllowed",
    "providerCallsAllowed",
    "notificationDispatchAllowed",
    "rawOperationRowsAllowed",
    "rawChildOperationRowsAllowed",
    "rawLockRowsAllowed",
    "rawRetryRowsAllowed",
    "rawExecutionLogsAllowed",
    "rawProviderPayloadsAllowed",
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
    "activityOperationQueueMode",
    "queueItemTypes",
    "queueStates",
    "queueLenses",
    "requiredGuards",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "queueSummaryReadOnly",
    "childOperationSummaryReadOnly",
    "lockStateReadOnly",
    "retryStateReadOnly",
    "blockedReasonSummaryOnly",
    "liveQueueQueryAllowed",
    "operationMutationAllowed",
    "workflowMutationAllowed",
    "workerDispatchAllowed",
    "providerCallsAllowed",
    "notificationDispatchAllowed",
    "rawOperationRowsAllowed",
    "rawChildOperationRowsAllowed",
    "rawLockRowsAllowed",
    "rawRetryRowsAllowed",
    "rawExecutionLogsAllowed",
    "rawProviderPayloadsAllowed",
    "rawUserDataAllowed",
    "rawRecipientDataAllowed",
    "credentialValuesAllowed",
    "tokenValuesAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "principalIdentifiersAllowed",
    "privateNetworkValuesAllowed",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("queueItemTypes", "activityOperationQueueItemTypes"),
    ("queueStates", "activityOperationQueueStates"),
    ("queueLenses", "activityOperationQueueLenses"),
    ("requiredGuards", "activityOperationQueueRequiredGuards"),
    ("blockedReasons", "activityOperationQueueBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[("requiredEvidence", REQUIRED_EVIDENCE)];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "activityOperationQueueMode",
    "queueSummaryReadOnly",
    "childOperationSummaryReadOnly",
    "lockStateReadOnly",
    "retryStateReadOnly",
    "blockedReasonSummaryOnly",
    "liveQueueQueryAllowed",
    "operationMutationAllowed",
    "workflowMutationAllowed",
    "workerDispatchAllowed",
    "providerCallsAllowed",
    "notificationDispatchAllowed",
    "rawOperationRowsAllowed",
    "rawChildOperationRowsAllowed",
    "rawLockRowsAllowed",
    "rawRetryRowsAllowed",
    "rawExecutionLogsAllowed",
    "rawProviderPayloadsAllowed",
    "rawUserDataAllowed",
    "rawRecipientDataAllowed",
    "credentialValuesAllowed",
    "tokenValuesAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "principalIdentifiersAllowed",
    "privateNetworkValuesAllowed",
    "queueItemTypes",
    "queueStates",
    "queueLenses",
    "requiredGuards",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
];
const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "activity-queue-read-only",
        decision: "block",
        requirement: "Activity queue summaries are read-only and must not run live queue queries, dispatch workers, call providers, or mutate operations.",
        evidence: "Activity queue summary",
    },
    RuleDetail {
        id: "operation-state-not-mutated",
        decision: "block",
        requirement: "Parent operation, child operation, lock, retry, and workflow state must remain unchanged by the Activity queue view.",
        evidence: "Parent operation summary",
    },
    RuleDetail {
        id: "blocked-reason-required",
        decision: "block",
        requirement: "Blocked and stale queue items require known operation scope, queue state, lock state, retry policy, blocked reason, and redacted evidence before handover.",
        evidence: "Blocked reason summary",
    },
    RuleDetail {
        id: "raw-activity-queue-data-not-exposed",
        decision: "block",
        requirement: "Activity queue evidence must not expose raw operation rows, raw child operation rows, raw lock rows, raw retry rows, raw execution logs, raw provider payloads, raw user data, raw recipient data, credential values, token values, tenant identifiers, object identifiers, principal identifiers, private network values, live endpoints, or URLs.",
        evidence: "Evidence references",
    },
];

#[derive(Debug, Deserialize)]
struct ActivityOperationQueueContext {
    catalog: Value,
    catalog_text: String,
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
    let context: ActivityOperationQueueContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid activity operation queue context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    scan_prohibited_value(
        &Value::String(context.catalog_text),
        CATALOG_PATH,
        &mut errors,
    );
    if !context.catalog.is_object() {
        return Ok(errors);
    }
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(
        &context.api_readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.api_readme),
        "api/Ryuki.Platform.Api/README.md",
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.catalog_readme),
        "catalog/README.md",
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.doc_readme),
        "docs/workflows/README.md",
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.doc),
        "docs/workflows/activity-operation-queue.md",
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid activity operation queue catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid activity operation queue program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid activity operation queue docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid activity operation queue prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("activity operation queue catalog must be a mapping".to_string());
        return;
    }
    validate_catalog_keys(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "activity operation queue version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "activity operation queue status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "activity operation queue source must be static-seed",
    );
    expect(
        string_value(catalog, "activityOperationQueueMode")
            == Some("static-activity-operation-queue"),
        errors,
        "activity operation queue mode must be static-activity-operation-queue",
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            bool_value(catalog, field) == Some(true),
            errors,
            format!("activity operation queue {field} must be true"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            format!("activity operation queue {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "queueItemTypes", REQUIRED_QUEUE_ITEM_TYPES, errors);
    validate_required_array(catalog, "queueStates", REQUIRED_QUEUE_STATES, errors);
    validate_required_array(catalog, "queueLenses", REQUIRED_QUEUE_LENSES, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);
    scan_prohibited_value(catalog, CATALOG_PATH, errors);
}

fn validate_catalog_keys(catalog: &Value, errors: &mut Vec<String>) {
    let Some(map) = catalog.as_object() else {
        return;
    };
    let required: BTreeSet<&str> = REQUIRED_CATALOG_KEYS.iter().copied().collect();
    let unexpected: Vec<&str> = map
        .keys()
        .map(String::as_str)
        .filter(|key| !required.contains(key))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "activity operation queue unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }
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
    for value in values {
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "{field} contains prohibited activity operation queue value {value}"
            ));
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rule_values: Vec<&Value> = match catalog.get("rules") {
        Some(Value::Array(values)) => values.iter().collect(),
        Some(value) => vec![value],
        None => Vec::new(),
    };
    for (index, rule) in rule_values.iter().enumerate() {
        if !rule.is_object() {
            errors.push(format!(
                "activity operation queue rule {index} must be a mapping"
            ));
        }
    }
    let rules: Vec<&Value> = rule_values
        .iter()
        .copied()
        .filter(|rule| rule.is_object())
        .collect();
    let parsed_rules: Vec<Rule> = rules
        .iter()
        .filter_map(|rule| {
            Some(Rule {
                id: rule.get("id")?.as_str()?.to_string(),
                decision: rule.get("decision")?.as_str()?.to_string(),
                requirement: rule.get("requirement")?.as_str()?.to_string(),
                evidence: rule.get("evidence")?.as_str()?.to_string(),
            })
        })
        .collect();
    let rule_ids: Vec<&str> = parsed_rules.iter().map(|rule| rule.id.as_str()).collect();
    let rule_details: Vec<(&str, &str, &str)> = parsed_rules
        .iter()
        .map(|rule| {
            (
                rule.decision.as_str(),
                rule.requirement.as_str(),
                rule.evidence.as_str(),
            )
        })
        .collect();
    let expected_ids: BTreeSet<&str> = REQUIRED_RULES.iter().map(|rule| rule.id).collect();
    let actual_ids: BTreeSet<&str> = rule_ids.iter().copied().collect();
    let missing: Vec<&str> = REQUIRED_RULES
        .iter()
        .map(|rule| rule.id)
        .filter(|id| !actual_ids.contains(id))
        .collect();
    let unexpected: Vec<&str> = rule_ids
        .iter()
        .copied()
        .filter(|id| !expected_ids.contains(id))
        .collect();
    expect(
        missing.is_empty(),
        errors,
        format!(
            "activity operation queue missing rules: {}",
            missing.join(", ")
        ),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "activity operation queue unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "activity operation queue rule IDs must be unique",
    );
    expect(
        rule_details.iter().collect::<BTreeSet<_>>().len() == rule_details.len(),
        errors,
        "activity operation queue rule details must be unique",
    );
    for rule in rules {
        let Some(map) = rule.as_object() else {
            continue;
        };
        let rule_id = rule
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("(missing id)");
        let actual_keys: BTreeSet<&str> = map.keys().map(String::as_str).collect();
        let expected_keys: BTreeSet<&str> = RULE_KEYS.iter().copied().collect();
        let unexpected_keys: Vec<&str> = actual_keys.difference(&expected_keys).copied().collect();
        let missing_keys: Vec<&str> = expected_keys.difference(&actual_keys).copied().collect();
        if !unexpected_keys.is_empty() {
            errors.push(format!(
                "activity operation queue rule {rule_id} unexpected rule keys: {}",
                unexpected_keys.join(", ")
            ));
        }
        if !missing_keys.is_empty() {
            errors.push(format!(
                "activity operation queue rule {rule_id} missing rule keys: {}",
                missing_keys.join(", ")
            ));
        }
    }
    for expected_rule in REQUIRED_RULES {
        let Some(rule) = parsed_rules.iter().find(|rule| rule.id == expected_rule.id) else {
            continue;
        };
        expect(
            rule.decision == expected_rule.decision,
            errors,
            format!(
                "activity operation queue rule {} decision must match",
                expected_rule.id
            ),
        );
        expect(
            rule.requirement == expected_rule.requirement,
            errors,
            format!(
                "activity operation queue rule {} requirement must match",
                expected_rule.id
            ),
        );
        expect(
            rule.evidence == expected_rule.evidence,
            errors,
            format!(
                "activity operation queue rule {} evidence must match",
                expected_rule.id
            ),
        );
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = strip_csharp_comments(program);
    let endpoint_count = endpoint_start_indices(&uncommented_program).len();
    expect(
        endpoint_count == 1,
        errors,
        "API must register exactly one activity operation queue endpoint",
    );
    let block = endpoint_block(&uncommented_program, errors);
    if block.is_empty() {
        return;
    }
    expect(
        exact_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static-seed source",
    );
    expect(
        exact_string_assignment(
            &block,
            "activityOperationQueueMode",
            "static-activity-operation-queue",
        ),
        errors,
        "API must keep static-activity-operation-queue mode",
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            exact_assignment(&block, field, "true"),
            errors,
            format!("API must keep {field} true"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            exact_assignment(&block, field, "false"),
            errors,
            format!("API must keep {field} disabled"),
        );
    }
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_assignment(&block, field, variable),
            errors,
            format!("API must bind {field} to {variable}"),
        );
        let values = csharp_array_values(&uncommented_program, variable);
        validate_api_array(field, values, string_array_like(catalog, field), errors);
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
    let catalog_rules = catalog_rules(catalog);
    let api_rules = api_rules(block);
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
    let stripped = strip_csharp_string_literals(block);
    for field in assignment_fields(&stripped) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has unexpected activity operation queue field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited activity operation queue field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    for (field, value) in assignment_values(&stripped) {
        if value != "true" || SAFE_TRUE_FIELDS.contains(&field.as_str()) {
            continue;
        }
        if [
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
            "queue",
            "worker",
            "operation",
            "lock",
            "retry",
        ]
        .iter()
        .any(|term| field.to_ascii_lowercase().contains(term))
        {
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
        "API README missing activity operation queue endpoint",
    );
    expect(
        catalog_readme.contains("activity-operation-queue-contract.yaml"),
        errors,
        "catalog README missing activity operation queue catalog",
    );
    expect(
        doc_readme.contains("activity-operation-queue.md"),
        errors,
        "workflow README missing activity operation queue doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "activity operation queue doc missing endpoint",
    );
    expect(
        doc.contains("No live queue queries"),
        errors,
        "activity operation queue doc must prohibit live queue queries",
    );
    expect(
        doc.contains(
            "No operation, workflow, lock, retry, worker, provider, or notification mutation",
        ),
        errors,
        "activity operation queue doc must prohibit mutation",
    );
    expect(
        doc.contains("No provider calls"),
        errors,
        "activity operation queue doc must prohibit provider calls",
    );
    for phrase in [
        "raw operation rows",
        "raw child operation rows",
        "raw execution logs",
        "raw provider payloads",
        "raw user data",
        "tenant identifiers",
    ] {
        expect(
            doc.contains(phrase),
            errors,
            format!("activity operation queue doc must prohibit {phrase}"),
        );
    }
    expect(
        doc.contains("static Activity operation queue summaries only"),
        errors,
        "activity operation queue doc must require static summaries",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_field(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited activity operation queue field"
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
                    "{path} contains prohibited activity operation queue value {text}"
                ));
            }
        }
        _ => {}
    }
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn safe_text_value(value: &str) -> bool {
    let text = value.trim();
    safe_text_arrays().iter().any(|items| items.contains(&text))
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, binding)| *binding == text)
        || REQUIRED_RULES
            .iter()
            .any(|rule| [rule.id, rule.decision, rule.requirement, rule.evidence].contains(&text))
        || [
            "draft",
            "static-seed",
            "static-activity-operation-queue",
            "block",
            "true",
            "false",
        ]
        .contains(&text)
}

fn safe_text_arrays() -> [&'static [&'static str]; 9] {
    [
        REQUIRED_QUEUE_ITEM_TYPES,
        REQUIRED_QUEUE_STATES,
        REQUIRED_QUEUE_LENSES,
        REQUIRED_GUARDS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        SAFE_TRUE_FIELDS,
        REQUIRED_DISABLED_FIELDS,
        REQUIRED_CATALOG_KEYS,
    ]
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize(value);
    if safe_text_value(value) {
        return false;
    }
    [
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
    ]
    .contains(&normalized.as_str())
        || [
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
            "username",
            "useremail",
            "privateip",
            "privatenetwork",
            "providerpayload",
            "rawprovider",
            "rawoperation",
            "operationrow",
            "rawchild",
            "childoperationrow",
            "rawlock",
            "lockrow",
            "rawretry",
            "retryrow",
            "rawexecution",
            "executionlog",
            "rawlog",
            "rawrow",
            "rawrows",
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
            "operationmutation",
            "workflowmutation",
            "workerdispatch",
            "providercall",
            "notificationdispatch",
            "livequeue",
        ]
        .iter()
        .any(|term| normalized.contains(term))
}

fn prohibited_value(text: &str) -> bool {
    text.contains("://")
        || text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----")
        || text.contains("AKIA")
        || contains_private_ip(text)
        || contains_uuid_like(text)
        || contains_email_like(text)
        || contains_secret_assignment(text)
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
        "token",
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

fn endpoint_block(uncommented_program: &str, errors: &mut Vec<String>) -> String {
    let Some(start_index) = endpoint_start_index(uncommented_program) else {
        errors.push("API missing activity operation queue endpoint".to_string());
        return String::new();
    };
    let next_index =
        next_endpoint_index(uncommented_program, start_index).unwrap_or(uncommented_program.len());
    uncommented_program[start_index..next_index].to_string()
}

fn endpoint_start_index(uncommented_program: &str) -> Option<usize> {
    endpoint_start_indices(uncommented_program)
        .into_iter()
        .next()
}

fn endpoint_start_indices(uncommented_program: &str) -> Vec<usize> {
    let route = format!("\"{ENDPOINT}\"");
    let mut indices = Vec::new();
    for (route_start, _) in uncommented_program.match_indices(&route) {
        let prefix = &uncommented_program[..route_start];
        let Some(map_index) = prefix.rfind("app.MapGet(") else {
            continue;
        };
        let before_map_line = uncommented_program[..map_index]
            .rsplit_once('\n')
            .map(|(_, line)| line)
            .unwrap_or(&uncommented_program[..map_index]);
        if !before_map_line.trim().is_empty() {
            continue;
        }
        let between = &uncommented_program[map_index + "app.MapGet(".len()..route_start];
        if between.trim().is_empty() {
            indices.push(map_index);
        }
    }
    indices
}

fn next_endpoint_index(program: &str, start_index: usize) -> Option<usize> {
    let mut offset = start_index + "app.MapGet(".len();
    while let Some(relative) = program[offset..].find("app.MapGet(") {
        let index = offset + relative;
        let line_prefix = program[..index]
            .rsplit_once('\n')
            .map(|(_, line)| line)
            .unwrap_or(&program[..index]);
        if line_prefix.trim().is_empty() {
            return Some(index);
        }
        offset = index + "app.MapGet(".len();
    }
    None
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
        .filter(|rule| rule.is_object())
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
    let values = assignment_values_for_field(block, field);
    values.len() == 1 && values[0] == value
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let values = assignment_values_for_field(block, field);
    values.len() == 1 && values[0] == format!("\"{value}\"")
}

fn assignment_values_for_field(block: &str, field: &str) -> Vec<String> {
    let prefix = format!("{field} =");
    block
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with(&prefix) && line.ends_with(','))
        .map(|line| {
            line[prefix.len()..]
                .trim()
                .trim_end_matches(',')
                .trim()
                .to_string()
        })
        .collect()
}

fn assignment_fields(block: &str) -> Vec<String> {
    block
        .match_indices('=')
        .filter_map(|(index, _)| field_before_equals(block, index))
        .collect()
}

fn assignment_values(block: &str) -> Vec<(String, String)> {
    block
        .lines()
        .filter_map(|line| {
            let index = line.find('=')?;
            let field = field_before_equals(line, index)?;
            let value = line[index + 1..]
                .trim()
                .trim_end_matches(',')
                .trim()
                .to_string();
            Some((field, value))
        })
        .collect()
}

fn field_before_equals(text: &str, equals_index: usize) -> Option<String> {
    let prefix = &text[..equals_index];
    let trimmed = prefix.trim_end();
    let end = trimmed.len();
    let start = trimmed
        .char_indices()
        .rev()
        .find(|(_, ch)| !(*ch == '_' || ch.is_ascii_alphanumeric()))
        .map(|(index, ch)| index + ch.len_utf8())
        .unwrap_or(0);
    let field = &trimmed[start..end];
    if field
        .chars()
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
    {
        Some(field.to_string())
    } else {
        None
    }
}

fn string_field(segment: &str, field: &str) -> Option<String> {
    let marker = format!("{field} = \"");
    let start = segment.find(&marker)? + marker.len();
    let end = segment[start..].find('"')? + start;
    Some(segment[start..end].to_string())
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut chars = text.char_indices().peekable();
    while let Some((_, ch)) = chars.next() {
        if ch != '"' {
            continue;
        }
        let mut value = String::new();
        let mut escaped = false;
        for (_, inner) in chars.by_ref() {
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
        result.push(value);
    }
    result
}

fn strip_csharp_comments(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if in_string {
            result.push(ch);
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
            result.push(ch);
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'/') {
            chars.next();
            for comment_ch in chars.by_ref() {
                if comment_ch == '\n' {
                    result.push('\n');
                    break;
                }
            }
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'*') {
            chars.next();
            let mut previous = '\0';
            for comment_ch in chars.by_ref() {
                if comment_ch == '\n' {
                    result.push('\n');
                }
                if previous == '*' && comment_ch == '/' {
                    break;
                }
                previous = comment_ch;
            }
            continue;
        }
        result.push(ch);
    }
    result
}

fn strip_csharp_string_literals(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
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
                result.push('"');
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
            result.push('"');
        } else {
            result.push(ch);
        }
    }
    result
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn endpoint_start_ignores_commented_decoy() {
        let program = format!(
            "// app.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"live\" }}));\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        let stripped = strip_csharp_comments(&program);
        let start = endpoint_start_index(&stripped).expect("real endpoint");
        assert!(stripped[start..].starts_with("app.MapGet("));
    }

    #[test]
    fn exact_assignment_rejects_duplicates_and_expressions() {
        let block =
            "    liveQueueQueryAllowed = requestedLiveQuery,\n    liveQueueQueryAllowed = false,\n";
        assert!(!exact_assignment(block, "liveQueueQueryAllowed", "false"));
    }

    #[test]
    fn prohibited_activity_key_variants_are_normalized() {
        assert!(prohibited_field("tenant/id"));
        assert!(prohibited_field("provider-payload"));
        assert!(prohibited_field("rawOperationRows"));
    }

    #[test]
    fn validate_program_rejects_duplicate_endpoint_registration() {
        let catalog = valid_catalog();
        let program = format!(
            "app.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        let mut errors = Vec::new();

        validate_program_text(&program, &catalog, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("exactly one activity operation queue endpoint")));
    }

    #[test]
    fn validate_catalog_rejects_duplicate_rule_details() {
        let mut catalog = valid_catalog();
        let rules = catalog
            .get_mut("rules")
            .and_then(Value::as_array_mut)
            .expect("rules array");
        rules[3]["decision"] = rules[0]["decision"].clone();
        rules[3]["requirement"] = rules[0]["requirement"].clone();
        rules[3]["evidence"] = rules[0]["evidence"].clone();
        let mut errors = Vec::new();

        validate_catalog_value(&catalog, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("rule details") && error.contains("unique")));
    }

    #[test]
    fn scan_prohibited_rejects_unsafe_operation_and_provider_literals() {
        let payload = json!({
            "operationSummary": "00000000-0000-0000-0000-000000000000",
            "providerRouteSummary": "https://activity.invalid/queue",
            "providerPayloadSummary": "safe-summary"
        });
        let mut errors = Vec::new();

        scan_prohibited_value(&payload, "synthetic", &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("synthetic.operationSummary")));
        assert!(errors
            .iter()
            .any(|error| error.contains("synthetic.providerRouteSummary")));
        assert!(errors
            .iter()
            .any(|error| error.contains("synthetic.providerPayloadSummary")));
    }

    fn valid_catalog() -> Value {
        json!({
            "version": 1,
            "status": "draft",
            "source": "static-seed",
            "activityOperationQueueMode": "static-activity-operation-queue",
            "queueItemTypes": REQUIRED_QUEUE_ITEM_TYPES,
            "queueStates": REQUIRED_QUEUE_STATES,
            "queueLenses": REQUIRED_QUEUE_LENSES,
            "requiredGuards": REQUIRED_GUARDS,
            "blockedReasons": REQUIRED_BLOCKED_REASONS,
            "requiredEvidence": REQUIRED_EVIDENCE,
            "rules": REQUIRED_RULES
                .iter()
                .map(|rule| json!({
                    "id": rule.id,
                    "decision": rule.decision,
                    "requirement": rule.requirement,
                    "evidence": rule.evidence
                }))
                .collect::<Vec<Value>>(),
            "queueSummaryReadOnly": true,
            "childOperationSummaryReadOnly": true,
            "lockStateReadOnly": true,
            "retryStateReadOnly": true,
            "blockedReasonSummaryOnly": true,
            "liveQueueQueryAllowed": false,
            "operationMutationAllowed": false,
            "workflowMutationAllowed": false,
            "workerDispatchAllowed": false,
            "providerCallsAllowed": false,
            "notificationDispatchAllowed": false,
            "rawOperationRowsAllowed": false,
            "rawChildOperationRowsAllowed": false,
            "rawLockRowsAllowed": false,
            "rawRetryRowsAllowed": false,
            "rawExecutionLogsAllowed": false,
            "rawProviderPayloadsAllowed": false,
            "rawUserDataAllowed": false,
            "rawRecipientDataAllowed": false,
            "credentialValuesAllowed": false,
            "tokenValuesAllowed": false,
            "tenantIdentifiersAllowed": false,
            "objectIdentifiersAllowed": false,
            "principalIdentifiersAllowed": false,
            "privateNetworkValuesAllowed": false
        })
    }
}
