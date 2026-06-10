use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/monitoring-coverage-gap-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/monitoring-coverage-gap.md";
const ENDPOINT: &str = "/api/observe/monitoring-coverage-gap-contract";
const REQUIRED_SCOPES: &[&str] = &[
    "host",
    "application",
    "site",
    "environment",
    "monitoring-profile",
    "support-group",
];
const REQUIRED_SIGNALS: &[&str] = &[
    "missing-zabbix-host",
    "missing-host-group",
    "missing-template",
    "missing-proxy-or-server",
    "missing-maintenance-window",
    "missing-owner",
    "missing-support-group",
    "alert-routing-gap",
    "stale-monitoring-inventory",
];
const REQUIRED_INPUTS: &[&str] = &[
    "assetScope",
    "site",
    "environment",
    "monitoringProfile",
    "hostGroupProfile",
    "templateProfile",
    "proxyOrServerProfile",
    "maintenanceWindow",
    "owner",
    "supportGroup",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "inventory-coverage-current",
    "monitoring-profile-known",
    "host-summary-known",
    "host-group-known",
    "template-known",
    "proxy-or-server-known",
    "maintenance-window-known",
    "owner-known",
    "support-group-known",
    "alert-routing-reviewed",
    "stale-data-marked",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "coverageSummary",
    "hostOnboardingState",
    "hostGroupTemplateReview",
    "proxyOrServerReview",
    "maintenanceWindowReview",
    "alertRoutingReview",
    "ownerRouting",
    "remediationDraft",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-remediation-disabled",
    "zabbix-mutation-disabled",
    "live-task-creation-disabled",
    "raw-host-rows-disabled",
    "raw-alert-payloads-disabled",
    "raw-problem-rows-disabled",
    "raw-provider-payloads-disabled",
    "asset-scope-unknown",
    "monitoring-profile-missing",
    "host-summary-unknown",
    "host-group-missing",
    "template-missing",
    "proxy-or-server-unknown",
    "maintenance-window-missing",
    "alert-routing-unknown",
    "owner-unknown",
    "support-group-unknown",
    "stale-monitoring-inventory",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Monitoring coverage summary",
    "Host onboarding state",
    "Host group and template review",
    "Proxy or server review",
    "Maintenance window review",
    "Alert routing review",
    "Owner routing",
    "Remediation draft",
    "Evidence references",
];
const TEMPLATE_DEFAULT_POSTURE: &str = "default-built-in-templates";
const TEMPLATE_EXCEPTION_PROFILES: &[&str] = &["lenovo-xcc-snmp"];
const TEMPLATE_EXCEPTION_EVIDENCE: &str = "Lenovo XCC SNMP";
const REQUIRED_RULES: &[(&str, &str, &str, &str)] = &[
    (
        "no-live-zabbix-coverage-remediation",
        "block",
        "Monitoring coverage gap reporting must not create hosts, update groups, link templates, assign proxies, change maintenance windows, or mutate Zabbix provider state.",
        "Remediation draft",
    ),
    (
        "aggregate-coverage-report-only",
        "block",
        "Operators receive aggregate coverage summaries only, never raw host rows, alert payloads, problem rows, object IDs, or provider payloads.",
        "Monitoring coverage summary",
    ),
    (
        "host-group-template-required",
        "block",
        "Host group and template coverage must be known before monitoring coverage status can be trusted.",
        "Host group and template review",
    ),
    (
        "proxy-maintenance-required",
        "block",
        "Proxy or server assignment and maintenance window coverage must be reviewed before a gap can be closed.",
        "Proxy or server review",
    ),
    (
        "alert-routing-reviewed",
        "block",
        "Alert routing must be reviewed before monitoring coverage is considered complete.",
        "Alert routing review",
    ),
    (
        "stale-monitoring-inventory-blocks",
        "block",
        "Stale monitoring inventory blocks coverage decisions until refreshed or routed to review.",
        "Monitoring coverage summary",
    ),
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "liveRemediationAllowed",
    "zabbixMutationAllowed",
    "liveTaskCreationAllowed",
    "rawHostRowsAllowed",
    "rawAlertPayloadsAllowed",
    "rawProblemRowsAllowed",
    "rawProviderPayloadsAllowed",
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str, &[&str])] = &[
    (
        "supportedScopes",
        "monitoringCoverageGapScopes",
        REQUIRED_SCOPES,
    ),
    (
        "gapSignals",
        "monitoringCoverageGapSignals",
        REQUIRED_SIGNALS,
    ),
    (
        "requiredGuards",
        "monitoringCoverageGapRequiredGuards",
        REQUIRED_GUARDS,
    ),
    (
        "planSections",
        "monitoringCoverageGapPlanSections",
        REQUIRED_PLAN_SECTIONS,
    ),
    (
        "blockedReasons",
        "monitoringCoverageGapBlockedReasons",
        REQUIRED_BLOCKED_REASONS,
    ),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "reportMode",
    "templateBaseline",
    "rules",
    "providerCallsEnabled",
    "liveRemediationAllowed",
    "zabbixMutationAllowed",
    "liveTaskCreationAllowed",
    "rawHostRowsAllowed",
    "rawAlertPayloadsAllowed",
    "rawProblemRowsAllowed",
    "rawProviderPayloadsAllowed",
    "supportedScopes",
    "gapSignals",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredInputs",
    "requiredEvidence",
];
const SAFE_CATALOG_KEYS: &[&str] = &[
    "source",
    "reportMode",
    "templateBaseline",
    "rules",
    "providerCallsEnabled",
    "liveRemediationAllowed",
    "zabbixMutationAllowed",
    "liveTaskCreationAllowed",
    "rawHostRowsAllowed",
    "rawAlertPayloadsAllowed",
    "rawProblemRowsAllowed",
    "rawProviderPayloadsAllowed",
    "supportedScopes",
    "gapSignals",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredInputs",
    "requiredEvidence",
    "version",
    "status",
    "requirement",
    "evidence",
    "decision",
    "id",
    "defaultPosture",
    "exceptionProfiles",
    "exceptionEvidence",
];
const RULE_FIELDS: &[&str] = &["id", "decision", "requirement", "evidence"];
const PROHIBITED_PROVIDER_KEYS: &[&str] = &[
    "hostname",
    "hostid",
    "zabbixhostid",
    "hostgroupid",
    "templateid",
    "proxyid",
    "maintenanceid",
    "actionid",
    "eventid",
    "problemid",
    "username",
    "password",
    "credential",
    "credentials",
    "secret",
    "token",
    "tenantid",
    "objectid",
    "endpoint",
    "endpointname",
    "privateip",
    "rawhostrows",
    "rawalertpayload",
    "rawalertpayloads",
    "rawproblemrows",
    "providerpayload",
    "providerpayloads",
    "rawproviderpayload",
    "rawproviderpayloads",
];
const PROHIBITED_PROVIDER_KEY_TOKENS: &[&str] = &[
    "hostname",
    "hostid",
    "zabbixhostid",
    "hostgroupid",
    "templateid",
    "proxyid",
    "maintenanceid",
    "actionid",
    "eventid",
    "problemid",
    "username",
    "password",
    "credential",
    "secret",
    "token",
    "tenantid",
    "objectid",
    "endpoint",
    "endpointname",
    "privateip",
    "rawhostrows",
    "rawalertpayload",
    "rawproblemrows",
    "providerpayload",
    "rawproviderpayload",
];
const HIGH_RISK_TEXT_TOKENS: &[&str] = &[
    "hostid",
    "zabbixhostid",
    "hostgroupid",
    "templateid",
    "proxyid",
    "maintenanceid",
    "actionid",
    "eventid",
    "problemid",
    "tenantid",
    "objectid",
    "endpointname",
    "privateip",
    "rawhostrows",
    "rawalertpayload",
    "rawalertpayloads",
    "rawproblemrows",
    "providerpayload",
    "providerpayloads",
    "rawproviderpayload",
    "rawproviderpayloads",
];
const UNSAFE_TRUE_FIELD_TOKENS: &[&str] = &[
    "live",
    "provider",
    "raw",
    "credential",
    "secret",
    "token",
    "tenant",
    "object",
    "endpoint",
    "private",
    "zabbix",
    "host",
    "template",
    "proxy",
    "maintenance",
    "alert",
    "problem",
    "inventory",
    "payload",
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
struct ScanInput {
    value: Value,
    path: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let input = fs::read_to_string(path)
        .map_err(|error| format!("failed to read monitoring coverage gap context: {error}"))?;
    let context: ContextInput = serde_json::from_str(&input)
        .map_err(|error| format!("invalid monitoring coverage gap context JSON: {error}"))?;
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
    scan_prohibited_text(&context.program, PROGRAM_PATH, &mut errors);
    scan_prohibited_text(&context.api_readme, API_README_PATH, &mut errors);
    scan_prohibited_text(&context.catalog_readme, CATALOG_README_PATH, &mut errors);
    scan_prohibited_text(&context.doc_readme, DOC_README_PATH, &mut errors);
    scan_prohibited_text(&context.doc, DOC_PATH, &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid monitoring coverage gap catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid monitoring coverage gap program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid monitoring coverage gap docs JSON: {error}"))?;
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
    let payload: ScanInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid monitoring coverage gap scan JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("monitoring coverage gap catalog must be a YAML mapping".to_string());
        return;
    }
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "monitoring coverage gap version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "monitoring coverage gap status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "monitoring coverage gap source must be static-seed",
    );
    expect(
        string_value(catalog, "reportMode") == Some("aggregate-gap-report"),
        errors,
        "monitoring coverage gap report mode must be aggregate-gap-report",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        let message = match *field {
            "providerCallsEnabled" => "monitoring coverage gap provider calls must be disabled",
            "liveRemediationAllowed" => "monitoring coverage gap live remediation must be disabled",
            "zabbixMutationAllowed" => "monitoring coverage gap Zabbix mutation must be disabled",
            "liveTaskCreationAllowed" => {
                "monitoring coverage gap live task creation must be disabled"
            }
            "rawHostRowsAllowed" => "monitoring coverage gap raw host rows must be disabled",
            "rawAlertPayloadsAllowed" => {
                "monitoring coverage gap raw alert payloads must be disabled"
            }
            "rawProblemRowsAllowed" => "monitoring coverage gap raw problem rows must be disabled",
            "rawProviderPayloadsAllowed" => {
                "monitoring coverage gap raw provider payloads must be disabled"
            }
            _ => "monitoring coverage gap disabled field must be false",
        };
        expect(bool_value(catalog, field) == Some(false), errors, message);
    }
    for (field, required) in [
        ("supportedScopes", REQUIRED_SCOPES),
        ("gapSignals", REQUIRED_SIGNALS),
        ("requiredInputs", REQUIRED_INPUTS),
        ("requiredGuards", REQUIRED_GUARDS),
        ("planSections", REQUIRED_PLAN_SECTIONS),
        ("blockedReasons", REQUIRED_BLOCKED_REASONS),
        ("requiredEvidence", REQUIRED_EVIDENCE),
    ] {
        validate_required_array(catalog, field, required, errors);
    }
    validate_template_baseline(catalog.get("templateBaseline"), errors);
    validate_no_prohibited_contract_terms(
        catalog,
        &[
            "supportedScopes",
            "gapSignals",
            "requiredInputs",
            "requiredGuards",
            "planSections",
        ],
        errors,
    );
    validate_required_rules(catalog, errors);
}

fn validate_template_baseline(baseline: Option<&Value>, errors: &mut Vec<String>) {
    let Some(baseline) = baseline.and_then(Value::as_object) else {
        errors.push(
            "monitoring coverage gap template baseline must require default built-in templates"
                .to_string(),
        );
        return;
    };
    expect(
        baseline.get("defaultPosture").and_then(Value::as_str) == Some(TEMPLATE_DEFAULT_POSTURE),
        errors,
        "monitoring coverage gap template baseline must require default built-in templates",
    );
    let profiles = baseline
        .get("exceptionProfiles")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let required_profiles = TEMPLATE_EXCEPTION_PROFILES
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    expect(
        profiles == required_profiles,
        errors,
        "monitoring coverage gap template baseline must allow only the Lenovo XCC SNMP exception",
    );
    expect(
        baseline.get("exceptionEvidence").and_then(Value::as_str)
            == Some(TEMPLATE_EXCEPTION_EVIDENCE),
        errors,
        "monitoring coverage gap template baseline must name Lenovo XCC SNMP exception evidence",
    );
}

fn validate_no_prohibited_contract_terms(
    catalog: &Value,
    fields: &[&str],
    errors: &mut Vec<String>,
) {
    for field in fields {
        let Some(values) = catalog.get(*field).and_then(Value::as_array) else {
            continue;
        };
        for value in values.iter().filter_map(Value::as_str) {
            if prohibited_provider_key(value, true) {
                errors.push(format!(
                    "{field} contains prohibited provider field {value}"
                ));
            }
        }
    }
}

fn validate_required_array(
    value: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) -> Vec<String> {
    let Some(array) = value.get(field).and_then(Value::as_array) else {
        errors.push(format!("{field} must be non-empty array"));
        return Vec::new();
    };
    let mut values = Vec::new();
    for item in array {
        if let Some(text) = item.as_str() {
            values.push(text.to_string());
        } else {
            errors.push(format!("{field} values must be strings"));
        }
    }
    expect(
        !values.is_empty(),
        errors,
        &format!("{field} must be non-empty array"),
    );
    push_missing_unexpected("", field, &values, required_values, errors);
    expect(
        unique(&values),
        errors,
        &format!("{field} values must be unique"),
    );
    values
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = catalog_rule_objects(catalog.get("rules"), errors);
    let rule_ids = rules
        .iter()
        .filter_map(|rule| string_value(rule, "id"))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let required_rule_ids = REQUIRED_RULES
        .iter()
        .map(|(id, _, _, _)| *id)
        .collect::<Vec<_>>();
    expect(
        unique(&rule_ids),
        errors,
        "monitoring coverage gap rule IDs must be unique",
    );
    push_rule_missing_unexpected(
        "monitoring coverage gap",
        &rule_ids,
        &required_rule_ids,
        errors,
    );
    validate_rule_detail_uniqueness_value(&rules, "monitoring coverage gap catalog", errors);
    for (id, decision, requirement, evidence) in REQUIRED_RULES {
        let Some(rule) = rules
            .iter()
            .find(|candidate| string_value(candidate, "id") == Some(*id))
        else {
            continue;
        };
        for (field, expected) in [
            ("decision", *decision),
            ("requirement", *requirement),
            ("evidence", *evidence),
        ] {
            expect(
                string_value(rule, field) == Some(expected),
                errors,
                &format!("monitoring coverage gap rule {id} has unexpected {field}"),
            );
        }
    }
}

fn catalog_rule_objects(value: Option<&Value>, errors: &mut Vec<String>) -> Vec<Value> {
    let Some(array) = value.and_then(Value::as_array) else {
        errors.push("monitoring coverage gap rules must be array of objects".to_string());
        return Vec::new();
    };
    let mut rules = Vec::new();
    for item in array {
        if item.is_object() {
            rules.push(item.clone());
        } else {
            errors.push("monitoring coverage gap rules must be array of objects".to_string());
        }
    }
    rules
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = csharp_without_comments(program);
    let endpoint = endpoint_block(program, errors);
    let block = endpoint_payload_block(&endpoint, errors);
    if block.is_empty() {
        return;
    }
    expect(
        exact_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static seed source",
    );
    expect(
        exact_string_assignment(&block, "reportMode", "aggregate-gap-report"),
        errors,
        "API must keep aggregate gap report mode",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            exact_assignment(&block, field, "false"),
            errors,
            &format!("API must keep {field} disabled"),
        );
    }
    validate_api_template_baseline(&block, catalog.get("templateBaseline"), errors);
    for (field, variable, required) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_assignment(&block, field, variable),
            errors,
            &format!("API endpoint missing {field} field"),
        );
        let values = csharp_array_values(&uncommented_program, variable, field, errors);
        validate_api_array(field, values.as_deref(), required, errors);
        validate_bound_array_not_reassigned(&uncommented_program, variable, field, errors);
        validate_bound_array_not_mutated(&uncommented_program, variable, field, errors);
    }
    for (field, required) in ENDPOINT_INLINE_ARRAYS {
        let values = endpoint_inline_array_values(&block, field, errors);
        validate_api_array(field, values.as_deref(), required, errors);
    }
    validate_api_rules(&block, catalog, errors);
    validate_endpoint_field_names(&block, errors);
    validate_no_unsafe_true_flags(&block, errors);
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let blocks = extract_endpoint_blocks(&csharp_without_comments(program));
    if blocks.is_empty() {
        errors.push("API missing monitoring coverage gap endpoint".to_string());
        return String::new();
    }
    if blocks.len() != 1 {
        errors.push(format!("API must register exactly one {ENDPOINT} endpoint"));
        return String::new();
    }
    blocks[0].clone()
}

fn extract_endpoint_blocks(program: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    each_mapget_registration(program, |start, open_paren, close_paren| {
        let args = &program[open_paren + 1..close_paren];
        let route_expression = first_top_level_argument(args);
        if static_route_value(&route_expression, Some(program), Some(start), &[]).as_deref()
            != Some(ENDPOINT)
        {
            return;
        }
        let statement_end = find_statement_end(program, close_paren + 1)
            .map(|index| index + 1)
            .unwrap_or(close_paren + 1);
        blocks.push(program[start..statement_end].to_string());
    });
    blocks
}

fn first_top_level_argument(args: &str) -> String {
    split_top_level(args, false)
        .first()
        .map(|value| value.trim().to_string())
        .unwrap_or_default()
}

fn static_route_value(
    expression: &str,
    program: Option<&str>,
    position: Option<usize>,
    seen_variables: &[String],
) -> Option<String> {
    let expression = strip_outer_parentheses(expression.trim());
    if is_plain_identifier(&expression) {
        if let (Some(program), Some(position)) = (program, position) {
            if seen_variables.contains(&expression) {
                return None;
            }
            if let Some(declaration) =
                static_route_variable_declaration(program, &expression, position)
            {
                let mut seen = seen_variables.to_vec();
                seen.push(expression.clone());
                return static_route_value(&declaration, Some(program), Some(position), &seen);
            }
        }
    }
    let parts = split_top_level_plus(&expression);
    if parts.len() == 1 {
        return csharp_string_literal_value(&expression);
    }
    let mut values = Vec::new();
    for part in parts {
        values.push(static_route_value(
            &part,
            program,
            position,
            seen_variables,
        )?);
    }
    Some(values.join(""))
}

fn static_route_variable_declaration(
    program: &str,
    variable: &str,
    position: usize,
) -> Option<String> {
    let mut declarations = Vec::new();
    let mut index = 0usize;
    while let Some(start) = next_code_match(program, variable, index) {
        if start >= position {
            break;
        }
        index = start + variable.len();
        if !identifier_boundary(program, start, start + variable.len()) {
            continue;
        }
        let prefix = &program[..start];
        let prefix_ok = ["var", "string", "const string"].iter().any(|keyword| {
            let trimmed_len = prefix.trim_end().len();
            trimmed_len >= keyword.len()
                && prefix[..trimmed_len].ends_with(keyword)
                && prefix[..trimmed_len - keyword.len()]
                    .chars()
                    .last()
                    .map(|ch| !is_identifier_byte(ch as u8))
                    .unwrap_or(true)
        });
        let cursor = skip_ascii_whitespace(program, start + variable.len());
        if !prefix_ok || program.as_bytes().get(cursor) != Some(&b'=') {
            continue;
        }
        if let Some(statement_end) = find_statement_end(program, cursor + 1) {
            declarations.push(program[cursor + 1..statement_end].trim().to_string());
        }
    }
    (declarations.len() == 1).then(|| declarations.remove(0))
}

fn strip_outer_parentheses(expression: &str) -> String {
    let mut current = expression.trim().to_string();
    loop {
        if !current.starts_with('(') {
            return current;
        }
        let Some(close) = matching_delimiter_index(&current, 0, b'(', b')') else {
            return current;
        };
        if close != current.len() - 1 {
            return current;
        }
        current = current[1..close].trim().to_string();
    }
}

fn split_top_level_plus(expression: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    let mut curly = 0isize;
    let mut paren = 0isize;
    let mut bracket = 0isize;
    while index < expression.len() {
        let byte = expression.as_bytes()[index];
        if byte == b'"' {
            index = csharp_string_end(expression, index).unwrap_or(expression.len());
            continue;
        }
        match byte {
            b'{' => curly += 1,
            b'}' => curly -= 1,
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b'+' if curly == 0 && paren == 0 && bracket == 0 => {
                parts.push(expression[start..index].trim().to_string());
                start = index + 1;
            }
            _ => {}
        }
        index += 1;
    }
    parts.push(expression[start..].trim().to_string());
    parts
}

fn csharp_string_literal_value(expression: &str) -> Option<String> {
    let expression = expression.trim();
    let quote = expression.find('"')?;
    let prefix = &expression[..quote];
    if !prefix.chars().all(|ch| ch == '@' || ch == '$') {
        return None;
    }
    let end = csharp_string_end(expression, quote)?;
    if !expression[end..].trim().is_empty() {
        return None;
    }
    let body = if expression[quote..].starts_with("\"\"\"") {
        let delimiter_len = expression[quote..]
            .bytes()
            .take_while(|byte| *byte == b'"')
            .count();
        &expression[quote + delimiter_len..end - delimiter_len]
    } else {
        &expression[quote + 1..end - 1]
    };
    if prefix.contains('$') && body.contains(['{', '}']) {
        return None;
    }
    if prefix.contains('@') {
        return Some(body.replace("\"\"", "\""));
    }
    Some(csharp_unescape_string(body))
}

fn each_mapget_registration(program: &str, mut callback: impl FnMut(usize, usize, usize)) {
    let mut index = 0usize;
    while let Some(start) = next_app_mapget_match(program, index) {
        let Some(open_relative) = program[start..].find('(') else {
            break;
        };
        let open = start + open_relative;
        let Some(close) = matching_delimiter_index(program, open, b'(', b')') else {
            break;
        };
        callback(start, open, close);
        index = close + 1;
    }
}

fn next_app_mapget_match(program: &str, start: usize) -> Option<usize> {
    let mut index = start;
    while let Some(candidate) = next_code_match(program, "app", index) {
        let mut cursor = candidate + "app".len();
        if !identifier_boundary(program, candidate, candidate + "app".len()) {
            index = candidate + "app".len();
            continue;
        }
        cursor = skip_ascii_whitespace(program, cursor);
        if program.as_bytes().get(cursor) != Some(&b'.') {
            index = candidate + "app".len();
            continue;
        }
        cursor = skip_ascii_whitespace(program, cursor + 1);
        if !program[cursor..].starts_with("MapGet")
            || !identifier_boundary(program, cursor, cursor + "MapGet".len())
        {
            index = candidate + "app".len();
            continue;
        }
        cursor = skip_ascii_whitespace(program, cursor + "MapGet".len());
        if program.as_bytes().get(cursor) == Some(&b'(') {
            return Some(candidate);
        }
        index = candidate + "app".len();
    }
    None
}

fn next_code_match(text: &str, needle: &str, start: usize) -> Option<usize> {
    let mut index = start;
    while index < text.len() {
        if text.as_bytes().get(index) == Some(&b'"') {
            index = csharp_string_end(text, index).unwrap_or(text.len());
            continue;
        }
        if text[index..].starts_with(needle) {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn find_statement_end(text: &str, start: usize) -> Option<usize> {
    let mut index = start;
    let mut curly = 0isize;
    let mut paren = 0isize;
    let mut bracket = 0isize;
    while index < text.len() {
        let byte = text.as_bytes()[index];
        if byte == b'"' {
            index = csharp_string_end(text, index)?;
            continue;
        }
        match byte {
            b'{' => curly += 1,
            b'}' => curly -= 1,
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b';' if curly == 0 && paren == 0 && bracket == 0 => return Some(index),
            _ => {}
        }
        index += 1;
    }
    None
}

fn endpoint_payload_block(endpoint: &str, errors: &mut Vec<String>) -> String {
    let all_json_indexes = results_json_indexes(endpoint, false);
    if all_json_indexes.len() > 1 {
        errors
            .push("API must declare exactly one monitoring coverage gap JSON payload".to_string());
        return String::new();
    }

    let json_indexes = results_json_indexes(endpoint, true);
    if json_indexes.is_empty() {
        if all_json_indexes.is_empty() {
            errors.push("API missing monitoring coverage gap JSON payload".to_string());
        } else {
            errors.push(
                "API monitoring coverage gap JSON payload must use anonymous Results.Json(new { ... })"
                    .to_string(),
            );
        }
        return String::new();
    }
    if json_indexes.len() != 1 {
        errors
            .push("API must declare exactly one monitoring coverage gap JSON payload".to_string());
        return String::new();
    }
    let json_index = json_indexes[0];
    let Some(object_start) = endpoint[json_index..]
        .find('{')
        .map(|index| json_index + index)
    else {
        errors.push("API monitoring coverage gap JSON payload must be a single object".to_string());
        return String::new();
    };
    let Some(object_end) = matching_brace_index(endpoint, object_start) else {
        errors.push("API monitoring coverage gap JSON payload must be a single object".to_string());
        return String::new();
    };
    if endpoint[object_end + 1..].trim() != "));" {
        errors.push(
            "API monitoring coverage gap JSON payload must be static anonymous object with no extra JSON arguments"
                .to_string(),
        );
        return String::new();
    }
    endpoint[object_start..=object_end].to_string()
}

fn results_json_indexes(endpoint: &str, require_anonymous: bool) -> Vec<usize> {
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
        cursor = skip_ascii_whitespace(&masked, cursor + "new".len());
        if require_anonymous && masked.as_bytes().get(cursor) != Some(&b'{') {
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
    let bodies = csharp_array_bodies(program, variable);
    if bodies.len() != 1 {
        errors.push(format!(
            "API {field} array must declare exactly one literal {variable} array"
        ));
        return None;
    }
    Some(csharp_array_literal_values(
        &bodies[0],
        &format!("API {field}"),
        errors,
    ))
}

fn csharp_array_bodies(program: &str, variable: &str) -> Vec<String> {
    let masked = csharp_code_mask(program);
    let mut bodies = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find(variable) {
        let start = offset + relative;
        let end = start + variable.len();
        offset = end;
        if !identifier_boundary(&masked, start, end) {
            continue;
        }
        let declaration = masked[..start].trim_end().ends_with("var");
        if !declaration {
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
        if let Some(close) = matching_brace_index(program, cursor) {
            let semicolon = skip_ascii_whitespace(&masked, close + 1);
            if masked.as_bytes().get(semicolon) == Some(&b';') {
                bodies.push(program[cursor + 1..close].to_string());
            }
        }
    }
    bodies
}

fn validate_api_array<T>(
    field: &str,
    values: Option<&[String]>,
    required_values: &[T],
    errors: &mut Vec<String>,
) where
    T: AsRef<str>,
{
    let Some(values) = values else {
        errors.push(format!("API missing {field} array"));
        return;
    };
    push_missing_unexpected("API", field, values, required_values, errors);
    expect(
        unique(values),
        errors,
        &format!("API {field} values must be unique"),
    );
}

fn validate_api_template_baseline(
    block: &str,
    catalog_baseline: Option<&Value>,
    errors: &mut Vec<String>,
) {
    let texts = top_level_assignment_texts(block, "templateBaseline");
    if texts.is_empty() {
        errors.push("API missing templateBaseline".to_string());
        return;
    }
    if texts.len() != 1 {
        errors.push("API templateBaseline must be declared once".to_string());
        return;
    }
    let Some(rhs) = assignment_rhs(&texts[0], "templateBaseline") else {
        errors.push("API templateBaseline must use a static anonymous object".to_string());
        return;
    };
    let trimmed = rhs.trim();
    if !trimmed.starts_with("new") || !identifier_boundary(trimmed, 0, "new".len()) {
        errors.push("API templateBaseline must use a static anonymous object".to_string());
        return;
    }
    let object_start = skip_ascii_whitespace(trimmed, "new".len());
    if trimmed.as_bytes().get(object_start) != Some(&b'{') {
        errors.push("API templateBaseline must use a static anonymous object".to_string());
        return;
    }
    let Some(object_end) = matching_brace_index(trimmed, object_start) else {
        errors.push("API templateBaseline must be a single static anonymous object".to_string());
        return;
    };
    if trimmed[object_end + 1..].trim() != "," {
        errors.push("API templateBaseline must be a single static anonymous object".to_string());
        return;
    }
    let baseline_block = &trimmed[object_start..=object_end];
    let allowed_fields = ["defaultPosture", "exceptionProfiles", "exceptionEvidence"];
    for field in top_level_assignment_fields(baseline_block) {
        if !allowed_fields.contains(&field.as_str()) {
            errors.push(format!("API templateBaseline has unexpected field {field}"));
        }
    }
    for field in allowed_fields {
        if top_level_assignment_indexes(baseline_block, field).len() != 1 {
            errors.push(format!(
                "API templateBaseline {field} must be declared once"
            ));
        }
    }

    let default_posture = catalog_baseline
        .and_then(|baseline| baseline.get("defaultPosture"))
        .and_then(Value::as_str)
        .unwrap_or(TEMPLATE_DEFAULT_POSTURE);
    let exception_profiles = catalog_baseline
        .and_then(|baseline| baseline.get("exceptionProfiles"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| {
            TEMPLATE_EXCEPTION_PROFILES
                .iter()
                .map(|value| (*value).to_string())
                .collect()
        });
    let exception_evidence = catalog_baseline
        .and_then(|baseline| baseline.get("exceptionEvidence"))
        .and_then(Value::as_str)
        .unwrap_or(TEMPLATE_EXCEPTION_EVIDENCE);

    expect(
        exact_string_assignment_optional_comma(baseline_block, "defaultPosture", default_posture),
        errors,
        "API templateBaseline must require default built-in templates",
    );
    let profile_values = endpoint_inline_array_values(baseline_block, "exceptionProfiles", errors);
    validate_api_array(
        "exceptionProfiles",
        profile_values.as_deref(),
        &exception_profiles,
        errors,
    );
    expect(
        exact_string_assignment_optional_comma(
            baseline_block,
            "exceptionEvidence",
            exception_evidence,
        ),
        errors,
        "API templateBaseline must name Lenovo XCC SNMP exception evidence",
    );
}

fn validate_bound_array_not_reassigned(
    program: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) {
    let masked = csharp_code_mask(program);
    let mut assignments = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find(variable) {
        let start = offset + relative;
        let end = start + variable.len();
        offset = end;
        if !identifier_boundary(&masked, start, end) {
            continue;
        }
        let cursor = skip_ascii_whitespace(&masked, end);
        if masked.as_bytes().get(cursor) == Some(&b'[') {
            continue;
        }
        if is_assignment_operator(&masked, cursor) {
            let declaration = masked[..start].trim_end().ends_with("var");
            assignments.push(declaration);
        }
    }
    if assignments.len() != 1 || assignments.iter().any(|declaration| !*declaration) {
        errors.push(format!(
            "API {field} bound array {variable} must not be reassigned"
        ));
    }
}

fn validate_bound_array_not_mutated(
    program: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) {
    let masked = csharp_code_mask(program);
    let mut mutations = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find(variable) {
        let start = offset + relative;
        let end = start + variable.len();
        offset = end;
        if !identifier_boundary(&masked, start, end) {
            continue;
        }
        let cursor = skip_ascii_whitespace(&masked, end);
        if is_assignment_operator(&masked, cursor) {
            let declaration = masked[..start].trim_end().ends_with("var");
            if !declaration {
                mutations.push(start);
            }
        } else if masked.as_bytes().get(cursor) == Some(&b'[') {
            if let Some(close) = matching_delimiter_index(&masked, cursor, b'[', b']') {
                if is_assignment_operator(&masked, skip_ascii_whitespace(&masked, close + 1)) {
                    mutations.push(start);
                }
            }
        }
    }
    let compact = without_ascii_whitespace(&masked);
    if compact_method_call_on_variable(&compact, variable, "SetValue")
        || compact_method_call_on_variable(&compact, variable, "CopyTo")
        || compact_array_mutation(&compact, variable)
    {
        mutations.push(0);
    }
    if !mutations.is_empty() {
        errors.push(format!(
            "API {field} bound array {variable} must not be mutated"
        ));
    }
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
    let line = &texts[0];
    let Some(rhs) = assignment_rhs(line, field) else {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] literal inline array"
        ));
        return None;
    };
    let trimmed = rhs.trim();
    if !trimmed.ends_with(',') {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] literal inline array"
        ));
        return None;
    }
    let array_text = trimmed[..trimmed.len() - 1].trim();
    if !array_text.starts_with("new[]") {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] literal inline array"
        ));
        return None;
    }
    let cursor = skip_ascii_whitespace(array_text, "new[]".len());
    if array_text.as_bytes().get(cursor) != Some(&b'{') {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] literal inline array"
        ));
        return None;
    }
    let Some(close) = matching_brace_index(array_text, cursor) else {
        errors.push(format!("API {field} array must be a single array"));
        return None;
    };
    if !array_text[close + 1..].trim().is_empty() {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] literal inline array"
        ));
        return None;
    }
    Some(csharp_array_literal_values(
        &array_text[cursor + 1..close],
        &format!("API {field}"),
        errors,
    ))
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let api_rules = direct_api_rule_objects(block, errors);
    let catalog_rules = object_array(catalog.get("rules"), "monitoring coverage gap rule", errors);
    let catalog_rule_ids = catalog_rules
        .iter()
        .filter_map(|rule| string_value(rule, "id"))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let api_rule_ids = api_rules
        .iter()
        .filter_map(|rule| rule.get("id").cloned())
        .collect::<Vec<_>>();
    for id in diff_values(&catalog_rule_ids, &api_rule_ids) {
        errors.push(format!("API missing rules: {id}"));
    }
    for id in diff_values(&api_rule_ids, &catalog_rule_ids) {
        errors.push(format!("API unexpected rules: {id}"));
    }
    expect(unique(&api_rule_ids), errors, "API rule IDs must be unique");
    validate_rule_detail_uniqueness_map(&api_rules, "monitoring coverage gap API", errors);
    for catalog_rule in catalog_rules {
        let Some(id) = string_value(&catalog_rule, "id") else {
            continue;
        };
        let Some(api_rule) = api_rules
            .iter()
            .find(|candidate| candidate.get("id").map(String::as_str) == Some(id))
        else {
            continue;
        };
        expect(
            api_rule.get("decision").map(String::as_str) == string_value(&catalog_rule, "decision"),
            errors,
            &format!("API rule {id} has wrong decision"),
        );
        expect(
            api_rule.get("requirement").map(String::as_str)
                == string_value(&catalog_rule, "requirement"),
            errors,
            &format!("API missing rule requirement {id}"),
        );
        expect(
            api_rule.get("evidence").map(String::as_str) == string_value(&catalog_rule, "evidence"),
            errors,
            &format!("API rule {id} has wrong evidence"),
        );
    }
}

fn direct_api_rule_objects(block: &str, errors: &mut Vec<String>) -> Vec<BTreeMap<String, String>> {
    let Some(array_block) = endpoint_array_block(block, "rules", errors) else {
        return Vec::new();
    };
    let mut rules = Vec::new();
    for object_block in direct_rule_object_blocks(&array_block, errors) {
        let fields = top_level_assignment_fields(&object_block);
        let mut rule = BTreeMap::new();
        for field in RULE_FIELDS {
            if let Some(value) = rule_string_field(&object_block, field) {
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
    let Some(array_start) = assignment.find('{') else {
        errors.push(format!("API {field} array must be a single array"));
        return None;
    };
    let Some(array_end) = matching_brace_index(assignment, array_start) else {
        errors.push(format!("API {field} array must be a single array"));
        return None;
    };
    if assignment[..array_start]
        .split_whitespace()
        .collect::<String>()
        != format!("{field}=new[]")
    {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] assignment"
        ));
        return None;
    }
    if !assignment[array_end + 1..]
        .trim()
        .trim_end_matches(',')
        .trim()
        .is_empty()
    {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] assignment"
        ));
    }
    Some(assignment[array_start..=array_end].to_string())
}

fn direct_rule_object_blocks(array_block: &str, errors: &mut Vec<String>) -> Vec<String> {
    let mut object_blocks = Vec::new();
    for member in top_level_array_members(array_block) {
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
        let Some(object_end) = matching_brace_index(text, cursor) else {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        };
        if !text[object_end + 1..].trim().is_empty() {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        }
        object_blocks.push(text[cursor..=object_end].to_string());
    }
    object_blocks
}

fn rule_string_field(object_block: &str, field: &str) -> Option<String> {
    let values = top_level_assignment_texts(object_block, field)
        .into_iter()
        .filter_map(|text| exact_string_assignment_value_optional_comma(&text, field))
        .collect::<Vec<_>>();
    if values.len() == 1 {
        Some(values[0].clone())
    } else {
        None
    }
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    for field in top_level_assignment_fields(block) {
        if ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            continue;
        }
        if prohibited_provider_key(&field, false) {
            errors.push(format!(
                "API endpoint has prohibited monitoring coverage gap field {field}"
            ));
        } else {
            errors.push(format!(
                "API endpoint has unexpected monitoring coverage gap field {field}"
            ));
        }
    }
    for field in assignment_fields(block) {
        if prohibited_provider_key(&field, true) {
            errors.push(format!(
                "API endpoint has prohibited monitoring coverage gap field {field}"
            ));
        }
    }
    for field in top_level_projection_fields(block) {
        if prohibited_provider_key(&field, false) {
            errors.push(format!(
                "API endpoint has prohibited monitoring coverage gap field {field}"
            ));
        } else {
            errors.push(format!(
                "API endpoint has unexpected monitoring coverage gap projection {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let masked = csharp_code_mask(block);
    for field in assignment_fields(block) {
        let texts = top_level_assignment_texts(&masked, &field);
        let top_level_true = texts
            .iter()
            .any(|text| line_matches_assignment(text, &field, "true", true));
        let any_true = top_level_true
            || assignment_texts_any_depth(block, &field)
                .iter()
                .any(|text| line_matches_assignment(text, &field, "true", true));
        if any_true && unsafe_true_field(&field) {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn unsafe_true_field(field: &str) -> bool {
    field.ends_with("Allowed")
        || field.ends_with("Enabled")
        || UNSAFE_TRUE_FIELD_TOKENS
            .iter()
            .any(|token| normalized_key(field).contains(token))
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
        "API README missing monitoring coverage gap endpoint",
    );
    expect(
        catalog_readme.contains("monitoring-coverage-gap-contract.yaml"),
        errors,
        "catalog README missing monitoring coverage gap catalog",
    );
    expect(
        doc_readme.contains("monitoring-coverage-gap.md"),
        errors,
        "workflow README missing monitoring coverage gap doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "monitoring coverage gap doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "monitoring coverage gap doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live remediation."),
        errors,
        "monitoring coverage gap doc must prohibit live remediation",
    );
    expect(
        doc.contains("No Zabbix mutation."),
        errors,
        "monitoring coverage gap doc must prohibit Zabbix mutation",
    );
    expect(
        doc.contains("aggregate coverage summaries only"),
        errors,
        "monitoring coverage gap doc must require aggregate summaries",
    );
    expect(
        doc.contains("default built-in templates"),
        errors,
        "monitoring coverage gap doc must require default built-in templates",
    );
    expect(
        doc.contains("Lenovo XCC SNMP"),
        errors,
        "monitoring coverage gap doc must document Lenovo XCC SNMP exception",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_provider_key(key, true) {
                    errors.push(format!("{path}.{key} contains prohibited provider field"));
                }
                scan_prohibited_value(child, &format!("{path}.{key}"), errors);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                scan_prohibited_value(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => scan_prohibited_text(text, path, errors),
        _ => {}
    }
}

fn scan_prohibited_text(text: &str, path: &str, errors: &mut Vec<String>) {
    if text.contains('\n') {
        for (index, line) in text.lines().enumerate() {
            scan_prohibited_text(line, &format!("{path}:{}", index + 1), errors);
        }
        return;
    }
    if let Some(field) = prohibited_text_key(text, path) {
        errors.push(format!("{path} contains prohibited provider field {field}"));
    }
    if prohibited_value(text) {
        errors.push(format!("{path} contains prohibited value"));
    }
}

fn prohibited_text_key(text: &str, path: &str) -> Option<String> {
    for identifier in colon_identifiers(text) {
        if prohibited_provider_text_identifier(&identifier) {
            return Some(identifier);
        }
    }
    let scan_text = mask_text_string_literals(text);
    for identifier in colon_identifiers(&scan_text) {
        if prohibited_provider_text_identifier(&identifier) {
            return Some(identifier);
        }
    }
    for (identifier, value) in assignment_identifiers(&scan_text) {
        if prohibited_provider_text_identifier(&identifier)
            && prohibited_assignment_text(text, path, &value)
        {
            return Some(identifier);
        }
    }
    if let Some(identifier) = prohibited_exact_text_token(&scan_text) {
        return Some(identifier);
    }
    None
}

fn colon_identifiers(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut identifiers = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if (index == 0 || matches!(bytes[index - 1], b'{' | b',' | b' ' | b'\t'))
            && (bytes[index] == b'"' || bytes[index] == b'\'' || is_identifier_start(bytes[index]))
        {
            let mut start = index;
            if bytes[start] == b'"' || bytes[start] == b'\'' {
                start += 1;
            }
            if start < bytes.len() && is_identifier_start(bytes[start]) {
                let mut end = start + 1;
                while end < bytes.len() && (is_identifier_byte(bytes[end]) || bytes[end] == b'-') {
                    end += 1;
                }
                let mut cursor = end;
                if cursor < bytes.len() && (bytes[cursor] == b'"' || bytes[cursor] == b'\'') {
                    cursor += 1;
                }
                cursor = skip_ascii_whitespace(text, cursor);
                if bytes.get(cursor) == Some(&b':') {
                    identifiers.push(text[start..end].to_string());
                    index = cursor + 1;
                    continue;
                }
            }
        }
        index += 1;
    }
    identifiers
}

fn assignment_identifiers(text: &str) -> Vec<(String, String)> {
    let bytes = text.as_bytes();
    let mut pairs = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if (index == 0 || matches!(bytes[index - 1], b'{' | b',' | b' ' | b'\t' | b'/'))
            && (bytes[index] == b'"' || bytes[index] == b'\'' || is_identifier_start(bytes[index]))
        {
            let mut start = index;
            if bytes[start] == b'"' || bytes[start] == b'\'' {
                start += 1;
            }
            if start < bytes.len() && is_identifier_start(bytes[start]) {
                let mut end = start + 1;
                while end < bytes.len() && (is_identifier_byte(bytes[end]) || bytes[end] == b'-') {
                    end += 1;
                }
                let mut cursor = end;
                if cursor < bytes.len() && (bytes[cursor] == b'"' || bytes[cursor] == b'\'') {
                    cursor += 1;
                }
                cursor = skip_ascii_whitespace(text, cursor);
                if bytes.get(cursor) == Some(&b'=') {
                    let value_start = skip_ascii_whitespace(text, cursor + 1);
                    let mut value_end = value_start;
                    while value_end < bytes.len()
                        && bytes[value_end] != b','
                        && bytes[value_end] != b'\r'
                        && bytes[value_end] != b'\n'
                    {
                        value_end += 1;
                    }
                    pairs.push((
                        text[start..end].to_string(),
                        text[value_start..value_end].to_string(),
                    ));
                    index = value_end;
                    continue;
                }
            }
        }
        index += 1;
    }
    pairs
}

fn prohibited_provider_text_identifier(identifier: &str) -> bool {
    let normalized = normalized_key(identifier);
    PROHIBITED_PROVIDER_KEYS.contains(&normalized.as_str())
        || HIGH_RISK_TEXT_TOKENS.contains(&normalized.as_str())
}

fn prohibited_exact_text_token(text: &str) -> Option<String> {
    text_identifiers(text).into_iter().find(|identifier| {
        bare_provider_identifier_token(identifier, text)
            && prohibited_provider_text_identifier(identifier)
    })
}

fn bare_provider_identifier_token(identifier: &str, text: &str) -> bool {
    let normalized = normalized_key(identifier);
    HIGH_RISK_TEXT_TOKENS.contains(&normalized.as_str())
        || bare_prohibited_identifier_list(text)
        || identifier.contains('_')
        || identifier.contains('-')
        || identifier.chars().skip(1).any(|ch| ch.is_ascii_uppercase())
}

fn bare_prohibited_identifier_list(text: &str) -> bool {
    let identifiers = text_identifiers(text);
    !identifiers.is_empty()
        && identifiers.iter().all(|identifier| {
            PROHIBITED_PROVIDER_KEYS.contains(&normalized_key(identifier).as_str())
        })
}

fn text_identifiers(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut identifiers = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if is_identifier_start(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len() && (is_identifier_byte(bytes[index]) || bytes[index] == b'-')
            {
                index += 1;
            }
            identifiers.push(text[start..index].to_string());
        } else {
            index += 1;
        }
    }
    identifiers
}

fn mask_text_string_literals(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut index = 0usize;
    while index < text.len() {
        if text.as_bytes().get(index) == Some(&b'"') {
            let end = csharp_string_end(text, index).unwrap_or(text.len());
            while index < end {
                output.push(if text.as_bytes()[index] == b'\n' {
                    '\n'
                } else {
                    ' '
                });
                index += 1;
            }
        } else {
            output.push(text.as_bytes()[index] as char);
            index += 1;
        }
    }
    output
}

fn prohibited_assignment_text(text: &str, path: &str, value: &str) -> bool {
    let trimmed = text.trim_start();
    if trimmed.starts_with("//")
        || trimmed.starts_with('#')
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
    {
        return true;
    }
    if !path.contains(".cs") {
        return true;
    }
    !safe_static_assignment_value(value)
}

fn safe_static_assignment_value(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed == "false"
        || trimmed == "true"
        || keyword_call_or_value(trimmed, "new")
        || keyword_call_or_value(trimmed, "Array.Empty")
        || trimmed
            .as_bytes()
            .first()
            .is_some_and(|byte| is_identifier_start(*byte))
            && trimmed.as_bytes()[1..]
                .iter()
                .all(|byte| is_identifier_byte(*byte))
}

fn keyword_call_or_value(text: &str, keyword: &str) -> bool {
    let Some(rest) = text.strip_prefix(keyword) else {
        return false;
    };
    rest.is_empty()
        || rest.as_bytes().first().is_some_and(|byte| {
            byte.is_ascii_whitespace() || [b'(', b'<', b'[', b'{'].contains(byte)
        })
}

fn prohibited_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("akia")
        || (lower.contains("-----begin ") && lower.contains("private key-----"))
        || lower.contains("://")
        || contains_private_ip(value)
        || contains_uuid(value)
        || token_assignment_like(&lower)
        || contains_domain_like(value)
        || contains_windows_domain(value)
        || contains_email(value)
}

fn contains_private_ip(value: &str) -> bool {
    for part in ascii_words(value, ".") {
        let octets = part.split('.').collect::<Vec<_>>();
        if octets.len() != 4 {
            continue;
        }
        let parsed = octets
            .iter()
            .map(|octet| octet.parse::<u8>())
            .collect::<Result<Vec<_>, _>>();
        let Ok(parsed) = parsed else {
            continue;
        };
        if parsed[0] == 10
            || (parsed[0] == 192 && parsed[1] == 168)
            || (parsed[0] == 172 && (16..=31).contains(&parsed[1]))
        {
            return true;
        }
    }
    false
}

fn contains_uuid(value: &str) -> bool {
    for part in ascii_words(value, "-") {
        let pieces = part.split('-').collect::<Vec<_>>();
        if pieces.len() == 5
            && [8, 4, 4, 4, 12]
                .iter()
                .zip(pieces.iter())
                .all(|(len, piece)| {
                    piece.len() == *len && piece.chars().all(|ch| ch.is_ascii_hexdigit())
                })
        {
            return true;
        }
    }
    false
}

fn token_assignment_like(lower: &str) -> bool {
    [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
    ]
    .iter()
    .any(|key| {
        lower.find(key).is_some_and(|index| {
            let rest = lower[index + key.len()..].trim_start();
            (rest.starts_with(':') || rest.starts_with('=')) && !rest[1..].trim_start().is_empty()
        })
    })
}

fn contains_domain_like(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut start = None;
    for (index, byte) in bytes.iter().enumerate() {
        let allowed =
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'.' || *byte == b'-';
        if allowed {
            start.get_or_insert(index);
        } else if let Some(token_start) = start.take() {
            if domain_token(&value[token_start..index]) {
                return true;
            }
        }
    }
    if let Some(token_start) = start {
        return domain_token(&value[token_start..]);
    }
    false
}

fn domain_token(token: &str) -> bool {
    let parts = token.split('.').collect::<Vec<_>>();
    parts.len() >= 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        })
}

fn contains_windows_domain(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let pieces = token.split('\\').collect::<Vec<_>>();
        pieces.len() == 2
            && pieces.iter().all(|piece| {
                !piece.is_empty()
                    && piece
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || "._-".contains(ch))
            })
    })
}

fn contains_email(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let Some((local, domain)) = token.split_once('@') else {
            return false;
        };
        !local.is_empty()
            && local
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || "._%+-".contains(ch))
            && domain_token(
                &domain
                    .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
                    .to_ascii_lowercase(),
            )
    })
}

fn csharp_array_literal_values(body: &str, label: &str, errors: &mut Vec<String>) -> Vec<String> {
    let mut values = Vec::new();
    for member in split_array_members(body) {
        let text = member.trim();
        if text.is_empty() {
            continue;
        }
        if let Some(value) = exact_string_literal(text) {
            values.push(value);
        } else {
            errors.push(format!(
                "{label} array must use literal string entries only"
            ));
        }
    }
    values
}

fn split_array_members(body: &str) -> Vec<&str> {
    split_top_level(body, true)
}

fn top_level_array_members(array_block: &str) -> Vec<&str> {
    let body = array_block.trim();
    let body = if body.starts_with('{') && body.ends_with('}') {
        &body[1..body.len() - 1]
    } else {
        body
    };
    split_top_level(body, false)
}

fn split_top_level(body: &str, commas_inside_braces_are_top_level: bool) -> Vec<&str> {
    let bytes = body.as_bytes();
    let mut members = Vec::new();
    let mut start = 0;
    let mut index = 0;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        if in_string {
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == b'"' {
                in_string = false;
            }
        } else if bytes[index] == b'"' {
            index = csharp_string_end(body, index).unwrap_or(body.len());
            continue;
        } else {
            match bytes[index] {
                b'(' => paren_depth += 1,
                b')' => paren_depth = paren_depth.saturating_sub(1),
                b'[' => bracket_depth += 1,
                b']' => bracket_depth = bracket_depth.saturating_sub(1),
                b'{' => brace_depth += 1,
                b'}' => brace_depth = brace_depth.saturating_sub(1),
                b',' if paren_depth == 0
                    && bracket_depth == 0
                    && (brace_depth == 0 || commas_inside_braces_are_top_level) =>
                {
                    members.push(&body[start..index]);
                    start = index + 1;
                }
                _ => {}
            }
        }
        index += 1;
    }
    members.push(&body[start..]);
    members
}

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let texts = top_level_assignment_texts(block, field);
    texts.len() == 1 && line_matches_assignment(&texts[0], field, value, true)
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let texts = top_level_assignment_texts(block, field);
    texts.len() == 1
        && exact_string_assignment_value(&texts[0], field, true).as_deref() == Some(value)
}

fn exact_string_assignment_optional_comma(block: &str, field: &str, value: &str) -> bool {
    let texts = top_level_assignment_texts(block, field);
    texts.len() == 1
        && exact_string_assignment_value_optional_comma(&texts[0], field).as_deref() == Some(value)
}

fn line_matches_assignment(line: &str, field: &str, value: &str, comma: bool) -> bool {
    let Some(rhs) = assignment_rhs(line, field) else {
        return false;
    };
    let expected = if comma {
        format!("{value},")
    } else {
        value.to_string()
    };
    rhs.trim() == expected
}

fn exact_string_assignment_value_optional_comma(line: &str, field: &str) -> Option<String> {
    exact_string_assignment_value(line, field, true)
        .or_else(|| exact_string_assignment_value(line, field, false))
}

fn exact_string_assignment_value(line: &str, field: &str, comma: bool) -> Option<String> {
    let rhs = assignment_rhs(line, field)?;
    let trimmed = rhs.trim();
    let value_part = if comma {
        trimmed.strip_suffix(',')?.trim()
    } else {
        trimmed
    };
    exact_string_literal(value_part)
}

fn exact_string_literal(text: &str) -> Option<String> {
    if text.starts_with('"')
        && text.ends_with('"')
        && text.len() >= 2
        && single_string_literal(text)
    {
        Some(text[1..text.len() - 1].to_string())
    } else {
        None
    }
}

fn assignment_rhs<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    let trimmed = line.trim_start();
    let trimmed = trimmed.strip_prefix('@').unwrap_or(trimmed);
    let rest = trimmed.strip_prefix(field)?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?;
    Some(rest)
}

fn top_level_assignment_texts(block: &str, field: &str) -> Vec<String> {
    top_level_assignment_indexes(block, field)
        .into_iter()
        .map(|index| {
            block[index..assignment_end_index(block, index)]
                .trim()
                .to_string()
        })
        .collect()
}

fn assignment_texts_any_depth(block: &str, field: &str) -> Vec<String> {
    assignment_indexes_any_depth(block, field)
        .into_iter()
        .map(|index| {
            block[index..assignment_end_index(block, index)]
                .trim()
                .to_string()
        })
        .collect()
}

fn assignment_indexes_any_depth(block: &str, field: &str) -> Vec<usize> {
    let masked = csharp_code_mask(block);
    let mut indexes = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find(field) {
        let start = offset + relative;
        let end = start + field.len();
        offset = end;
        let candidate_start = if start > 0 && masked.as_bytes()[start - 1] == b'@' {
            start - 1
        } else {
            start
        };
        if identifier_boundary(&masked, start, end)
            && skip_ascii_whitespace(&masked, end) < masked.len()
            && masked.as_bytes()[skip_ascii_whitespace(&masked, end)] == b'='
        {
            indexes.push(candidate_start);
        }
    }
    indexes
}

fn top_level_assignment_indexes(block: &str, field: &str) -> Vec<usize> {
    assignment_indexes_any_depth(block, field)
        .into_iter()
        .filter(|index| brace_depth_at(block, *index) == 1)
        .collect()
}

fn assignment_end_index(block: &str, start_index: usize) -> usize {
    let bytes = block.as_bytes();
    let mut index = start_index;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        if in_string {
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == b'"' {
                in_string = false;
            }
        } else if bytes[index] == b'"' {
            in_string = true;
        } else if bytes[index] == b',' && brace_depth_at(block, index) == 1 {
            return index + 1;
        } else if bytes[index] == b'}' && brace_depth_at(block, index) <= 1 {
            return index;
        }
        index += 1;
    }
    block.len()
}

fn top_level_assignment_fields(block: &str) -> Vec<String> {
    assignment_fields_at_depth(block, 1)
}

fn top_level_projection_fields(block: &str) -> Vec<String> {
    top_level_object_members(block)
        .into_iter()
        .filter_map(|member| {
            let text = member.trim();
            if text.contains('=') {
                return None;
            }
            let text = text.strip_prefix('@').unwrap_or(text);
            if is_plain_identifier(text) {
                Some(text.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn top_level_object_members(block: &str) -> Vec<&str> {
    let body = block.trim();
    let body = if body.starts_with('{') && body.ends_with('}') {
        &body[1..body.len() - 1]
    } else {
        body
    };
    split_top_level(body, false)
}

fn assignment_fields(block: &str) -> Vec<String> {
    let masked = csharp_code_mask(block);
    let bytes = masked.as_bytes();
    let mut fields = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if is_identifier_start(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len() && is_identifier_byte(bytes[index]) {
                index += 1;
            }
            let end = index;
            let cursor = skip_ascii_whitespace(&masked, end);
            if cursor < bytes.len() && bytes[cursor] == b'=' {
                fields.push(masked[start..end].to_string());
            }
        } else {
            index += 1;
        }
    }
    fields
}

fn assignment_fields_at_depth(block: &str, depth: usize) -> Vec<String> {
    let masked = csharp_code_mask(block);
    let bytes = masked.as_bytes();
    let mut fields = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if is_identifier_start(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len() && is_identifier_byte(bytes[index]) {
                index += 1;
            }
            let end = index;
            let cursor = skip_ascii_whitespace(&masked, end);
            if cursor < bytes.len()
                && bytes[cursor] == b'='
                && brace_depth_at(&masked, start) == depth
            {
                fields.push(masked[start..end].to_string());
            }
        } else {
            index += 1;
        }
    }
    fields
}

fn csharp_without_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            let end = csharp_string_end(text, index).unwrap_or(text.len());
            output.push_str(&text[index..end]);
            index = end;
        } else if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'/' {
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(' ');
                index += 1;
            }
        } else if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'*' {
            output.push(' ');
            output.push(' ');
            index += 2;
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
            if index + 1 < bytes.len() {
                output.push(' ');
                output.push(' ');
                index += 2;
            }
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    output
}

fn csharp_code_mask(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'/' {
            output.push_str("  ");
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(' ');
                index += 1;
            }
        } else if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'*' {
            output.push_str("  ");
            index += 2;
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
            if index + 1 < bytes.len() {
                output.push_str("  ");
                index += 2;
            }
        } else if bytes[index] == b'"' {
            let end = csharp_string_end(text, index).unwrap_or(text.len());
            while index < end {
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

fn matching_brace_index(source: &str, start_index: usize) -> Option<usize> {
    matching_delimiter_index(source, start_index, b'{', b'}')
}

fn matching_delimiter_index(
    source: &str,
    start_index: usize,
    open: u8,
    close: u8,
) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut index = start_index;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        if in_string {
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == b'"' {
                in_string = false;
            }
        } else if bytes[index] == b'"' {
            index = csharp_string_end(source, index).unwrap_or(source.len());
            continue;
        } else if bytes[index] == open {
            depth += 1;
        } else if bytes[index] == close {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(index);
            }
        }
        index += 1;
    }
    None
}

fn brace_depth_at(source: &str, target_index: usize) -> usize {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < target_index && index < bytes.len() {
        if in_string {
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == b'"' {
                in_string = false;
            }
        } else if bytes[index] == b'"' {
            in_string = true;
        } else if bytes[index] == b'{' {
            depth += 1;
        } else if bytes[index] == b'}' {
            depth = depth.saturating_sub(1);
        }
        index += 1;
    }
    depth
}

fn without_ascii_whitespace(text: &str) -> String {
    text.chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect()
}

fn compact_method_call_on_variable(compact: &str, variable: &str, method: &str) -> bool {
    let pattern = format!("{variable}.{method}(");
    let mut offset = 0;
    while let Some(relative) = compact[offset..].find(&pattern) {
        let start = offset + relative;
        let end = start + variable.len();
        offset = start + pattern.len();
        if identifier_boundary(compact, start, end) {
            return true;
        }
    }
    false
}

fn compact_array_mutation(compact: &str, variable: &str) -> bool {
    for prefix in ["Array.", "System.Array.", "global::System.Array."] {
        for method in [
            "Fill",
            "Clear",
            "Reverse",
            "Sort",
            "Resize",
            "Copy",
            "ConstrainedCopy",
        ] {
            let pattern = format!("{prefix}{method}(");
            let mut offset = 0;
            while let Some(relative) = compact[offset..].find(&pattern) {
                let start = offset + relative;
                let open = start + pattern.len() - 1;
                offset = open + 1;
                let Some(close) = matching_delimiter_index(compact, open, b'(', b')') else {
                    continue;
                };
                let args = split_top_level_args(&compact[open + 1..close]);
                let mutates = match method {
                    "Fill" | "Clear" | "Reverse" | "Sort" => args
                        .first()
                        .is_some_and(|arg| argument_matches_variable(arg, variable)),
                    "Resize" => args.first().is_some_and(|arg| {
                        argument_matches_variable(arg, variable)
                            || argument_matches_variable(
                                arg.strip_prefix("ref").unwrap_or(arg),
                                variable,
                            )
                    }),
                    "Copy" => {
                        args.get(1)
                            .is_some_and(|arg| argument_matches_variable(arg, variable))
                            || args
                                .get(2)
                                .is_some_and(|arg| argument_matches_variable(arg, variable))
                    }
                    "ConstrainedCopy" => args
                        .get(2)
                        .is_some_and(|arg| argument_matches_variable(arg, variable)),
                    _ => false,
                };
                if mutates {
                    return true;
                }
            }
        }
    }
    false
}

fn argument_matches_variable(argument: &str, variable: &str) -> bool {
    normalize_argument(argument) == variable
}

fn normalize_argument(argument: &str) -> String {
    let mut text = argument.trim();
    for prefix in ["ref", "in", "out"] {
        if let Some(rest) = text.strip_prefix(prefix) {
            if rest
                .as_bytes()
                .first()
                .is_some_and(|byte| byte.is_ascii_whitespace())
            {
                text = rest.trim();
                break;
            }
        }
    }

    loop {
        let trimmed = text.trim();
        if trimmed.starts_with('(') && trimmed.ends_with(')') {
            if let Some(close) = matching_delimiter_index(trimmed, 0, b'(', b')') {
                if close == trimmed.len() - 1 {
                    text = &trimmed[1..trimmed.len() - 1];
                    continue;
                }
            }
        }
        return trimmed.to_string();
    }
}

fn split_top_level_args(body: &str) -> Vec<&str> {
    split_top_level(body, false)
        .into_iter()
        .map(str::trim)
        .collect()
}

fn validate_rule_detail_uniqueness_value(rules: &[Value], label: &str, errors: &mut Vec<String>) {
    let details = rules
        .iter()
        .map(|rule| {
            RULE_FIELDS[1..]
                .iter()
                .map(|field| string_value(rule, field).unwrap_or_default().to_string())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    expect(
        unique(&details),
        errors,
        &format!("{label} rule details must be unique"),
    );
}

fn validate_rule_detail_uniqueness_map(
    rules: &[BTreeMap<String, String>],
    label: &str,
    errors: &mut Vec<String>,
) {
    let details = rules
        .iter()
        .map(|rule| {
            ["decision", "requirement", "evidence"]
                .iter()
                .map(|field| rule.get(*field).cloned().unwrap_or_default())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    expect(
        unique(&details),
        errors,
        &format!("{label} rule details must be unique"),
    );
}

fn object_array(value: Option<&Value>, label: &str, errors: &mut Vec<String>) -> Vec<Value> {
    let Some(array) = value.and_then(Value::as_array) else {
        errors.push(format!("{label}s must be non-empty array"));
        return Vec::new();
    };
    let mut objects = Vec::new();
    for item in array {
        if item.is_object() {
            objects.push(item.clone());
        } else {
            errors.push(format!("{label} must be object"));
        }
    }
    objects
}

fn push_missing_unexpected<T>(
    prefix: &str,
    field: &str,
    values: &[String],
    required_values: &[T],
    errors: &mut Vec<String>,
) where
    T: AsRef<str>,
{
    let missing = diff_values(
        &required_values
            .iter()
            .map(|value| value.as_ref().to_string())
            .collect::<Vec<_>>(),
        values,
    );
    let unexpected = diff_values(
        values,
        &required_values
            .iter()
            .map(|value| value.as_ref().to_string())
            .collect::<Vec<_>>(),
    );
    let label = if prefix.is_empty() {
        field.to_string()
    } else {
        format!("{prefix} {field}")
    };
    if !missing.is_empty() {
        errors.push(format!("{label} missing values: {}", missing.join(", ")));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "{label} unexpected values: {}",
            unexpected.join(", ")
        ));
    }
}

fn push_rule_missing_unexpected(
    prefix: &str,
    values: &[String],
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let missing = diff_values(
        &required_values
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>(),
        values,
    );
    let unexpected = diff_values(
        values,
        &required_values
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>(),
    );
    if !missing.is_empty() {
        errors.push(format!("{prefix} missing rules: {}", missing.join(", ")));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "{prefix} unexpected rules: {}",
            unexpected.join(", ")
        ));
    }
}

fn diff_values(left: &[String], right: &[String]) -> Vec<String> {
    let right_set = right.iter().map(String::as_str).collect::<BTreeSet<_>>();
    left.iter()
        .map(String::as_str)
        .filter(|value| !right_set.contains(*value))
        .map(str::to_string)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn string_value<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn bool_value(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}

fn normalized_key(key: &str) -> String {
    key.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn prohibited_provider_key(key: &str, honor_safe_catalog_keys: bool) -> bool {
    if honor_safe_catalog_keys && SAFE_CATALOG_KEYS.contains(&key) {
        return false;
    }
    let normalized = normalized_key(key);
    PROHIBITED_PROVIDER_KEYS.contains(&normalized.as_str())
        || PROHIBITED_PROVIDER_KEY_TOKENS
            .iter()
            .any(|token| normalized.contains(token))
}

fn unique<T: Ord + Clone>(values: &[T]) -> bool {
    values.iter().cloned().collect::<BTreeSet<_>>().len() == values.len()
}

fn expect(condition: bool, errors: &mut Vec<String>, message: &str) {
    if !condition {
        errors.push(message.to_string());
    }
}

fn line_start_indexes(text: &str) -> Vec<usize> {
    let mut indexes = vec![0];
    for (index, byte) in text.as_bytes().iter().enumerate() {
        if *byte == b'\n' && index + 1 < text.len() {
            indexes.push(index + 1);
        }
    }
    indexes
}

fn skip_horizontal_whitespace(source: &str, mut index: usize) -> usize {
    while source
        .as_bytes()
        .get(index)
        .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
    {
        index += 1;
    }
    index
}

fn skip_ascii_whitespace(source: &str, mut index: usize) -> usize {
    while source
        .as_bytes()
        .get(index)
        .is_some_and(u8::is_ascii_whitespace)
    {
        index += 1;
    }
    index
}

fn is_assignment_operator(source: &str, index: usize) -> bool {
    let rest = &source[index..];
    if rest.starts_with("==") || rest.starts_with("=>") {
        return false;
    }
    rest.starts_with('=')
        || [
            "??=", "<<=", ">>=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
        ]
        .iter()
        .any(|operator| rest.starts_with(operator))
}

fn identifier_boundary(source: &str, start: usize, end: usize) -> bool {
    let bytes = source.as_bytes();
    (start == 0 || !is_identifier_byte(bytes[start - 1]))
        && (end >= bytes.len() || !is_identifier_byte(bytes[end]))
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn single_string_literal(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'"' {
        return false;
    }
    let mut index = 1;
    let mut escaped = false;
    while index < bytes.len() {
        if escaped {
            escaped = false;
        } else if bytes[index] == b'\\' {
            escaped = true;
        } else if bytes[index] == b'"' {
            return index == bytes.len() - 1;
        }
        index += 1;
    }
    false
}

fn csharp_string_end(text: &str, start: usize) -> Option<usize> {
    if text.as_bytes().get(start) != Some(&b'"') {
        return None;
    }
    let quote_count = text[start..]
        .bytes()
        .take_while(|byte| *byte == b'"')
        .count();
    if quote_count >= 3 {
        let delimiter = "\"".repeat(quote_count);
        return text[start + quote_count..]
            .find(&delimiter)
            .map(|relative| start + quote_count + relative + quote_count)
            .or(Some(text.len()));
    }
    let verbatim = start > 0 && text.as_bytes().get(start - 1) == Some(&b'@');
    let mut index = start + 1;
    while index < text.len() {
        let byte = text.as_bytes()[index];
        let next = text.as_bytes().get(index + 1).copied();
        if verbatim && byte == b'"' && next == Some(b'"') {
            index += 2;
            continue;
        }
        if byte == b'"' {
            return Some(index + 1);
        }
        if !verbatim && byte == b'\\' && next.is_some() {
            index += 2;
        } else {
            index += 1;
        }
    }
    Some(text.len())
}

fn csharp_unescape_string(body: &str) -> String {
    let mut value = String::new();
    let mut chars = body.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            value.push(ch);
            continue;
        }
        match chars.next() {
            Some('"') => value.push('"'),
            Some('\\') => value.push('\\'),
            Some('/') => value.push('/'),
            Some('b') => value.push('\u{0008}'),
            Some('f') => value.push('\u{000c}'),
            Some('n') => value.push('\n'),
            Some('r') => value.push('\r'),
            Some('t') => value.push('\t'),
            Some(other) => value.push(other),
            None => value.push('\\'),
        }
    }
    value
}

fn is_plain_identifier(value: &str) -> bool {
    let value = value.trim();
    let Some(first) = value.as_bytes().first() else {
        return false;
    };
    is_identifier_start(*first)
        && value.as_bytes()[1..]
            .iter()
            .all(|byte| is_identifier_byte(*byte))
}

fn ascii_words<'a>(value: &'a str, extra: &str) -> Vec<&'a str> {
    value
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || extra.contains(ch)))
        .filter(|part| !part.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monitoring_coverage_gap_endpoint_blocks_ignore_comment_and_raw_string_decoys() {
        let program = format!(
            r###"
// app.MapGet("{endpoint}", () => Results.Json(new {{ source = "static-seed" }}));
var decoy = """
app.MapGet("{endpoint}", () => Results.Json(new {{ source = "static-seed" }}));
""";
app.MapGet("{endpoint}", () => Results.Json(new {{ source = "static-seed" }}));
"###,
            endpoint = ENDPOINT
        );

        assert_eq!(
            extract_endpoint_blocks(&csharp_without_comments(&program)).len(),
            1
        );
    }

    #[test]
    fn monitoring_coverage_gap_route_parser_resolves_static_variable_parts() {
        let program = r#"
const string prefix = "/api/observe/";
var suffix = "monitoring-coverage-gap-contract";
var route = prefix + suffix;
var decoy = "app.MapGet(\"/api/observe/monitoring-coverage-gap-contract\", () => Results.Json(new { source = \"static-seed\" }));";
app.MapGet(route, () => Results.Json(new { source = "static-seed" }));
"#;

        let blocks = extract_endpoint_blocks(&csharp_without_comments(program));

        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].contains("app.MapGet(route"));
    }

    #[test]
    fn monitoring_coverage_gap_bound_array_helpers_reject_reassignment_and_mutation() {
        let reassigned_program = r#"
var monitoringCoverageGapSignals = new[] { "missing-zabbix-host" };
monitoringCoverageGapSignals = BuildProviderSignals();
"#;
        let mutated_program = r#"
var monitoringCoverageGapSignals = new[] { "missing-zabbix-host" };
monitoringCoverageGapSignals[0] = "hostId";
Array.Copy(sourceSignals, monitoringCoverageGapSignals, 1);
"#;
        let mut reassignment_errors = Vec::new();
        let mut mutation_errors = Vec::new();

        validate_bound_array_not_reassigned(
            reassigned_program,
            "monitoringCoverageGapSignals",
            "gapSignals",
            &mut reassignment_errors,
        );
        validate_bound_array_not_mutated(
            mutated_program,
            "monitoringCoverageGapSignals",
            "gapSignals",
            &mut mutation_errors,
        );

        assert!(reassignment_errors.iter().any(|error| {
            error.contains("gapSignals") && error.contains("must not be reassigned")
        }));
        assert!(mutation_errors
            .iter()
            .any(|error| error.contains("gapSignals") && error.contains("must not be mutated")));
    }

    #[test]
    fn monitoring_coverage_gap_prohibited_scan_flags_identifier_literals() {
        let mut errors = Vec::new();

        scan_prohibited_text(
            "endpointName = synthetic-placeholder;",
            "synthetic-doc",
            &mut errors,
        );
        scan_prohibited_text(r#"{ "hostId": "safe" }"#, "quoted-key-doc", &mut errors);

        assert!(errors.iter().any(|error| error.contains("endpointName")));
        assert!(errors.iter().any(|error| error.contains("hostId")));
    }
}
