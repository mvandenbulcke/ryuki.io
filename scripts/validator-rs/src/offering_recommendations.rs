use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/offering-recommendations-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/offering-recommendations.md";
const ENDPOINT: &str = "/api/catalog/recommendations-contract";
const REQUIRED_RECOMMENDED_OFFERINGS: &[&str] = &[
    "windows-server-deployment",
    "request-preflight",
    "patch-wave-planning",
    "controlled-restore-request",
    "zabbix-onboarding",
    "cmdb-import",
    "operator-runbook-launch",
    "platform-health-dashboard",
];
const REQUIRED_DIMENSIONS: &[&str] = &[
    "role",
    "application-profile",
    "site",
    "lifecycle-category",
    "risk-context",
    "freshness-state",
];
const REQUIRED_SIGNALS: &[&str] = &[
    "role-fit",
    "site-readiness",
    "service-lifecycle-fit",
    "dry-run-required",
    "approval-route-known",
    "evidence-profile-known",
];
const REQUIRED_VIEWS: &[&str] = &[
    "role-defaults",
    "application-profile-defaults",
    "site-defaults",
    "lifecycle-category-defaults",
    "safe-next-offerings",
];
const REQUIRED_GUARDS: &[&str] = &[
    "catalog-source-reviewed",
    "role-scope-summarized",
    "application-profile-summarized",
    "site-scope-summarized",
    "approval-route-known",
    "dry-run-required",
    "evidence-redacted",
    "live-personalization-blocked",
];
const SAFE_TRUE_FIELDS: &[&str] = &[
    "recommendationsReadOnly",
    "roleDefaultsReadOnly",
    "siteDefaultsReadOnly",
    "evidenceReferencesReadOnly",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "livePersonalizationAllowed",
    "liveCatalogQueryAllowed",
    "liveRequestCreationAllowed",
    "workflowMutationAllowed",
    "providerCallsAllowed",
    "identityLookupAllowed",
    "rawUserDataAllowed",
    "rawApplicationDataAllowed",
    "rawSiteDataAllowed",
    "rawRequestPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "rawRecipientDataAllowed",
    "credentialValuesAllowed",
    "tokenValuesAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "principalIdentifiersAllowed",
    "privateNetworkValuesAllowed",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "catalog-recommendation-live-personalization-disabled",
    "catalog-live-query-disabled",
    "request-creation-disabled",
    "workflow-mutation-disabled",
    "provider-calls-disabled",
    "identity-lookup-disabled",
    "raw-user-data-disabled",
    "raw-application-data-disabled",
    "raw-site-data-disabled",
    "raw-request-payloads-disabled",
    "raw-provider-payloads-disabled",
    "raw-recipient-data-disabled",
    "credential-values-disabled",
    "token-values-disabled",
    "tenant-identifiers-disabled",
    "object-identifiers-disabled",
    "principal-identifiers-disabled",
    "private-network-values-disabled",
    "role-scope-missing",
    "application-profile-missing",
    "site-scope-missing",
    "recommendation-signal-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Recommendation summary",
    "Role fit summary",
    "Application profile summary",
    "Site fit summary",
    "Evidence references",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "recommendationMode",
    "recommendedOfferingIds",
    "recommendationDimensions",
    "recommendationSignals",
    "recommendationViews",
    "requiredGuards",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "recommendationsReadOnly",
    "roleDefaultsReadOnly",
    "siteDefaultsReadOnly",
    "evidenceReferencesReadOnly",
    "livePersonalizationAllowed",
    "liveCatalogQueryAllowed",
    "liveRequestCreationAllowed",
    "workflowMutationAllowed",
    "providerCallsAllowed",
    "identityLookupAllowed",
    "rawUserDataAllowed",
    "rawApplicationDataAllowed",
    "rawSiteDataAllowed",
    "rawRequestPayloadsAllowed",
    "rawProviderPayloadsAllowed",
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
    ("recommendedOfferingIds", "offeringRecommendationIds"),
    (
        "recommendationDimensions",
        "offeringRecommendationDimensions",
    ),
    ("recommendationSignals", "offeringRecommendationSignals"),
    ("recommendationViews", "offeringRecommendationViews"),
    ("requiredGuards", "offeringRecommendationRequiredGuards"),
    ("blockedReasons", "offeringRecommendationBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredEvidence"];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "recommendationMode",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
    "recommendationsReadOnly",
    "roleDefaultsReadOnly",
    "siteDefaultsReadOnly",
    "evidenceReferencesReadOnly",
    "livePersonalizationAllowed",
    "liveCatalogQueryAllowed",
    "liveRequestCreationAllowed",
    "workflowMutationAllowed",
    "providerCallsAllowed",
    "identityLookupAllowed",
    "rawUserDataAllowed",
    "rawApplicationDataAllowed",
    "rawSiteDataAllowed",
    "rawRequestPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "rawRecipientDataAllowed",
    "credentialValuesAllowed",
    "tokenValuesAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "principalIdentifiersAllowed",
    "privateNetworkValuesAllowed",
    "recommendedOfferingIds",
    "recommendationDimensions",
    "recommendationSignals",
    "recommendationViews",
    "requiredGuards",
    "blockedReasons",
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

const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "recommendations-read-only",
        decision: "block",
        requirement: "Offering recommendations are static summaries and must not perform live personalization, query live catalogs, create requests, call providers, or mutate workflows.",
        evidence: "Recommendation summary",
    },
    RuleDetail {
        id: "catalog-source-alignment-required",
        decision: "block",
        requirement: "Recommended offering IDs must stay aligned to the static offering catalog and preserve dry-run, approval, and evidence expectations.",
        evidence: "Recommendation summary",
    },
    RuleDetail {
        id: "role-app-site-summary-required",
        decision: "block",
        requirement: "Role, application profile, site, lifecycle category, risk context, freshness state, approval route, and evidence profile must be safe summaries before recommendations are shown.",
        evidence: "Role fit summary",
    },
    RuleDetail {
        id: "raw-recommendation-data-not-exposed",
        decision: "block",
        requirement: "Offering recommendation evidence must not expose raw user data, raw application data, raw site data, raw request payloads, raw provider payloads, raw recipient data, credential values, token values, tenant identifiers, object identifiers, principal identifiers, private network values, live endpoints, or URLs.",
        evidence: "Evidence references",
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

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload).map_err(|error| {
        format!("invalid offering recommendations contract context JSON: {error}")
    })?;
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
    validate_no_prohibited_values(&docs_scope, "offering-recommendations", &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let payload: Value = serde_json::from_str(input).map_err(|error| {
        format!("invalid offering recommendations contract catalog JSON: {error}")
    })?;
    let mut errors = Vec::new();
    validate_catalog_value(&payload, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input).map_err(|error| {
        format!("invalid offering recommendations contract program JSON: {error}")
    })?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid offering recommendations contract docs JSON: {error}"))?;
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
        format!("invalid offering recommendations contract prohibited JSON: {error}")
    })?;
    let mut errors = Vec::new();
    validate_no_prohibited_values(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    validate_catalog_keys(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "offering recommendations contract version must be 1",
    );
    expect(
        catalog.get("status").and_then(Value::as_str) == Some("draft"),
        errors,
        "offering recommendations contract status must be draft",
    );
    expect(
        catalog.get("source").and_then(Value::as_str) == Some("static-seed"),
        errors,
        "offering recommendations contract source must be static-seed",
    );
    expect(
        catalog.get("recommendationMode").and_then(Value::as_str)
            == Some("static-offering-recommendations"),
        errors,
        "offering recommendations mode must be static-offering-recommendations",
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            catalog.get(*field).and_then(Value::as_bool) == Some(true),
            errors,
            format!("offering recommendations {field} must be true"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            catalog.get(*field).and_then(Value::as_bool) == Some(false),
            errors,
            format!("offering recommendations {field} must be disabled"),
        );
    }
    validate_required_array(
        catalog,
        "recommendedOfferingIds",
        REQUIRED_RECOMMENDED_OFFERINGS,
        false,
        errors,
    );
    validate_required_array(
        catalog,
        "recommendationDimensions",
        REQUIRED_DIMENSIONS,
        false,
        errors,
    );
    validate_required_array(
        catalog,
        "recommendationSignals",
        REQUIRED_SIGNALS,
        false,
        errors,
    );
    validate_required_array(
        catalog,
        "recommendationViews",
        REQUIRED_VIEWS,
        false,
        errors,
    );
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, false, errors);
    validate_required_array(
        catalog,
        "blockedReasons",
        REQUIRED_BLOCKED_REASONS,
        false,
        errors,
    );
    validate_required_array(
        catalog,
        "requiredEvidence",
        REQUIRED_EVIDENCE,
        false,
        errors,
    );
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
            "offering recommendations unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required_values: &[&str],
    exact_order: bool,
    errors: &mut Vec<String>,
) {
    let required: Vec<String> = required_values
        .iter()
        .map(|value| value.to_string())
        .collect();
    validate_required_array_strings(catalog, field, &required, exact_order, errors);
}

fn validate_required_array_strings(
    catalog: &Value,
    field: &str,
    required_values: &[String],
    exact_order: bool,
    errors: &mut Vec<String>,
) {
    if let Some(array) = catalog.get(field).and_then(Value::as_array) {
        if array.iter().any(|value| !value.is_string()) {
            errors.push(format!("{field} must contain only strings"));
        }
    } else if catalog.get(field).is_some() {
        errors.push(format!("{field} must be an array"));
    }
    let values = string_array_like(catalog, field);
    expect(
        !values.is_empty(),
        errors,
        format!("{field} must be non-empty array"),
    );
    let missing = missing_values(required_values, &values);
    let extra = extra_values(&values, required_values);
    expect(
        missing.is_empty(),
        errors,
        format!("{field} missing values: {}", missing.join(", ")),
    );
    expect(
        extra.is_empty(),
        errors,
        format!("{field} unexpected values: {}", extra.join(", ")),
    );
    let unique: HashSet<&String> = values.iter().collect();
    expect(
        unique.len() == values.len(),
        errors,
        format!("{field} values must be unique"),
    );
    if exact_order {
        expect(
            values == required_values,
            errors,
            format!("{field} must preserve canonical order"),
        );
    }
    for value in values {
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "{field} contains prohibited offering recommendations value {value}"
            ));
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let Some(rules) = catalog.get("rules").and_then(Value::as_array) else {
        errors.push("offering recommendations rules must be an array of hashes".to_string());
        return;
    };
    if !rules.iter().all(Value::is_object) {
        errors.push("offering recommendations rules must be an array of hashes".to_string());
        return;
    }

    let rule_ids: Vec<String> = rules
        .iter()
        .filter_map(|rule| rule.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let required_ids: Vec<String> = REQUIRED_RULES
        .iter()
        .map(|rule| rule.id.to_string())
        .collect();
    let missing = missing_values(&required_ids, &rule_ids);
    let extra = extra_values(&rule_ids, &required_ids);
    expect(
        missing.is_empty(),
        errors,
        format!(
            "offering recommendations missing rules: {}",
            missing.join(", ")
        ),
    );
    expect(
        extra.is_empty(),
        errors,
        format!(
            "offering recommendations unexpected rules: {}",
            extra.join(", ")
        ),
    );
    let unique: HashSet<&String> = rule_ids.iter().collect();
    expect(
        unique.len() == rule_ids.len(),
        errors,
        "offering recommendations rule IDs must be unique",
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
    let unique_details: HashSet<&Vec<String>> = rule_details.iter().collect();
    expect(
        unique_details.len() == rule_details.len(),
        errors,
        "offering recommendations rule details must be unique",
    );
    for rule in rules {
        let keys: Vec<String> = rule
            .as_object()
            .map(|map| map.keys().cloned().collect())
            .unwrap_or_default();
        let unexpected: Vec<String> = keys
            .iter()
            .filter(|key| !RULE_KEYS.contains(&key.as_str()))
            .cloned()
            .collect();
        let missing_keys: Vec<String> = RULE_KEYS
            .iter()
            .filter(|key| !keys.iter().any(|actual| actual == **key))
            .map(|key| key.to_string())
            .collect();
        let id = rule
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("(missing id)");
        if !unexpected.is_empty() {
            errors.push(format!(
                "offering recommendations rule {id} unexpected rule keys: {}",
                unexpected.join(", ")
            ));
        }
        if !missing_keys.is_empty() {
            errors.push(format!(
                "offering recommendations rule {id} missing rule keys: {}",
                missing_keys.join(", ")
            ));
        }
    }
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
                    "offering recommendations rule {} {field} must match",
                    expected_rule.id
                ),
            );
        }
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = strip_csharp_comments(program);
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
        "recommendationMode",
        "static-offering-recommendations",
        errors,
        "API must keep static-offering-recommendations mode",
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
    }
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            csharp_array_values(&uncommented_program, variable)
                == Some(string_array_like(catalog, field)),
            errors,
            format!("API {field} must match catalog"),
        );
    }
    for field in ENDPOINT_INLINE_ARRAYS {
        expect(
            endpoint_inline_array_values(&block, field) == Some(string_array_like(catalog, field)),
            errors,
            format!("API {field} must match catalog"),
        );
    }
    validate_api_rules(&block, catalog, errors);
    validate_endpoint_field_names(&block, errors);
    validate_no_unsafe_true_flags(&block, errors);
    validate_no_prohibited_values(&Value::String(block), PROGRAM_PATH, errors);
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let Some(catalog_rules) = catalog.get("rules").and_then(Value::as_array) else {
        errors.push("offering recommendations rules must be an array of hashes".to_string());
        return;
    };
    if !catalog_rules.iter().all(Value::is_object) {
        errors.push("offering recommendations rules must be an array of hashes".to_string());
        return;
    }
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
    for id in missing_values(&catalog_rule_ids, &api_rule_ids) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in extra_values(&api_rule_ids, &catalog_rule_ids) {
        errors.push(format!("API has unexpected API rule {id}"));
    }
    let unique: HashSet<&String> = api_rule_ids.iter().collect();
    expect(
        unique.len() == api_rule_ids.len(),
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
    let unique_api_details: HashSet<&Vec<String>> = api_rule_details.iter().collect();
    expect(
        unique_api_details.len() == api_rule_details.len(),
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
        "API README must document offering recommendations endpoint",
    );
    expect(
        catalog_readme.contains("offering-recommendations-contract.yaml"),
        errors,
        "catalog README missing offering recommendations catalog",
    );
    expect(
        doc_readme.contains("offering-recommendations.md"),
        errors,
        "workflow README missing offering recommendations doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "offering recommendations doc missing endpoint",
    );
    expect(
        doc.contains("No live personalization"),
        errors,
        "offering recommendations doc must prohibit live personalization",
    );
    expect(
        doc.contains("No live catalog queries"),
        errors,
        "offering recommendations doc must prohibit live catalog queries",
    );
    expect(
        doc.contains("No live request creation"),
        errors,
        "offering recommendations doc must prohibit live request creation",
    );
    expect(
        doc.contains("No identity lookup"),
        errors,
        "offering recommendations doc must prohibit identity lookup",
    );
    expect(
        doc.contains("raw user data"),
        errors,
        "offering recommendations doc must prohibit raw user data",
    );
    expect(
        doc.contains("raw application data"),
        errors,
        "offering recommendations doc must prohibit raw application data",
    );
    expect(
        doc.contains("raw site data"),
        errors,
        "offering recommendations doc must prohibit raw site data",
    );
    expect(
        doc.contains("raw recipient data"),
        errors,
        "offering recommendations doc must prohibit raw recipient data",
    );
    expect(
        doc.contains("static offering recommendation summaries only"),
        errors,
        "offering recommendations doc must require static summaries",
    );
}

fn endpoint_response_body(program: &str, errors: &mut Vec<String>) -> String {
    let start_indexes = endpoint_start_indexes(program);
    if start_indexes.is_empty() {
        errors.push(format!("API missing endpoint {ENDPOINT}"));
        return String::new();
    }
    if start_indexes.len() != 1 {
        errors.push(format!(
            "API endpoint {ENDPOINT} must have exactly one active route"
        ));
        return String::new();
    }
    let start_index = start_indexes[0];
    let masked = mask_csharp_string_literals(program);
    let open_index = start_index + "app.MapGet".len();
    let Some(close_index) = matching_paren_index(&masked, open_index) else {
        errors.push(format!("API endpoint {ENDPOINT} block is incomplete"));
        return String::new();
    };
    let call = &program[start_index..=close_index];
    let masked_call = &masked[start_index..=close_index];
    if !validate_results_json_shape(masked_call, errors) {
        return String::new();
    }
    let marker_index = response_marker_indexes(masked_call, "Results.Json(new")[0];
    let Some(open_relative) = masked_call[marker_index..].find('{') else {
        errors.push(format!(
            "API endpoint {ENDPOINT} must return object initializer"
        ));
        return String::new();
    };
    let open_index = marker_index + open_relative;
    let Some(close_index) = matching_brace_index(call, open_index) else {
        errors.push(format!("API endpoint {ENDPOINT} block is incomplete"));
        return String::new();
    };
    call[open_index + 1..close_index].to_string()
}

fn endpoint_start_indexes(program: &str) -> Vec<usize> {
    let masked = mask_csharp_string_literals(program);
    let mut indexes = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find("app.MapGet(") {
        let index = offset + relative;
        let route_start = index + "app.MapGet(".len();
        if brace_depth_at(&masked, index) == 0
            && parse_csharp_string_literal_at(program, route_start)
                .is_some_and(|(route, _)| route == ENDPOINT)
        {
            indexes.push(index);
        }
        offset = index + "app.MapGet(".len();
    }
    indexes
}

fn validate_results_json_shape(masked_call: &str, errors: &mut Vec<String>) -> bool {
    let all_markers = response_marker_indexes(masked_call, "Results.Json(");
    let object_markers = response_marker_indexes(masked_call, "Results.Json(new");
    if object_markers.is_empty() {
        errors.push(format!(
            "API endpoint {ENDPOINT} must return Results.Json object"
        ));
        return false;
    }
    if all_markers.len() != 1
        || object_markers.len() != 1
        || all_markers[0] != object_markers[0]
        || !response_marker_is_unconditional(masked_call, object_markers[0])
    {
        errors.push(format!(
            "API endpoint {ENDPOINT} must return one unconditional Results.Json object"
        ));
        return false;
    }
    let marker_index = object_markers[0];
    let Some(open_relative) = masked_call[marker_index..].find('{') else {
        errors.push(format!(
            "API endpoint {ENDPOINT} must return object initializer"
        ));
        return false;
    };
    let open_index = marker_index + open_relative;
    let Some(close_index) = matching_brace_index(masked_call, open_index) else {
        errors.push(format!("API endpoint {ENDPOINT} block is incomplete"));
        return false;
    };
    if !results_json_object_argument_is_exact(masked_call, marker_index, close_index) {
        errors.push(format!(
            "API endpoint {ENDPOINT} must return object initializer"
        ));
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
    let assignments = assignment_records_for_field(block, field);
    if assignments.len() != 1 {
        errors.push(format!(
            "API endpoint {field} must have exactly one assignment"
        ));
        return;
    }
    expect(assignments[0].value == expected, errors, message);
}

fn endpoint_rules_body(block: &str, errors: &mut Vec<String>) -> Option<String> {
    let assignments = assignment_records_for_field(block, "rules");
    if assignments.len() != 1 {
        errors.push("API endpoint rules must have exactly one assignment".to_string());
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
    let mut malformed = false;
    for element in elements {
        let trimmed = element.trim();
        let Some(new_index) = trimmed.find("new") else {
            malformed = true;
            continue;
        };
        if new_index != 0 {
            malformed = true;
            continue;
        }
        let Some(open_index) = next_non_whitespace_index(trimmed, "new".len())
            .filter(|index| trimmed.as_bytes().get(*index) == Some(&b'{'))
        else {
            malformed = true;
            continue;
        };
        let Some(close_index) = matching_brace_index(trimmed, open_index) else {
            malformed = true;
            continue;
        };
        if !trimmed[close_index + 1..].trim().is_empty() {
            malformed = true;
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
            malformed = true;
        }
    }
    if malformed {
        errors.push("API endpoint rules array contains malformed rule hash".to_string());
    }
    rules
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    let assignments = assignment_records_for_field(block, field);
    if assignments.len() != 1 || assignments[0].value != "new[]" {
        return None;
    }
    let open_index = next_non_whitespace_index(block, assignments[0].end)?;
    if block.as_bytes().get(open_index) != Some(&b'{') {
        return None;
    }
    let close_index = matching_brace_index(block, open_index)?;
    if !block[close_index + 1..].trim_start().starts_with(',') {
        return None;
    }
    csharp_array_literal_values(&block[open_index + 1..close_index])
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    for field in endpoint_assignment_fields(block) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has unexpected offering recommendations field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited offering recommendations field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for field in endpoint_assignment_fields(block) {
        if !exact_assignment(block, &field, "true") || SAFE_TRUE_FIELDS.contains(&field.as_str()) {
            continue;
        }
        let lower = field.to_ascii_lowercase();
        if [
            "provider",
            "workflow",
            "live",
            "raw",
            "credential",
            "tenant",
            "object",
            "private",
            "submission",
            "approval",
        ]
        .iter()
        .any(|term| lower.contains(term))
        {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
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
            ',' if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 => return index,
            _ => {}
        }
    }
    masked.len()
}

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let assignments = assignment_records_for_field(block, field);
    assignments.len() == 1 && assignments[0].value == value
}

fn endpoint_assignment_fields(block: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let masked = mask_csharp_string_literals(block);
    let mut index = 0;
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

fn inline_object_string_fields(block: &str) -> Vec<(String, Value)> {
    let mut fields = Vec::new();
    let masked = mask_csharp_string_literals(block);
    let mut index = 0;
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

fn string_array_like(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn missing_values(required_values: &[String], values: &[String]) -> Vec<String> {
    required_values
        .iter()
        .filter(|required| !values.contains(*required))
        .cloned()
        .collect()
}

fn extra_values(values: &[String], required_values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter(|value| !required_values.contains(*value))
        .cloned()
        .collect()
}

fn validate_no_prohibited_values(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_field(key) {
                    errors.push(format!(
                        "{path}.{key} contains prohibited offering recommendations field"
                    ));
                }
                validate_no_prohibited_values(child, &format!("{path}.{key}"), errors);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_no_prohibited_values(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => {
            if whole_file_text(path, text) {
                if prohibited_value(text) {
                    errors.push(format!("{path} contains prohibited value"));
                }
                if prohibited_provider_identifier_value(text) {
                    errors.push(format!(
                        "{path} contains prohibited provider-identifying value"
                    ));
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
            if prohibited_field(text) {
                errors.push(format!(
                    "{path} contains prohibited offering recommendations field {text}"
                ));
            }
        }
        _ => {}
    }
}

fn prohibited_value(text: &str) -> bool {
    text.contains("://")
        || contains_private_key_like(text)
        || contains_aws_access_key_like(text)
        || contains_private_ip(text)
        || contains_uuid_like(text)
        || contains_email_like(text)
        || contains_secret_assignment(text)
}

fn contains_email_like(text: &str) -> bool {
    text.split_whitespace().any(|candidate| {
        let candidate = candidate.trim_matches(|ch: char| {
            !(ch.is_ascii_alphanumeric() || matches!(ch, '@' | '.' | '_' | '%' | '+' | '-'))
        });
        let candidate = candidate.trim_matches('.');
        let Some((local, domain)) = candidate.split_once('@') else {
            return false;
        };
        !local.is_empty()
            && domain.contains('.')
            && domain.rsplit_once('.').is_some_and(|(_, tld)| {
                tld.len() >= 2 && tld.chars().all(|ch| ch.is_ascii_alphabetic())
            })
    })
}

fn prohibited_provider_identifier_value(text: &str) -> bool {
    contains_sha40_like(text) || contains_provider_serial_like(text)
}

fn contains_sha40_like(text: &str) -> bool {
    text.split(|ch: char| !ch.is_ascii_hexdigit())
        .any(|term| term.len() >= 40 && term.chars().all(|ch| ch.is_ascii_hexdigit()))
}

fn contains_provider_serial_like(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'))
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
            let payload: String = rest
                .chars()
                .take_while(|ch| ch.is_ascii_alphanumeric())
                .collect();
            payload.len() >= 6
                && payload.chars().all(|ch| ch.is_ascii_alphanumeric())
                && payload.chars().any(|ch| ch.is_ascii_digit())
        })
}

fn contains_private_key_like(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    upper.contains("-----BEGIN ") && upper.contains("PRIVATE KEY-----")
}

fn contains_aws_access_key_like(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    upper.as_bytes().windows(20).any(|window| {
        window.starts_with(b"AKIA") && window[4..].iter().all(|byte| byte.is_ascii_alphanumeric())
    })
}

fn contains_private_ip(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
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

fn contains_uuid_like(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_hexdigit() || ch == '-'))
        .any(|candidate| {
            let parts: Vec<&str> = candidate.split('-').collect();
            parts.windows(5).any(|window| {
                [8, 4, 4, 4, 12]
                    .iter()
                    .zip(window.iter())
                    .all(|(len, part)| {
                        part.len() == *len && part.chars().all(|ch| ch.is_ascii_hexdigit())
                    })
            })
        })
}

fn contains_secret_assignment(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    for term in [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
        "token",
    ] {
        let mut offset = 0;
        while let Some(relative) = lower[offset..].find(term) {
            let index = offset + relative + term.len();
            let tail = lower[index..].trim_start();
            if tail.starts_with(':') || tail.starts_with('=') {
                return true;
            }
            offset = index;
        }
    }
    false
}

fn safe_text_value(value: &str) -> bool {
    let safe_values = safe_text_values();
    safe_values.contains(&value)
}

fn safe_text_values() -> Vec<&'static str> {
    let mut values = Vec::new();
    values.extend(REQUIRED_RECOMMENDED_OFFERINGS);
    values.extend(REQUIRED_DIMENSIONS);
    values.extend(REQUIRED_SIGNALS);
    values.extend(REQUIRED_VIEWS);
    values.extend(REQUIRED_GUARDS);
    values.extend(REQUIRED_DISABLED_FIELDS);
    values.extend(SAFE_TRUE_FIELDS);
    values.extend(REQUIRED_BLOCKED_REASONS);
    values.extend(REQUIRED_EVIDENCE);
    values.extend(REQUIRED_RULES.iter().map(|rule| rule.id));
    values.extend(
        REQUIRED_RULES
            .iter()
            .flat_map(|rule| [rule.decision, rule.requirement, rule.evidence]),
    );
    values.extend(REQUIRED_CATALOG_KEYS);
    values.extend(
        ENDPOINT_ARRAY_BINDINGS
            .iter()
            .map(|(_, variable)| *variable),
    );
    values.extend([
        "draft",
        "static-seed",
        "static-offering-recommendations",
        "block",
        "true",
        "false",
    ]);
    values
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
    PROHIBITED_FIELD_ALIASES.contains(&normalized.as_str())
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
            "rawuser",
            "userdata",
            "rawapplication",
            "applicationdata",
            "rawsite",
            "sitedata",
            "rawrequest",
            "requestpayload",
            "rawrecipient",
            "recipientemail",
            "recipientaddress",
            "recipientdata",
            "endpointurl",
            "url",
            "token",
            "bearer",
            "secret",
            "livepersonalization",
            "identitylookup",
            "providercall",
            "workflowmutation",
            "requestcreation",
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
    ) || has_any(&tokens, &["url", "uri", "endpoint"])
        || (has_any(&tokens, &["private", "ip"])
            && has_any(&tokens, &["address", "value", "network"]))
        || (has_any(
            &tokens,
            &["tenant", "object", "provider", "principal", "user"],
        ) && has_any(
            &tokens,
            &[
                "id",
                "identifier",
                "payload",
                "row",
                "rows",
                "value",
                "email",
                "data",
            ],
        ))
        || (tokens.iter().any(|token| token == "raw")
            && has_any(
                &tokens,
                &[
                    "request",
                    "user",
                    "application",
                    "site",
                    "provider",
                    "recipient",
                    "payload",
                    "log",
                    "content",
                    "row",
                    "rows",
                    "data",
                    "submission",
                    "submissions",
                ],
            ))
        || tokens.iter().any(|token| token == "recipient")
}

fn field_tokens(value: &str) -> Vec<String> {
    let mut expanded = String::new();
    let mut previous: Option<char> = None;
    for ch in value.chars() {
        if let Some(prev) = previous {
            if (prev.is_ascii_lowercase() || prev.is_ascii_digit()) && ch.is_ascii_uppercase() {
                expanded.push(' ');
            }
        }
        expanded.push(ch.to_ascii_lowercase());
        previous = Some(ch);
    }
    expanded
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect()
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
        .flat_map(char::to_lowercase)
        .collect()
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
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
    let mut escaped = false;
    while index < source.len() {
        let ch = source[index..].chars().next()?;
        if escaped {
            value.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some((value, index + 1));
        } else {
            value.push(ch);
        }
        index += ch.len_utf8();
    }
    None
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
    let mut result = String::with_capacity(source.len());
    let mut index = 0;
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
    let mut count = 0;
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

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn catalog() -> Value {
        json!({
            "version": 1,
            "status": "draft",
            "source": "static-seed",
            "recommendationMode": "static-offering-recommendations",
            "recommendationsReadOnly": true,
            "roleDefaultsReadOnly": true,
            "siteDefaultsReadOnly": true,
            "evidenceReferencesReadOnly": true,
            "livePersonalizationAllowed": false,
            "liveCatalogQueryAllowed": false,
            "liveRequestCreationAllowed": false,
            "workflowMutationAllowed": false,
            "providerCallsAllowed": false,
            "identityLookupAllowed": false,
            "rawUserDataAllowed": false,
            "rawApplicationDataAllowed": false,
            "rawSiteDataAllowed": false,
            "rawRequestPayloadsAllowed": false,
            "rawProviderPayloadsAllowed": false,
            "rawRecipientDataAllowed": false,
            "credentialValuesAllowed": false,
            "tokenValuesAllowed": false,
            "tenantIdentifiersAllowed": false,
            "objectIdentifiersAllowed": false,
            "principalIdentifiersAllowed": false,
            "privateNetworkValuesAllowed": false,
            "recommendedOfferingIds": REQUIRED_RECOMMENDED_OFFERINGS,
            "recommendationDimensions": REQUIRED_DIMENSIONS,
            "recommendationSignals": REQUIRED_SIGNALS,
            "recommendationViews": REQUIRED_VIEWS,
            "requiredGuards": REQUIRED_GUARDS,
            "blockedReasons": REQUIRED_BLOCKED_REASONS,
            "requiredEvidence": REQUIRED_EVIDENCE,
            "rules": REQUIRED_RULES.iter().map(|rule| json!({
                "id": rule.id,
                "decision": rule.decision,
                "requirement": rule.requirement,
                "evidence": rule.evidence,
            })).collect::<Vec<_>>(),
        })
    }

    fn api_rules_block() -> String {
        format!(
            "rules = new[] {{\n{}\n}},",
            REQUIRED_RULES
                .iter()
                .map(|rule| format!(
                    "        new {{ id = \"{}\", decision = \"{}\", requirement = \"{}\", evidence = \"{}\" }}",
                    csharp_string(rule.id),
                    csharp_string(rule.decision),
                    csharp_string(rule.requirement),
                    csharp_string(rule.evidence),
                ))
                .collect::<Vec<_>>()
                .join(",\n")
        )
    }

    fn csharp_string(value: &str) -> String {
        value.replace('\\', "\\\\").replace('"', "\\\"")
    }

    #[test]
    fn offering_recommendations_duplicate_catalog_rule_ids_and_details_are_rejected() {
        let mut duplicate_id_catalog = catalog();
        let rules = duplicate_id_catalog
            .get_mut("rules")
            .and_then(Value::as_array_mut)
            .expect("rules array");
        rules[1]["id"] = rules[0]["id"].clone();
        let mut errors = Vec::new();

        validate_catalog_value(&duplicate_id_catalog, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("rule IDs") && error.contains("unique")));

        let mut duplicate_detail_catalog = catalog();
        let rules = duplicate_detail_catalog
            .get_mut("rules")
            .and_then(Value::as_array_mut)
            .expect("rules array");
        let first = rules[0].clone();
        rules[1]["decision"] = first["decision"].clone();
        rules[1]["requirement"] = first["requirement"].clone();
        rules[1]["evidence"] = first["evidence"].clone();
        errors.clear();

        validate_catalog_value(&duplicate_detail_catalog, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("rule details") && error.contains("unique")));
    }

    #[test]
    fn offering_recommendations_duplicate_api_rule_ids_and_details_are_rejected() {
        let catalog = catalog();
        let mut duplicate_id_block = api_rules_block().replace(
            "id = \"raw-recommendation-data-not-exposed\"",
            "id = \"recommendations-read-only\"",
        );
        let mut errors = Vec::new();

        validate_api_rules(&duplicate_id_block, &catalog, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("API rule IDs") && error.contains("unique")));

        duplicate_id_block = api_rules_block().replace(
            "requirement = \"Recommended offering IDs must stay aligned to the static offering catalog and preserve dry-run, approval, and evidence expectations.\", evidence = \"Recommendation summary\"",
            "requirement = \"Offering recommendations are static summaries and must not perform live personalization, query live catalogs, create requests, call providers, or mutate workflows.\", evidence = \"Recommendation summary\"",
        );
        errors.clear();

        validate_api_rules(&duplicate_id_block, &catalog, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("API rule details") && error.contains("unique")));
    }

    #[test]
    fn offering_recommendations_commented_valid_assignment_decoys_are_ignored() {
        let block = strip_csharp_comments(
            r#"
{
    // recommendationMode = "static-offering-recommendations",
    recommendationMode = "live-offering-recommendations",
}
"#,
        );
        let mut errors = Vec::new();

        validate_exact_string_assignment(
            &block,
            "recommendationMode",
            "static-offering-recommendations",
            &mut errors,
            "API must keep static-offering-recommendations mode",
        );

        assert!(errors
            .iter()
            .any(|error| error.contains("static-offering-recommendations")));
    }

    #[test]
    fn offering_recommendations_string_endpoint_decoys_do_not_count_as_routes() {
        let program = format!(
            r#"
var decoy = """
app.MapGet("{ENDPOINT}", () => Results.Json(new
{{
    source = "static-seed",
    recommendationMode = "static-offering-recommendations",
}}));
""";

app.MapGet("{ENDPOINT}", () => Results.Json(new
{{
    source = "static-seed",
    recommendationMode = "live-offering-recommendations",
}}));
"#
        );

        let routes = endpoint_start_indexes(&strip_csharp_comments(&program));

        assert_eq!(routes.len(), 1);
    }

    #[test]
    fn offering_recommendations_array_decoys_and_suffix_bypasses_are_rejected() {
        let valid = r#"
const string recommendationArrayDecoy = """
var offeringRecommendationIds = new[] { "unsafe-offering" };
""";
if (false)
{
    var offeringRecommendationIds = new[] { "unsafe-offering" };
}
var offeringRecommendationIds = new[] { "windows-server-deployment", "request-preflight", "patch-wave-planning", "controlled-restore-request", "zabbix-onboarding", "cmdb-import", "operator-runbook-launch", "platform-health-dashboard" };
"#;

        assert_eq!(
            csharp_array_values(valid, "offeringRecommendationIds"),
            Some(
                REQUIRED_RECOMMENDED_OFFERINGS
                    .iter()
                    .map(|value| value.to_string())
                    .collect()
            )
        );

        let suffix_bypass = r#"
var offeringRecommendationIds = new[] { "windows-server-deployment", "request-preflight", "patch-wave-planning", "controlled-restore-request", "zabbix-onboarding", "cmdb-import", "operator-runbook-launch", "platform-health-dashboard" }.Concat(new[] { "unsafe-offering" });
"#;

        assert_eq!(
            csharp_array_values(suffix_bypass, "offeringRecommendationIds"),
            None
        );
    }

    #[test]
    fn offering_recommendations_prohibited_fields_and_literals_are_rust_owned() {
        let contact = [
            ["contact", "summary"].join("-"),
            ["example", "invalid"].join("."),
        ]
        .join("@");
        let private_network = ["10", "10", "10", "10"].join(".");
        let provider_id = ["01234567", "89abcdef", "01234567", "89abcdef", "01234567"].join("");
        let mut errors = Vec::new();

        validate_no_prohibited_values(
            &json!({
                "rawUserDataAllowedForDebug": "redacted",
                "contactSummary": contact,
                "privateNetworkSummary": private_network,
                "providerSummary": provider_id,
            }),
            "synthetic",
            &mut errors,
        );

        assert!(errors
            .iter()
            .any(|error| error.contains("rawUserDataAllowedForDebug")));
        assert!(errors.iter().any(|error| error.contains("contactSummary")));
        assert!(errors
            .iter()
            .any(|error| error.contains("privateNetworkSummary")));
        assert!(errors.iter().any(|error| error.contains("providerSummary")));
    }
}
