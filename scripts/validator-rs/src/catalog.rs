use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const PRIORITIES: &[&str] = &["P0", "P1", "P2", "P3"];
const DECISIONS: &[&str] = &["block", "warn", "review"];
const CATALOG_STATUSES: &[&str] = &["planned", "active", "draft", "deprecated"];
const POLICY_STATUSES: &[&str] = &["draft", "active"];
const ACCESS_STATUSES: &[&str] = &["draft", "active"];
const REQUIRED_ROLES: &[&str] = &[
    "Platform Admin",
    "Datacenter Approver",
    "VMware Operator",
    "Hyper-V Operator",
    "Proxmox Operator",
    "Wintel/Linux Operator",
    "Backup Operator",
    "Monitoring Operator",
    "Service Desk",
    "Auditor",
    "Requester",
];
const REQUIRED_EXECUTION_GUARDS: &[&str] = &[
    "validation-passed",
    "provider-safe-dry-run",
    "required-approvals",
    "active-lock",
    "redacted-evidence-ready",
    "dependency-health-known",
    "secret-reference-approved",
];
const SECRET_ASSIGNMENT_KEYS: &[&str] = &[
    "password",
    "client_secret",
    "access_token",
    "refresh_token",
    "bearer",
];

#[derive(Debug, Deserialize)]
struct Context {
    site_catalog: Value,
    offering_catalog: Value,
    policy_catalog: Value,
    access_catalog: Value,
}

#[derive(Debug, Deserialize)]
struct CatalogCheck {
    kind: String,
    #[serde(default)]
    site_catalog: Value,
    #[serde(default)]
    offering_catalog: Value,
    #[serde(default)]
    policy_catalog: Value,
    #[serde(default)]
    access_catalog: Value,
}

#[derive(Debug, Deserialize)]
struct ProhibitedInput {
    value: Value,
    path: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid catalog context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_site_catalog(&context.site_catalog, &mut errors);
    validate_offering_catalog(&context.offering_catalog, &mut errors);
    validate_policy_guardrails(
        &context.policy_catalog,
        &context.site_catalog,
        &context.offering_catalog,
        &mut errors,
    );
    validate_access_control_catalog(
        &context.access_catalog,
        &context.offering_catalog,
        &mut errors,
    );

    let mut values = Map::new();
    values.insert(
        "catalog/site-catalog.yaml".to_string(),
        context.site_catalog,
    );
    values.insert(
        "catalog/offering-catalog.yaml".to_string(),
        context.offering_catalog,
    );
    values.insert(
        "catalog/policy-guardrails.yaml".to_string(),
        context.policy_catalog,
    );
    values.insert(
        "catalog/access-control-catalog.yaml".to_string(),
        context.access_catalog,
    );
    validate_no_secret_shape(&Value::Object(values), "catalog", &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let payload: CatalogCheck = serde_json::from_str(input)
        .map_err(|error| format!("invalid catalog check JSON: {error}"))?;
    let mut errors = Vec::new();
    match payload.kind.as_str() {
        "site" => validate_site_catalog(&payload.site_catalog, &mut errors),
        "offering" => validate_offering_catalog(&payload.offering_catalog, &mut errors),
        "policy" => validate_policy_guardrails(
            &payload.policy_catalog,
            &payload.site_catalog,
            &payload.offering_catalog,
            &mut errors,
        ),
        "access" => validate_access_control_catalog(
            &payload.access_catalog,
            &payload.offering_catalog,
            &mut errors,
        ),
        "roles" => validate_roles(&payload.access_catalog, &mut errors),
        "approval-routes" => validate_approval_routes(
            &payload.access_catalog,
            &payload.offering_catalog,
            &mut errors,
        ),
        "execution-guards" => validate_execution_guards(&payload.access_catalog, &mut errors),
        "evidence-profile" => validate_evidence_profile(&payload.access_catalog, &mut errors),
        other => return Err(format!("unknown catalog check kind: {other}")),
    }
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid catalog prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_no_secret_shape(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_site_catalog(data: &Value, errors: &mut Vec<String>) {
    expect(
        data.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "site-catalog version must be 1",
    );
    expect(
        non_empty_string(data.get("domain")),
        errors,
        "site-catalog domain is required",
    );
    let pattern = data
        .get("ouPattern")
        .and_then(Value::as_str)
        .unwrap_or_default();
    expect(
        pattern.contains("<SITE>") && pattern.contains("<COUNTRY>"),
        errors,
        "ouPattern must include <SITE> and <COUNTRY>",
    );
    let sites = array_values(data, "sites");
    expect(
        !sites.is_empty(),
        errors,
        "site-catalog sites must be a non-empty array",
    );

    let mut specs = Vec::new();
    let mut site_codes = Vec::new();
    for (index, site) in sites.iter().enumerate() {
        let prefix = format!("site-catalog sites[{index}]");
        expect(
            non_empty_string(site.get("spec")),
            errors,
            format!("{prefix} spec is required"),
        );
        expect(
            site.get("country")
                .and_then(Value::as_str)
                .is_some_and(is_iso_country),
            errors,
            format!("{prefix} country must be ISO-style uppercase"),
        );
        let site_code = site
            .get("site")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        expect(
            is_site_code(&site_code),
            errors,
            format!("{prefix} site must be uppercase code"),
        );
        expect(
            site.get("timezoneCode").and_then(Value::as_i64).is_some(),
            errors,
            format!("{prefix} timezoneCode must be integer"),
        );
        if let Some(spec) = site.get("spec").and_then(Value::as_str) {
            specs.push(spec.to_string());
        }
        if !site_code.is_empty() {
            site_codes.push(site_code);
        }
    }

    expect(
        all_unique(&specs),
        errors,
        "site-catalog specs must be unique",
    );
    expect(
        all_unique(&site_codes),
        errors,
        "site-catalog site codes must be unique",
    );
    validate_no_secret_shape(data, "site-catalog", errors);
}

fn validate_offering_catalog(data: &Value, errors: &mut Vec<String>) {
    expect(
        data.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "offering-catalog version must be 1",
    );
    let categories = string_array(data, "categories", errors, "offering-catalog categories");
    let offerings = array_values(data, "offerings");
    expect(
        !categories.is_empty(),
        errors,
        "offering-catalog categories are required",
    );
    expect(
        all_unique(&categories),
        errors,
        "offering-catalog categories must be unique",
    );
    expect(
        !offerings.is_empty(),
        errors,
        "offering-catalog offerings are required",
    );

    let mut ids = Vec::new();
    let mut used_categories = Vec::new();
    for (index, offering) in offerings.iter().enumerate() {
        let prefix = format!("offering-catalog offerings[{index}]");
        let id = offering
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        ids.push(id.clone());
        expect(
            is_kebab_case(&id),
            errors,
            format!("{prefix} id must be kebab-case"),
        );
        expect(
            non_empty_string(offering.get("title")),
            errors,
            format!("{prefix} title is required"),
        );
        let category = offering
            .get("category")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if !category.is_empty() {
            used_categories.push(category.clone());
        }
        expect(
            categories.contains(&category),
            errors,
            format!("{prefix} category must be declared"),
        );
        expect(
            str_in(offering.get("priority"), PRIORITIES),
            errors,
            format!("{prefix} priority must be P0-P3"),
        );
        expect(
            offering
                .get("dryRunRequired")
                .and_then(Value::as_bool)
                .is_some(),
            errors,
            format!("{prefix} dryRunRequired must be boolean"),
        );
        expect(
            str_in(offering.get("status"), CATALOG_STATUSES),
            errors,
            format!("{prefix} status is invalid"),
        );
        for field in [
            "persona",
            "requiredInputs",
            "approvals",
            "evidence",
            "integrationData",
        ] {
            expect(
                non_empty_array(offering.get(field)),
                errors,
                format!("{prefix} {field} must be non-empty array"),
            );
        }
    }

    expect(
        all_unique(&ids),
        errors,
        "offering-catalog ids must be unique",
    );
    let empty_categories: Vec<String> = categories
        .iter()
        .filter(|category| !used_categories.contains(category))
        .cloned()
        .collect();
    expect(
        empty_categories.is_empty(),
        errors,
        format!(
            "offering-catalog categories without offerings: {}",
            empty_categories.join(", ")
        ),
    );
    validate_no_secret_shape(data, "offering-catalog", errors);
}

fn validate_policy_guardrails(
    data: &Value,
    site_catalog: &Value,
    offering_catalog: &Value,
    errors: &mut Vec<String>,
) {
    expect(
        data.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "policy-guardrails version must be 1",
    );
    expect(
        str_in(data.get("status"), POLICY_STATUSES),
        errors,
        "policy-guardrails status is invalid",
    );
    let families = string_array(data, "policyFamilies", errors, "policyFamilies");
    let future_workflows = string_array(data, "futureWorkflowIds", errors, "futureWorkflowIds");
    let rules = array_values(data, "rules");
    let mut allowed_targets = offering_ids(offering_catalog);
    allowed_targets.extend(future_workflows.iter().cloned());

    expect(!families.is_empty(), errors, "policyFamilies are required");
    expect(
        all_unique(&families),
        errors,
        "policyFamilies must be unique",
    );
    expect(
        future_workflows
            .iter()
            .all(|workflow| is_kebab_case(workflow)),
        errors,
        "futureWorkflowIds must be kebab-case",
    );
    expect(
        all_unique(&future_workflows),
        errors,
        "futureWorkflowIds must be unique",
    );
    expect(!rules.is_empty(), errors, "policy rules are required");

    let mut ids = Vec::new();
    for (index, rule) in rules.iter().enumerate() {
        let prefix = format!("policy-guardrails rules[{index}]");
        let id = rule
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        ids.push(id.clone());
        expect(
            is_kebab_case(&id),
            errors,
            format!("{prefix} id must be kebab-case"),
        );
        let family = rule
            .get("family")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        expect(
            families.contains(&family),
            errors,
            format!("{prefix} family must be declared"),
        );
        expect(
            str_in(rule.get("priority"), PRIORITIES),
            errors,
            format!("{prefix} priority must be P0-P3"),
        );
        expect(
            str_in(rule.get("decision"), DECISIONS),
            errors,
            format!("{prefix} decision must be block, warn, or review"),
        );
        expect(
            non_empty_string(rule.get("failureMessage")),
            errors,
            format!("{prefix} failureMessage is required"),
        );
        expect(
            non_empty_string(rule.get("remediation")),
            errors,
            format!("{prefix} remediation is required"),
        );
        for field in ["appliesTo", "requiredInputs", "evidence"] {
            expect(
                non_empty_array(rule.get(field)),
                errors,
                format!("{prefix} {field} must be non-empty array"),
            );
        }
        let applies_to = string_array(rule, "appliesTo", errors, &format!("{prefix} appliesTo"));
        let unknown_targets: Vec<String> = applies_to
            .into_iter()
            .filter(|target| !allowed_targets.contains(target))
            .collect();
        expect(
            unknown_targets.is_empty(),
            errors,
            format!(
                "{prefix} appliesTo unknown targets: {}",
                unknown_targets.join(", ")
            ),
        );
    }

    expect(all_unique(&ids), errors, "policy rule ids must be unique");

    let catalog_sites = sorted_site_codes(site_catalog);
    let bound_sites = sorted_keys(data.get("siteBindings"));
    expect(
        bound_sites == catalog_sites,
        errors,
        "policy siteBindings must cover exactly catalog sites",
    );
    if let Some(bindings) = data.get("siteBindings").and_then(Value::as_object) {
        for (site, binding) in bindings {
            let binding_families = string_array(
                binding,
                "policyFamilies",
                errors,
                &format!("siteBindings {site} policyFamilies"),
            );
            expect(
                !binding_families.is_empty(),
                errors,
                format!("siteBindings {site} policyFamilies are required"),
            );
            let unknown: Vec<String> = binding_families
                .into_iter()
                .filter(|family| !families.contains(family))
                .collect();
            expect(
                unknown.is_empty(),
                errors,
                format!(
                    "siteBindings {site} unknown families: {}",
                    unknown.join(", ")
                ),
            );
        }
    }

    validate_no_secret_shape(data, "policy-guardrails", errors);
}

fn validate_access_control_catalog(
    data: &Value,
    offering_catalog: &Value,
    errors: &mut Vec<String>,
) {
    expect(
        data.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "access-control-catalog version must be 1",
    );
    expect(
        str_in(data.get("status"), ACCESS_STATUSES),
        errors,
        "access-control-catalog status is invalid",
    );
    expect(
        data.get("identityProvider").and_then(Value::as_str) == Some("Microsoft Entra ID"),
        errors,
        "access-control-catalog identityProvider must be Microsoft Entra ID",
    );
    validate_roles(data, errors);
    validate_approval_routes(data, offering_catalog, errors);
    validate_execution_guards(data, errors);
    validate_evidence_profile(data, errors);
    validate_no_secret_shape(data, "access-control-catalog", errors);
}

fn validate_roles(data: &Value, errors: &mut Vec<String>) {
    let roles = array_values(data, "roles");
    let role_ids: Vec<String> = roles
        .iter()
        .filter_map(|role| role.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let role_titles: Vec<String> = roles
        .iter()
        .filter_map(|role| {
            role.get("title")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect();

    expect(
        !roles.is_empty(),
        errors,
        "access-control-catalog roles are required",
    );
    let missing_roles: Vec<&str> = REQUIRED_ROLES
        .iter()
        .copied()
        .filter(|role| !role_titles.iter().any(|title| title == role))
        .collect();
    expect(
        missing_roles.is_empty(),
        errors,
        format!(
            "access-control-catalog missing roles: {}",
            missing_roles.join(", ")
        ),
    );
    expect(
        all_unique(&role_ids),
        errors,
        "access-control-catalog role ids must be unique",
    );
    expect(
        all_unique(&role_titles),
        errors,
        "access-control-catalog role titles must be unique",
    );

    for (index, role) in roles.iter().enumerate() {
        let prefix = format!("access-control-catalog roles[{index}]");
        let id = role.get("id").and_then(Value::as_str).unwrap_or_default();
        expect(
            is_kebab_case(id),
            errors,
            format!("{prefix} id must be kebab-case"),
        );
        expect(
            non_empty_string(role.get("title")),
            errors,
            format!("{prefix} title is required"),
        );
        expect(
            non_empty_string(role.get("visibility")),
            errors,
            format!("{prefix} visibility is required"),
        );
        for field in [
            "canRequest",
            "canApprove",
            "canExecute",
            "canAdmin",
            "canAudit",
        ] {
            expect(
                role.get(field).and_then(Value::as_bool).is_some(),
                errors,
                format!("{prefix} {field} must be boolean"),
            );
        }
        expect(
            non_empty_array(role.get("executionDomains")),
            errors,
            format!("{prefix} executionDomains must be non-empty array"),
        );
    }
}

fn validate_approval_routes(data: &Value, offering_catalog: &Value, errors: &mut Vec<String>) {
    let actors = string_array(
        data,
        "approvalActors",
        errors,
        "access-control-catalog approvalActors",
    );
    let routes = array_values(data, "approvalRoutes");
    let offering_ids = offering_ids(offering_catalog);
    let offering_approval_actors = offering_approval_actors(offering_catalog);
    let route_targets = routes
        .iter()
        .flat_map(|route| string_array_silent(route, "appliesTo"))
        .collect::<BTreeSet<_>>();

    expect(
        !actors.is_empty(),
        errors,
        "access-control-catalog approvalActors are required",
    );
    let missing_approval_actors: Vec<String> = offering_approval_actors
        .into_iter()
        .filter(|actor| !actors.contains(actor))
        .collect();
    expect(
        missing_approval_actors.is_empty(),
        errors,
        format!(
            "access-control-catalog approvalActors missing offering approvals: {}",
            missing_approval_actors.join(", ")
        ),
    );
    expect(
        !routes.is_empty(),
        errors,
        "access-control-catalog approvalRoutes are required",
    );
    let missing_offerings: Vec<String> = offering_ids
        .iter()
        .filter(|id| !route_targets.contains(*id))
        .cloned()
        .collect();
    expect(
        missing_offerings.is_empty(),
        errors,
        format!(
            "access-control-catalog approvalRoutes missing offerings: {}",
            missing_offerings.join(", ")
        ),
    );

    for (index, route) in routes.iter().enumerate() {
        let prefix = format!("access-control-catalog approvalRoutes[{index}]");
        let id = route.get("id").and_then(Value::as_str).unwrap_or_default();
        expect(
            is_kebab_case(id),
            errors,
            format!("{prefix} id must be kebab-case"),
        );
        expect(
            non_empty_array(route.get("appliesTo")),
            errors,
            format!("{prefix} appliesTo must be non-empty array"),
        );
        let applies_to = string_array(route, "appliesTo", errors, &format!("{prefix} appliesTo"));
        let unknown_targets: Vec<String> = applies_to
            .into_iter()
            .filter(|target| !offering_ids.contains(target))
            .collect();
        expect(
            unknown_targets.is_empty(),
            errors,
            format!(
                "{prefix} appliesTo unknown offerings: {}",
                unknown_targets.join(", ")
            ),
        );
        let required = string_array(
            route,
            "requiredActors",
            errors,
            &format!("{prefix} requiredActors"),
        );
        let conditional = string_array(
            route,
            "conditionalActors",
            errors,
            &format!("{prefix} conditionalActors"),
        );
        expect(
            !required.is_empty(),
            errors,
            format!("{prefix} requiredActors must be non-empty array"),
        );
        let unknown_actors: Vec<String> = required
            .iter()
            .chain(conditional.iter())
            .filter(|actor| !actors.contains(*actor))
            .cloned()
            .collect();
        expect(
            unknown_actors.is_empty(),
            errors,
            format!(
                "{prefix} references unknown approval actors: {}",
                unknown_actors.join(", ")
            ),
        );
        expect(
            route
                .get("emergencyAllowed")
                .and_then(Value::as_bool)
                .is_some(),
            errors,
            format!("{prefix} emergencyAllowed must be boolean"),
        );
        let evidence = string_array(route, "evidence", errors, &format!("{prefix} evidence"));
        expect(
            evidence.iter().any(|item| item == "Approval decisions"),
            errors,
            format!("{prefix} evidence must include Approval decisions"),
        );
        if route.get("emergencyAllowed").and_then(Value::as_bool) == Some(true) {
            expect(
                evidence.iter().any(|item| item == "Emergency flag"),
                errors,
                format!("{prefix} emergency evidence must include Emergency flag"),
            );
            expect(
                evidence.iter().any(|item| item == "Delegated authority"),
                errors,
                format!("{prefix} emergency evidence must include Delegated authority"),
            );
        }
    }
}

fn validate_execution_guards(data: &Value, errors: &mut Vec<String>) {
    let guards = array_values(data, "executionGuards");
    let guard_ids: Vec<String> = guards
        .iter()
        .filter_map(|guard| guard.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let missing: Vec<&str> = REQUIRED_EXECUTION_GUARDS
        .iter()
        .copied()
        .filter(|guard| !guard_ids.iter().any(|id| id == guard))
        .collect();
    expect(
        missing.is_empty(),
        errors,
        format!(
            "access-control-catalog missing execution guards: {}",
            missing.join(", ")
        ),
    );
    expect(
        all_unique(&guard_ids),
        errors,
        "access-control-catalog execution guard ids must be unique",
    );
    for (index, guard) in guards.iter().enumerate() {
        let prefix = format!("access-control-catalog executionGuards[{index}]");
        let id = guard.get("id").and_then(Value::as_str).unwrap_or_default();
        expect(
            is_kebab_case(id),
            errors,
            format!("{prefix} id must be kebab-case"),
        );
        expect(
            guard.get("decision").and_then(Value::as_str) == Some("block"),
            errors,
            format!("{prefix} decision must be block"),
        );
        expect(
            non_empty_string(guard.get("evidence")),
            errors,
            format!("{prefix} evidence is required"),
        );
    }
}

fn validate_evidence_profile(data: &Value, errors: &mut Vec<String>) {
    let profile = data.get("evidenceProfile").unwrap_or(&Value::Null);
    let records = string_array(
        profile,
        "requiredRecords",
        errors,
        "access-control-catalog evidenceProfile requiredRecords",
    );
    let prohibited = string_array(
        profile,
        "prohibitedContent",
        errors,
        "access-control-catalog evidenceProfile prohibitedContent",
    );
    let id = profile
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    expect(
        is_kebab_case(id),
        errors,
        "access-control-catalog evidenceProfile id must be kebab-case",
    );
    expect(
        records
            .iter()
            .any(|record| record == "Redacted execution log"),
        errors,
        "access-control-catalog evidenceProfile must require redacted execution log",
    );
    expect(
        records.iter().any(|record| record == "Evidence references"),
        errors,
        "access-control-catalog evidenceProfile must require evidence references",
    );
    expect(
        prohibited
            .iter()
            .any(|content| content == "raw provider payloads"),
        errors,
        "access-control-catalog evidenceProfile must prohibit raw provider payloads",
    );
    expect(
        prohibited
            .iter()
            .any(|content| content == "unfiltered logs"),
        errors,
        "access-control-catalog evidenceProfile must prohibit unfiltered logs",
    );
}

fn validate_no_secret_shape(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let key_path = format!("{path}.{key}");
                expect(
                    !forbidden_key(key),
                    errors,
                    format!("{key_path} uses forbidden sensitive key name"),
                );
                validate_no_secret_shape(child, &key_path, errors);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                validate_no_secret_shape(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => {
            expect(
                !secret_like_value(text),
                errors,
                format!("{path} contains secret-like value"),
            );
        }
        _ => {}
    }
}

fn array_values<'a>(value: &'a Value, key: &str) -> Vec<&'a Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_default()
}

fn string_array(value: &Value, key: &str, errors: &mut Vec<String>, label: &str) -> Vec<String> {
    let Some(items) = value.get(key).and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut values = Vec::new();
    for item in items {
        if let Some(text) = item.as_str() {
            values.push(text.to_string());
        } else {
            errors.push(format!("{label} must contain only strings"));
        }
    }
    values
}

fn string_array_silent(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn non_empty_array(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
}

fn non_empty_string(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|text| !text.trim().is_empty())
}

fn str_in(value: Option<&Value>, allowed: &[&str]) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|text| allowed.contains(&text))
}

fn is_kebab_case(value: &str) -> bool {
    if value.is_empty() || value.starts_with('-') || value.ends_with('-') || value.contains("--") {
        return false;
    }
    value
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_iso_country(value: &str) -> bool {
    value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_uppercase())
}

fn is_site_code(value: &str) -> bool {
    (3..=5).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn all_unique(values: &[String]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn offering_ids(offering_catalog: &Value) -> Vec<String> {
    array_values(offering_catalog, "offerings")
        .iter()
        .filter_map(|offering| {
            offering
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect()
}

fn offering_approval_actors(offering_catalog: &Value) -> Vec<String> {
    array_values(offering_catalog, "offerings")
        .iter()
        .flat_map(|offering| string_array_silent(offering, "approvals"))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn sorted_site_codes(site_catalog: &Value) -> Vec<String> {
    let mut sites: Vec<String> = array_values(site_catalog, "sites")
        .iter()
        .filter_map(|site| site.get("site").and_then(Value::as_str).map(str::to_string))
        .collect();
    sites.sort();
    sites
}

fn sorted_keys(value: Option<&Value>) -> Vec<String> {
    let mut keys: Vec<String> = value
        .and_then(Value::as_object)
        .map(|map| map.keys().cloned().collect())
        .unwrap_or_default();
    keys.sort();
    keys
}

fn forbidden_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    [
        "password",
        "passwd",
        "secret",
        "token",
        "clientid",
        "clientsecret",
        "tenantid",
        "objectid",
        "subscriptionid",
        "privatekey",
        "privateip",
        "endpoint",
        "url",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn secret_like_value(text: &str) -> bool {
    contains_aws_access_key(text)
        || text.to_ascii_uppercase().contains("-----BEGIN ")
            && text.to_ascii_uppercase().contains("PRIVATE KEY-----")
        || contains_url(text)
        || contains_private_ip(text)
        || contains_uuid(text)
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

fn word_boundary_before(bytes: &[u8], index: usize) -> bool {
    index == 0 || !is_word_byte(bytes[index - 1])
}

fn word_boundary_after(bytes: &[u8], index: usize) -> bool {
    index >= bytes.len() || !is_word_byte(bytes[index])
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
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
            .any(|needle| normalized == *needle || normalized.ends_with(&format!("_{needle}")))
        {
            return true;
        }
    }
    false
}

fn normalize_assignment_key(key: &str) -> String {
    let trimmed = key
        .trim()
        .trim_matches(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'));
    trimmed
        .chars()
        .map(|ch| {
            if ch == '-' {
                '_'
            } else {
                ch.to_ascii_lowercase()
            }
        })
        .collect()
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}
