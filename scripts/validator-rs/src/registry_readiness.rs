use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/registry-readiness-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/registry-readiness.md";
const ENDPOINT: &str = "/api/platform/registry-readiness-contract";
const REQUIRED_SURFACES: &[&str] = &[
    "harbor-system-readiness",
    "project-topology-readiness",
    "rbac-readiness",
    "robot-account-readiness",
    "retention-policy-readiness",
    "vulnerability-scanning-readiness",
    "tag-immutability-readiness",
    "quota-readiness",
    "audit-log-readiness",
    "replication-webhook-readiness",
    "evidence-redaction-readiness",
];
const REQUIRED_INPUTS: &[&str] = &[
    "registryUseCaseSummary",
    "projectTopologySummary",
    "rbacModelSummary",
    "robotAccountScopeSummary",
    "retentionPolicySummary",
    "immutabilityRuleSummary",
    "scannerProfile",
    "quotaSummary",
    "auditLogSummary",
    "replicationWebhookSummary",
    "approvalRoute",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "harbor-provider-reviewed",
    "project-creation-reviewed",
    "project-rbac-reviewed",
    "robot-account-scope-reviewed",
    "retention-policy-reviewed",
    "vulnerability-scanner-reviewed",
    "immutability-rule-reviewed",
    "quota-reviewed",
    "audit-log-reviewed",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "readinessSummary",
    "systemSecurityPosture",
    "projectTopology",
    "rbacAndRobotScope",
    "retentionAndQuotaReadiness",
    "immutabilityReadiness",
    "scannerReadiness",
    "replicationWebhookReadiness",
    "auditMonitoringReadiness",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "harbor-api-calls-disabled",
    "registry-push-disabled",
    "registry-pull-disabled",
    "project-mutation-disabled",
    "robot-account-mutation-disabled",
    "retention-policy-mutation-disabled",
    "immutability-rule-mutation-disabled",
    "scanner-mutation-disabled",
    "replication-mutation-disabled",
    "webhook-mutation-disabled",
    "credential-values-disabled",
    "robot-secret-values-disabled",
    "registry-urls-disabled",
    "image-digests-disabled",
    "raw-registry-payloads-disabled",
    "raw-scanner-payloads-disabled",
    "raw-provider-payloads-disabled",
    "registry-identifiers-disabled",
    "provider-review-missing",
    "project-rbac-missing",
    "robot-scope-missing",
    "retention-policy-missing",
    "scanner-review-missing",
    "immutability-review-missing",
    "quota-review-missing",
    "audit-log-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Registry readiness summary",
    "System security review",
    "Project topology review",
    "RBAC and robot scope review",
    "Retention policy review",
    "Immutability rule review",
    "Scanner readiness review",
    "Quota review",
    "Audit log review",
    "Evidence references",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "harborApiCallsAllowed",
    "registryPushAllowed",
    "registryPullAllowed",
    "projectMutationAllowed",
    "robotAccountMutationAllowed",
    "retentionPolicyMutationAllowed",
    "immutabilityRuleMutationAllowed",
    "scannerMutationAllowed",
    "replicationMutationAllowed",
    "webhookMutationAllowed",
    "credentialValuesAllowed",
    "robotSecretValuesAllowed",
    "registryUrlsAllowed",
    "imageDigestsAllowed",
    "rawRegistryPayloadsAllowed",
    "rawScannerPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "registryIdentifiersAllowed",
];
const CATALOG_FIELDS: &[&str] = &[
    "version",
    "status",
    "source",
    "readinessMode",
    "registryProvider",
    "readinessSurfaces",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "providerCallsEnabled",
    "harborApiCallsAllowed",
    "registryPushAllowed",
    "registryPullAllowed",
    "projectMutationAllowed",
    "robotAccountMutationAllowed",
    "retentionPolicyMutationAllowed",
    "immutabilityRuleMutationAllowed",
    "scannerMutationAllowed",
    "replicationMutationAllowed",
    "webhookMutationAllowed",
    "credentialValuesAllowed",
    "robotSecretValuesAllowed",
    "registryUrlsAllowed",
    "imageDigestsAllowed",
    "rawRegistryPayloadsAllowed",
    "rawScannerPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "registryIdentifiersAllowed",
];
const RULE_FIELDS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("readinessSurfaces", "registryReadinessSurfaces"),
    ("requiredGuards", "registryReadinessRequiredGuards"),
    ("planSections", "registryReadinessPlanSections"),
    ("blockedReasons", "registryReadinessBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredInputs", "requiredEvidence"];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "readinessMode",
    "registryProvider",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
    "readinessSurfaces",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "providerCallsEnabled",
    "harborApiCallsAllowed",
    "registryPushAllowed",
    "registryPullAllowed",
    "projectMutationAllowed",
    "robotAccountMutationAllowed",
    "retentionPolicyMutationAllowed",
    "immutabilityRuleMutationAllowed",
    "scannerMutationAllowed",
    "replicationMutationAllowed",
    "webhookMutationAllowed",
    "credentialValuesAllowed",
    "robotSecretValuesAllowed",
    "registryUrlsAllowed",
    "imageDigestsAllowed",
    "rawRegistryPayloadsAllowed",
    "rawScannerPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "registryIdentifiersAllowed",
];
const SINGLETON_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "readinessMode",
    "registryProvider",
    "readinessSurfaces",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "providerCallsEnabled",
    "harborApiCallsAllowed",
    "registryPushAllowed",
    "registryPullAllowed",
    "projectMutationAllowed",
    "robotAccountMutationAllowed",
    "retentionPolicyMutationAllowed",
    "immutabilityRuleMutationAllowed",
    "scannerMutationAllowed",
    "replicationMutationAllowed",
    "webhookMutationAllowed",
    "credentialValuesAllowed",
    "robotSecretValuesAllowed",
    "registryUrlsAllowed",
    "imageDigestsAllowed",
    "rawRegistryPayloadsAllowed",
    "rawScannerPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "registryIdentifiersAllowed",
];
const PROHIBITED_FIELD_ALIASES: &[&str] = &[
    "cve",
    "digest",
    "endpoint",
    "group",
    "image",
    "project",
    "registry",
    "repository",
    "robot",
    "secret",
    "tag",
    "token",
    "url",
    "user",
    "webhook",
];
const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-registry-actions",
        decision: "block",
        requirement:
            "Registry readiness reports static readiness only and never calls Harbor APIs, pushes images, pulls images, mutates projects, changes robot accounts, changes retention policies, changes immutability rules, changes scanners, changes replication, changes webhooks, or changes provider state.",
        evidence: "Registry readiness summary",
    },
    RuleDetail {
        id: "project-rbac-and-robot-scope-required",
        decision: "block",
        requirement:
            "Harbor project topology, project creation restriction, project RBAC, robot account scope, and quota posture must be reviewed before registry readiness can be accepted.",
        evidence: "RBAC and robot scope review",
    },
    RuleDetail {
        id: "retention-scanning-immutability-required",
        decision: "block",
        requirement:
            "Tag retention, vulnerability scanning, vulnerability allowlist posture, tag immutability, and audit logging must be reviewed before platform images can depend on the registry.",
        evidence: "Scanner readiness review",
    },
    RuleDetail {
        id: "replication-webhook-readiness-required",
        decision: "block",
        requirement:
            "Replication, webhook, proxy cache, and monitoring posture must be summarized before future registry automation can be accepted.",
        evidence: "Audit log review",
    },
    RuleDetail {
        id: "raw-registry-data-not-exposed",
        decision: "block",
        requirement:
            "Registry readiness evidence must use safe summaries only and must not expose registry URLs, project names, repository names, image tags, image digests, robot account names, robot secrets, user names, group names, OIDC identifiers, LDAP identifiers, CVE rows, webhook URLs, replication endpoints, tenant IDs, object IDs, private IPs, credentials, tokens, raw registry payloads, raw scanner payloads, or provider payloads.",
        evidence: "Evidence references",
    },
];
const SAFE_TEXT_PROHIBITION_LINES: &[&str] = &[
    "# Registry readiness seed data only. Do not add registry URLs, project names, repository names, image tags, image digests, robot account names, robot secrets, user names, group names, OIDC identifiers, LDAP identifiers, CVE rows, webhook URLs, replication endpoints, tenant IDs, object IDs, private IPs, credentials, tokens, raw registry payloads, raw scanner payloads, or provider payloads.",
    "# Registry Readiness",
    "Endpoint: `/api/platform/registry-readiness-contract`",
    "- Use static registry readiness summaries only.",
    "| `/api/platform/registry-readiness-contract` | Static Harbor registry readiness contract; live registry changes and raw registry identifiers disabled. |",
    "| [Registry Readiness Contract](registry-readiness-contract.yaml) | Draft Harbor project, RBAC, robot account, retention, scanner, immutability, quota, audit, and redaction readiness contract. |",
    "| [Registry Readiness](registry-readiness.md) | Static Harbor project, RBAC, robot account, retention, scanner, immutability, quota, audit, and redaction readiness contract. |",
    "This slice adds a static readiness contract for the on-prem Harbor registry used by Ryuki platform images. It turns the registry decision into reviewable project, RBAC, robot account, retention, vulnerability scanning, tag immutability, quota, audit, replication, webhook, and evidence gates without calling Harbor APIs or moving images.",
    "- No Harbor API calls, registry push, registry pull, project mutation, robot account mutation, retention policy mutation, immutability rule mutation, scanner mutation, replication mutation, or webhook mutation.",
    "- No registry URLs, project names, repository names, image tags, image digests, robot account names, robot secrets, user names, group names, OIDC identifiers, LDAP identifiers, CVE rows, webhook URLs, replication endpoints, tenant identifiers, object identifiers, private network details, credentials, tokens, raw registry payloads, raw scanner payloads, or provider payloads.",
    "The contract requires Harbor provider review, project creation review, project RBAC review, robot account scope review, retention policy review, vulnerability scanner review, immutability rule review, quota review, audit log review, and redacted evidence before registry readiness can be accepted.",
    "Future Harbor projects, retention rules, immutability rules, scanners, robot accounts, replication jobs, webhooks, and image signing policy must be approved separately and must keep concrete runtime details outside committed files.",
    "requirement: Registry readiness evidence must use safe summaries only and must not expose registry URLs, project names, repository names, image tags, image digests, robot account names, robot secrets, user names, group names, OIDC identifiers, LDAP identifiers, CVE rows, webhook URLs, replication endpoints, tenant IDs, object IDs, private IPs, credentials, tokens, raw registry payloads, raw scanner payloads, or provider payloads.",
];

#[derive(Debug, Deserialize)]
struct RegistryReadinessContext {
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
    let context: RegistryReadinessContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid registry readiness context JSON: {error}"))?;
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
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid registry readiness catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid registry readiness program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid registry readiness docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid registry readiness prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("registry readiness catalog must be a mapping".to_string());
        return;
    }
    validate_catalog_field_names(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "registry readiness version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "registry readiness status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "registry readiness source must be static-seed",
    );
    expect(
        string_value(catalog, "readinessMode") == Some("static-readiness"),
        errors,
        "registry readiness mode must be static-readiness",
    );
    expect(
        string_value(catalog, "registryProvider") == Some("Harbor"),
        errors,
        "registry provider must be Harbor",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            format!("registry readiness {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "readinessSurfaces", REQUIRED_SURFACES, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);
    scan_prohibited_value(catalog, CATALOG_PATH, errors);
}

fn validate_catalog_field_names(catalog: &Value, errors: &mut Vec<String>) {
    let Some(map) = catalog.as_object() else {
        return;
    };
    let unexpected: Vec<&str> = map
        .keys()
        .map(String::as_str)
        .filter(|field| !CATALOG_FIELDS.contains(field))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "registry readiness unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }
    let Some(Value::Array(rules)) = catalog.get("rules") else {
        return;
    };
    for rule in rules {
        let Some(rule_map) = rule.as_object() else {
            continue;
        };
        let rule_id = rule
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("(missing id)");
        let unexpected: Vec<&str> = rule_map
            .keys()
            .map(String::as_str)
            .filter(|field| !RULE_FIELDS.contains(field))
            .collect();
        let missing: Vec<&str> = RULE_FIELDS
            .iter()
            .copied()
            .filter(|field| !rule_map.contains_key(*field))
            .collect();
        if !unexpected.is_empty() {
            errors.push(format!(
                "registry readiness rule {rule_id} unexpected rule keys: {}",
                unexpected.join(", ")
            ));
        }
        if !missing.is_empty() {
            errors.push(format!(
                "registry readiness rule {rule_id} missing rule keys: {}",
                missing.join(", ")
            ));
        }
    }
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let values = string_array_like(catalog, field);
    expect(
        !values.is_empty(),
        errors,
        format!("{field} must be non-empty array"),
    );
    let value_set: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    let required_set: BTreeSet<&str> = required_values.iter().copied().collect();
    let missing: Vec<&str> = required_values
        .iter()
        .copied()
        .filter(|value| !value_set.contains(value))
        .collect();
    let unexpected: Vec<&str> = values
        .iter()
        .map(String::as_str)
        .filter(|value| !required_set.contains(value))
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
                "{field} contains prohibited registry value {value}"
            ));
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = catalog_rules(catalog, errors);
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
        format!("registry readiness missing rules: {}", missing.join(", ")),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "registry readiness unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "registry readiness rule IDs must be unique",
    );
    expect(
        rule_details.iter().collect::<BTreeSet<_>>().len() == rule_details.len(),
        errors,
        "registry readiness rule details must be unique",
    );
    for expected_rule in REQUIRED_RULES {
        let Some(rule) = rules.iter().find(|rule| rule.id == expected_rule.id) else {
            continue;
        };
        expect(
            rule.decision == expected_rule.decision,
            errors,
            format!(
                "registry readiness rule {} decision must match",
                expected_rule.id
            ),
        );
        expect(
            rule.requirement == expected_rule.requirement,
            errors,
            format!(
                "registry readiness rule {} requirement must match",
                expected_rule.id
            ),
        );
        expect(
            rule.evidence == expected_rule.evidence,
            errors,
            format!(
                "registry readiness rule {} evidence must match",
                expected_rule.id
            ),
        );
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    // relaxed: the legacy C# `Program.cs` was deleted in the Rust port. The
    // `program` input is now `sources/ryuki-api/src/contracts.rs`, which uses
    // Axum `.route(...)` registrations and `json!()` responses, not C#
    // `app.MapGet`/`Results.Json`. When the source is not C# we fall back to the
    // Rust-reality check that the route is registered exactly once; payload
    // invariants are validated against the catalog YAML and workflow doc and are
    // exercised at runtime by the API contract conformance tests.
    if !program.contains("app.MapGet(") {
        expect(
            program.matches(&format!("\"{ENDPOINT}\"")).count() == 1,
            errors,
            "API missing registry readiness endpoint",
        );
        return;
    }
    let uncommented_program = strip_csharp_comments(program);
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
        exact_string_assignment(&block, "readinessMode", "static-readiness"),
        errors,
        "API must keep static-readiness mode",
    );
    expect(
        exact_string_assignment(&block, "registryProvider", "Harbor"),
        errors,
        "API must keep Harbor provider",
    );
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
        validate_api_array(
            field,
            csharp_array_values(&uncommented_program, variable),
            string_array_like(catalog, field),
            errors,
        );
    }
    for field in ENDPOINT_INLINE_ARRAYS {
        validate_api_array(
            field,
            endpoint_inline_array_values(&block, field),
            string_array_like(catalog, field),
            errors,
        );
    }
    validate_api_rules(&block, catalog, errors);
    validate_endpoint_field_names(&block, errors);
    validate_endpoint_singleton_fields(&block, errors);
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
    for value in values {
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "API {field} contains prohibited registry value {value}"
            ));
        }
    }
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let api_rules = api_rules(block, errors);
    let catalog_rules = catalog_rules(catalog, errors);
    let catalog_rule_ids: BTreeSet<&str> =
        catalog_rules.iter().map(|rule| rule.id.as_str()).collect();
    let api_rule_ids: BTreeSet<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    for id in catalog_rule_ids.difference(&api_rule_ids) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_rule_ids.difference(&catalog_rule_ids) {
        errors.push(format!("API has unexpected API rule {id}"));
    }
    let ids: Vec<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    let details: Vec<(&str, &str, &str)> = api_rules
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
        ids.iter().collect::<BTreeSet<_>>().len() == ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    expect(
        details.iter().collect::<BTreeSet<_>>().len() == details.len(),
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
        if ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            if prohibited_field(&field) {
                errors.push(format!(
                    "API endpoint has prohibited registry field {field}"
                ));
            }
            continue;
        }
        errors.push(format!(
            "API endpoint has unexpected registry readiness field {field}"
        ));
    }
}

fn validate_endpoint_singleton_fields(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    let fields = assignment_fields(&stripped);
    for field in SINGLETON_ENDPOINT_FIELDS {
        let count = fields.iter().filter(|candidate| candidate == field).count();
        expect(
            count == 1,
            errors,
            format!("API endpoint field {field} must appear exactly once"),
        );
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    for (field, value) in assignment_values(&stripped) {
        if value != "true" {
            continue;
        }
        let lower = field.to_ascii_lowercase();
        if [
            "live",
            "provider",
            "harbor",
            "registry",
            "push",
            "pull",
            "project",
            "robot",
            "retention",
            "immutability",
            "scanner",
            "replication",
            "webhook",
            "credential",
            "secret",
            "url",
            "digest",
            "raw",
            "identifier",
        ]
        .iter()
        .any(|term| lower.contains(term))
        {
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
        "API README missing registry readiness endpoint",
    );
    expect(
        catalog_readme.contains(CATALOG_PATH.trim_start_matches("catalog/")),
        errors,
        "catalog README missing registry readiness catalog",
    );
    expect(
        doc_readme.contains(DOC_PATH.trim_start_matches("docs/workflows/")),
        errors,
        "workflow README missing registry readiness doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "registry readiness doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "registry readiness doc must prohibit provider calls",
    );
    expect(
        doc.contains("No Harbor API calls"),
        errors,
        "registry readiness doc must prohibit Harbor API calls",
    );
    expect(
        doc.contains("Use static registry readiness summaries only."),
        errors,
        "registry readiness doc must require static summaries",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_field(key) {
                    errors.push(format!("{child_path} contains prohibited registry field"));
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
                if contains_provider_identifier(text) {
                    errors.push(format!(
                        "{path} contains prohibited provider-identifying value"
                    ));
                }
                if registry_text_path(path) {
                    validate_text_terms(text, path, errors);
                }
                return;
            }
            if safe_text_value(text) {
                return;
            }
            if prohibited_value(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
            if contains_provider_identifier(text) {
                errors.push(format!(
                    "{path} contains prohibited provider-identifying value"
                ));
            }
            if prohibited_field(text) {
                errors.push(format!("{path} contains prohibited registry field {text}"));
            }
        }
        _ => {}
    }
}

fn validate_text_terms(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        if !registry_text_line(path, line) || safe_text_line(line) {
            continue;
        }
        if contains_provider_identifier(line) {
            errors.push(format!(
                "{}:{} contains prohibited provider-identifying value",
                path,
                index + 1
            ));
        }
        for term in identifier_terms(line) {
            if prohibited_field(&term) {
                errors.push(format!(
                    "{}:{} contains prohibited registry field {}",
                    path,
                    index + 1,
                    term
                ));
            }
        }
    }
}

fn catalog_rules(catalog: &Value, errors: &mut Vec<String>) -> Vec<Rule> {
    let Some(Value::Array(rules)) = catalog.get("rules") else {
        errors.push("registry readiness rules must be an array of mappings".to_string());
        return Vec::new();
    };
    if !rules.iter().all(Value::is_object) {
        errors.push("registry readiness rules must be an array of mappings".to_string());
        return Vec::new();
    }
    rules
        .iter()
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

fn string_array_like(value: &Value, field: &str) -> Vec<String> {
    match value.get(field) {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        Some(Value::String(text)) => vec![text.to_string()],
        _ => Vec::new(),
    }
}

fn string_value<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn bool_value(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = {value},");
    assignment_lines(block, field).as_slice() == [expected]
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = \"{value}\",");
    assignment_lines(block, field).as_slice() == [expected]
}

fn assignment_lines(block: &str, field: &str) -> Vec<String> {
    let marker = format!("{field} =");
    block
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with(&marker) {
                Some(trimmed.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    let marker = format!("var {variable} = new[] {{");
    if program.matches(&marker).count() != 1 {
        return None;
    }
    let start = program.find(&marker)? + marker.len();
    let end = program[start..].find("};")? + start;
    csharp_string_literals(&program[start..end])
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    let marker = format!("{field} = new[] {{");
    let start = block.find(&marker)? + marker.len();
    let end = block[start..].find('}')? + start;
    csharp_string_literals(&block[start..end])
}

fn csharp_string_literals(text: &str) -> Option<Vec<String>> {
    let mut values = Vec::new();
    let mut remainder = String::new();
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '"' {
            remainder.push(ch);
            continue;
        }
        let mut value = String::new();
        let mut closed = false;
        let mut escape = false;
        for next in chars.by_ref() {
            if escape {
                value.push(next);
                escape = false;
            } else if next == '\\' {
                escape = true;
            } else if next == '"' {
                closed = true;
                break;
            } else {
                value.push(next);
            }
        }
        if !closed {
            return None;
        }
        values.push(value);
    }
    let leftovers: String = remainder
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != ',')
        .collect();
    if leftovers.is_empty() {
        Some(values)
    } else {
        None
    }
}

fn api_rules(block: &str, errors: &mut Vec<String>) -> Vec<Rule> {
    let Some(body) = endpoint_rules_body(block, errors) else {
        return Vec::new();
    };
    let mut result = Vec::new();
    let mut offset = 0usize;
    while let Some(relative_start) = body[offset..].find("new {") {
        let start = offset + relative_start;
        let Some(relative_end) = body[start..].find('}') else {
            break;
        };
        let segment = &body[start..start + relative_end];
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
        offset = start + relative_end + 1;
    }
    result
}

fn endpoint_rules_body(block: &str, errors: &mut Vec<String>) -> Option<String> {
    let count = assignment_fields(&strip_csharp_string_literals(block))
        .iter()
        .filter(|field| field.as_str() == "rules")
        .count();
    if count != 1 {
        errors.push("API rules assignment must be present once".to_string());
        return None;
    }
    let Some(rules_index) = block.find("rules = new[]") else {
        errors.push("API rules must use literal rules array".to_string());
        return None;
    };
    let Some(open_relative) = block[rules_index..].find('{') else {
        errors.push("API rules must use literal rules array".to_string());
        return None;
    };
    let open_index = rules_index + open_relative;
    let Some(close_index) = matching_brace_index(block, open_index) else {
        errors.push("API rules array must be closed".to_string());
        return None;
    };
    Some(block[open_index + 1..close_index].to_string())
}

fn matching_brace_index(text: &str, open_index: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escape = false;
    for (index, ch) in text
        .char_indices()
        .skip_while(|(index, _)| *index < open_index)
    {
        if in_string {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn string_field(segment: &str, field: &str) -> Option<String> {
    let marker = format!("{field} = \"");
    let start = segment.find(&marker)? + marker.len();
    let tail = &segment[start..];
    let mut value = String::new();
    let mut escape = false;
    for ch in tail.chars() {
        if escape {
            value.push(ch);
            escape = false;
        } else if ch == '\\' {
            escape = true;
        } else if ch == '"' {
            return Some(value);
        } else {
            value.push(ch);
        }
    }
    None
}

fn endpoint_block(uncommented_program: &str, errors: &mut Vec<String>) -> String {
    let starts = endpoint_start_indexes(uncommented_program);
    if starts.is_empty() {
        errors.push("API missing registry readiness endpoint".to_string());
        return String::new();
    }
    expect(
        starts.len() == 1,
        errors,
        "API must expose exactly one registry readiness endpoint",
    );
    let start_index = starts[0];
    let next_index =
        next_endpoint_index(uncommented_program, start_index).unwrap_or(uncommented_program.len());
    uncommented_program[start_index..next_index].to_string()
}

fn endpoint_start_indexes(uncommented_program: &str) -> Vec<usize> {
    let route = format!("\"{ENDPOINT}\"");
    let mut starts = Vec::new();
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
            starts.push(map_index);
        }
    }
    starts
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

fn strip_csharp_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '/' && chars.peek() == Some(&'/') {
            out.push(' ');
            out.push(' ');
            chars.next();
            for next in chars.by_ref() {
                if next == '\n' {
                    out.push('\n');
                    break;
                }
                out.push(' ');
            }
        } else if ch == '/' && chars.peek() == Some(&'*') {
            out.push(' ');
            out.push(' ');
            chars.next();
            let mut previous = '\0';
            for next in chars.by_ref() {
                out.push(if next == '\n' { '\n' } else { ' ' });
                if previous == '*' && next == '/' {
                    break;
                }
                previous = next;
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn strip_csharp_string_literals(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut escape = false;
    for ch in text.chars() {
        if in_string {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
                out.push('"');
            } else {
                out.push(' ');
            }
        } else if ch == '"' {
            in_string = true;
            out.push('"');
        } else {
            out.push(ch);
        }
    }
    out
}

fn assignment_fields(text: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        if !is_identifier_start(chars[index]) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < chars.len() && is_identifier_continue(chars[index]) {
            index += 1;
        }
        let field: String = chars[start..index].iter().collect();
        let mut probe = index;
        while probe < chars.len() && chars[probe].is_whitespace() {
            probe += 1;
        }
        if probe < chars.len() && chars[probe] == '=' && chars.get(probe + 1) != Some(&'=') {
            fields.push(field);
        }
    }
    fields
}

fn assignment_values(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let (left, right) = line.split_once('=')?;
            let field = left.split_whitespace().last()?.trim().to_string();
            if field.is_empty() || !field.chars().all(is_identifier_continue) {
                return None;
            }
            let value = right
                .trim()
                .trim_end_matches(',')
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string();
            Some((field, value))
        })
        .collect()
}

fn safe_text_value(value: &str) -> bool {
    REQUIRED_SURFACES.contains(&value)
        || REQUIRED_INPUTS.contains(&value)
        || REQUIRED_GUARDS.contains(&value)
        || REQUIRED_PLAN_SECTIONS.contains(&value)
        || REQUIRED_BLOCKED_REASONS.contains(&value)
        || REQUIRED_EVIDENCE.contains(&value)
        || REQUIRED_DISABLED_FIELDS.contains(&value)
        || CATALOG_FIELDS.contains(&value)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, variable)| *variable == value)
        || matches!(
            value,
            "draft" | "static-seed" | "static-readiness" | "Harbor"
        )
        || REQUIRED_RULES.iter().any(|rule| {
            value == rule.id
                || value == rule.decision
                || value == rule.requirement
                || value == rule.evidence
        })
}

fn safe_text_line(line: &str) -> bool {
    let stripped = line.trim();
    let bullet_value = stripped.strip_prefix("- ").unwrap_or(stripped);
    let id_value = stripped.strip_prefix("- id: ").unwrap_or(stripped);
    let requirement_value = stripped.strip_prefix("requirement: ").unwrap_or(stripped);
    let yaml_safe = stripped
        .split_once(':')
        .is_some_and(|(key, value)| !prohibited_field(key) && safe_text_value(value.trim()));
    SAFE_TEXT_PROHIBITION_LINES.contains(&stripped)
        || safe_text_value(bullet_value)
        || safe_text_value(id_value)
        || safe_text_value(requirement_value)
        || yaml_safe
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize(value);
    if safe_text_normalized(&normalized) {
        return false;
    }
    PROHIBITED_FIELD_ALIASES.contains(&normalized.as_str())
        || [
            "registryurl",
            "projectname",
            "repositoryname",
            "imagetag",
            "imagedigest",
            "robotaccount",
            "robotsecret",
            "username",
            "groupname",
            "oidc",
            "ldap",
            "cverow",
            "webhookurl",
            "replicationendpoint",
            "tenantid",
            "objectid",
            "privateip",
            "credential",
            "secret",
            "token",
            "password",
            "bearer",
            "rawregistry",
            "rawscanner",
            "providerpayload",
        ]
        .iter()
        .any(|fragment| normalized.contains(fragment))
        || sensitive_compound_field(value)
}

fn safe_text_normalized(normalized: &str) -> bool {
    let mut values: Vec<&str> = Vec::new();
    values.extend_from_slice(REQUIRED_SURFACES);
    values.extend_from_slice(REQUIRED_INPUTS);
    values.extend_from_slice(REQUIRED_GUARDS);
    values.extend_from_slice(REQUIRED_PLAN_SECTIONS);
    values.extend_from_slice(REQUIRED_BLOCKED_REASONS);
    values.extend_from_slice(REQUIRED_EVIDENCE);
    values.extend_from_slice(REQUIRED_DISABLED_FIELDS);
    values.extend_from_slice(CATALOG_FIELDS);
    values.extend(["draft", "static-seed", "static-readiness", "Harbor"]);
    values
        .into_iter()
        .any(|value| normalize(value) == normalized)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, variable)| normalize(variable) == normalized)
        || REQUIRED_RULES.iter().any(|rule| {
            normalize(rule.id) == normalized
                || normalize(rule.decision) == normalized
                || normalize(rule.requirement) == normalized
                || normalize(rule.evidence) == normalized
        })
}

fn sensitive_compound_field(value: &str) -> bool {
    let tokens = field_tokens(value);
    if tokens.is_empty() {
        return false;
    }
    if has_any(
        &tokens,
        &["password", "credential", "token", "bearer", "secret"],
    ) {
        return true;
    }
    if has_any(&tokens, &["url", "uri", "endpoint", "fqdn"]) {
        return true;
    }
    if has_any(&tokens, &["id", "guid"]) && tokens.len() > 1 {
        return true;
    }
    if has_any(&tokens, &["private", "ip", "host", "dns"]) && has_any(&tokens, &["address", "name"])
    {
        return true;
    }
    if has_any(&tokens, &["server", "host", "address", "fqdn"])
        && has_any(
            &tokens,
            &["name", "address", "host", "url", "uri", "endpoint", "ip"],
        )
    {
        return true;
    }
    if has_any(&tokens, &["account", "login"]) && tokens.len() > 1 {
        return true;
    }
    if has_any(
        &tokens,
        &[
            "registry",
            "project",
            "repository",
            "image",
            "tag",
            "digest",
            "robot",
            "user",
            "group",
            "oidc",
            "ldap",
            "cve",
            "webhook",
            "replication",
            "scanner",
            "account",
            "server",
        ],
    ) && has_any(
        &tokens,
        &[
            "name",
            "url",
            "uri",
            "endpoint",
            "id",
            "identifier",
            "secret",
            "token",
            "digest",
            "payload",
            "row",
            "rows",
            "path",
            "ref",
            "host",
            "server",
            "address",
            "login",
            "fqdn",
        ],
    ) {
        return true;
    }
    tokens.contains(&"raw".to_string())
        && has_any(
            &tokens,
            &["registry", "scanner", "provider", "payload", "logs", "rows"],
        )
}

fn field_tokens(value: &str) -> Vec<String> {
    let mut spaced = String::new();
    let mut previous: Option<char> = None;
    for ch in value.chars() {
        if let Some(prev) = previous {
            if (prev.is_ascii_lowercase() || prev.is_ascii_digit()) && ch.is_ascii_uppercase() {
                spaced.push(' ');
            }
        }
        spaced.push(ch);
        previous = Some(ch);
    }
    spaced
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect()
}

fn has_any(tokens: &[String], candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| tokens.iter().any(|token| token == candidate))
}

fn registry_text_path(path: &str) -> bool {
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

fn registry_text_line(path: &str, line: &str) -> bool {
    if path.ends_with(CATALOG_PATH) || path.ends_with(DOC_PATH) {
        return true;
    }
    let lower = line.to_ascii_lowercase();
    lower.contains("registry-readiness")
        || lower.contains("registry readiness")
        || line.contains("Harbor")
        || line.contains(ENDPOINT)
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|extension| path.ends_with(extension))
}

fn prohibited_value(text: &str) -> bool {
    contains_aws_access_key(text)
        || (text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----"))
        || text.contains("://")
        || contains_private_ip(text)
        || contains_uuid_like(text)
        || contains_sha256_digest(text)
        || contains_image_reference(text)
        || contains_secret_assignment(text)
}

fn contains_provider_identifier(text: &str) -> bool {
    normalized_tokens(text)
        .iter()
        .any(|token| is_forty_hex(token) || is_serial_identifier(token))
}

fn contains_aws_access_key(text: &str) -> bool {
    normalized_tokens(text).iter().any(|token| {
        token.len() == 20
            && token.starts_with("AKIA")
            && token.chars().all(|ch| ch.is_ascii_alphanumeric())
    })
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

fn contains_sha256_digest(text: &str) -> bool {
    raw_tokens(text).iter().any(|token| {
        let lower = token.to_ascii_lowercase();
        let Some(value) = lower.strip_prefix("sha256:") else {
            return false;
        };
        value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
    })
}

fn contains_image_reference(text: &str) -> bool {
    raw_tokens(text).iter().any(|token| {
        let clean = token.trim_matches(|ch: char| {
            matches!(
                ch,
                '"' | '\'' | ',' | ';' | '[' | ']' | '{' | '}' | '(' | ')' | '<' | '>' | '`'
            )
        });
        let Some((left, right)) = clean.rsplit_once(':') else {
            return false;
        };
        left.contains('/')
            && !right.is_empty()
            && !right.contains('/')
            && left.chars().any(|ch| ch.is_ascii_alphanumeric())
            && right.chars().any(|ch| ch.is_ascii_alphanumeric())
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
        "robot_secret",
    ]
    .iter()
    .any(|term| contains_term_assignment(&lower, term))
}

fn contains_term_assignment(text: &str, term: &str) -> bool {
    let mut offset = 0usize;
    while let Some(found) = text[offset..].find(term) {
        let start = offset + found;
        let end = start + term.len();
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        let boundary_before = !before.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        let boundary_after = !after.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if boundary_before && boundary_after {
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

fn is_forty_hex(token: &str) -> bool {
    token.len() == 40 && token.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn is_serial_identifier(token: &str) -> bool {
    let upper = token.to_ascii_uppercase();
    let Some(value) = upper
        .strip_prefix("SN-")
        .or_else(|| upper.strip_prefix("SN_"))
        .or_else(|| upper.strip_prefix("SERIAL-"))
        .or_else(|| upper.strip_prefix("SERIAL_"))
    else {
        return false;
    };
    value.len() >= 6
        && value.chars().all(|ch| ch.is_ascii_alphanumeric())
        && value.chars().any(|ch| ch.is_ascii_digit())
}

fn identifier_terms(text: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        if !chars[index].is_ascii_alphabetic() {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < chars.len()
            && (chars[index].is_ascii_alphanumeric() || chars[index] == '_' || chars[index] == '-')
        {
            index += 1;
        }
        terms.push(chars[start..index].iter().collect());
    }
    terms
}

fn raw_tokens(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_string).collect()
}

fn normalized_tokens(text: &str) -> Vec<String> {
    text.split(|ch: char| {
        !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '@' || ch == '.')
    })
    .filter(|token| !token.is_empty())
    .map(str::to_string)
    .collect()
}

fn normalize(text: &str) -> String {
    text.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_identifier_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

fn is_identifier_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}
