use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/gmsa-lifecycle-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/gmsa-lifecycle.md";
const CATALOG_FILE: &str = "gmsa-lifecycle-contract.yaml";
const DOC_FILE: &str = "gmsa-lifecycle.md";
const ENDPOINT: &str = "/api/identity/gmsa-lifecycle-contract";

const REQUIRED_ACTIONS: &[&str] = &[
    "gmsa-create-review",
    "gmsa-assign-review",
    "gmsa-validate-review",
    "gmsa-worker-use-review",
    "gmsa-delegation-review",
    "gmsa-retire-review",
];
const REQUIRED_SIGNALS: &[&str] = &[
    "kds-root-key-readiness",
    "retrieval-scope-summary",
    "kerberos-encryption-policy",
    "spn-policy-match",
    "delegation-risk",
    "worker-capability-match",
    "approval-state",
    "evidence-redaction",
];
const REQUIRED_INPUTS: &[&str] = &[
    "lifecycleAction",
    "requestContext",
    "serviceAccountSummary",
    "retrievalScopeSummary",
    "workerUsageSummary",
    "kerberosPolicySummary",
    "spnPolicySummary",
    "delegationPolicySummary",
    "owner",
    "supportGroup",
    "approvalRoute",
    "rollbackPlan",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "request-context-known",
    "service-account-scope-summarized",
    "kds-root-key-readiness-reviewed",
    "retrieval-scope-reviewed",
    "kerberos-policy-reviewed",
    "spn-policy-reviewed",
    "delegation-risk-reviewed",
    "worker-capability-reviewed",
    "approval-route-assigned",
    "rollback-plan-ready",
    "recovery-readiness-reviewed",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "lifecycleSummary",
    "serviceAccountScope",
    "retrievalScopeReview",
    "kerberosPolicyReview",
    "spnPolicyReview",
    "delegationRiskReview",
    "workerRoutingReview",
    "approvalRoute",
    "rollbackPlan",
    "recoveryReadiness",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "worker-execution-disabled",
    "live-directory-change-disabled",
    "gmsa-creation-disabled",
    "gmsa-assignment-disabled",
    "gmsa-validation-disabled",
    "gmsa-retire-disabled",
    "password-retrieval-disabled",
    "managed-password-material-disabled",
    "spn-change-disabled",
    "delegation-change-disabled",
    "raw-service-account-data-disabled",
    "raw-log-content-disabled",
    "raw-rows-disabled",
    "serial-numbers-disabled",
    "raw-recipient-data-disabled",
    "principal-identifiers-disabled",
    "distinguished-names-disabled",
    "domain-identifiers-disabled",
    "object-identifiers-disabled",
    "security-identifiers-disabled",
    "target-identifiers-disabled",
    "credential-values-disabled",
    "raw-provider-payloads-disabled",
    "approval-missing",
    "rollback-plan-missing",
    "recovery-readiness-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "gMSA lifecycle review summary",
    "Service account scope summary",
    "Password retrieval scope review",
    "Kerberos policy review",
    "SPN policy review",
    "Delegation risk review",
    "Worker usage review",
    "Approval route",
    "Rollback plan",
    "Recovery readiness",
    "Evidence references",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "workerExecutionAllowed",
    "liveDirectoryChangesAllowed",
    "gmsaCreationAllowed",
    "gmsaAssignmentAllowed",
    "gmsaValidationAllowed",
    "gmsaRetireAllowed",
    "passwordRetrievalAllowed",
    "managedPasswordMaterialAllowed",
    "spnChangesAllowed",
    "delegationChangesAllowed",
    "rawServiceAccountDataAllowed",
    "rawLogContentAllowed",
    "rawRowsAllowed",
    "serialNumbersAllowed",
    "rawRecipientDataAllowed",
    "principalIdentifiersAllowed",
    "distinguishedNamesAllowed",
    "domainIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "securityIdentifiersAllowed",
    "targetIdentifiersAllowed",
    "credentialValuesAllowed",
    "rawProviderPayloadsAllowed",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "lifecycleMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "workerExecutionAllowed",
    "liveDirectoryChangesAllowed",
    "gmsaCreationAllowed",
    "gmsaAssignmentAllowed",
    "gmsaValidationAllowed",
    "gmsaRetireAllowed",
    "passwordRetrievalAllowed",
    "managedPasswordMaterialAllowed",
    "spnChangesAllowed",
    "delegationChangesAllowed",
    "rawServiceAccountDataAllowed",
    "rawLogContentAllowed",
    "rawRowsAllowed",
    "serialNumbersAllowed",
    "rawRecipientDataAllowed",
    "principalIdentifiersAllowed",
    "distinguishedNamesAllowed",
    "domainIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "securityIdentifiersAllowed",
    "targetIdentifiersAllowed",
    "credentialValuesAllowed",
    "rawProviderPayloadsAllowed",
    "lifecycleActions",
    "reviewSignals",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("lifecycleActions", "gmsaLifecycleActions"),
    ("reviewSignals", "gmsaLifecycleSignals"),
    ("requiredGuards", "gmsaLifecycleRequiredGuards"),
    ("planSections", "gmsaLifecyclePlanSections"),
    ("blockedReasons", "gmsaLifecycleBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredInputs", "requiredEvidence"];
const RULE_FIELD_NAMES: &[&str] = &["id", "decision", "requirement", "evidence"];
const TOP_LEVEL_ENDPOINT_FIELDS: &[&str] = &[
    "version",
    "status",
    "source",
    "lifecycleMode",
    "dryRunRequired",
    "rules",
    "providerCallsEnabled",
    "workerExecutionAllowed",
    "liveDirectoryChangesAllowed",
    "gmsaCreationAllowed",
    "gmsaAssignmentAllowed",
    "gmsaValidationAllowed",
    "gmsaRetireAllowed",
    "passwordRetrievalAllowed",
    "managedPasswordMaterialAllowed",
    "spnChangesAllowed",
    "delegationChangesAllowed",
    "rawServiceAccountDataAllowed",
    "rawLogContentAllowed",
    "rawRowsAllowed",
    "serialNumbersAllowed",
    "rawRecipientDataAllowed",
    "principalIdentifiersAllowed",
    "distinguishedNamesAllowed",
    "domainIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "securityIdentifiersAllowed",
    "targetIdentifiersAllowed",
    "credentialValuesAllowed",
    "rawProviderPayloadsAllowed",
    "lifecycleActions",
    "reviewSignals",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
];
const REQUIRED_RULE_DETAILS: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-gmsa-changes",
        decision: "block",
        requirement: "gMSA lifecycle records review plans only and never creates, assigns, validates, removes, delegates, changes SPNs, retrieves managed passwords, executes workers, or mutates directory service account objects.",
        evidence: "gMSA lifecycle review summary",
    },
    RuleDetail {
        id: "retrieval-scope-review-required",
        decision: "block",
        requirement: "KDS root key readiness, password retrieval scope, worker usage, Kerberos policy, SPN policy, and delegation risk must be reviewed before any gMSA lifecycle decision can be accepted.",
        evidence: "Password retrieval scope review",
    },
    RuleDetail {
        id: "approval-worker-and-rollback-required",
        decision: "block",
        requirement: "Approval route, worker capability review, rollback plan, and recovery readiness must be present before future directory execution can be considered.",
        evidence: "Rollback plan",
    },
    RuleDetail {
        id: "raw-gmsa-data-not-exposed",
        decision: "block",
        requirement: "gMSA lifecycle evidence must use safe summaries only and must not expose gMSA names, service account names, sAMAccountNames, DNS host names, SPNs, allowed password-retrieval principals, distinguished names, domain names, object GUIDs, object SIDs, security identifiers, principal IDs, hostnames, FQDNs, user names, group names, tenant IDs, object IDs, private IPs, managed password material, credentials, secret values, access tokens, raw service account data, raw log content, raw rows, serial numbers, raw recipient data, or provider payloads.",
        evidence: "Evidence references",
    },
];
const PROHIBITED_FIELD_TOKENS: &[&str] = &[
    "gmsaname",
    "serviceaccountname",
    "managedserviceaccountname",
    "samaccountname",
    "dnshostname",
    "hostname",
    "fqdn",
    "spn",
    "serviceprincipalname",
    "allowedtoretrievepassword",
    "passwordretrievalprincipal",
    "retrievalprincipal",
    "distinguishedname",
    "domainname",
    "objectguid",
    "objectsid",
    "sid",
    "securityidentifier",
    "principalid",
    "username",
    "groupname",
    "tenantid",
    "tenantidentifier",
    "objectid",
    "objectidentifier",
    "privateip",
    "managedpassword",
    "rawserviceaccount",
    "rawlog",
    "logcontent",
    "rawrow",
    "rawrows",
    "serialnumber",
    "serial",
    "rawrecipient",
    "recipientdata",
    "providerpayload",
    "credentialvalue",
    "secretvalue",
    "accesstoken",
    "credential",
    "secret",
    "token",
    "password",
];
const SAFE_TEXT_PROHIBITION_LINES: &[&str] = &[
    "# gMSA lifecycle seed data only. Do not add gMSA names, service account names, sAMAccountNames, DNS host names, SPNs, allowed password-retrieval principals, distinguished names, domain names, object GUIDs, object SIDs, security identifiers, principal IDs, hostnames, FQDNs, user names, group names, tenant IDs, object IDs, live endpoints, private IPs, managed password material, credentials, tokens, raw service account data, raw log content, raw rows, serial numbers, raw recipient data, or provider payloads.",
    "- No gMSA creation, assignment, validation, retire, password retrieval, managed password handling, SPN changes, or delegation changes.",
    "- No gMSA names, service account names, sAMAccountNames, DNS host names, SPNs, allowed password-retrieval principals, distinguished names, domain names, object GUIDs, object SIDs, security identifiers, principal identifiers, hostnames, FQDNs, user names, group names, tenant identifiers, object identifiers, private network details, managed password material, credential values, secret values, access tokens, raw service account data, raw log content, raw rows, serial numbers, raw recipient data, or provider payloads in committed files.",
    "| `/api/identity/gmsa-lifecycle-contract` | Static gMSA lifecycle review contract; live directory changes and raw AD gMSA identifiers disabled. |",
    "requirement: gMSA lifecycle evidence must use safe summaries only and must not expose gMSA names, service account names, sAMAccountNames, DNS host names, SPNs, allowed password-retrieval principals, distinguished names, domain names, object GUIDs, object SIDs, security identifiers, principal IDs, hostnames, FQDNs, user names, group names, tenant IDs, object IDs, private IPs, managed password material, credentials, secret values, access tokens, raw service account data, raw log content, raw rows, serial numbers, raw recipient data, or provider payloads.",
];
const SAFE_PROGRAM_TEXT_SEGMENTS: &[&str] = &[
    "Wintel/Linux Operator",
    "Accepted/rejected rows",
    "Accepted/rejected policy rows",
    "Accepted/rejected edges",
    "Before/after inventory",
    "Before/after monitoring state",
    "CORP.local",
    "OU=Servers,OU=<SITE>,OU=<COUNTRY>,DC=corp,DC=local",
    "ESBUR1/BUR1 hub-spoke capacity impact must be visible for shared target planning.",
    "Kubernetes auth, workload secret delivery, injector boundary, service account posture, and secret-reference behavior must be reviewed before workloads can depend on Vault.",
    "Kubernetes runtime readiness evidence must use safe summaries only and must not expose kubeconfigs, cluster identifiers, context identifiers, namespace identifiers, ingress identifiers, TLS material identifiers, workload identity identifiers, identity material, pod identifiers, image pull material, registry material, organization-scope identifiers, provider-side identifiers, private network details, sensitive auth material, raw Kubernetes payloads, or provider-returned content.",
    "Vault deployment readiness evidence must use safe summaries only and must not expose Vault URLs, namespaces, mount paths, secret paths, policy names, role names, service account token data, TLS material, root tokens, recovery keys, unseal keys, audit log lines, storage class names, tenant IDs, object IDs, private IPs, credentials, tokens, raw Vault payloads, raw Kubernetes payloads, or provider payloads.",
];
const ROUTE_SAFE_SERVICE_CLASSES: &[&str] = &[
    "access",
    "admin",
    "analytics",
    "api",
    "approvals",
    "auth",
    "catalog",
    "categories",
    "cmdb",
    "control",
    "coverage",
    "dashboard",
    "deploy",
    "docs",
    "doc",
    "evidence",
    "fixtures",
    "home",
    "hyperv",
    "identity",
    "images",
    "integrations",
    "inventory",
    "local",
    "observe",
    "operations",
    "opt",
    "patching",
    "platform",
    "portal",
    "preflight",
    "protect",
    "proxmox",
    "readiness",
    "requests",
    "scripts",
    "servicenow",
    "software",
    "source",
    "sources",
    "srv",
    "summary",
    "test",
    "tests",
    "tmp",
    "usr",
    "var",
    "veeam",
    "vmware",
    "windows",
    "workflows",
    "zabbix",
];

#[derive(Deserialize)]
struct ValidationContext {
    program: String,
    catalog: Value,
}

#[derive(Deserialize)]
struct ProgramInput {
    program: String,
    catalog: Value,
}

#[derive(Deserialize)]
struct DocsInput {
    #[serde(alias = "readme")]
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
}

#[derive(Deserialize)]
struct ScanInput {
    value: Value,
    path: String,
    scan_kind: Option<String>,
}

#[derive(Clone)]
struct RuleDetail {
    id: &'static str,
    decision: &'static str,
    requirement: &'static str,
    evidence: &'static str,
}

#[derive(Clone)]
struct ApiRule {
    id: String,
    decision: String,
    requirement: String,
    evidence: String,
}

#[derive(Clone)]
struct RouteMatch {
    start: usize,
    route: Option<String>,
    dynamic: bool,
}

struct CSharpLiteral {
    value: String,
    end: usize,
}

struct ProgramLineSegments {
    code: String,
    segments: Vec<String>,
    in_block_comment: bool,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let input = fs::read_to_string(path)
        .map_err(|error| format!("failed to read context JSON {}: {error}", path.display()))?;
    let context: ValidationContext = serde_json::from_str(&input)
        .map_err(|error| format!("invalid gMSA lifecycle context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_program_text(&context.program, &context.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid gMSA lifecycle catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid gMSA lifecycle program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid gMSA lifecycle docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid gMSA lifecycle scan JSON: {error}"))?;
    let mut errors = Vec::new();
    match payload.scan_kind.as_deref() {
        Some("test-literals") => {} // removed: Ruby file no longer exists
        _ => validate_no_prohibited_scan(&payload.value, &payload.path, &mut errors),
    }
    Ok(errors)
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let blocks = endpoint_blocks(program, errors);
    if blocks.is_empty() {
        return;
    }
    let uncommented = strip_csharp_comments(program);
    for block in blocks {
        validate_endpoint_block(&block, catalog, &uncommented, errors);
    }
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    validate_catalog_keys(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "gMSA lifecycle version must be 1",
    );
    expect(
        catalog.get("status").and_then(Value::as_str) == Some("draft"),
        errors,
        "gMSA lifecycle status must be draft",
    );
    expect(
        catalog.get("source").and_then(Value::as_str) == Some("static-seed"),
        errors,
        "gMSA lifecycle source must be static-seed",
    );
    expect(
        catalog.get("lifecycleMode").and_then(Value::as_str) == Some("review-only"),
        errors,
        "gMSA lifecycle mode must be review-only",
    );
    expect(
        catalog.get("dryRunRequired").and_then(Value::as_bool) == Some(true),
        errors,
        "gMSA lifecycle must require dry-run",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            catalog.get(field).and_then(Value::as_bool) == Some(false),
            errors,
            format!("gMSA lifecycle {field} must be disabled"),
        );
    }
    validate_required_catalog_array(catalog, "lifecycleActions", REQUIRED_ACTIONS, errors);
    validate_required_catalog_array(catalog, "reviewSignals", REQUIRED_SIGNALS, errors);
    validate_required_catalog_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_catalog_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_catalog_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_catalog_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_catalog_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_catalog_rules(catalog, errors);
    validate_no_prohibited_json(catalog, CATALOG_PATH, errors);
}

fn validate_catalog_keys(catalog: &Value, errors: &mut Vec<String>) {
    let Some(object) = catalog.as_object() else {
        errors.push("gMSA lifecycle catalog must be an object".to_string());
        return;
    };
    let required: BTreeSet<&str> = REQUIRED_CATALOG_KEYS.iter().copied().collect();
    let unexpected: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|key| !required.contains(key))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "gMSA lifecycle unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }
}

fn validate_required_catalog_array(
    catalog: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let values = catalog_array_values(catalog, field);
    expect(
        !values.is_empty(),
        errors,
        format!("{field} must be non-empty array"),
    );
    let actual: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    let required: BTreeSet<&str> = required_values.iter().copied().collect();
    let missing: Vec<&str> = required.difference(&actual).copied().collect();
    let unexpected: Vec<&str> = actual.difference(&required).copied().collect();
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
        format!("{field} values must be unique"),
    );
}

fn validate_required_catalog_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = explicit_catalog_rules(catalog);
    let rule_ids: Vec<String> = rules.iter().map(|rule| rule.id.clone()).collect();
    let actual: BTreeSet<&str> = rule_ids.iter().map(String::as_str).collect();
    let required: BTreeSet<&str> = REQUIRED_RULE_DETAILS.iter().map(|rule| rule.id).collect();
    let missing: Vec<&str> = required.difference(&actual).copied().collect();
    let unexpected: Vec<&str> = actual.difference(&required).copied().collect();
    if !missing.is_empty() {
        errors.push(format!(
            "gMSA lifecycle missing rules: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "gMSA lifecycle unexpected rules: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        rule_ids.len() == actual.len(),
        errors,
        "gMSA lifecycle rule IDs must be unique",
    );
    let mut detail_keys = BTreeSet::new();
    for rule in &rules {
        if !detail_keys.insert(format!(
            "{}\n{}\n{}",
            rule.decision, rule.requirement, rule.evidence
        )) {
            errors.push("gMSA lifecycle rule details must be unique".to_string());
        }
    }
    for expected in REQUIRED_RULE_DETAILS {
        let Some(rule) = rules.iter().find(|candidate| candidate.id == expected.id) else {
            continue;
        };
        if let Some(keys) = catalog_rule_keys(catalog, expected.id) {
            let allowed: BTreeSet<&str> = RULE_FIELD_NAMES.iter().copied().collect();
            let unexpected_keys: Vec<&str> = keys
                .iter()
                .map(String::as_str)
                .filter(|key| !allowed.contains(key))
                .collect();
            if !unexpected_keys.is_empty() {
                errors.push(format!(
                    "gMSA lifecycle rule {} has unexpected keys: {}",
                    expected.id,
                    unexpected_keys.join(", ")
                ));
            }
        }
        expect(
            rule.decision == expected.decision,
            errors,
            format!("gMSA lifecycle rule {} decision must match", expected.id),
        );
        expect(
            rule.requirement == expected.requirement,
            errors,
            format!("gMSA lifecycle rule {} requirement must match", expected.id),
        );
        expect(
            rule.evidence == expected.evidence,
            errors,
            format!("gMSA lifecycle rule {} evidence must match", expected.id),
        );
    }
}

fn validate_endpoint_block(
    block: &str,
    catalog: &Value,
    uncommented_program: &str,
    errors: &mut Vec<String>,
) {
    expect(
        exact_assignment(block, "version", "1"),
        errors,
        "API must keep catalog version",
    );
    expect(
        exact_string_assignment(block, "status", "draft"),
        errors,
        "API must keep draft status",
    );
    expect(
        exact_string_assignment(block, "source", "static-seed"),
        errors,
        "API must keep static-seed source",
    );
    expect(
        exact_string_assignment(block, "lifecycleMode", "review-only"),
        errors,
        "API must keep review-only mode",
    );
    expect(
        exact_assignment(block, "dryRunRequired", "true"),
        errors,
        "API must require dry-run",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            exact_assignment(block, field, "false"),
            errors,
            format!("API must keep {field} disabled"),
        );
    }
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_assignment(block, field, variable),
            errors,
            format!("API must bind {field} to {variable}"),
        );
        validate_api_array(
            field,
            csharp_array_values(uncommented_program, variable),
            catalog_string_array(catalog, field),
            errors,
        );
    }
    for field in ENDPOINT_INLINE_ARRAYS {
        validate_api_array(
            field,
            endpoint_inline_array_values(block, field),
            catalog_string_array(catalog, field),
            errors,
        );
    }
    validate_api_rules(block, catalog, errors);
    validate_endpoint_field_names(block, errors);
    validate_no_unsafe_true_flags(block, errors);
    validate_endpoint_prohibited_values(block, errors);
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
        "API README missing gMSA lifecycle endpoint",
    );
    expect(
        catalog_readme.contains(CATALOG_FILE),
        errors,
        "catalog README missing gMSA lifecycle catalog",
    );
    expect(
        doc_readme.contains(DOC_FILE),
        errors,
        "workflow README missing gMSA lifecycle doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "gMSA lifecycle doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "gMSA lifecycle doc must prohibit provider calls",
    );
    expect(
        doc.contains("No worker execution."),
        errors,
        "gMSA lifecycle doc must prohibit worker execution",
    );
    expect(
        doc.contains("No live directory changes."),
        errors,
        "gMSA lifecycle doc must prohibit directory changes",
    );
    expect(
        doc.contains("No gMSA creation, assignment, validation, retire, password retrieval, managed password handling, SPN changes, or delegation changes."),
        errors,
        "gMSA lifecycle doc must prohibit gMSA actions",
    );
    expect(
        doc.contains("static gMSA lifecycle summaries only"),
        errors,
        "gMSA lifecycle doc must require static summaries",
    );
}

fn endpoint_blocks(program: &str, errors: &mut Vec<String>) -> Vec<String> {
    let uncommented = strip_csharp_comments(program);
    let matches = mapget_route_matches(program, &uncommented);
    for route_match in matches.iter().filter(|route_match| route_match.dynamic) {
        let _ = route_match;
        errors.push("API has dynamic MapGet route; static literal routes required".to_string());
    }
    let starts: Vec<usize> = matches
        .iter()
        .filter(|route_match| route_match.route.as_deref() == Some(ENDPOINT))
        .map(|route_match| route_match.start)
        .collect();
    if starts.is_empty() {
        errors.push("API missing gMSA lifecycle endpoint".to_string());
        return Vec::new();
    }
    if starts.len() > 1 {
        errors.push("API has duplicate gMSA lifecycle endpoints".to_string());
    }
    let all_starts: Vec<usize> = matches
        .iter()
        .map(|route_match| route_match.start)
        .collect();
    starts
        .into_iter()
        .map(|start| {
            let end = all_starts
                .iter()
                .copied()
                .filter(|candidate| *candidate > start)
                .min()
                .unwrap_or(program.len());
            program[start..end].to_string()
        })
        .collect()
}

fn mapget_route_matches(program: &str, uncommented: &str) -> Vec<RouteMatch> {
    let code = csharp_code_mask(uncommented);
    let mut matches = Vec::new();
    let mut index = 0usize;
    while let Some((start, paren)) = next_mapget_call(&code, index) {
        let route_start = skip_ascii_whitespace(program, paren + 1);
        let (route, dynamic) = route_argument_value(program, route_start, start);
        matches.push(RouteMatch {
            start,
            route,
            dynamic,
        });
        index = paren + 1;
    }
    matches
}

fn next_mapget_call(code: &str, start_index: usize) -> Option<(usize, usize)> {
    let mut index = start_index;
    while let Some(start) = identifier_match(code, "app", index) {
        let dot = skip_ascii_whitespace(code, start + 3);
        if code.as_bytes().get(dot) != Some(&b'.') {
            index = start + 3;
            continue;
        }
        let name = skip_ascii_whitespace(code, dot + 1);
        if !identifier_at(code, name, "MapGet") {
            index = start + 3;
            continue;
        }
        let paren = skip_ascii_whitespace(code, name + "MapGet".len());
        if code.as_bytes().get(paren) == Some(&b'(') {
            return Some((start, paren));
        }
        index = start + 3;
    }
    None
}

fn route_argument_value(
    program: &str,
    route_start: usize,
    before: usize,
) -> (Option<String>, bool) {
    if let Some(literal) = csharp_literal_at(program, route_start, true) {
        let after = skip_ascii_whitespace(program, literal.end);
        return (
            Some(literal.value),
            program.as_bytes().get(after) != Some(&b','),
        );
    }
    let Some((identifier, end)) = identifier_value_at(program, route_start) else {
        return (None, true);
    };
    let after = skip_ascii_whitespace(program, end);
    if program.as_bytes().get(after) != Some(&b',') {
        return (None, true);
    }
    match static_route_value(program, &identifier, before) {
        Some(route) => (Some(route), false),
        None => (None, true),
    }
}

fn static_route_value(program: &str, variable: &str, before: usize) -> Option<String> {
    let prefix = &program[..before];
    let masked = csharp_code_mask(&strip_csharp_comments(prefix));
    let mut index = 0usize;
    while let Some(start) = identifier_match(&masked, variable, index) {
        if declaration_prefix_ok(&masked, start) {
            let equals = skip_ascii_whitespace(prefix, start + variable.len());
            if prefix.as_bytes().get(equals) == Some(&b'=') {
                let value_start = skip_ascii_whitespace(prefix, equals + 1);
                if let Some(literal) = csharp_literal_at(prefix, value_start, false) {
                    return Some(literal.value);
                }
            }
        }
        index = start + variable.len();
    }
    None
}

fn declaration_prefix_ok(masked: &str, variable_start: usize) -> bool {
    let statement_start = masked[..variable_start]
        .rfind([';', '\n'])
        .map(|position| position + 1)
        .unwrap_or(0);
    let before = masked[statement_start..variable_start].trim();
    let tokens: Vec<&str> = before.split_whitespace().collect();
    tokens
        .last()
        .is_some_and(|token| *token == "string" || *token == "var")
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
    let actual: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    let catalog: BTreeSet<&str> = catalog_values.iter().map(String::as_str).collect();
    let missing: Vec<&str> = catalog.difference(&actual).copied().collect();
    let unexpected: Vec<&str> = actual.difference(&catalog).copied().collect();
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
        format!("API {field} values must be unique"),
    );
    for value in values {
        if safe_text_value(&value) {
            continue;
        }
        if prohibited_field(&value) {
            errors.push(format!(
                "API {field} contains prohibited gMSA lifecycle value {value}"
            ));
        }
        if let Some(phrase) = prohibited_phrase(&value) {
            errors.push(format!(
                "API {field} contains prohibited gMSA lifecycle phrase {phrase}"
            ));
        }
    }
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let api_rules = api_rules(block);
    let catalog_rules = catalog_rules(catalog);
    let api_ids: Vec<String> = api_rules.iter().map(|rule| rule.id.clone()).collect();
    let catalog_ids: Vec<String> = catalog_rules.iter().map(|rule| rule.id.clone()).collect();
    let api_set: BTreeSet<&str> = api_ids.iter().map(String::as_str).collect();
    let catalog_set: BTreeSet<&str> = catalog_ids.iter().map(String::as_str).collect();
    for id in catalog_set.difference(&api_set) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_set.difference(&catalog_set) {
        errors.push(format!("API has unexpected API rule {id}"));
    }
    expect(
        api_ids.len() == api_set.len(),
        errors,
        "API rule IDs must be unique",
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
    for rule in api_rules {
        for field in object_assignment_fields(&rule_source(block, &rule.id)) {
            if !RULE_FIELD_NAMES.contains(&field.as_str()) {
                errors.push(format!(
                    "API rule has unexpected gMSA lifecycle field {field}"
                ));
            }
        }
    }
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    for field in assignment_fields_at_depth(block, 1) {
        if RULE_FIELD_NAMES.contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has misplaced gMSA lifecycle rule field {field}"
            ));
            continue;
        }
        if !TOP_LEVEL_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has unexpected gMSA lifecycle field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited gMSA lifecycle field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for (field, value) in assignment_values(block) {
        if value != "true" || field == "dryRunRequired" {
            continue;
        }
        let normalized = field.to_ascii_lowercase();
        if [
            "live",
            "provider",
            "worker",
            "gmsa",
            "assignment",
            "validation",
            "retrieval",
            "password",
            "managed",
            "spn",
            "delegation",
            "raw",
            "log",
            "row",
            "serial",
            "recipient",
            "principal",
            "distinguished",
            "domain",
            "object",
            "security",
            "target",
            "credential",
            "payload",
        ]
        .iter()
        .any(|term| normalized.contains(term))
        {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn validate_endpoint_prohibited_values(block: &str, errors: &mut Vec<String>) {
    for (line, literal) in csharp_string_literals_with_lines(block) {
        if literal == ENDPOINT || safe_text_value(&literal) {
            continue;
        }
        if contains_prohibited_value(&literal) {
            errors.push(format!(
                "API endpoint line {line} contains prohibited value"
            ));
        }
    }
}

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = {value},");
    block.lines().any(|line| line.trim() == expected)
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    exact_assignment(block, field, &format!("\"{value}\""))
}

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    let masked = csharp_code_mask(program);
    let mut index = 0usize;
    while let Some(start) = identifier_match(&masked, variable, index) {
        if declaration_prefix_ok(&masked, start) {
            let equals = skip_ascii_whitespace(program, start + variable.len());
            let after_equals = skip_ascii_whitespace(program, equals + 1);
            if program.as_bytes().get(equals) == Some(&b'=')
                && starts_with_new_array(&masked, after_equals)
            {
                let open = masked[after_equals..]
                    .find('{')
                    .map(|offset| after_equals + offset)?;
                let close = matching_delimiter_index(&masked, open, b'{', b'}')?;
                return Some(csharp_string_literals(&program[(open + 1)..close]));
            }
        }
        index = start + variable.len();
    }
    None
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    let masked = csharp_code_mask(block);
    let mut index = 0usize;
    while let Some(start) = identifier_match(&masked, field, index) {
        let equals = skip_ascii_whitespace(&masked, start + field.len());
        let after_equals = skip_ascii_whitespace(&masked, equals + 1);
        if masked.as_bytes().get(equals) == Some(&b'=')
            && starts_with_new_array(&masked, after_equals)
        {
            let open = masked[after_equals..]
                .find('{')
                .map(|offset| after_equals + offset)?;
            let close = matching_delimiter_index(&masked, open, b'{', b'}')?;
            return Some(csharp_string_literals(&block[(open + 1)..close]));
        }
        index = start + field.len();
    }
    None
}

fn starts_with_new_array(masked: &str, index: usize) -> bool {
    let after_new = if identifier_at(masked, index, "new") {
        skip_ascii_whitespace(masked, index + 3)
    } else {
        return false;
    };
    masked[after_new..].starts_with("[]")
}

fn api_rules(block: &str) -> Vec<ApiRule> {
    block
        .lines()
        .filter(|line| line.contains("new") && line.contains("id") && line.contains("decision"))
        .filter_map(parse_rule_line)
        .collect()
}

fn parse_rule_line(line: &str) -> Option<ApiRule> {
    let id = assignment_string_value(line, "id")?;
    let decision = assignment_string_value(line, "decision")?;
    let requirement = assignment_string_value(line, "requirement")?;
    let evidence = assignment_string_value(line, "evidence")?;
    Some(ApiRule {
        id,
        decision,
        requirement,
        evidence,
    })
}

fn assignment_string_value(line: &str, field: &str) -> Option<String> {
    let masked = csharp_code_mask(line);
    let start = identifier_match(&masked, field, 0)?;
    let equals = skip_ascii_whitespace(&masked, start + field.len());
    if masked.as_bytes().get(equals) != Some(&b'=') {
        return None;
    }
    let value_start = skip_ascii_whitespace(line, equals + 1);
    csharp_literal_at(line, value_start, false).map(|literal| literal.value)
}

fn rule_source(block: &str, id: &str) -> String {
    block
        .lines()
        .find(|line| line.contains(id) && line.contains("new"))
        .unwrap_or_default()
        .to_string()
}

fn object_assignment_fields(line: &str) -> Vec<String> {
    let masked = decode_csharp_identifier_escapes(&csharp_code_mask(line));
    let Some(open) = masked.find('{') else {
        return Vec::new();
    };
    let close = masked.rfind('}').unwrap_or(masked.len());
    let mut fields = Vec::new();
    let mut index = open + 1;
    while index < close {
        if let Some((identifier, end)) = identifier_value_at(&masked, index) {
            let equals = skip_ascii_whitespace(&masked, end);
            if equals < close && masked.as_bytes().get(equals) == Some(&b'=') {
                fields.push(identifier);
                index = equals + 1;
                continue;
            }
            index = end;
        } else {
            index += 1;
        }
    }
    fields
}

fn assignment_fields_at_depth(block: &str, target_depth: usize) -> Vec<String> {
    let code = decode_csharp_identifier_escapes(&csharp_code_mask(block));
    let bytes = code.as_bytes();
    let mut fields = Vec::new();
    let mut depth = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'{' => {
                depth += 1;
                index += 1;
            }
            b'}' => {
                depth = depth.saturating_sub(1);
                index += 1;
            }
            _ if depth == target_depth && is_identifier_start(bytes[index]) => {
                let start = index;
                index += 1;
                while index < bytes.len() && is_identifier_continue(bytes[index]) {
                    index += 1;
                }
                let equals = skip_ascii_whitespace(&code, index);
                if code.as_bytes().get(equals) == Some(&b'=')
                    && code.as_bytes().get(equals + 1) != Some(&b'=')
                {
                    fields.push(code[start..index].to_string());
                    index = equals + 1;
                }
            }
            _ => index += 1,
        }
    }
    fields
}

fn assignment_values(block: &str) -> Vec<(String, String)> {
    let code = decode_csharp_identifier_escapes(&csharp_code_mask(block));
    let bytes = code.as_bytes();
    let mut values = Vec::new();
    let mut index = 0usize;
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
        let equals = skip_ascii_whitespace(&code, index);
        if code.as_bytes().get(equals) != Some(&b'=')
            || code.as_bytes().get(equals + 1) == Some(&b'=')
        {
            continue;
        }
        let value_start = skip_ascii_whitespace(&code, equals + 1);
        if let Some((value, end)) = identifier_value_at(&code, value_start) {
            values.push((code[start..index].to_string(), value));
            index = end;
        }
    }
    values
}

fn catalog_rules(catalog: &Value) -> Vec<ApiRule> {
    catalog
        .get("rules")
        .and_then(Value::as_array)
        .map(|rules| {
            rules
                .iter()
                .filter_map(|rule| {
                    Some(ApiRule {
                        id: rule.get("id")?.as_str()?.to_string(),
                        decision: rule.get("decision")?.as_str()?.to_string(),
                        requirement: rule.get("requirement")?.as_str()?.to_string(),
                        evidence: rule.get("evidence")?.as_str()?.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_else(|| {
            REQUIRED_RULE_DETAILS
                .iter()
                .map(|rule| ApiRule {
                    id: rule.id.to_string(),
                    decision: rule.decision.to_string(),
                    requirement: rule.requirement.to_string(),
                    evidence: rule.evidence.to_string(),
                })
                .collect()
        })
}

fn explicit_catalog_rules(catalog: &Value) -> Vec<ApiRule> {
    catalog
        .get("rules")
        .and_then(Value::as_array)
        .map(|rules| {
            rules
                .iter()
                .filter_map(|rule| {
                    Some(ApiRule {
                        id: rule.get("id")?.as_str()?.to_string(),
                        decision: rule.get("decision")?.as_str()?.to_string(),
                        requirement: rule.get("requirement")?.as_str()?.to_string(),
                        evidence: rule.get("evidence")?.as_str()?.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn catalog_rule_keys(catalog: &Value, id: &str) -> Option<Vec<String>> {
    catalog
        .get("rules")?
        .as_array()?
        .iter()
        .find(|rule| rule.get("id").and_then(Value::as_str) == Some(id))?
        .as_object()
        .map(|object| object.keys().cloned().collect())
}

fn catalog_array_values(catalog: &Value, field: &str) -> Vec<String> {
    match catalog.get(field) {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        Some(Value::String(value)) => vec![value.to_string()],
        _ => Vec::new(),
    }
}

fn catalog_string_array(catalog: &Value, field: &str) -> Vec<String> {
    catalog
        .get(field)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn validate_no_prohibited_json(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let child_path = format!("{path}.{key}");
                validate_no_prohibited_text(key, &child_path, errors);
                validate_no_prohibited_json(child, &child_path, errors);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_no_prohibited_json(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => validate_no_prohibited_text(text, path, errors),
        _ => {}
    }
}

fn validate_no_prohibited_scan(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let child_path = format!("{path}.{key}");
                if prohibited_field(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited gMSA lifecycle field"
                    ));
                }
                validate_no_prohibited_scan(child, &child_path, errors);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_no_prohibited_scan(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => {
            if whole_file_text(path, text) {
                if gmsa_text_path(path) {
                    validate_text_terms(text, path, errors);
                }
                return;
            }
            validate_no_prohibited_text(text, path, errors);
        }
        _ => {}
    }
}

fn validate_no_prohibited_text(text: &str, path: &str, errors: &mut Vec<String>) {
    if safe_text_value(text) {
        return;
    }
    if prohibited_field(text) {
        errors.push(format!(
            "{path} contains prohibited gMSA lifecycle field {text}"
        ));
    }
    if let Some(phrase) = prohibited_phrase(text) {
        errors.push(format!(
            "{path} contains prohibited gMSA lifecycle phrase {phrase}"
        ));
    }
    if contains_prohibited_value(text) {
        errors.push(format!("{path} contains prohibited value"));
    }
}

fn validate_text_terms(text: &str, path: &str, errors: &mut Vec<String>) {
    if path.ends_with(PROGRAM_PATH) {
        validate_program_text_terms(text, path, errors);
        return;
    }

    for (line_index, line) in text.lines().enumerate() {
        if !gmsa_text_line(path, line) || safe_text_line(line) {
            continue;
        }
        if let Some(phrase) = prohibited_phrase(line) {
            errors.push(format!(
                "{path}:{} contains prohibited gMSA lifecycle phrase {phrase}",
                line_index + 1
            ));
        }
        if contains_prohibited_text_value(line) {
            errors.push(format!(
                "{path}:{} contains prohibited value",
                line_index + 1
            ));
        }
        for term in split_tokens(line, |ch| {
            ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'
        }) {
            if prohibited_field(term) {
                errors.push(format!(
                    "{path}:{} contains prohibited gMSA lifecycle field {term}",
                    line_index + 1
                ));
            }
        }
    }
}

fn validate_program_text_terms(text: &str, path: &str, errors: &mut Vec<String>) {
    validate_csharp_string_literal_terms(text, path, errors);
    let mut in_block_comment = false;
    let mut gmsa_context_depth = 0isize;
    for (line_index, line) in text.lines().enumerate() {
        let parsed = program_line_segments(line, in_block_comment);
        in_block_comment = parsed.in_block_comment;
        let normalized_code = decode_csharp_identifier_escapes(&parsed.code);
        if normalized_code.contains("app.MapGet")
            && !parsed
                .segments
                .iter()
                .any(|segment| segment.contains("gMSA") || segment.contains(ENDPOINT))
        {
            gmsa_context_depth = 0;
        }
        let has_gmsa_context = gmsa_context_depth != 0
            || program_line_has_gmsa_context(&normalized_code, &parsed.segments);
        validate_program_segments(
            line,
            &normalized_code,
            &parsed.segments,
            has_gmsa_context,
            path,
            line_index + 1,
            errors,
        );
        gmsa_context_depth =
            next_gmsa_context_depth(&normalized_code, has_gmsa_context, gmsa_context_depth);
    }
}

fn validate_csharp_string_literal_terms(text: &str, path: &str, errors: &mut Vec<String>) {
    for (line, literal) in csharp_string_literals_with_lines(text) {
        if safe_text_value(&literal) || SAFE_PROGRAM_TEXT_SEGMENTS.contains(&literal.as_str()) {
            continue;
        }
        if local_api_route(&literal) {
            if route_prohibited_value(&literal) {
                errors.push(format!("{path}:{line} contains prohibited value"));
            }
            continue;
        }
        if contains_prohibited_value(&literal) {
            errors.push(format!("{path}:{line} contains prohibited value"));
        }
    }
}

fn program_line_segments(line: &str, mut in_block_comment: bool) -> ProgramLineSegments {
    let mut code = String::new();
    let mut segments = Vec::new();
    let mut position = 0usize;
    while position < line.len() {
        if in_block_comment {
            if let Some(offset) = line[position..].find("*/") {
                let block_end = position + offset;
                segments.push(line[position..block_end].to_string());
                position = block_end + 2;
                in_block_comment = false;
            } else {
                segments.push(line[position..].to_string());
                position = line.len();
            }
            continue;
        }
        if let Some(literal) = csharp_literal_at(line, position, false) {
            segments.push(literal.value);
            code.push(' ');
            position = literal.end;
            continue;
        }
        if line.as_bytes().get(position) == Some(&b'/')
            && line.as_bytes().get(position + 1) == Some(&b'/')
        {
            segments.push(line[(position + 2)..].to_string());
            position = line.len();
            continue;
        }
        if line.as_bytes().get(position) == Some(&b'/')
            && line.as_bytes().get(position + 1) == Some(&b'*')
        {
            if let Some(offset) = line[(position + 2)..].find("*/") {
                let block_end = position + 2 + offset;
                segments.push(line[(position + 2)..block_end].to_string());
                position = block_end + 2;
            } else {
                segments.push(line[(position + 2)..].to_string());
                in_block_comment = true;
                position = line.len();
            }
            continue;
        }
        code.push(line.as_bytes()[position] as char);
        position += 1;
    }
    ProgramLineSegments {
        code,
        segments,
        in_block_comment,
    }
}

fn validate_program_segments(
    line: &str,
    code: &str,
    segments: &[String],
    has_gmsa_context: bool,
    path: &str,
    line_number: usize,
    errors: &mut Vec<String>,
) {
    for segment in segments {
        if segment == ENDPOINT
            || safe_text_value(segment)
            || SAFE_PROGRAM_TEXT_SEGMENTS.contains(&segment.as_str())
        {
            continue;
        }
        if local_api_route(segment) {
            if route_prohibited_value(segment) {
                errors.push(format!("{path}:{line_number} contains prohibited value"));
            }
            continue;
        }
        if contains_prohibited_value(segment) {
            errors.push(format!("{path}:{line_number} contains prohibited value"));
        }
        let segment_has_context =
            has_gmsa_context || segment.contains("gMSA") || segment.contains(ENDPOINT);
        if !segment_has_context {
            continue;
        }
        if let Some(phrase) = prohibited_phrase(segment) {
            errors.push(format!(
                "{path}:{line_number} contains prohibited gMSA lifecycle phrase {phrase}"
            ));
        }
        if prohibited_field(segment) {
            errors.push(format!(
                "{path}:{line_number} contains prohibited gMSA lifecycle value {segment}"
            ));
        }
    }
    if safe_text_line(line) || !has_gmsa_context {
        return;
    }
    for term in split_tokens(code, |ch| {
        ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'
    }) {
        if prohibited_field(term) {
            errors.push(format!(
                "{path}:{line_number} contains prohibited gMSA lifecycle field {term}"
            ));
        }
    }
}

fn program_line_has_gmsa_context(code: &str, segments: &[String]) -> bool {
    let lower = code.to_ascii_lowercase();
    [
        "gmsa",
        "spn",
        "serviceaccount",
        "managedpassword",
        "passwordretrieval",
        "retrievalscope",
        "kerberos",
        "workerusage",
        "kds",
    ]
    .iter()
    .any(|term| lower.contains(term))
        || segments
            .iter()
            .any(|segment| segment.contains("gMSA") || segment.contains(ENDPOINT))
}

fn next_gmsa_context_depth(code: &str, has_gmsa_context: bool, current_depth: isize) -> isize {
    if !has_gmsa_context && current_depth == 0 {
        return 0;
    }
    let open_count = code.matches('{').count() as isize;
    let close_count = code.matches('}').count() as isize;
    let mut depth = if current_depth == -1 {
        (open_count - close_count).max(0)
    } else {
        (current_depth + open_count - close_count).max(0)
    };
    if has_gmsa_context && depth == 0 && !code.contains(';') {
        depth = -1;
    } else if !has_gmsa_context && current_depth > 0 && code.contains(';') {
        depth = 0;
    }
    depth
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|extension| path.ends_with(extension))
}

fn gmsa_text_path(path: &str) -> bool {
    [
        PROGRAM_PATH,
        CATALOG_PATH,
        DOC_PATH,
        API_README_PATH,
        CATALOG_README_PATH,
        DOC_README_PATH,
    ]
    .iter()
    .any(|text_path| path.ends_with(text_path))
}

fn gmsa_text_line(path: &str, line: &str) -> bool {
    path.ends_with(CATALOG_PATH)
        || path.ends_with(DOC_PATH)
        || line.contains("gMSA")
        || line.contains("service account")
        || line.contains(ENDPOINT)
}

fn safe_text_line(line: &str) -> bool {
    let stripped = line.trim();
    if SAFE_TEXT_PROHIBITION_LINES.contains(&stripped) || safe_csharp_rule_line(stripped) {
        return true;
    }
    if let Some((field, value)) = stripped.split_once(':') {
        if REQUIRED_DISABLED_FIELDS.contains(&field.trim()) && value.trim() == "false" {
            return true;
        }
    }
    [
        stripped.strip_prefix("- ").unwrap_or(stripped),
        stripped.strip_prefix("- id: ").unwrap_or(stripped),
        stripped.strip_prefix("requirement: ").unwrap_or(stripped),
        stripped.strip_prefix("evidence: ").unwrap_or(stripped),
    ]
    .iter()
    .any(|value| safe_text_value(value))
}

fn safe_csharp_rule_line(line: &str) -> bool {
    let Some(rule) = parse_rule_line(line) else {
        return false;
    };
    REQUIRED_RULE_DETAILS.iter().any(|expected| {
        rule.id == expected.id
            && rule.decision == expected.decision
            && rule.requirement == expected.requirement
            && rule.evidence == expected.evidence
    })
}

fn local_api_route(segment: &str) -> bool {
    segment.starts_with("/api/")
        && segment.chars().all(|ch| {
            ch.is_ascii_alphanumeric()
                || matches!(
                    ch,
                    '/' | '{' | '}' | '.' | '_' | '-' | ':' | '?' | '&' | '=' | '+'
                )
        })
}

fn route_prohibited_value(route: &str) -> bool {
    contains_url_scheme(route)
        || contains_private_ipv4(route)
        || contains_private_ipv6(route)
        || contains_uuid(route)
        || contains_sid(route)
        || contains_distinguished_name(route)
        || contains_secret_assignment(&route.to_ascii_lowercase())
        || contains_dns_value(route)
        || route_spn_value(route)
}

fn route_spn_value(route: &str) -> bool {
    let segments: Vec<&str> = route.trim_start_matches('/').split('/').collect();
    segments.windows(2).any(|pair| {
        is_route_spn_service(pair[0]) && pair[1].split(':').next().is_some_and(is_spn_target)
    })
}

fn is_route_spn_service(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    !ROUTE_SAFE_SERVICE_CLASSES.contains(&lower.as_str())
        && value.chars().enumerate().all(|(index, ch)| {
            if index == 0 {
                ch.is_ascii_alphabetic()
            } else {
                ch.is_ascii_alphanumeric()
            }
        })
        && is_spn_service(value)
}

fn strip_csharp_comments(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if let Some(literal) = csharp_literal_at(text, index, false) {
            output.push_str(&text[index..literal.end]);
            index = literal.end;
            continue;
        }
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            let start = index;
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            for _ in start..index {
                output.push(' ');
            }
            continue;
        }
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            let start = index;
            index += 2;
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                index += 1;
            }
            index = (index + 2).min(bytes.len());
            for byte in text[start..index].bytes() {
                output.push(if byte == b'\n' { '\n' } else { ' ' });
            }
            continue;
        }
        output.push(bytes[index] as char);
        index += 1;
    }
    output
}

fn csharp_code_mask(text: &str) -> String {
    let mut output = text.as_bytes().to_vec();
    let bytes = text.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if let Some(literal) = csharp_literal_at(text, index, false) {
            mask_range(&mut output, index, literal.end);
            index = literal.end;
            continue;
        }
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            let start = index;
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            mask_range(&mut output, start, index);
            continue;
        }
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            let start = index;
            index += 2;
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                index += 1;
            }
            index = (index + 2).min(bytes.len());
            mask_range(&mut output, start, index);
            continue;
        }
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn mask_range(output: &mut [u8], start: usize, end: usize) {
    let capped_end = end.min(output.len());
    for byte in &mut output[start..capped_end] {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

fn csharp_literal_at(text: &str, index: usize, skip_whitespace: bool) -> Option<CSharpLiteral> {
    let mut cursor = index;
    while skip_whitespace && cursor < text.len() && text.as_bytes()[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    let prefix_start = cursor;
    while cursor < text.len() && matches!(text.as_bytes()[cursor], b'$' | b'@') {
        cursor += 1;
    }
    if text.as_bytes().get(cursor) != Some(&b'"') {
        return None;
    }
    let verbatim = text[prefix_start..cursor].contains('@');
    let quote_count = text[cursor..]
        .bytes()
        .take_while(|byte| *byte == b'"')
        .count();
    if quote_count >= 3 {
        let delimiter = "\"".repeat(quote_count);
        let content_start = cursor + quote_count;
        let content_end = text[content_start..]
            .find(&delimiter)
            .map(|offset| content_start + offset)?;
        return Some(CSharpLiteral {
            value: text[content_start..content_end].trim().to_string(),
            end: content_end + quote_count,
        });
    }
    let mut position = cursor + 1;
    let mut value = String::new();
    while position < text.len() {
        let byte = text.as_bytes()[position];
        if verbatim {
            if byte == b'"' && text.as_bytes().get(position + 1) == Some(&b'"') {
                value.push('"');
                position += 2;
                continue;
            }
            if byte == b'"' {
                return Some(CSharpLiteral {
                    value,
                    end: position + 1,
                });
            }
            value.push(byte as char);
            position += 1;
            continue;
        }
        if byte == b'\\' {
            let (decoded, end) = decode_csharp_escape(text, position);
            value.push(decoded);
            position = end;
            continue;
        }
        if byte == b'"' {
            return Some(CSharpLiteral {
                value,
                end: position + 1,
            });
        }
        value.push(byte as char);
        position += 1;
    }
    None
}

fn decode_csharp_escape(text: &str, backslash: usize) -> (char, usize) {
    let bytes = text.as_bytes();
    let Some(marker) = bytes.get(backslash + 1).copied() else {
        return (' ', backslash + 1);
    };
    match marker {
        b'x' => {
            let end = hex_escape_end(text, backslash + 2, 4);
            let value = u32::from_str_radix(&text[(backslash + 2)..end], 16).unwrap_or(b' ' as u32);
            (char::from_u32(value).unwrap_or(' '), end)
        }
        b'u' => {
            let end = (backslash + 6).min(text.len());
            let value = u32::from_str_radix(&text[(backslash + 2)..end], 16).unwrap_or(b' ' as u32);
            (char::from_u32(value).unwrap_or(' '), end)
        }
        b'U' => {
            let end = (backslash + 10).min(text.len());
            let value = u32::from_str_radix(&text[(backslash + 2)..end], 16).unwrap_or(b' ' as u32);
            (char::from_u32(value).unwrap_or(' '), end)
        }
        b'/' => ('/', backslash + 2),
        b'.' => ('.', backslash + 2),
        b'n' | b'r' | b't' | b'"' | b'\'' | b'\\' => (' ', backslash + 2),
        _ => (marker as char, backslash + 2),
    }
}

fn hex_escape_end(text: &str, start: usize, max_len: usize) -> usize {
    let mut end = start;
    while end < text.len() && end - start < max_len && text.as_bytes()[end].is_ascii_hexdigit() {
        end += 1;
    }
    if end == start {
        start
    } else {
        end
    }
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let mut index = 0usize;
    while index < text.len() {
        if let Some(literal) = csharp_literal_at(text, index, false) {
            literals.push(literal.value);
            index = literal.end;
        } else {
            index += 1;
        }
    }
    literals
}

fn csharp_string_literals_with_lines(text: &str) -> Vec<(usize, String)> {
    let mut literals = Vec::new();
    let mut index = 0usize;
    let mut line = 1usize;
    while index < text.len() {
        if let Some(literal) = csharp_literal_at(text, index, false) {
            literals.push((line, literal.value));
            line += text[index..literal.end]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count();
            index = literal.end;
        } else {
            if text.as_bytes()[index] == b'\n' {
                line += 1;
            }
            index += 1;
        }
    }
    literals
}

fn decode_csharp_identifier_escapes(text: &str) -> String {
    let mut output = String::new();
    let mut index = 0usize;
    while index < text.len() {
        if text.as_bytes()[index] == b'\\'
            && matches!(text.as_bytes().get(index + 1), Some(b'u' | b'U'))
        {
            let (decoded, end) = decode_csharp_escape(text, index);
            output.push(decoded);
            index = end;
        } else {
            output.push(text.as_bytes()[index] as char);
            index += 1;
        }
    }
    output
}

fn matching_delimiter_index(source: &str, start: usize, open: u8, close: u8) -> Option<usize> {
    if source.as_bytes().get(start) != Some(&open) {
        return None;
    }
    let mut depth = 0usize;
    for (index, byte) in source.as_bytes().iter().enumerate().skip(start) {
        if *byte == open {
            depth += 1;
        } else if *byte == close {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn safe_text_value(value: &str) -> bool {
    REQUIRED_ACTIONS.contains(&value)
        || REQUIRED_SIGNALS.contains(&value)
        || REQUIRED_INPUTS.contains(&value)
        || REQUIRED_GUARDS.contains(&value)
        || REQUIRED_PLAN_SECTIONS.contains(&value)
        || REQUIRED_BLOCKED_REASONS.contains(&value)
        || REQUIRED_EVIDENCE.contains(&value)
        || REQUIRED_DISABLED_FIELDS.contains(&value)
        || REQUIRED_CATALOG_KEYS.contains(&value)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, variable)| *variable == value)
        || REQUIRED_RULE_DETAILS.iter().any(|rule| {
            value == rule.id
                || value == rule.decision
                || value == rule.requirement
                || value == rule.evidence
        })
        || matches!(value, "draft" | "static-seed" | "review-only" | "block")
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize_identifier(value);
    if safe_normalized_values().contains(normalized.as_str()) {
        return false;
    }
    PROHIBITED_FIELD_TOKENS
        .iter()
        .any(|token| normalized.contains(token))
}

fn safe_normalized_values() -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    for value in REQUIRED_ACTIONS
        .iter()
        .chain(REQUIRED_SIGNALS)
        .chain(REQUIRED_INPUTS)
        .chain(REQUIRED_GUARDS)
        .chain(REQUIRED_PLAN_SECTIONS)
        .chain(REQUIRED_BLOCKED_REASONS)
        .chain(REQUIRED_EVIDENCE)
        .chain(REQUIRED_DISABLED_FIELDS)
        .chain(REQUIRED_CATALOG_KEYS)
    {
        values.insert(normalize_identifier(value));
    }
    for (_, variable) in ENDPOINT_ARRAY_BINDINGS {
        values.insert(normalize_identifier(variable));
    }
    for rule in REQUIRED_RULE_DETAILS {
        values.insert(normalize_identifier(rule.id));
        values.insert(normalize_identifier(rule.decision));
        values.insert(normalize_identifier(rule.requirement));
        values.insert(normalize_identifier(rule.evidence));
    }
    for value in ["draft", "static-seed", "review-only", "block"] {
        values.insert(normalize_identifier(value));
    }
    values
}

fn prohibited_phrase(value: &str) -> Option<&'static str> {
    let normalized = value
        .to_ascii_lowercase()
        .replace(['_', '-'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    [
        ("gMSA name", "gmsa name"),
        ("service account name", "service account name"),
        (
            "managed service account name",
            "managed service account name",
        ),
        ("DNS host name", "dns host name"),
        ("host name", "host name"),
        ("FQDN", "fqdn"),
        ("sAMAccountName", "samaccountname"),
        ("SPN", "spn"),
        (
            "allowed password-retrieval principal",
            "allowed password retrieval principal",
        ),
        (
            "password retrieval principal",
            "password retrieval principal",
        ),
        ("distinguished name", "distinguished name"),
        ("domain name", "domain name"),
        ("service principal name", "service principal name"),
        ("object GUID", "object guid"),
        ("object SID", "object sid"),
        ("security identifier", "security identifier"),
        ("principal ID", "principal id"),
        ("user name", "user name"),
        ("group name", "group name"),
        ("tenant ID", "tenant id"),
        ("object ID", "object id"),
        ("private IP", "private ip"),
        ("managed password material", "managed password material"),
        ("raw service account data", "raw service account data"),
        ("raw logs", "raw logs"),
        ("raw log content", "raw log content"),
        ("raw rows", "raw rows"),
        ("serial number", "serial number"),
        ("raw recipient data", "raw recipient data"),
        ("provider payload", "provider payload"),
        ("credential value", "credential value"),
        ("secret value", "secret value"),
        ("access token", "access token"),
    ]
    .into_iter()
    .find_map(|(phrase, needle)| normalized.contains(needle).then_some(phrase))
}

fn contains_prohibited_value(value: &str) -> bool {
    let text = value.trim_matches(|ch: char| ch.is_ascii_punctuation() && ch != '/' && ch != ':');
    let lower = text.to_ascii_lowercase();
    contains_akia(text)
        || lower.contains("-----begin ") && lower.contains("private key-----")
        || contains_url_scheme(text)
        || contains_private_ipv4(text)
        || contains_private_ipv6(text)
        || contains_uuid(text)
        || contains_sid(text)
        || contains_distinguished_name(text)
        || contains_secret_assignment(&lower)
        || contains_spn_value(text)
        || contains_dns_value(text)
}

fn contains_prohibited_text_value(value: &str) -> bool {
    let text = value.trim_matches(|ch: char| ch.is_ascii_punctuation() && ch != '/' && ch != ':');
    let lower = text.to_ascii_lowercase();
    contains_akia(text)
        || lower.contains("-----begin ") && lower.contains("private key-----")
        || contains_url_scheme(text)
        || contains_private_ipv4(text)
        || contains_private_ipv6(text)
        || contains_uuid(text)
        || contains_sid(text)
        || contains_distinguished_name(text)
        || contains_secret_assignment(&lower)
        || contains_spn_value(text)
        || contains_text_dns_value(text)
}

fn contains_akia(value: &str) -> bool {
    value
        .to_ascii_uppercase()
        .as_bytes()
        .windows(20)
        .any(|window| window.starts_with(b"AKIA") && window.iter().all(u8::is_ascii_alphanumeric))
}

fn contains_url_scheme(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let Some(index) = token.find("://") else {
            return false;
        };
        let scheme = &token[..index];
        !scheme.is_empty()
            && scheme.chars().enumerate().all(|(position, ch)| {
                if position == 0 {
                    ch.is_ascii_alphabetic()
                } else {
                    ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-')
                }
            })
    })
}

fn contains_private_ipv4(value: &str) -> bool {
    for token in split_tokens(value, |ch| ch.is_ascii_digit() || ch == '.') {
        let octets: Vec<u16> = token
            .split('.')
            .filter_map(|part| part.parse::<u16>().ok())
            .collect();
        if octets.len() == 4
            && octets.iter().all(|octet| *octet <= 255)
            && (octets[0] == 10
                || octets[0] == 192 && octets[1] == 168
                || octets[0] == 172 && (16..=31).contains(&octets[1]))
        {
            return true;
        }
    }
    false
}

fn contains_private_ipv6(value: &str) -> bool {
    value
        .to_ascii_lowercase()
        .split(|ch: char| !(ch.is_ascii_hexdigit() || ch == ':'))
        .any(|token| {
            token.contains(':')
                && (token.starts_with("fc")
                    || token.starts_with("fd")
                    || token.starts_with("fe80:")
                    || token == "fc00::"
                    || token == "fd00::")
        })
}

fn contains_uuid(value: &str) -> bool {
    split_tokens(value, |ch| ch.is_ascii_hexdigit() || ch == '-')
        .into_iter()
        .any(|token| {
            let parts: Vec<&str> = token.split('-').collect();
            [8, 4, 4, 4, 12] == parts.iter().map(|part| part.len()).collect::<Vec<_>>()[..]
                && parts
                    .iter()
                    .all(|part| part.chars().all(|ch| ch.is_ascii_hexdigit()))
        })
}

fn contains_sid(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let token = token.trim_matches(|ch: char| ch.is_ascii_punctuation());
        token.starts_with("S-")
            && token.split('-').count() >= 6
            && token[2..]
                .split('-')
                .all(|part| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit()))
    })
}

fn contains_distinguished_name(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    (upper.contains("CN=") || upper.contains("OU=") || upper.contains("DC="))
        && upper.matches(',').count() >= 2
}

fn contains_secret_assignment(lower: &str) -> bool {
    [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
    ]
    .iter()
    .any(|term| {
        lower.find(term).is_some_and(|index| {
            lower[index + term.len()..]
                .chars()
                .skip_while(|ch| ch.is_ascii_whitespace())
                .next()
                .is_some_and(|ch| matches!(ch, ':' | '='))
        })
    })
}

fn contains_dns_value(value: &str) -> bool {
    split_tokens(value, |ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-')
    })
    .into_iter()
    .any(|token| {
        let labels: Vec<&str> = token.trim_matches('.').split('.').collect();
        labels.len() >= 2
            && labels.iter().all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    && label
                        .as_bytes()
                        .last()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    && label
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
            })
    })
}

fn contains_text_dns_value(value: &str) -> bool {
    const SAFE_EXTENSIONS: &[&str] = &[
        "md", "yaml", "yml", "rb", "cs", "csproj", "json", "sh", "txt", "html", "css", "xml",
        "png", "jpg", "jpeg", "svg", "pdf",
    ];
    split_tokens(value, |ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-')
    })
    .into_iter()
    .any(|token| {
        let labels: Vec<&str> = token.trim_matches('.').split('.').collect();
        labels.len() >= 2
            && !labels.last().is_some_and(|extension| {
                SAFE_EXTENSIONS
                    .iter()
                    .any(|safe| extension.eq_ignore_ascii_case(safe))
            })
            && labels.iter().all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    && label
                        .as_bytes()
                        .last()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    && label
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
            })
    })
}

fn contains_spn_value(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        token
            .trim_matches(|ch: char| ch.is_ascii_punctuation() && ch != '/' && ch != ':')
            .split('/')
            .collect::<Vec<_>>()
            .windows(2)
            .any(|pair| is_spn_service(pair[0]) && is_spn_target(pair[1]))
    })
}

fn is_spn_service(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "HOST" | "HTTP" | "MSSQLSVC" | "TERMSRV" | "WSMAN" | "CIFS" | "LDAP" | "CUSTOM" | "MYAPP"
    ) || value
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic())
        && value.len() > 1
        && !ROUTE_SAFE_SERVICE_CLASSES.contains(&value.to_ascii_lowercase().as_str())
}

fn is_spn_target(value: &str) -> bool {
    let target = value.split(':').next().unwrap_or(value);
    !target.is_empty()
        && target
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

fn split_tokens<F>(value: &str, keep: F) -> Vec<&str>
where
    F: Fn(char) -> bool,
{
    let mut tokens = Vec::new();
    let mut start = None;
    for (index, ch) in value.char_indices() {
        if keep(ch) {
            start.get_or_insert(index);
        } else if let Some(token_start) = start.take() {
            tokens.push(&value[token_start..index]);
        }
    }
    if let Some(token_start) = start {
        tokens.push(&value[token_start..]);
    }
    tokens
}

fn normalize_identifier(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn identifier_match(text: &str, identifier: &str, start: usize) -> Option<usize> {
    let mut index = start;
    while let Some(offset) = text[index..].find(identifier) {
        let position = index + offset;
        if identifier_at(text, position, identifier) {
            return Some(position);
        }
        index = position + identifier.len();
    }
    None
}

fn identifier_at(text: &str, index: usize, identifier: &str) -> bool {
    text[index..].starts_with(identifier)
        && (index == 0 || !is_identifier_continue(text.as_bytes()[index - 1]))
        && text
            .as_bytes()
            .get(index + identifier.len())
            .is_none_or(|byte| !is_identifier_continue(*byte))
}

fn identifier_value_at(text: &str, index: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    if index >= bytes.len() || !is_identifier_start(bytes[index]) {
        return None;
    }
    let start = index;
    let mut end = index + 1;
    while end < bytes.len() && is_identifier_continue(bytes[end]) {
        end += 1;
    }
    Some((text[start..end].to_string(), end))
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_identifier_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn skip_ascii_whitespace(text: &str, mut index: usize) -> usize {
    while index < text.len() && text.as_bytes()[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn gmsa_test_stub() {}
}
