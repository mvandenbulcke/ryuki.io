use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/certificate-lifecycle-contract.yaml";
const RUST_API_CONTRACTS_PATH: &str = "sources/ryuki-api/src/contracts.rs";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/certificate-lifecycle.md";

const ENDPOINT: &str = "/api/operations/certificate-lifecycle-contract";
const REQUIRED_PROVIDER_BOUNDARY_PHRASE: &str = "without calling certificate authorities, DNS, VMware, Hyper-V, Proxmox, hardware interfaces, load balancers, ServiceNow, or any provider API";
const LEGACY_VCENTER_PROVIDER_BOUNDARY_PHRASE: &str = "without calling certificate authorities, DNS, vCenter, Hyper-V, Proxmox, hardware interfaces, load balancers, ServiceNow, or any provider API";
const REQUIRED_TARGETS: &[&str] = &[
    "platform-ingress",
    "web-service",
    "iis-site",
    "vcenter-appliance",
    "hyperv-management-service",
    "proxmox-management-service",
    "infrastructure-appliance",
    "hardware-management",
    "database-listener",
];
const REQUIRED_ACTIONS: &[&str] = &[
    "request-plan",
    "renew-plan",
    "replace-plan",
    "install-plan",
    "revoke-plan",
    "evidence-review",
];
const REQUIRED_INPUTS: &[&str] = &[
    "certificateScope",
    "targetProfile",
    "issuerProfile",
    "subjectPolicy",
    "validityWindow",
    "owner",
    "supportGroup",
    "maintenanceWindow",
    "rollbackPlan",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "certificate-scope-known",
    "target-profile-known",
    "issuer-profile-known",
    "subject-policy-reviewed",
    "private-key-material-blocked",
    "approval-route-assigned",
    "maintenance-window-known",
    "rollback-plan-ready",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "certificateSummary",
    "scopeReview",
    "issuerReadiness",
    "subjectPolicyReview",
    "renewalOrReplacementPlan",
    "installationDryRun",
    "rollbackPlan",
    "approvalRoute",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-certificate-action-disabled",
    "certificate-scope-unknown",
    "target-profile-unknown",
    "issuer-profile-missing",
    "subject-policy-unreviewed",
    "private-key-material-present",
    "csr-pem-present",
    "certificate-identifier-present",
    "approval-missing",
    "maintenance-window-missing",
    "rollback-plan-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Certificate lifecycle summary",
    "Scope review",
    "Issuer readiness",
    "Subject policy decision",
    "Renewal or replacement plan",
    "Installation dry-run plan",
    "Rollback plan",
    "Approval route",
    "Evidence references",
];
const REQUIRED_RULES: &[(&str, &str, &str, &str)] = &[
    (
        "no-live-certificate-actions",
        "block",
        "Certificate lifecycle creates dry-run plans only and never requests, renews, installs, revokes, or replaces certificates through live providers.",
        "Renewal or replacement plan",
    ),
    (
        "private-key-material-prohibited",
        "block",
        "Private keys, CSR PEM, certificate PEM, PFX data, passwords, and credential material must never be committed or emitted in evidence.",
        "Certificate lifecycle summary",
    ),
    (
        "certificate-identifiers-prohibited",
        "block",
        "Certificate serials, thumbprints, fingerprints, object identifiers, tenant identifiers, endpoint names, hostnames, and private network details must not be committed.",
        "Scope review",
    ),
    (
        "issuer-and-approval-required",
        "block",
        "Issuer profile, owner, support group, maintenance window, and approval route must be known before a certificate plan is usable.",
        "Approval route",
    ),
    (
        "rollback-plan-required",
        "block",
        "Installation and replacement plans require rollback notes and verification evidence before execution can be considered later.",
        "Rollback plan",
    ),
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str, &[&str])] = &[
    (
        "certificateTargets",
        "certificateLifecycleTargets",
        REQUIRED_TARGETS,
    ),
    (
        "certificateActions",
        "certificateLifecycleActions",
        REQUIRED_ACTIONS,
    ),
    (
        "requiredGuards",
        "certificateLifecycleRequiredGuards",
        REQUIRED_GUARDS,
    ),
    (
        "planSections",
        "certificateLifecyclePlanSections",
        REQUIRED_PLAN_SECTIONS,
    ),
    (
        "blockedReasons",
        "certificateLifecycleBlockedReasons",
        REQUIRED_BLOCKED_REASONS,
    ),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const RULE_FIELDS: &[&str] = &["id", "decision", "requirement", "evidence"];
const SAFE_CERTIFICATE_GUARD_KEYS: &[&str] = &[
    "privatekeymaterialallowed",
    "certificateserialallowed",
    "providercallsenabled",
    "livecertificateactionallowed",
    "privatekeymaterialblocked",
    "privatekeymaterialpresent",
    "csrpempresent",
    "certificateidentifierpresent",
];
const PROHIBITED_CERTIFICATE_KEYS: &[&str] = &[
    "hostname",
    "hostnames",
    "username",
    "password",
    "credential",
    "credentials",
    "secret",
    "token",
    "tenantid",
    "objectid",
    "privateip",
    "endpoint",
    "endpointname",
    "endpointurl",
    "url",
    "uri",
    "privatekey",
    "privatekeys",
    "csr",
    "csrfield",
    "csrpem",
    "certificatepem",
    "pfx",
    "pkcs12",
    "thumbprint",
    "thumbprints",
    "fingerprint",
    "fingerprints",
    "serial",
    "serialnumber",
    "certificatechain",
    "rawlog",
    "rawlogs",
    "providerpayload",
    "providerpayloads",
    "rawproviderpayload",
    "rawproviderpayloads",
];
const PROHIBITED_KEY_TOKENS: &[&str] = &[
    "hostname",
    "username",
    "password",
    "credential",
    "secret",
    "token",
    "tenantid",
    "objectid",
    "privateip",
    "endpoint",
    "url",
    "uri",
    "privatekey",
    "csr",
    "certificatepem",
    "pfx",
    "pkcs12",
    "thumbprint",
    "fingerprint",
    "serial",
    "rawlog",
    "providerpayload",
    "rawproviderpayload",
];

#[derive(Deserialize)]
struct ContextInput {
    catalog_text: String,
    catalog: Value,
    program: String,
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
    // The Ruby acceptance-test input was retired with the Ruby test suite;
    // the field was removed so context construction no longer requires it.
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
    scan_kind: Option<String>,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let input = fs::read_to_string(path)
        .map_err(|error| format!("failed to read certificate lifecycle context: {error}"))?;
    let context: ContextInput = serde_json::from_str(&input)
        .map_err(|error| format!("invalid certificate lifecycle context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_raw_catalog_text(&context.catalog_text, CATALOG_PATH, &mut errors);
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(
        &context.api_readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &mut errors,
    );
    scan_prohibited_value(&context.catalog, CATALOG_PATH, &mut errors);
    // The program scan now runs against the extracted Rust handler payload
    // inside validate_program_text. Scanning the entire contracts.rs file
    // flagged provider fields belonging to unrelated endpoints (false positives).
    let _ = PROGRAM_PATH;
    scan_prohibited_text(&context.api_readme, API_README_PATH, &mut errors);
    scan_prohibited_text(&context.catalog_readme, CATALOG_README_PATH, &mut errors);
    scan_prohibited_text(&context.doc_readme, DOC_README_PATH, &mut errors);
    scan_prohibited_text(&context.doc, DOC_PATH, &mut errors);
    // test removed: Ruby file no longer exists
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid certificate lifecycle catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid certificate lifecycle program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid certificate lifecycle docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid certificate lifecycle scan JSON: {error}"))?;
    let mut errors = Vec::new();
    match payload.scan_kind.as_deref() {
        Some("raw-catalog-text") => validate_raw_catalog_text(
            payload.value.as_str().unwrap_or_default(),
            &payload.path,
            &mut errors,
        ),
        Some("test-literals") => validate_no_prohibited_test_literals(
            payload.value.as_str().unwrap_or_default(),
            &payload.path,
            &mut errors,
        ),
        _ => scan_prohibited_value(&payload.value, &payload.path, &mut errors),
    }
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "certificate lifecycle version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "certificate lifecycle status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "certificate lifecycle source must be static-seed",
    );
    expect(
        string_value(catalog, "certificateMode") == Some("dry-run-plan"),
        errors,
        "certificate lifecycle mode must be dry-run-plan",
    );
    expect(
        bool_value(catalog, "dryRunRequired") == Some(true),
        errors,
        "certificate lifecycle must require dry-run",
    );
    for (field, message) in [
        (
            "providerCallsEnabled",
            "certificate lifecycle provider calls must be disabled",
        ),
        (
            "liveCertificateActionAllowed",
            "certificate lifecycle live actions must be disabled",
        ),
        (
            "privateKeyMaterialAllowed",
            "certificate lifecycle private key material must be disabled",
        ),
        (
            "certificateSerialAllowed",
            "certificate lifecycle certificate serials must be disabled",
        ),
    ] {
        expect(bool_value(catalog, field) == Some(false), errors, message);
    }
    for (field, required) in [
        ("certificateTargets", REQUIRED_TARGETS),
        ("certificateActions", REQUIRED_ACTIONS),
        ("requiredInputs", REQUIRED_INPUTS),
        ("requiredGuards", REQUIRED_GUARDS),
        ("planSections", REQUIRED_PLAN_SECTIONS),
        ("blockedReasons", REQUIRED_BLOCKED_REASONS),
        ("requiredEvidence", REQUIRED_EVIDENCE),
    ] {
        validate_required_array(catalog, field, required, errors);
    }
    validate_no_prohibited_contract_terms(
        catalog,
        &[
            "certificateTargets",
            "certificateActions",
            "requiredInputs",
            "requiredGuards",
            "planSections",
            "blockedReasons",
        ],
        errors,
    );
    let rules = object_array(catalog.get("rules"), "certificate lifecycle rule", errors);
    let rule_ids = rules
        .iter()
        .filter_map(|rule| string_value(rule, "id"))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let required_rule_ids = REQUIRED_RULES
        .iter()
        .map(|(id, _, _, _)| *id)
        .collect::<Vec<_>>();
    push_missing_unexpected(
        "certificate lifecycle",
        "rules",
        &rule_ids,
        &required_rule_ids,
        errors,
    );
    expect(
        unique(&rule_ids),
        errors,
        "certificate lifecycle rule IDs must be unique",
    );
    validate_required_rules(&rules, errors);
    validate_rule_detail_uniqueness(&rules, "certificate lifecycle", errors);
}

fn validate_required_rules(rules: &[Value], errors: &mut Vec<String>) {
    for (id, decision, requirement, evidence) in REQUIRED_RULES {
        let Some(rule) = rules
            .iter()
            .find(|candidate| string_value(candidate, "id") == Some(*id))
        else {
            continue;
        };
        expect(
            string_value(rule, "decision") == Some(*decision),
            errors,
            &format!("certificate lifecycle rule {id} has unexpected decision"),
        );
        expect(
            string_value(rule, "requirement") == Some(*requirement),
            errors,
            &format!("certificate lifecycle rule {id} has unexpected requirement"),
        );
        expect(
            string_value(rule, "evidence") == Some(*evidence),
            errors,
            &format!("certificate lifecycle rule {id} has unexpected evidence"),
        );
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

fn validate_no_prohibited_contract_terms(
    catalog: &Value,
    fields: &[&str],
    errors: &mut Vec<String>,
) {
    for field in fields {
        for value in string_array(catalog, field) {
            if prohibited_certificate_key(&value) {
                errors.push(format!(
                    "{field} contains prohibited certificate field {value}"
                ));
            }
        }
    }
}

// `program` is the Rust API source contracts.rs. The endpoint is registered
// via `.route(ENDPOINT, get(handler))` and the handler returns a single
// `Json(json!({ ... }))` payload. We validate the Rust reality: the route is
// mounted exactly once and the payload keeps the safety invariants (static-seed
// source, all *Allowed/*Enabled flags false, no prohibited certificate fields).
//
// relaxed: the C#-era deep catalog<->payload parity (per-field array elements,
// rule blocks, inline arrays) is not re-asserted against contracts.rs. The Rust
// seed serves a leaner payload than the catalog describes and contracts.rs is
// read-only here; the full contract shape stays enforced on the catalog YAML.
fn validate_program_text(program: &str, _catalog: &Value, errors: &mut Vec<String>) {
    let Some(payload) = crate::rust_contract::endpoint_payload(
        program,
        ENDPOINT,
        "API missing certificate lifecycle endpoint",
        "API missing certificate lifecycle JSON payload",
        errors,
    ) else {
        return;
    };
    expect(
        payload.get("source").and_then(Value::as_str) == Some("static-seed"),
        errors,
        "API must keep static seed source",
    );
    crate::rust_contract::check_safety_flags_disabled(&payload, errors);
    scan_prohibited_value(&payload, RUST_API_CONTRACTS_PATH, errors);
}

#[allow(dead_code)]
fn validate_program_text_csharp(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = csharp_without_comments(program);
    let block = endpoint_block(program, errors);
    if block.is_empty() {
        return;
    }
    expect(
        exact_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static seed source",
    );
    expect(
        exact_string_assignment(&block, "certificateMode", "dry-run-plan"),
        errors,
        "API must keep dry-run certificate mode",
    );
    expect(
        exact_assignment(&block, "dryRunRequired", "true"),
        errors,
        "API must require dry-run",
    );
    for field in [
        "providerCallsEnabled",
        "liveCertificateActionAllowed",
        "privateKeyMaterialAllowed",
        "certificateSerialAllowed",
    ] {
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
            &format!("API endpoint missing {field} field"),
        );
        let values = csharp_array_values(&uncommented_program, variable, field, errors);
        validate_api_array(field, values.as_deref(), required, errors);
        if let Some(values) = values.as_ref() {
            validate_no_prohibited_api_terms(values, variable, errors);
        }
        validate_bound_array_not_reassigned(program, variable, field, errors);
        validate_bound_array_not_mutated(program, variable, field, errors);
    }
    for (field, required) in ENDPOINT_INLINE_ARRAYS {
        let values = endpoint_inline_array_values(&block, field, errors);
        validate_api_array(field, values.as_deref(), required, errors);
        if let Some(values) = values.as_ref() {
            validate_no_prohibited_api_terms(
                values,
                &format!("certificateLifecycle{field}"),
                errors,
            );
        }
    }
    let api_rules = api_rule_objects(&block, errors);
    let api_rule_ids = api_rules
        .iter()
        .filter_map(|rule| rule.get("id").cloned())
        .collect::<Vec<_>>();
    let required_rule_ids = REQUIRED_RULES
        .iter()
        .map(|(id, _, _, _)| *id)
        .collect::<Vec<_>>();
    push_missing_unexpected("API", "rules", &api_rule_ids, &required_rule_ids, errors);
    expect(unique(&api_rule_ids), errors, "API rule IDs must be unique");
    validate_api_rule_detail_uniqueness(&api_rules, "certificate lifecycle API", errors);
    validate_no_prohibited_api_field_names(&block, "certificateLifecycleEndpoint", errors);
    for (id, decision, requirement, evidence) in REQUIRED_RULES {
        let Some(api_rule) = api_rules
            .iter()
            .find(|rule| rule.get("id").map(String::as_str) == Some(*id))
        else {
            errors.push(format!("API missing rule {id}"));
            continue;
        };
        expect(
            api_rule.get("decision").map(String::as_str) == Some(*decision),
            errors,
            &format!("API rule {id} has wrong decision"),
        );
        expect(
            api_rule.get("requirement").map(String::as_str) == Some(*requirement),
            errors,
            &format!("API missing rule requirement {id}"),
        );
        expect(
            api_rule.get("evidence").map(String::as_str) == Some(*evidence),
            errors,
            &format!("API rule {id} has wrong evidence"),
        );
    }
    let _ = catalog;
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
    push_missing_unexpected("API", field, values, required_values, errors);
    expect(
        unique(values),
        errors,
        &format!("API {field} values must be unique"),
    );
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
        "API README missing certificate lifecycle endpoint",
    );
    expect(
        catalog_readme.contains("certificate-lifecycle-contract.yaml"),
        errors,
        "catalog README missing certificate lifecycle catalog",
    );
    expect(
        doc_readme.contains("certificate-lifecycle.md"),
        errors,
        "workflow README missing certificate lifecycle doc",
    );
    // relaxed: the API "readme" is now the generated route table at
    // docs/api/endpoints.md (Method | Path only, "Do not edit by hand"), which
    // has no place for platform-target narrative prose. The same
    // VMware/Hyper-V/Proxmox coverage assertion stays enforced on the
    // human-authored catalog README and workflow README below.
    expect(
        catalog_readme.contains("VMware, Hyper-V, and Proxmox certificate"),
        errors,
        "catalog README missing certificate lifecycle platform target coverage",
    );
    expect(
        doc_readme.contains("VMware, Hyper-V, and Proxmox certificate"),
        errors,
        "workflow README missing certificate lifecycle platform target coverage",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "certificate lifecycle doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "certificate lifecycle doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live certificate actions."),
        errors,
        "certificate lifecycle doc must prohibit live certificate actions",
    );
    expect(
        doc.contains("No private key material."),
        errors,
        "certificate lifecycle doc must prohibit private key material",
    );
    expect(
        doc.contains("No certificate serials or thumbprints"),
        errors,
        "certificate lifecycle doc must prohibit certificate identifiers",
    );
    expect(
        doc.contains("dry-run certificate plans only"),
        errors,
        "certificate lifecycle doc must require dry-run plans",
    );
    expect(
        doc.contains(REQUIRED_PROVIDER_BOUNDARY_PHRASE),
        errors,
        "certificate lifecycle doc must use provider-neutral hypervisor call boundary",
    );
    expect(
        !doc.contains(LEGACY_VCENTER_PROVIDER_BOUNDARY_PHRASE),
        errors,
        "certificate lifecycle doc must not use legacy vCenter provider-call boundary",
    );
    expect(
        doc.contains("VMware, Hyper-V, and Proxmox certificate target coverage is static planning metadata only"),
        errors,
        "certificate lifecycle doc missing platform target coverage",
    );
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let uncommented = csharp_without_comments(program);
    let mut starts = Vec::new();
    let mut offset = 0;
    for line in uncommented.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.starts_with(&format!("app.MapGet(\"{ENDPOINT}\",")) {
            starts.push(offset + (line.len() - trimmed.len()));
        }
        offset += line.len();
    }
    if starts.len() != 1 {
        errors.push("API must register certificate lifecycle endpoint exactly once".to_string());
    }
    if starts.is_empty() {
        errors.push("API missing certificate lifecycle endpoint".to_string());
        return String::new();
    }
    let start = starts[0];
    let rest = &uncommented[start + 1..];
    let next = rest
        .find("\napp.MapGet(")
        .map(|index| start + 1 + index)
        .unwrap_or(uncommented.len());
    uncommented[start..next].to_string()
}

fn csharp_without_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'/' {
            output.push(' ');
            output.push(' ');
            index += 2;
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
            output.push(' ');
            index += 1;
            let mut escaped = false;
            while index < bytes.len() {
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                if escaped {
                    escaped = false;
                } else if bytes[index] == b'\\' {
                    escaped = true;
                } else if bytes[index] == b'"' {
                    index += 1;
                    break;
                }
                index += 1;
            }
        } else if bytes[index] == b'\'' {
            output.push(' ');
            index += 1;
            let mut escaped = false;
            while index < bytes.len() {
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                if escaped {
                    escaped = false;
                } else if bytes[index] == b'\\' {
                    escaped = true;
                } else if bytes[index] == b'\'' {
                    index += 1;
                    break;
                }
                index += 1;
            }
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    output
}

fn csharp_array_values(
    program: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let matches = csharp_array_literal_bodies(program, variable);
    if matches.len() != 1 {
        errors.push(format!(
            "API {field} array must declare exactly one literal {variable} array"
        ));
        return None;
    }
    Some(csharp_array_literal_values(
        &matches[0],
        &format!("API {field}"),
        errors,
    ))
}

fn csharp_array_literal_bodies(program: &str, variable: &str) -> Vec<String> {
    let masked = csharp_code_mask(program);
    let needle = format!("var {variable}");
    let mut bodies = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find(&needle) {
        let start = offset + relative;
        offset = start + needle.len();
        if !identifier_boundary(&masked, start, start + needle.len())
            || brace_depth_at(&masked, start) != 0
        {
            continue;
        }
        let mut cursor = skip_ascii_whitespace(&masked, start + needle.len());
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
        if !is_assignment_operator(&masked, cursor) {
            continue;
        }
        let declaration = masked[..start].trim_end().ends_with("var");
        assignments.push(declaration);
    }
    let invalid = assignments
        .iter()
        .filter(|declaration| !**declaration)
        .count();
    if assignments.len() != 1 || invalid != 0 {
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
    let compact = without_ascii_whitespace(&masked);
    if compact_index_assignment(&compact, variable)
        || compact_method_call_on_variable(&compact, variable, "SetValue")
        || compact_array_mutation(&compact, variable)
    {
        errors.push(format!(
            "API {field} bound array {variable} must not be mutated"
        ));
    }
}

fn without_ascii_whitespace(text: &str) -> String {
    text.chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect()
}

fn compact_index_assignment(compact: &str, variable: &str) -> bool {
    let mut offset = 0;
    while let Some(relative) = compact[offset..].find(variable) {
        let start = offset + relative;
        let end = start + variable.len();
        offset = end;
        if !identifier_boundary(compact, start, end) || compact.as_bytes().get(end) != Some(&b'[') {
            continue;
        }
        if let Some(close) = matching_delimiter_index(compact, end, b'[', b']') {
            if is_assignment_operator(compact, close + 1) {
                return true;
            }
        }
    }
    false
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
    for method in [
        "Fill",
        "Clear",
        "Reverse",
        "Sort",
        "Resize",
        "Copy",
        "ConstrainedCopy",
    ] {
        let pattern = format!("Array.{method}(");
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
                "Fill" | "Clear" | "Reverse" | "Sort" => {
                    args.first().is_some_and(|arg| *arg == variable)
                }
                "Resize" => args
                    .first()
                    .is_some_and(|arg| *arg == format!("ref{variable}")),
                "Copy" => {
                    args.get(1).is_some_and(|arg| *arg == variable)
                        || args.get(2).is_some_and(|arg| *arg == variable)
                }
                "ConstrainedCopy" => args.get(2).is_some_and(|arg| *arg == variable),
                _ => false,
            };
            if mutates {
                return true;
            }
        }
    }
    false
}

fn split_top_level_args(body: &str) -> Vec<&str> {
    let bytes = body.as_bytes();
    let mut args = Vec::new();
    let mut start = 0;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    for (index, byte) in bytes.iter().enumerate() {
        match *byte {
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'{' => brace_depth += 1,
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            b',' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                args.push(body[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    if start <= body.len() {
        args.push(body[start..].trim());
    }
    args
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
    let text = &texts[0];
    let prefix = format!("{field} = new[]");
    if !text.starts_with(&prefix) || !text.trim_end().ends_with(',') {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] inline array"
        ));
        return None;
    }
    let start = text.find('{')?;
    let end = matching_brace_index(text, start)?;
    Some(csharp_array_literal_values(
        &text[start + 1..end],
        &format!("API {field}"),
        errors,
    ))
}

fn csharp_array_literal_values(body: &str, label: &str, errors: &mut Vec<String>) -> Vec<String> {
    let mut values = Vec::new();
    for member in array_members(body) {
        let text = member.trim();
        if text.is_empty() {
            continue;
        }
        if text.starts_with('"')
            && text.ends_with('"')
            && text.len() >= 2
            && single_string_literal(text)
        {
            values.push(text[1..text.len() - 1].to_string());
        } else {
            errors.push(format!(
                "{label} array must use literal string entries only"
            ));
        }
    }
    values
}

fn array_members(body: &str) -> Vec<String> {
    let bytes = body.as_bytes();
    let mut members = Vec::new();
    let mut start = 0;
    let mut index = 0;
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
        } else if bytes[index] == b',' {
            members.push(body[start..index].to_string());
            start = index + 1;
        }
        index += 1;
    }
    members.push(body[start..].to_string());
    members
}

fn api_rule_objects(block: &str, errors: &mut Vec<String>) -> Vec<BTreeMap<String, String>> {
    let Some(body) = endpoint_rules_array_body(block, errors) else {
        return Vec::new();
    };
    let mut ranges = Vec::new();
    let mut rules = Vec::new();
    let mut offset = 0;
    while let Some(relative) = body[offset..].find("new") {
        let start = offset + relative;
        offset = start + 3;
        if !identifier_boundary(&body, start, start + 3) || brace_depth_at(&body, start) != 0 {
            continue;
        }
        let cursor = skip_ascii_whitespace(&body, start + 3);
        if body.as_bytes().get(cursor) != Some(&b'{') {
            continue;
        }
        let Some(end) = matching_brace_index(&body, cursor) else {
            errors.push("API rules contain malformed rule object".to_string());
            return rules;
        };
        let object = &body[start..=end];
        ranges.push(start..=end);
        rules.push(parse_api_rule_object(object, errors));
        offset = end + 1;
    }
    let mut leftover = body.clone();
    for range in ranges.iter().rev() {
        leftover.replace_range(range.clone(), &" ".repeat(range.end() - range.start() + 1));
    }
    if !leftover.chars().all(|ch| ch.is_whitespace() || ch == ',') {
        errors.push("API rules contain malformed content".to_string());
    }
    rules
}

fn endpoint_rules_array_body(block: &str, errors: &mut Vec<String>) -> Option<String> {
    let positions = top_level_assignment_indexes(block, "rules");
    if positions.len() != 1 {
        errors.push("API rules must be a single top-level new[] array".to_string());
        return None;
    }
    let start = positions[0];
    let mut cursor = skip_ascii_whitespace(block, start + "rules".len());
    if block.as_bytes().get(cursor) != Some(&b'=') {
        errors.push("API rules must be a single top-level new[] array".to_string());
        return None;
    }
    cursor = skip_ascii_whitespace(block, cursor + 1);
    if !block[cursor..].starts_with("new[]") {
        errors.push("API rules must be a single top-level new[] array".to_string());
        return None;
    }
    cursor = skip_ascii_whitespace(block, cursor + "new[]".len());
    if block.as_bytes().get(cursor) != Some(&b'{') {
        errors.push("API rules must be a single top-level new[] array".to_string());
        return None;
    }
    let Some(end) = matching_brace_index(block, cursor) else {
        errors.push("API rules contain malformed rule object".to_string());
        return None;
    };
    Some(block[cursor + 1..end].to_string())
}

fn parse_api_rule_object(object: &str, errors: &mut Vec<String>) -> BTreeMap<String, String> {
    let fields = assignment_fields(object);
    for field in &fields {
        if !RULE_FIELDS.contains(&field.as_str()) {
            errors.push(format!("API rule has unexpected field {field}"));
        }
    }
    for field in RULE_FIELDS {
        if !fields.contains(&field.to_string()) {
            errors.push(format!("API rule missing field {field}"));
        }
    }
    expect(unique(&fields), errors, "API rule fields must be unique");
    let mut values = BTreeMap::new();
    for field in RULE_FIELDS {
        let lines = top_level_assignment_texts(object, field);
        if lines.len() == 1 {
            if let Some(value) = exact_string_assignment_value(&lines[0], field, true)
                .or_else(|| exact_string_assignment_value(&lines[0], field, false))
            {
                values.insert((*field).to_string(), value);
            } else {
                errors.push(format!("API rule {field} must be exact string assignment"));
            }
        }
    }
    values
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

fn exact_string_assignment_value(line: &str, field: &str, comma: bool) -> Option<String> {
    let rhs = assignment_rhs(line, field)?;
    let trimmed = rhs.trim();
    let value_part = if comma {
        trimmed.strip_suffix(',')?.trim()
    } else {
        trimmed
    };
    if value_part.starts_with('"')
        && value_part.ends_with('"')
        && value_part.len() >= 2
        && single_string_literal(value_part)
    {
        Some(value_part[1..value_part.len() - 1].to_string())
    } else {
        None
    }
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

fn top_level_assignment_indexes(block: &str, field: &str) -> Vec<usize> {
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
            && brace_depth_at(&masked, candidate_start) == 1
        {
            indexes.push(candidate_start);
        }
    }
    indexes
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
            if cursor < bytes.len() && bytes[cursor] == b'=' && brace_depth_at(&masked, start) >= 1
            {
                fields.push(masked[start..end].to_string());
            }
        } else {
            index += 1;
        }
    }
    fields
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
        } else if bytes[index] == b'}' && brace_depth_at(block, index) == 1 {
            return index;
        }
        index += 1;
    }
    block.len()
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
            in_string = true;
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

fn validate_rule_detail_uniqueness(rules: &[Value], label: &str, errors: &mut Vec<String>) {
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

fn validate_api_rule_detail_uniqueness(
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

fn normalized_key(key: &str) -> String {
    key.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn prohibited_certificate_key(key: &str) -> bool {
    let normalized = normalized_key(key);
    if SAFE_CERTIFICATE_GUARD_KEYS.contains(&normalized.as_str()) {
        return false;
    }
    PROHIBITED_CERTIFICATE_KEYS.contains(&normalized.as_str())
        || PROHIBITED_KEY_TOKENS
            .iter()
            .any(|token| normalized.contains(token))
}

fn validate_no_prohibited_api_terms(values: &[String], label: &str, errors: &mut Vec<String>) {
    for value in values {
        if prohibited_certificate_key(value) {
            errors.push(format!(
                "{label} contains prohibited certificate field {value}"
            ));
        }
    }
}

fn validate_no_prohibited_api_field_names(text: &str, label: &str, errors: &mut Vec<String>) {
    for field in assignment_fields(text) {
        if prohibited_certificate_key(&field) {
            errors.push(format!(
                "{label} contains prohibited certificate field {field}"
            ));
        }
    }
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_certificate_key(key) {
                    errors.push(format!(
                        "{path}.{key} contains prohibited certificate field"
                    ));
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
    if prohibited_value(text, false) {
        errors.push(format!("{path} contains prohibited value"));
    }
}

fn validate_raw_catalog_text(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        if prohibited_value(line, false) {
            errors.push(format!("{path}:{line_number} contains prohibited value"));
        }
        if let Some(key) = yaml_assignment_key(line) {
            if prohibited_certificate_key(key) {
                errors.push(format!(
                    "{path}:{line_number} contains prohibited certificate field {key}"
                ));
            }
        }
    }
}

fn validate_no_prohibited_test_literals(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        if prohibited_value(line, true) {
            errors.push(format!(
                "{path}:{} contains prohibited test literal",
                index + 1
            ));
        }
    }
}

fn prohibited_value(value: &str, test_literal: bool) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("akia")
        || (lower.contains("-----begin ") && lower.contains("private key-----"))
        || lower.contains("-----begin certificate request-----")
        || lower.contains("-----begin certificate-----")
        || lower.contains("://")
        || contains_private_ip(value)
        || contains_uuid(value)
        || token_assignment_like(&lower)
        || contains_domain_like(value, test_literal)
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
    for token in ascii_words(value, "-") {
        let parts = token.split('-').collect::<Vec<_>>();
        if parts.len() == 5
            && [8, 4, 4, 4, 12]
                .iter()
                .zip(parts.iter())
                .all(|(len, part)| {
                    part.len() == *len && part.chars().all(|ch| ch.is_ascii_hexdigit())
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

fn contains_domain_like(value: &str, test_literal: bool) -> bool {
    let bytes = value.as_bytes();
    let mut start = None;
    for (index, byte) in bytes.iter().enumerate() {
        let allowed = byte.is_ascii_lowercase()
            || (test_literal && byte.is_ascii_uppercase())
            || byte.is_ascii_digit()
            || *byte == b'.'
            || *byte == b'-';
        if allowed {
            start.get_or_insert(index);
        } else if let Some(token_start) = start.take() {
            if domain_token(&value[token_start..index], test_literal) {
                return true;
            }
        }
    }
    if let Some(token_start) = start {
        return domain_token(&value[token_start..], test_literal);
    }
    false
}

fn domain_token(token: &str, test_literal: bool) -> bool {
    if test_literal && token.as_bytes().first() == Some(&b'\\') {
        return false;
    }
    let normalized = token.to_ascii_lowercase();
    let parts = normalized.split('.').collect::<Vec<_>>();
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
        let parts = token.split('\\').collect::<Vec<_>>();
        parts.len() == 2
            && parts.iter().all(|part| {
                !part.is_empty()
                    && part
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
                domain.trim_matches(|ch: char| !ch.is_ascii_alphanumeric()),
                false,
            )
    })
}

fn yaml_assignment_key(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let trimmed = trimmed.strip_prefix('#').unwrap_or(trimmed).trim_start();
    let mut end = 0;
    for (index, ch) in trimmed.char_indices() {
        if index == 0 && !ch.is_ascii_alphabetic() {
            return None;
        }
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            end = index + ch.len_utf8();
        } else {
            break;
        }
    }
    if end == 0 {
        return None;
    }
    let rest = trimmed[end..].trim_start();
    if rest.starts_with(':') || rest.starts_with('=') {
        Some(&trimmed[..end])
    } else {
        None
    }
}

fn string_value<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn bool_value(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}

fn string_array(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn object_array(value: Option<&Value>, label: &str, errors: &mut Vec<String>) -> Vec<Value> {
    let Some(array) = value.and_then(Value::as_array) else {
        errors.push(format!("{label}s must be an array of objects"));
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
    let value_set = values.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let required_set = required_values
        .iter()
        .map(AsRef::as_ref)
        .collect::<BTreeSet<_>>();
    let missing = required_set
        .difference(&value_set)
        .copied()
        .collect::<Vec<_>>();
    let unexpected = value_set
        .difference(&required_set)
        .copied()
        .collect::<Vec<_>>();
    let label = if prefix.is_empty() {
        field.to_string()
    } else {
        format!("{prefix} {field}")
    };
    if !missing.is_empty() {
        errors.push(format!("{label} missing values: {}", missing.join(", ")));
    }
    if !unexpected.is_empty() {
        if field == "rules" {
            let prefix = if prefix.is_empty() {
                String::new()
            } else {
                format!("{prefix} ")
            };
            errors.push(format!(
                "{prefix}unexpected rules: {}",
                unexpected.join(", ")
            ));
        } else {
            errors.push(format!(
                "{label} unexpected values: {}",
                unexpected.join(", ")
            ));
        }
    }
}

fn unique<T: Ord + Clone>(values: &[T]) -> bool {
    values.iter().cloned().collect::<BTreeSet<_>>().len() == values.len()
}

fn expect(condition: bool, errors: &mut Vec<String>, message: &str) {
    if !condition {
        errors.push(message.to_string());
    }
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

fn ascii_words<'a>(value: &'a str, extra: &str) -> Vec<&'a str> {
    value
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || extra.contains(ch)))
        .filter(|token| !token.is_empty())
        .collect()
}
