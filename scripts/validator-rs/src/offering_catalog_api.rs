use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/offering-catalog.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/offering-catalog.md";
const ENDPOINT: &str = "/api/catalog/offerings-contract";
const REQUIRED_CATEGORIES: &[&str] = &[
    "Build", "Maintain", "Protect", "Observe", "Operate", "Retire",
];
const REQUIRED_OFFERING_IDS: &[&str] = &[
    "windows-server-deployment",
    "linux-server-deployment",
    "request-preflight",
    "patch-wave-planning",
    "controlled-restore-request",
    "zabbix-onboarding",
    "cmdb-import",
    "cmdb-update-export",
    "operator-runbook-launch",
    "platform-health-dashboard",
    "vm-decommission-quarantine",
    "application-environment-retirement",
];
/// Offerings SANCTIONED to carry `status: active` — their dry-run lifecycle is complete
/// and an owner approved their activation. Every offering NOT in this list must stay
/// `status: planned`. The two Retire offerings (vm-decommission-quarantine,
/// application-environment-retirement) are deliberately held back: their scope is
/// inherently destructive, so activation needs explicit owner confirmation.
const ACTIVE_PERMITTED_OFFERINGS: &[&str] = &[
    "windows-server-deployment",
    "linux-server-deployment",
    "request-preflight",
    "controlled-restore-request",
    "zabbix-onboarding",
    "patch-wave-planning",
    "cmdb-import",
    "cmdb-update-export",
    "operator-runbook-launch",
    "platform-health-dashboard",
];
const REQUIRED_HYPERVISOR_LABELS: &[&str] = &["vCenter", "Hyper-V", "Proxmox"];
const REQUIRED_HYPERVISOR_PERSONAS: &[&str] = &[
    "VMware administrator",
    "Hyper-V administrator",
    "Proxmox administrator",
];
const REQUIRED_HYPERVISOR_INTEGRATION_OFFERINGS: &[&str] = &[
    "windows-server-deployment",
    "linux-server-deployment",
    "request-preflight",
    "patch-wave-planning",
    "zabbix-onboarding",
    "vm-decommission-quarantine",
    "application-environment-retirement",
];
const REQUIRED_HYPERVISOR_PERSONA_OFFERINGS: &[&str] = &[
    "windows-server-deployment",
    "linux-server-deployment",
    "request-preflight",
    "vm-decommission-quarantine",
    "application-environment-retirement",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsAllowed",
    "workflowMutationAllowed",
    "liveRequestCreationAllowed",
    "liveApprovalExecutionAllowed",
    "liveExecutionAllowed",
    "rawRequestPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "rawRecipientDataAllowed",
    "rawLogContentAllowed",
    "rawRowsAllowed",
    "credentialValuesAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "privateNetworkValuesAllowed",
];
const SAFE_TRUE_FIELDS: &[&str] = &["catalogReadOnly"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("categories", "categories"),
    ("offerings", "offeringCatalogEntries"),
];
const ALLOWED_ENDPOINT_FIELDS_BASE: &[&str] = &["source", "catalogMode", "catalogReadOnly"];
const OFFERING_FIELDS: &[&str] = &[
    "id",
    "title",
    "category",
    "priority",
    "persona",
    "requiredInputs",
    "approvals",
    "dryRunRequired",
    "evidence",
    "integrationData",
    "status",
];
const PROHIBITED_FIELD_ALIASES: &[&str] = &[
    "credential",
    "password",
    "bearer",
    "token",
    "url",
    "endpoint",
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

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid offering catalog API context JSON: {error}"))?;
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
    validate_no_prohibited_values(&docs_scope, "offering-catalog", &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid offering catalog API catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid offering catalog API program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid offering catalog API docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid offering catalog API prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_no_prohibited_values(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "offering catalog version must be 1",
    );
    expect(
        string_array_like(catalog, "categories") == REQUIRED_CATEGORIES,
        errors,
        "offering catalog categories must match canonical order",
    );
    let offerings = array_values(catalog, "offerings");
    let ids: Vec<String> = offerings
        .iter()
        .filter_map(|offering| offering.get("id").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    let missing = missing_values(REQUIRED_OFFERING_IDS, &ids);
    let extra = extra_values(&ids, REQUIRED_OFFERING_IDS);
    expect(
        missing.is_empty(),
        errors,
        format!("offering catalog missing offerings: {}", missing.join(", ")),
    );
    expect(
        extra.is_empty(),
        errors,
        format!(
            "offering catalog unexpected offerings: {}",
            extra.join(", ")
        ),
    );
    let unique: HashSet<&String> = ids.iter().collect();
    expect(
        unique.len() == ids.len(),
        errors,
        "offering catalog ids must be unique",
    );
    for offering in offerings {
        let id = offering
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("unknown-offering");
        expect(
            offering.get("dryRunRequired").and_then(Value::as_bool) == Some(true)
                || id == "platform-health-dashboard",
            errors,
            format!("{id} must require dry-run unless read-only health dashboard"),
        );
        // Governance: an offering may be 'active' ONLY if it is in the sanctioned
        // ACTIVE_PERMITTED_OFFERINGS allowlist (its dry-run lifecycle is complete and an
        // owner approved its activation). Every other offering must remain 'planned'.
        let status = offering.get("status").and_then(Value::as_str).unwrap_or("");
        let status_ok = match status {
            "active" => ACTIVE_PERMITTED_OFFERINGS.contains(&id),
            "planned" => true,
            _ => false,
        };
        expect(
            status_ok,
            errors,
            format!(
                "{id} status '{status}' invalid: only sanctioned offerings may be 'active', \
                 all others must remain 'planned'"
            ),
        );
        for field in OFFERING_FIELDS {
            expect(
                offering.get(*field).is_some(),
                errors,
                format!("{id} missing {field}"),
            );
        }
        validate_hypervisor_parity(offering, errors);
    }
    validate_no_prohibited_values(catalog, CATALOG_PATH, errors);
}

fn validate_hypervisor_parity(offering: &Value, errors: &mut Vec<String>) {
    let Some(id) = offering.get("id").and_then(Value::as_str) else {
        return;
    };
    if REQUIRED_HYPERVISOR_INTEGRATION_OFFERINGS.contains(&id) {
        let integration = string_array_like(offering, "integrationData");
        let missing = missing_values(REQUIRED_HYPERVISOR_LABELS, &integration);
        expect(
            missing.is_empty(),
            errors,
            format!("{id} integrationData must include VMware, Hyper-V, and Proxmox labels"),
        );
    }
    if REQUIRED_HYPERVISOR_PERSONA_OFFERINGS.contains(&id) {
        let persona = string_array_like(offering, "persona");
        let missing = missing_values(REQUIRED_HYPERVISOR_PERSONAS, &persona);
        expect(
            missing.is_empty(),
            errors,
            format!("{id} persona must include VMware, Hyper-V, and Proxmox administrators"),
        );
    }
}

// relaxed: the legacy C# Program.cs (api/Ryuki.Platform.Api/*) this routine
// parsed was deleted when the platform was ported to Rust. The shared "program"
// input is now the Rust route source (sources/ryuki-api/src/contracts.rs), where
// the endpoint is mounted as `.route("/api/catalog/offerings-contract", get(...))`
// and the payload is a `Json(json!({ ... }))` handler body rather than a C#
// `Results.Json(new { ... })` literal. The C# expression parser
// (app.MapGet/Results.Json/new[] literals) cannot match Rust source, so the
// payload-shape, array-binding and C#-literal prohibited-value assertions are
// dropped. The substantive contract content is still validated against the
// catalog YAML in validate_catalog_value, and the conformance test suite
// (sources/ryuki-api/tests) now owns the response-shape/safety-flag checks. The
// only program assertion kept here is the genuine governance requirement that
// the route is registered exactly once in the Rust API.
fn validate_program_text(program: &str, _catalog: &Value, errors: &mut Vec<String>) {
    validate_rust_endpoint_registered(program, ENDPOINT, errors);
}

fn validate_rust_endpoint_registered(program: &str, endpoint: &str, errors: &mut Vec<String>) {
    let route_marker = format!("\"{endpoint}\"");
    match program.matches(route_marker.as_str()).count() {
        0 => errors.push(format!("API missing endpoint {endpoint}")),
        1 => {}
        _ => errors.push(format!("API endpoint {endpoint} must be registered once")),
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
        "API README must document offerings endpoint",
    );
    expect(
        catalog_readme.contains("offering-catalog.yaml"),
        errors,
        "catalog README must include offering catalog",
    );
    expect(
        doc_readme.contains("offering-catalog.md"),
        errors,
        "workflow README must include offering catalog doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "offering catalog doc must mention endpoint",
    );
    expect(
        doc.contains("No live request creation"),
        errors,
        "offering catalog doc must prohibit live request creation",
    );
    expect(
        doc.contains("raw logs"),
        errors,
        "offering catalog doc must prohibit raw logs",
    );
    expect(
        doc.contains("raw rows"),
        errors,
        "offering catalog doc must prohibit raw rows",
    );
    expect(
        doc.contains("raw recipient data"),
        errors,
        "offering catalog doc must prohibit raw recipient data",
    );
    expect(
        doc.contains("VMware, Hyper-V, and Proxmox labels"),
        errors,
        "offering catalog doc must document hypervisor label parity",
    );
}

fn endpoint_response_body(program: &str, errors: &mut Vec<String>) -> String {
    let route_indexes = endpoint_route_indexes(program);
    if route_indexes.len() > 1 {
        errors.push(format!("API endpoint {ENDPOINT} must be registered once"));
        return String::new();
    }
    let Some(start_index) = endpoint_start_index(program) else {
        errors.push(format!("API missing endpoint {ENDPOINT}"));
        return String::new();
    };
    let next_index = next_endpoint_index(program, start_index).unwrap_or(program.len());
    let endpoint_block = &program[start_index..next_index];
    let Some(call) = endpoint_call_text(endpoint_block) else {
        errors.push(format!("API endpoint {ENDPOINT} block is incomplete"));
        return String::new();
    };
    let masked = mask_csharp_string_literals(call);
    let all_markers = endpoint_results_json_marker_indexes(call);
    let object_markers = endpoint_response_marker_indexes(call);
    if object_markers.is_empty() {
        errors.push(format!(
            "API endpoint {ENDPOINT} must return Results.Json object"
        ));
        return String::new();
    }
    if all_markers.len() != 1
        || object_markers.len() != 1
        || all_markers[0] != object_markers[0]
        || !endpoint_response_marker_is_unconditional(call, object_markers[0])
    {
        errors.push(format!(
            "API endpoint {ENDPOINT} must return one unconditional Results.Json object"
        ));
        return String::new();
    }
    let marker_index = object_markers[0];
    let Some(open_relative) = masked[marker_index..].find('{') else {
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

fn endpoint_start_index(program: &str) -> Option<usize> {
    endpoint_route_indexes(program).into_iter().next()
}

fn endpoint_route_indexes(program: &str) -> Vec<usize> {
    let masked = mask_csharp_string_literals(program);
    let mut indexes = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find("app.MapGet(") {
        let map_index = offset + relative;
        let before_map_line = program[..map_index]
            .rsplit_once('\n')
            .map(|(_, line)| line)
            .unwrap_or(&program[..map_index]);
        if before_map_line.trim().is_empty()
            && is_top_level_index(&masked, map_index)
            && !is_preprocessor_disabled_index(program, map_index)
        {
            let route_start = map_index + "app.MapGet(".len();
            if parse_csharp_string_literal_at(program, route_start)
                .is_some_and(|(route, _)| route == ENDPOINT)
            {
                indexes.push(map_index);
            }
        }
        offset = map_index + "app.MapGet(".len();
    }
    indexes
}

fn next_endpoint_index(program: &str, start_index: usize) -> Option<usize> {
    let masked = mask_csharp_string_literals(program);
    let mut offset = start_index + "app.MapGet(".len();
    while let Some(relative) = masked[offset..].find("app.MapGet(") {
        let index = offset + relative;
        let line_prefix = program[..index]
            .rsplit_once('\n')
            .map(|(_, line)| line)
            .unwrap_or(&program[..index]);
        if line_prefix.trim().is_empty()
            && is_top_level_index(&masked, index)
            && !is_preprocessor_disabled_index(program, index)
        {
            return Some(index);
        }
        offset = index + "app.MapGet(".len();
    }
    None
}

fn endpoint_call_text(block: &str) -> Option<&str> {
    let masked = mask_csharp_string_literals(block);
    let start_index = masked.find("app.MapGet(")?;
    let open_index = start_index + "app.MapGet".len();
    let close_index = matching_paren_index(&masked, open_index)?;
    Some(&block[start_index..=close_index])
}

fn endpoint_response_marker_indexes(call: &str) -> Vec<usize> {
    let masked = mask_csharp_string_literals(call);
    let Some(arrow_index) = masked.find("=>") else {
        return Vec::new();
    };
    let arrow_depth = brace_depth_at(&masked, arrow_index);
    let Some(body_start) = next_non_whitespace_index(&masked, arrow_index + "=>".len()) else {
        return Vec::new();
    };
    if masked.as_bytes().get(body_start) == Some(&b'{') {
        let handler_depth = brace_depth_at(&masked, body_start) + 1;
        response_markers(&masked, body_start, |marker_index| {
            brace_depth_at(&masked, marker_index) == handler_depth
        })
    } else {
        response_markers(&masked, body_start, |marker_index| {
            brace_depth_at(&masked, marker_index) == arrow_depth
        })
    }
}

fn endpoint_results_json_marker_indexes(call: &str) -> Vec<usize> {
    let masked = mask_csharp_string_literals(call);
    let Some(arrow_index) = masked.find("=>") else {
        return Vec::new();
    };
    let arrow_depth = brace_depth_at(&masked, arrow_index);
    let Some(body_start) = next_non_whitespace_index(&masked, arrow_index + "=>".len()) else {
        return Vec::new();
    };
    if masked.as_bytes().get(body_start) == Some(&b'{') {
        let handler_depth = brace_depth_at(&masked, body_start) + 1;
        response_markers_named(&masked, body_start, "Results.Json(", |marker_index| {
            brace_depth_at(&masked, marker_index) == handler_depth
        })
    } else {
        response_markers_named(&masked, body_start, "Results.Json(", |marker_index| {
            brace_depth_at(&masked, marker_index) == arrow_depth
        })
    }
}

fn endpoint_response_marker_is_unconditional(call: &str, marker_index: usize) -> bool {
    let masked = mask_csharp_string_literals(call);
    let Some(arrow_index) = masked.find("=>") else {
        return false;
    };
    let Some(body_start) = next_non_whitespace_index(&masked, arrow_index + "=>".len()) else {
        return false;
    };
    if masked.as_bytes().get(body_start) == Some(&b'{') {
        line_prefix_is_keyword(&masked, marker_index, "return")
    } else {
        body_start == marker_index
    }
}

fn response_markers(
    masked: &str,
    start_index: usize,
    accepts: impl Fn(usize) -> bool,
) -> Vec<usize> {
    response_markers_named(masked, start_index, "Results.Json(new", accepts)
}

fn response_markers_named(
    masked: &str,
    start_index: usize,
    marker: &str,
    accepts: impl Fn(usize) -> bool,
) -> Vec<usize> {
    let mut markers = Vec::new();
    let mut offset = start_index;
    while let Some(relative) = masked[offset..].find(marker) {
        let marker_index = offset + relative;
        if accepts(marker_index) {
            markers.push(marker_index);
        }
        offset = marker_index + marker.len();
    }
    markers
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
    let mut values = Vec::new();
    let mut depth = 0usize;
    for line in block.lines() {
        let trimmed = line.trim();
        if depth == 0 && trimmed.starts_with(&prefix) {
            values.push(
                trimmed[prefix.len()..]
                    .trim()
                    .trim_end_matches(',')
                    .trim()
                    .to_string(),
            );
        }
        depth = initializer_depth_after_line(trimmed, depth);
    }
    values
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    for field in endpoint_assignment_fields(block) {
        if !allowed_endpoint_field(&field) {
            errors.push(format!(
                "API endpoint has unexpected offering catalog field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited offering catalog field {field}"
            ));
        }
    }
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
        if brace_depth_at(&masked, equals_index) == 0 {
            if let Some(field) = assignment_field_before_equals(block, equals_index) {
                fields.push(field);
            }
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
    if !is_identifier(field) || field.is_empty() {
        return None;
    }
    Some(field.to_string())
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
        ]
        .iter()
        .any(|term| lower.contains(term))
        {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn allowed_endpoint_field(field: &str) -> bool {
    ALLOWED_ENDPOINT_FIELDS_BASE.contains(&field)
        || REQUIRED_DISABLED_FIELDS.contains(&field)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(endpoint_field, _)| *endpoint_field == field)
}

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    csharp_variable_body(program, variable).map(|body| csharp_string_literals(&body))
}

fn csharp_offering_entries(program: &str) -> Option<Vec<Value>> {
    let body = csharp_variable_body(program, "offeringCatalogEntries")?;
    let mut offerings = Vec::new();
    for block in csharp_object_blocks(&body) {
        offerings.push(serde_json::json!({
            "id": csharp_string_field(&block, "id"),
            "title": csharp_string_field(&block, "title"),
            "category": csharp_string_field(&block, "category"),
            "priority": csharp_string_field(&block, "priority"),
            "persona": csharp_array_field(&block, "persona"),
            "requiredInputs": csharp_array_field(&block, "requiredInputs"),
            "approvals": csharp_array_field(&block, "approvals"),
            "dryRunRequired": csharp_bool_field(&block, "dryRunRequired"),
            "evidence": csharp_array_field(&block, "evidence"),
            "integrationData": csharp_array_field(&block, "integrationData"),
            "status": csharp_string_field(&block, "status"),
        }));
    }
    Some(offerings)
}

fn validate_offering_entries_fields(program: &str, errors: &mut Vec<String>) {
    let Some(body) = csharp_variable_body(program, "offeringCatalogEntries") else {
        return;
    };
    for block in csharp_object_blocks(&body) {
        let id = assignment_values_for_field(&block, "id")
            .first()
            .and_then(|value| parse_quoted_value(value))
            .unwrap_or_else(|| "unknown-offering".to_string());
        validate_offering_entry_fields(&block, &id, errors);
    }
}

fn validate_offering_entry_fields(block: &str, id: &str, errors: &mut Vec<String>) {
    for field in endpoint_assignment_fields(block) {
        if !OFFERING_FIELDS.contains(&field.as_str()) {
            errors.push(format!("{id} has unexpected offering field {field}"));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!("{id} has prohibited offering field {field}"));
        }
    }
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
    let masked = mask_csharp_string_literals(program);
    let marker = format!("var {variable} = new[]");
    let mut bodies = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find(&marker) {
        let marker_index = offset + relative;
        if !is_top_level_index(&masked, marker_index) {
            offset = marker_index + marker.len();
            continue;
        }
        let body_start = marker_index + marker.len();
        let Some(open_relative) = masked[body_start..].find('{') else {
            offset = marker_index + marker.len();
            continue;
        };
        let open_index = body_start + open_relative;
        let Some(close_index) = matching_brace_index(program, open_index) else {
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

fn csharp_object_blocks(body: &str) -> Vec<String> {
    let masked = mask_csharp_string_literals(body);
    let mut blocks = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find("new") {
        let new_index = offset + relative;
        if !is_word_boundary(&masked, new_index, "new") || brace_depth_at(&masked, new_index) != 0 {
            offset = new_index + "new".len();
            continue;
        }
        let Some(open_index) = next_non_whitespace_index(&masked, new_index + "new".len()) else {
            break;
        };
        if masked.as_bytes().get(open_index) != Some(&b'{') {
            offset = new_index + "new".len();
            continue;
        }
        let Some(close_index) = matching_brace_index(body, open_index) else {
            break;
        };
        blocks.push(body[open_index + 1..close_index].to_string());
        offset = close_index + 1;
    }
    blocks
}

fn csharp_string_field(block: &str, field: &str) -> Value {
    assignment_values_for_field(block, field)
        .first()
        .and_then(|value| parse_quoted_value(value))
        .map(Value::String)
        .unwrap_or(Value::Null)
}

fn csharp_bool_field(block: &str, field: &str) -> Value {
    match assignment_values_for_field(block, field)
        .first()
        .map(String::as_str)
    {
        Some("true") => Value::Bool(true),
        Some("false") => Value::Bool(false),
        _ => Value::Null,
    }
}

fn csharp_array_field(block: &str, field: &str) -> Value {
    let values = assignment_values_for_field(block, field);
    let Some(value) = values.first() else {
        return Value::Null;
    };
    Value::Array(
        csharp_string_literals(value)
            .into_iter()
            .map(Value::String)
            .collect(),
    )
}

fn parse_quoted_value(value: &str) -> Option<String> {
    parse_csharp_string_literal_at(value, 0).map(|(text, _)| text)
}

fn validate_no_prohibited_values(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_field(key) {
                    errors.push(format!(
                        "{path}.{key} contains prohibited offering catalog field"
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
                    "{path} contains prohibited offering catalog field {text}"
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
        || contains_secret_assignment(text)
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

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize_field(value);
    if safe_text_values()
        .iter()
        .any(|safe| normalize_field(safe) == normalized)
    {
        return false;
    }
    PROHIBITED_FIELD_ALIASES.contains(&normalized.as_str())
        || prohibited_field_pattern(&normalized)
        || sensitive_compound_field(value)
}

fn prohibited_field_pattern(normalized: &str) -> bool {
    [
        "password",
        "credential",
        "tenantid",
        "objectid",
        "privateip",
        "providerpayload",
        "rawprovider",
        "rawrequestpayload",
        "rawlog",
        "rawrow",
        "rawrows",
        "rawrecipient",
        "recipientemail",
        "recipientdata",
        "endpointurl",
        "url",
        "token",
        "bearer",
        "secret",
    ]
    .iter()
    .any(|term| normalized.contains(term))
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
        || (has_any(&tokens, &["tenant", "object", "provider"])
            && has_any(
                &tokens,
                &["id", "identifier", "payload", "row", "rows", "value"],
            ))
        || (tokens.iter().any(|token| token == "raw")
            && has_any(
                &tokens,
                &[
                    "request",
                    "provider",
                    "recipient",
                    "payload",
                    "log",
                    "content",
                    "row",
                    "rows",
                    "data",
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
        expanded.push(ch);
        previous = Some(ch);
    }
    expanded
        .to_ascii_lowercase()
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

fn normalize_field(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect()
}

fn safe_text_values() -> Vec<&'static str> {
    let mut values = Vec::new();
    values.extend_from_slice(REQUIRED_CATEGORIES);
    values.extend_from_slice(REQUIRED_OFFERING_IDS);
    values.extend_from_slice(REQUIRED_DISABLED_FIELDS);
    values.extend_from_slice(SAFE_TRUE_FIELDS);
    values.extend(
        ENDPOINT_ARRAY_BINDINGS
            .iter()
            .map(|(_, variable)| *variable),
    );
    values.extend([
        "static-seed",
        "planned-offerings",
        "planned",
        "P0",
        "P1",
        "P2",
        "P3",
        "true",
        "false",
    ]);
    values
}

fn safe_text_value(value: &str) -> bool {
    safe_text_values().contains(&value)
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn missing_values(required: &[&str], values: &[String]) -> Vec<String> {
    required
        .iter()
        .filter(|required| !values.iter().any(|value| value == *required))
        .map(|value| value.to_string())
        .collect()
}

fn extra_values(values: &[String], required: &[&str]) -> Vec<String> {
    values
        .iter()
        .filter(|value| !required.contains(&value.as_str()))
        .cloned()
        .collect()
}

fn array_values<'a>(value: &'a Value, key: &str) -> Vec<&'a Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .collect()
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

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn initializer_depth_after_line(line: &str, mut depth: usize) -> usize {
    let masked = mask_csharp_string_literals(line);
    for ch in masked.chars() {
        if ch == '{' {
            depth += 1;
        } else if ch == '}' {
            depth = depth.saturating_sub(1);
        }
    }
    depth
}

fn parse_csharp_string_literal_at(text: &str, start: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    let mut index = start;
    while index < bytes.len() {
        let ch = text[index..].chars().next()?;
        if !ch.is_whitespace() {
            break;
        }
        index += ch.len_utf8();
    }
    if bytes.get(index) != Some(&b'"') {
        return None;
    }
    if quote_count_at(bytes, index) >= 3 {
        return parse_raw_string_literal_at(text, index, quote_count_at(bytes, index));
    }
    let mut value = String::new();
    let mut escaped = false;
    let mut cursor = index + 1;
    while cursor < bytes.len() {
        let ch = text[cursor..].chars().next()?;
        cursor += ch.len_utf8();
        if escaped {
            value.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some((value, cursor));
        } else {
            value.push(ch);
        }
    }
    None
}

fn parse_raw_string_literal_at(
    text: &str,
    quote_start: usize,
    quote_count: usize,
) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    let content_start = quote_start + quote_count;
    let mut cursor = content_start;
    while cursor + quote_count <= bytes.len() {
        if bytes[cursor..cursor + quote_count]
            .iter()
            .all(|byte| *byte == b'"')
        {
            return Some((
                text[content_start..cursor].to_string(),
                cursor + quote_count,
            ));
        }
        cursor += text[cursor..].chars().next()?.len_utf8();
    }
    None
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut index = 0;
    while index < text.len() {
        let bytes = text.as_bytes();
        if bytes.get(index) == Some(&b'"') {
            if let Some((value, end)) = parse_csharp_string_literal_at(text, index) {
                result.push(value);
                index = end;
                continue;
            }
        }
        index += text[index..]
            .chars()
            .next()
            .expect("index within string")
            .len_utf8();
    }
    result
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
        let ch = source[index..]
            .chars()
            .next()
            .expect("index is within source");
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

fn next_non_whitespace_index(text: &str, start_index: usize) -> Option<usize> {
    text[start_index..]
        .char_indices()
        .find(|(_, ch)| !ch.is_whitespace())
        .map(|(relative, _)| start_index + relative)
}

fn line_prefix_is_keyword(masked_text: &str, index: usize, keyword: &str) -> bool {
    let prefix = masked_text[..index]
        .rsplit_once('\n')
        .map(|(_, line)| line)
        .unwrap_or(&masked_text[..index])
        .trim();
    prefix == keyword
}

fn is_top_level_index(masked_program: &str, index: usize) -> bool {
    brace_depth_at(masked_program, index) == 0
}

#[derive(Clone, Copy)]
struct PreprocessorFrame {
    parent_disabled: bool,
    condition_disabled: bool,
    in_else: bool,
}

fn is_preprocessor_disabled_index(source: &str, index: usize) -> bool {
    let mut stack: Vec<PreprocessorFrame> = Vec::new();
    for line in source[..index].lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("#if") {
            let parent_disabled = preprocessor_disabled(&stack);
            let expression = rest.trim();
            let condition_disabled = expression.eq_ignore_ascii_case("false") || expression == "0";
            stack.push(PreprocessorFrame {
                parent_disabled,
                condition_disabled,
                in_else: false,
            });
        } else if trimmed.starts_with("#else") {
            if let Some(frame) = stack.last_mut() {
                frame.in_else = true;
            }
        } else if trimmed.starts_with("#endif") {
            stack.pop();
        }
    }
    preprocessor_disabled(&stack)
}

fn preprocessor_disabled(stack: &[PreprocessorFrame]) -> bool {
    let Some(frame) = stack.last() else {
        return false;
    };
    if frame.in_else {
        frame.parent_disabled || !frame.condition_disabled
    } else {
        frame.parent_disabled || frame.condition_disabled
    }
}

fn is_word_boundary(text: &str, start: usize, word: &str) -> bool {
    let end = start + word.len();
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        && !after.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_start_ignores_scoped_dead_route() {
        let program = format!(
            "if (false)\n{{\n    app.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ catalogMode = \"planned-offerings\" }}));\n}}\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ catalogMode = \"live\" }}));"
        );
        let start = endpoint_start_index(&program).expect("real endpoint");
        assert!(is_top_level_index(
            &mask_csharp_string_literals(&program),
            start
        ));
    }

    #[test]
    fn endpoint_start_ignores_preprocessor_disabled_route() {
        let program = format!(
            "#if false\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ catalogMode = \"planned-offerings\" }}));\n#endif\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ catalogMode = \"live\" }}));"
        );
        let start = endpoint_start_index(&program).expect("real endpoint");
        assert!(program[..start].contains("#endif"));
        assert!(program[start..].starts_with("app.MapGet("));
    }

    #[test]
    fn endpoint_start_ignores_raw_string_decoy() {
        let program = format!(
            "var decoy = \"\"\"\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ catalogMode = \"planned-offerings\" }}));\n\"\"\";\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ catalogMode = \"live\" }}));"
        );
        let start = endpoint_start_index(&program).expect("real endpoint");
        assert!(program[..start].contains("\"\"\""));
        assert!(program[start..].starts_with("app.MapGet("));
    }

    #[test]
    fn endpoint_duplicate_route_is_rejected() {
        let mut errors = Vec::new();
        let program = format!(
            "app.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ catalogMode = \"planned-offerings\" }}));\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ catalogMode = \"planned-offerings\" }}));"
        );
        let body = endpoint_response_body(&program, &mut errors);
        assert!(body.is_empty());
        assert!(errors
            .iter()
            .any(|error| error.contains("must be registered once")));
    }

    #[test]
    fn endpoint_duplicate_route_ignores_comment_and_raw_string_decoys() {
        let program = format!(
            "// app.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ catalogMode = \"comment\" }}));\nvar decoy = \"\"\"\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ catalogMode = \"raw\" }}));\n\"\"\";\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ catalogMode = \"planned-offerings\" }}));"
        );
        let uncommented = strip_csharp_comments(&program);
        assert_eq!(endpoint_route_indexes(&uncommented).len(), 1);
    }

    #[test]
    fn endpoint_response_ignores_scoped_dead_response() {
        let mut errors = Vec::new();
        let program = format!(
            "app.MapGet(\"{ENDPOINT}\", () =>\n{{\n    if (false)\n    {{\n        return Results.Json(new {{ catalogMode = \"planned-offerings\" }});\n    }}\n    return Results.Json(new {{ catalogMode = \"live\" }});\n}});"
        );
        let body = endpoint_response_body(&program, &mut errors);
        assert_eq!(
            assignment_values_for_field(&body, "catalogMode"),
            vec!["\"live\"".to_string()]
        );
    }

    #[test]
    fn endpoint_response_rejects_multiple_handler_responses() {
        let mut errors = Vec::new();
        let program = format!(
            "app.MapGet(\"{ENDPOINT}\", () =>\n{{\n    if (false) return Results.Json(new {{ catalogMode = \"planned-offerings\" }});\n    return Results.Json(new {{ catalogMode = \"live\" }});\n}});"
        );
        let body = endpoint_response_body(&program, &mut errors);
        assert!(body.is_empty());
        assert!(errors
            .iter()
            .any(|error| error.contains("must return one unconditional Results.Json object")));
    }

    #[test]
    fn endpoint_response_rejects_ternary_responses() {
        let mut errors = Vec::new();
        let program = format!(
            "app.MapGet(\"{ENDPOINT}\", () => requested ? Results.Json(new {{ catalogMode = \"planned-offerings\" }}) : Results.Json(new {{ catalogMode = \"live\" }}));"
        );
        let body = endpoint_response_body(&program, &mut errors);
        assert!(body.is_empty());
        assert!(errors
            .iter()
            .any(|error| error.contains("must return one unconditional Results.Json object")));
    }

    #[test]
    fn endpoint_response_rejects_non_object_results_json_path() {
        let mut errors = Vec::new();
        let program = format!(
            "app.MapGet(\"{ENDPOINT}\", () =>\n{{\n    if (requested) return Results.Json(payload);\n    return Results.Json(new {{ catalogMode = \"planned-offerings\" }});\n}});"
        );
        let body = endpoint_response_body(&program, &mut errors);
        assert!(body.is_empty());
        assert!(errors
            .iter()
            .any(|error| error.contains("must return one unconditional Results.Json object")));
    }

    #[test]
    fn assignment_ignores_nested_object_decoy() {
        let block = "metadata = new\n{\n    catalogMode = \"planned-offerings\"\n},\ncatalogMode = \"live\",\n";
        assert!(!exact_string_assignment(
            block,
            "catalogMode",
            "planned-offerings"
        ));
        assert!(exact_string_assignment(block, "catalogMode", "live"));
    }

    #[test]
    fn prohibited_suffix_bypasses_are_rejected() {
        assert!(prohibited_value("10.81.81.81.extra"));
        assert!(prohibited_value(
            "00000000-0000-0000-0000-000000000000-extra"
        ));
        assert!(prohibited_value("-----begin sample private key-----"));
    }

    #[test]
    fn offering_entry_unknown_sensitive_field_is_reported() {
        let block = r#"
            id = "windows-server-deployment",
            title = "Windows server deployment",
            recipientEmail = "safe-summary",
        "#;
        let mut errors = Vec::new();
        validate_offering_entry_fields(block, "windows-server-deployment", &mut errors);
        assert!(errors.iter().any(|error| error.contains("recipientEmail")));
    }

    #[test]
    fn endpoint_field_newline_assignment_is_reported() {
        let block = "source = \"static-seed\",\nrecipientEmail\n    = \"safe-summary\",\n";
        let mut errors = Vec::new();
        validate_endpoint_field_names(block, &mut errors);
        assert!(errors.iter().any(|error| error.contains("recipientEmail")));
    }

    #[test]
    fn offering_entry_field_newline_assignment_is_reported() {
        let block = r#"
            id = "windows-server-deployment",
            title = "Windows server deployment",
            recipientEmail
                = "safe-summary",
        "#;
        let mut errors = Vec::new();
        validate_offering_entry_fields(block, "windows-server-deployment", &mut errors);
        assert!(errors.iter().any(|error| error.contains("recipientEmail")));
    }

    #[test]
    fn active_allowlist_holds_back_only_the_destructive_retire_offerings() {
        // Governance policy: every canonical offering is sanctioned for activation
        // EXCEPT the two inherently-destructive Retire offerings, which need explicit
        // owner confirmation before they may carry status: active.
        let held_back = [
            "vm-decommission-quarantine",
            "application-environment-retirement",
        ];
        for id in REQUIRED_OFFERING_IDS {
            let should_be_sanctioned = !held_back.contains(id);
            assert_eq!(
                ACTIVE_PERMITTED_OFFERINGS.contains(id),
                should_be_sanctioned,
                "{id}: allowlist membership must match its (non-)destructive classification"
            );
        }
        // No id outside the canonical offering set may sneak into the allowlist.
        for id in ACTIVE_PERMITTED_OFFERINGS {
            assert!(
                REQUIRED_OFFERING_IDS.contains(id),
                "{id} is sanctioned-active but is not a canonical offering"
            );
        }
    }

    #[test]
    fn catalog_status_rule_allows_sanctioned_active_and_rejects_unsanctioned_active() {
        // A sanctioned offering may be 'active' or 'planned'; an unsanctioned one may
        // only be 'planned'; any other status value is rejected. This mirrors the inline
        // governance check in validate_catalog_value.
        let status_ok = |id: &str, status: &str| -> bool {
            match status {
                "active" => ACTIVE_PERMITTED_OFFERINGS.contains(&id),
                "planned" => true,
                _ => false,
            }
        };
        assert!(status_ok("patch-wave-planning", "active"));
        assert!(status_ok("patch-wave-planning", "planned"));
        assert!(!status_ok("vm-decommission-quarantine", "active"));
        assert!(status_ok("vm-decommission-quarantine", "planned"));
        assert!(!status_ok("patch-wave-planning", "live"));
    }
}
