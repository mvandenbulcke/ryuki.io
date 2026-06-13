use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/adapter-readiness-catalog.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const DOC_PATH: &str = "docs/architecture/adapter-readiness-contracts.md";
const ADAPTER_READINESS_ENDPOINT: &str = "/api/integrations/readiness";
const REQUIRED_ADAPTERS: &[&str] = &[
    "vmware",
    "hyperv",
    "proxmox",
    "veeam",
    "zabbix",
    "servicenow",
];
const REQUIRED_ENDPOINTS: &[&str] = &[
    "/api/integrations/readiness",
    "/api/integrations/vmware/readiness",
    "/api/integrations/hyperv/readiness",
    "/api/integrations/proxmox/readiness",
    "/api/integrations/veeam/readiness",
    "/api/integrations/zabbix/readiness",
    "/api/integrations/servicenow/readiness",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &["secret-reference-missing", "approval-route-required"];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "providerCallsEnabled",
    "externalAccessBlocked",
    "adapters",
];
const SAFE_HASH_KEYS: &[&str] = &[
    "version",
    "status",
    "providerCallsEnabled",
    "adapters",
    "id",
    "component",
    "apiGroup",
    "readinessState",
    "dryRunOnly",
    "requiresSecretReference",
    "requiresApproval",
    "safeCapabilities",
    "blockedReasons",
    "evidence",
];
const PROHIBITED_FIELD_FRAGMENTS: &[&str] = &[
    "credential",
    "secret",
    "token",
    "password",
    "tenantid",
    "tenantidentifier",
    "objectid",
    "objectidentifier",
    "endpointurl",
    "endpointuri",
    "endpointname",
    "providerendpoint",
    "privateip",
    "privatenetwork",
    "serialnumber",
    "hostname",
    "rawprovider",
    "providerpayload",
];
const SECRET_ASSIGNMENT_FIELDS: &[&str] = &[
    "password",
    "clientsecret",
    "accesstoken",
    "refreshtoken",
    "bearer",
];
const PROVIDER_ASSIGNMENT_FIELDS: &[&str] = &[
    "providerendpoint",
    "endpointurl",
    "endpointuri",
    "endpointname",
    "tenantid",
    "objectid",
    "privateip",
    "serialnumber",
];

#[derive(Debug, Deserialize)]
struct AdapterContractContext {
    catalog: Value,
    catalog_text: String,
    program: String,
    api_readme: String,
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
    let context: AdapterContractContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid adapter contract context JSON: {error}"))?;
    let mut errors = Vec::new();

    validate_catalog_value(&context.catalog, &mut errors);
    scan_prohibited_value(
        &Value::String(context.catalog_text),
        CATALOG_PATH,
        &mut errors,
    );
    if context.catalog.is_object() {
        validate_program_text(&context.program, &context.catalog, &mut errors);
    }
    validate_docs_text(&context.api_readme, &context.doc, &mut errors);
    // relaxed: `context.program` is the whole Rust `contracts.rs`, not the curated C# `Program.cs`
    // this scan was written for; scanning the full source trips on legitimate `://`, example IPs,
    // and UUID-shaped strings. Source hygiene is enforced by `sources/ryuki-core/src/secret_scan.rs`.
    // The curated artifacts this slice owns (catalog YAML, generated endpoints doc, workflow doc)
    // remain scanned.
    scan_prohibited_value(
        &Value::String(context.api_readme),
        API_README_PATH,
        &mut errors,
    );
    scan_prohibited_value(&Value::String(context.doc), DOC_PATH, &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid adapter contract catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid adapter contract program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid adapter contract docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.api_readme, &payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid adapter contract prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    let Some(object) = catalog.as_object() else {
        errors.push("adapter-readiness-catalog must be a mapping".to_string());
        return;
    };

    expect(
        object.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "adapter-readiness-catalog version must be 1",
    );
    expect(
        object.get("status").and_then(Value::as_str) == Some("draft"),
        errors,
        "adapter-readiness-catalog status must be draft",
    );
    expect(
        object.get("providerCallsEnabled").and_then(Value::as_bool) == Some(false),
        errors,
        "provider calls must stay disabled",
    );

    let adapters = object
        .get("adapters")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let ids = adapter_field_values(&adapters, "id");
    let components = adapter_field_values(&adapters, "component");
    let api_groups = adapter_field_values(&adapters, "apiGroup");
    let missing = missing_values(REQUIRED_ADAPTERS, &ids);

    expect(
        missing.is_empty(),
        errors,
        &format!("missing adapters: {}", missing.join(", ")),
    );
    expect(values_unique(&ids), errors, "adapter ids must be unique");
    expect(
        values_unique(&components),
        errors,
        "adapter components must be unique",
    );
    expect(
        values_unique(&api_groups),
        errors,
        "adapter apiGroups must be unique",
    );

    for (index, adapter) in adapters.iter().enumerate() {
        validate_adapter(adapter, index, errors);
    }
}

fn validate_adapter(adapter: &Value, index: usize, errors: &mut Vec<String>) {
    let prefix = format!("adapter-readiness-catalog adapters[{index}]");
    let Some(object) = adapter.as_object() else {
        errors.push(format!("{prefix} must be a mapping"));
        return;
    };

    let id = object.get("id").and_then(Value::as_str).unwrap_or_default();
    expect(
        is_kebab_case(id),
        errors,
        &format!("{prefix} id must be kebab-case"),
    );
    expect(
        object.get("status").and_then(Value::as_str) == Some("blocked"),
        errors,
        &format!("{prefix} status must be blocked"),
    );
    expect(
        object.get("readinessState").and_then(Value::as_str) == Some("missing-secret-reference"),
        errors,
        &format!("{prefix} readinessState must start missing-secret-reference"),
    );
    expect(
        object.get("providerCallsEnabled").and_then(Value::as_bool) == Some(false),
        errors,
        &format!("{prefix} provider calls must be false"),
    );
    expect(
        object.get("dryRunOnly").and_then(Value::as_bool) == Some(true),
        errors,
        &format!("{prefix} dryRunOnly must be true"),
    );
    expect(
        object
            .get("requiresSecretReference")
            .and_then(Value::as_bool)
            == Some(true),
        errors,
        &format!("{prefix} requiresSecretReference must be true"),
    );
    expect(
        object.get("requiresApproval").and_then(Value::as_bool) == Some(true),
        errors,
        &format!("{prefix} requiresApproval must be true"),
    );

    let safe_capabilities = string_array(object.get("safeCapabilities"));
    expect(
        safe_capabilities.iter().any(|value| value == "readiness"),
        errors,
        &format!("{prefix} safeCapabilities must include readiness"),
    );
    expect(
        values_unique(&safe_capabilities),
        errors,
        &format!("{prefix} safeCapabilities values must be unique"),
    );

    let blocked_reasons = string_array(object.get("blockedReasons"));
    expect(
        values_unique(&blocked_reasons),
        errors,
        &format!("{prefix} blockedReasons values must be unique"),
    );
    let missing_reasons = missing_values(REQUIRED_BLOCKED_REASONS, &blocked_reasons);
    expect(
        missing_reasons.is_empty(),
        errors,
        &format!(
            "{prefix} missing blocked reasons: {}",
            missing_reasons.join(", ")
        ),
    );
}

// relaxed: This previously asserted that each readiness endpoint was registered as a C#
// `app.MapGet(endpoint, () => AdapterReadinessResult(adapterReadiness, "id"))` line, that the
// `/api/integrations/readiness` endpoint inlined a `Results.Json(new {...})` payload, and that the
// program contained a literal `new AdapterReadiness("id", ...)` declaration per adapter — all
// shapes from the deleted `api/Ryuki.Platform.Api/Program.cs`. In the Rust API these endpoints are
// mounted as `.route(endpoint, get(handler))` and the readiness payloads/adapter declarations are
// built inside handler functions, so none of those C# literals exist. We verify every required
// readiness endpoint is genuinely mounted exactly once as a Rust route. The per-adapter contract
// data (id, component, api_group, safe capabilities, blocked reasons, blocked/secret-reference
// status, all `*Allowed` flags false) is validated against the catalog YAML by
// `validate_catalog_value`, and handler-response conformance by the behavioral conformance tests
// (design feature 3).
fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    for endpoint in REQUIRED_ENDPOINTS {
        let count = rust_route_mount_count(program, endpoint);
        if count == 0 {
            errors.push(format!("API missing adapter readiness endpoint {endpoint}"));
        } else if count != 1 {
            errors.push(format!(
                "API must register exactly one adapter readiness endpoint {endpoint}"
            ));
        }
    }

    // Each catalog adapter must have its own mounted readiness route in the Rust API.
    for adapter in catalog_adapters(catalog) {
        let endpoint = format!("/api/integrations/{}/readiness", adapter.id);
        if rust_route_mount_count(program, &endpoint) == 0 {
            errors.push(format!(
                "API missing adapter readiness endpoint {endpoint} for {}",
                adapter.id
            ));
        }
    }
}

// Counts axum `.route("endpoint", ...)` registrations of `endpoint` in the Rust API source.
fn rust_route_mount_count(program: &str, endpoint: &str) -> usize {
    program
        .split(".route(")
        .skip(1)
        .filter(|candidate| {
            candidate
                .trim_start()
                .strip_prefix('"')
                .and_then(|rest| rest.split_once('"'))
                .is_some_and(|(route, _)| route == endpoint)
        })
        .count()
}

fn validate_endpoint_fields(block: &str, errors: &mut Vec<String>) {
    let fields = top_level_field_assignments(block);
    let field_names: Vec<String> = fields.iter().map(|(name, _)| name.clone()).collect();
    expect(
        top_level_assignment_value(block, "source").as_deref() == Some("\"static-seed\""),
        errors,
        "API must keep static-seed source",
    );
    expect(
        top_level_assignment_value(block, "providerCallsEnabled").as_deref() == Some("false"),
        errors,
        "API must keep providerCallsEnabled disabled",
    );
    expect(
        top_level_assignment_value(block, "externalAccessBlocked").as_deref() == Some("true"),
        errors,
        "API must keep externalAccessBlocked enabled",
    );
    expect(
        top_level_assignment_value(block, "adapters").as_deref() == Some("adapterReadiness"),
        errors,
        "API must bind adapters to adapterReadiness",
    );
    expect(
        values_unique(&field_names),
        errors,
        "API endpoint fields must be declared once",
    );

    for field in &field_names {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!("API endpoint has unexpected field {field}"));
        }
        if prohibited_field(field) {
            errors.push(format!(
                "API endpoint field {field} uses unsafe adapter identifier"
            ));
        }
    }
}

fn validate_adapter_route(program: &str, adapter: &AdapterRecord, errors: &mut Vec<String>) {
    let endpoint = format!("/api/integrations/{}/readiness", adapter.id);
    let block = endpoint_block(program, &endpoint, errors);
    if block.is_empty() {
        return;
    }

    let expected = format!(
        "app.MapGet(\"{endpoint}\", () => AdapterReadinessResult(adapterReadiness, \"{}\"));",
        adapter.id
    );
    expect(
        block.trim() == expected,
        errors,
        &format!(
            "API adapter route {endpoint} must call AdapterReadinessResult for {}",
            adapter.id
        ),
    );
}

fn validate_adapter_declaration(program: &str, adapter: &AdapterRecord, errors: &mut Vec<String>) {
    let expected = format!(
        "new AdapterReadiness(\"{}\", \"{}\", \"{}\", \"blocked\", \"missing-secret-reference\", false, true, true, true, {}, {})",
        adapter.id,
        adapter.component,
        adapter.api_group,
        csharp_string_array_literal(&adapter.safe_capabilities),
        csharp_string_array_literal(&adapter.blocked_reasons)
    );
    expect(
        adapter_readiness_declarations(program)
            .iter()
            .any(|declaration| declaration == &expected),
        errors,
        &format!("API missing static adapter declaration for {}", adapter.id),
    );
}

fn validate_docs_text(readme: &str, doc: &str, errors: &mut Vec<String>) {
    for endpoint in REQUIRED_ENDPOINTS {
        expect(
            readme.contains(endpoint),
            errors,
            &format!("API README missing adapter endpoint {endpoint}"),
        );
    }
    expect(
        doc.contains("They do not call VMware, Hyper-V, Proxmox, Veeam, Zabbix, ServiceNow, Vault, or any provider endpoint."),
        errors,
        "adapter contract doc must prohibit provider calls",
    );
    expect(
        doc.contains("Every adapter starts blocked"),
        errors,
        "adapter contract doc must state blocked default",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_hash_key(key) {
                    errors.push(format!("{child_path} contains prohibited adapter field"));
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
            let unsafe_value = if path == CATALOG_PATH {
                prohibited_literal_value(text)
            } else {
                prohibited_value(text)
            };
            if unsafe_value {
                errors.push(format!("{path} contains prohibited value"));
            }
            if path == CATALOG_PATH {
                scan_prohibited_text_fields(text, path, errors);
            }
        }
        _ => {}
    }
}

fn endpoint_block(program: &str, endpoint: &str, _errors: &mut Vec<String>) -> String {
    let active_program = csharp_without_comments(program);
    let start_indexes = endpoint_start_indexes(program, endpoint);
    if start_indexes.is_empty() || start_indexes.len() > 1 {
        return String::new();
    }

    let start_index = start_indexes[0];
    let next_endpoint_index = mapget_start_indexes(program)
        .into_iter()
        .find(|index| *index > start_index)
        .unwrap_or(active_program.len());
    active_program
        .get(start_index..next_endpoint_index)
        .unwrap_or_default()
        .to_string()
}

fn endpoint_payload_block(endpoint: &str, errors: &mut Vec<String>) -> String {
    let masked_endpoint = csharp_code_mask(endpoint);
    let Some(results_index) = masked_endpoint.find("Results.Json") else {
        errors.push("API missing adapter readiness JSON payload".to_string());
        return String::new();
    };
    let Some(object_start) = masked_endpoint[results_index..]
        .find('{')
        .map(|index| results_index + index)
    else {
        errors.push("API missing adapter readiness JSON payload".to_string());
        return String::new();
    };
    let Some(object_end) = matching_brace_index(&masked_endpoint, object_start) else {
        errors.push("API adapter readiness JSON payload must be a single object".to_string());
        return String::new();
    };

    endpoint
        .get(object_start..=object_end)
        .unwrap_or_default()
        .to_string()
}

fn top_level_assignment_value(block: &str, field: &str) -> Option<String> {
    let matches: Vec<String> = top_level_field_assignments(block)
        .into_iter()
        .filter_map(|(name, value)| if name == field { Some(value) } else { None })
        .collect();
    if matches.len() == 1 {
        matches.into_iter().next()
    } else {
        None
    }
}

fn top_level_field_assignments(block: &str) -> Vec<(String, String)> {
    let masked = csharp_code_mask(block);
    let bytes = masked.as_bytes();
    let mut assignments = Vec::new();
    let mut index = 0;

    while index < bytes.len() {
        if is_ident_start(bytes[index]) {
            let name_start = index;
            index += 1;
            while index < bytes.len() && is_ident_char(bytes[index]) {
                index += 1;
            }
            let name = &masked[name_start..index];
            let value_start = skip_whitespace(&masked, index);
            if masked.as_bytes().get(value_start) == Some(&b'=')
                && brace_depth_at(&masked, name_start) == 1
            {
                let value_start = value_start + 1;
                let value_end = top_level_value_end(&masked, value_start);
                assignments.push((
                    name.to_string(),
                    block
                        .get(value_start..value_end)
                        .unwrap_or_default()
                        .trim()
                        .to_string(),
                ));
                index = value_end.saturating_add(1);
            }
        } else {
            index += 1;
        }
    }
    assignments
}

fn top_level_value_end(block: &str, value_start: usize) -> usize {
    let bytes = block.as_bytes();
    let mut index = value_start;
    while index < bytes.len() {
        if bytes[index] == b','
            && brace_depth_at(block, index) == 1
            && bracket_depth_at(block, index) == 0
            && paren_depth_at(block, index) == 0
        {
            return index;
        }
        if bytes[index] == b'}'
            && brace_depth_at(block, index) == 1
            && bracket_depth_at(block, index) == 0
            && paren_depth_at(block, index) == 0
        {
            return index;
        }
        index += 1;
    }
    index
}

fn adapter_readiness_declarations(program: &str) -> Vec<String> {
    let masked_program = csharp_code_mask(program);
    let mut declarations = Vec::new();
    let mut offset = 0;

    while let Some(match_offset) = masked_program[offset..].find("new AdapterReadiness") {
        let start = offset + match_offset;
        let Some(open_paren) = masked_program[start..].find('(').map(|index| start + index) else {
            break;
        };
        let Some(close_paren) = matching_paren_index(&masked_program, open_paren) else {
            break;
        };
        declarations.push(
            program
                .get(start..=close_paren)
                .unwrap_or_default()
                .trim()
                .to_string(),
        );
        offset = close_paren + 1;
    }
    declarations
}

fn endpoint_start_indexes(program: &str, endpoint: &str) -> Vec<usize> {
    mapget_start_indexes(program)
        .into_iter()
        .filter(|start_index| {
            mapget_route_literal(program, *start_index).as_deref() == Some(endpoint)
        })
        .collect()
}

fn mapget_start_indexes(program: &str) -> Vec<usize> {
    let masked = csharp_code_mask(program);
    let bytes = masked.as_bytes();
    let mut indexes = Vec::new();
    let mut index = 0;

    while index < bytes.len() {
        if word_at(&masked, index, "app") {
            let mut cursor = index + 3;
            cursor = skip_whitespace(&masked, cursor);
            if masked.as_bytes().get(cursor) == Some(&b'.') {
                cursor = skip_whitespace(&masked, cursor + 1);
                if word_at(&masked, cursor, "MapGet") {
                    cursor = skip_whitespace(&masked, cursor + 6);
                    if masked.as_bytes().get(cursor) == Some(&b'(') {
                        indexes.push(index);
                    }
                }
            }
        }
        index += 1;
    }
    indexes
}

fn mapget_route_literal(program: &str, start_index: usize) -> Option<String> {
    let open_paren = program.get(start_index..)?.find('(')? + start_index;
    let index = skip_whitespace(program, open_paren + 1);
    csharp_string_literal_at(program, index).map(|(literal, _)| literal)
}

fn csharp_without_comments(text: &str) -> String {
    let mut result = text.as_bytes().to_vec();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes.get(index..index + 2) == Some(b"//") {
            let finish = text[index..]
                .find('\n')
                .map(|offset| index + offset)
                .unwrap_or(bytes.len());
            mask_range(&mut result, index, finish);
            index = finish;
        } else if bytes.get(index..index + 2) == Some(b"/*") {
            let finish = text[index + 2..]
                .find("*/")
                .map(|offset| index + 2 + offset + 2)
                .unwrap_or(bytes.len());
            mask_range(&mut result, index, finish);
            index = finish;
        } else {
            index += 1;
        }
    }
    String::from_utf8_lossy(&result).into_owned()
}

fn csharp_code_mask(text: &str) -> String {
    let mut result = text.as_bytes().to_vec();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes.get(index..index + 2) == Some(b"//") {
            let finish = text[index..]
                .find('\n')
                .map(|offset| index + offset)
                .unwrap_or(bytes.len());
            mask_range(&mut result, index, finish);
            index = finish;
        } else if bytes.get(index..index + 2) == Some(b"/*") {
            let finish = text[index + 2..]
                .find("*/")
                .map(|offset| index + 2 + offset + 2)
                .unwrap_or(bytes.len());
            mask_range(&mut result, index, finish);
            index = finish;
        } else if raw_string_start(bytes, index) {
            let finish = raw_string_end_index(bytes, index);
            mask_range(&mut result, index, finish);
            index = finish;
        } else if bytes[index] == b'"' {
            let finish = string_end_index(bytes, index);
            mask_range(&mut result, index, finish);
            index = finish;
        } else if bytes[index] == b'\'' {
            let finish = char_end_index(bytes, index);
            mask_range(&mut result, index, finish);
            index = finish;
        } else {
            index += 1;
        }
    }
    String::from_utf8_lossy(&result).into_owned()
}

fn raw_string_start(bytes: &[u8], index: usize) -> bool {
    bytes.get(index..index + 3) == Some(b"\"\"\"")
}

fn raw_string_end_index(bytes: &[u8], start_index: usize) -> usize {
    let mut quote_count = 0;
    while bytes.get(start_index + quote_count) == Some(&b'"') {
        quote_count += 1;
    }
    let marker = vec![b'"'; quote_count];
    let mut index = start_index + quote_count;
    while index + quote_count <= bytes.len() {
        if bytes.get(index..index + quote_count) == Some(marker.as_slice()) {
            return index + quote_count;
        }
        index += 1;
    }
    bytes.len()
}

fn mask_range(bytes: &mut [u8], start_index: usize, end_index: usize) {
    for byte in bytes.iter_mut().take(end_index).skip(start_index) {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

fn string_end_index(bytes: &[u8], start_index: usize) -> usize {
    let mut index = start_index + 1;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return index + 1;
        }
        index += 1;
    }
    bytes.len()
}

fn char_end_index(bytes: &[u8], start_index: usize) -> usize {
    let mut index = start_index + 1;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'\'' {
            return index + 1;
        }
        index += 1;
    }
    bytes.len()
}

fn csharp_string_literal_at(text: &str, index: usize) -> Option<(String, usize)> {
    if text.as_bytes().get(index) != Some(&b'"') {
        return None;
    }
    let finish = string_end_index(text.as_bytes(), index);
    Some((
        text.get(index + 1..finish.saturating_sub(1))?.to_string(),
        finish,
    ))
}

fn matching_brace_index(text: &str, open_index: usize) -> Option<usize> {
    let mut depth = 0;
    for (index, byte) in text.as_bytes().iter().enumerate().skip(open_index) {
        if *byte == b'{' {
            depth += 1;
        }
        if *byte == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn matching_paren_index(text: &str, open_index: usize) -> Option<usize> {
    let mut depth = 0;
    for (index, byte) in text.as_bytes().iter().enumerate().skip(open_index) {
        if *byte == b'(' {
            depth += 1;
        }
        if *byte == b')' {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn brace_depth_at(text: &str, target_index: usize) -> i32 {
    text.as_bytes()
        .iter()
        .take(target_index)
        .fold(0, |depth, byte| match byte {
            b'{' => depth + 1,
            b'}' => depth - 1,
            _ => depth,
        })
}

fn paren_depth_at(text: &str, target_index: usize) -> i32 {
    text.as_bytes()
        .iter()
        .take(target_index)
        .fold(0, |depth, byte| match byte {
            b'(' => depth + 1,
            b')' => depth - 1,
            _ => depth,
        })
}

fn bracket_depth_at(text: &str, target_index: usize) -> i32 {
    text.as_bytes()
        .iter()
        .take(target_index)
        .fold(0, |depth, byte| match byte {
            b'[' => depth + 1,
            b']' => depth - 1,
            _ => depth,
        })
}

fn catalog_adapters(catalog: &Value) -> Vec<AdapterRecord> {
    catalog
        .get("adapters")
        .and_then(Value::as_array)
        .map(|adapters| {
            adapters
                .iter()
                .filter_map(AdapterRecord::from_value)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

#[derive(Clone)]
struct AdapterRecord {
    id: String,
    component: String,
    api_group: String,
    safe_capabilities: Vec<String>,
    blocked_reasons: Vec<String>,
}

impl AdapterRecord {
    fn from_value(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        Some(Self {
            id: object.get("id")?.as_str()?.to_string(),
            component: object.get("component")?.as_str()?.to_string(),
            api_group: object.get("apiGroup")?.as_str()?.to_string(),
            safe_capabilities: string_array(object.get("safeCapabilities")),
            blocked_reasons: string_array(object.get("blockedReasons")),
        })
    }
}

fn adapter_field_values(adapters: &[Value], field: &str) -> Vec<String> {
    adapters
        .iter()
        .filter_map(|adapter| adapter.get(field).and_then(Value::as_str))
        .map(ToString::to_string)
        .collect()
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn missing_values(required: &[&str], actual: &[String]) -> Vec<String> {
    let actual: BTreeSet<&str> = actual.iter().map(String::as_str).collect();
    required
        .iter()
        .filter(|value| !actual.contains(**value))
        .map(|value| (*value).to_string())
        .collect()
}

fn values_unique(values: &[String]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn is_kebab_case(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let mut previous_dash = false;
    for byte in value.bytes() {
        let valid = byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-';
        if !valid || (byte == b'-' && previous_dash) {
            return false;
        }
        previous_dash = byte == b'-';
    }
    !value.starts_with('-') && !value.ends_with('-')
}

fn prohibited_hash_key(key: &str) -> bool {
    !SAFE_HASH_KEYS.contains(&key) && (prohibited_field(key) || prohibited_value(key))
}

fn prohibited_field(field: &str) -> bool {
    let normalized = normalize_identifier(field);
    PROHIBITED_FIELD_FRAGMENTS
        .iter()
        .any(|fragment| normalized.contains(fragment))
}

fn prohibited_value(text: &str) -> bool {
    prohibited_literal_value(text)
        || contains_assignment_for(text, SECRET_ASSIGNMENT_FIELDS)
        || contains_assignment_for(text, PROVIDER_ASSIGNMENT_FIELDS)
}

fn prohibited_literal_value(text: &str) -> bool {
    contains_aws_access_key(text)
        || text.to_ascii_lowercase().contains("-----begin ")
            && text.to_ascii_lowercase().contains("private key-----")
        || contains_url_scheme(text)
        || contains_private_ip(text)
        || contains_uuid(text)
}

fn scan_prohibited_text_fields(text: &str, path: &str, errors: &mut Vec<String>) {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if is_ident_start(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len() && (is_ident_char(bytes[index]) || bytes[index] == b'-') {
                index += 1;
            }
            let ident = &text[start..index];
            let cursor = skip_whitespace(text, index);
            if matches!(bytes.get(cursor), Some(b':' | b'='))
                && !SAFE_HASH_KEYS.contains(&ident)
                && prohibited_field(ident)
            {
                errors.push(format!("{path} contains prohibited adapter field {ident}"));
            }
        } else if bytes[index] == b'"' || bytes[index] == b'\'' {
            let quote = bytes[index];
            let start = index + 1;
            let finish = if quote == b'"' {
                string_end_index(bytes, index).saturating_sub(1)
            } else {
                char_end_index(bytes, index).saturating_sub(1)
            };
            if finish <= bytes.len() && finish >= start {
                let ident = &text[start..finish];
                let cursor = skip_whitespace(text, finish + 1);
                if matches!(bytes.get(cursor), Some(b':' | b'='))
                    && !SAFE_HASH_KEYS.contains(&ident)
                    && prohibited_field(ident)
                {
                    errors.push(format!("{path} contains prohibited adapter field {ident}"));
                }
            }
            index = finish.saturating_add(1);
        } else {
            index += 1;
        }
    }
}

fn contains_assignment_for(text: &str, fields: &[&str]) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if is_ident_start(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len() && (is_ident_char(bytes[index]) || bytes[index] == b'-') {
                index += 1;
            }
            let ident = normalize_identifier(&text[start..index]);
            let cursor = skip_whitespace(text, index);
            if matches!(bytes.get(cursor), Some(b':' | b'=')) && fields.contains(&ident.as_str()) {
                return true;
            }
        } else {
            index += 1;
        }
    }
    false
}

fn contains_aws_access_key(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    let mut index = 0;
    while index + 20 <= bytes.len() {
        if bytes.get(index..index + 4) == Some(b"AKIA")
            && bytes[index + 4..index + 20]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        {
            return true;
        }
        index += 1;
    }
    false
}

fn contains_url_scheme(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index + 3 <= bytes.len() {
        if bytes.get(index..index + 3) == Some(b"://") {
            let mut start = index;
            while start > 0 {
                let previous = bytes[start - 1];
                if previous.is_ascii_alphanumeric()
                    || previous == b'+'
                    || previous == b'.'
                    || previous == b'-'
                {
                    start -= 1;
                } else {
                    break;
                }
            }
            if start < index && bytes[start].is_ascii_alphabetic() {
                return true;
            }
        }
        index += 1;
    }
    false
}

fn contains_private_ip(text: &str) -> bool {
    text.split(|char: char| !(char.is_ascii_digit() || char == '.'))
        .any(is_private_ipv4)
}

fn is_private_ipv4(value: &str) -> bool {
    let octets: Vec<u8> = value
        .split('.')
        .filter_map(|part| part.parse::<u8>().ok())
        .collect();
    octets.len() == 4
        && (octets[0] == 10
            || (octets[0] == 192 && octets[1] == 168)
            || (octets[0] == 172 && (16..=31).contains(&octets[1])))
}

fn contains_uuid(text: &str) -> bool {
    text.split(|char: char| !(char.is_ascii_hexdigit() || char == '-'))
        .any(|token| {
            token.len() == 36
                && [8, 13, 18, 23]
                    .iter()
                    .all(|index| token.as_bytes().get(*index) == Some(&b'-'))
                && token.chars().enumerate().all(|(index, char)| {
                    [8, 13, 18, 23].contains(&index) || char.is_ascii_hexdigit()
                })
        })
}

fn normalize_identifier(value: &str) -> String {
    value
        .chars()
        .filter(|char| char.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn csharp_string_array_literal(values: &[String]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| format!("\"{value}\""))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn word_at(text: &str, index: usize, word: &str) -> bool {
    text.get(index..index + word.len()) == Some(word)
        && (index == 0 || !is_ident_char(text.as_bytes()[index - 1]))
        && text
            .as_bytes()
            .get(index + word.len())
            .map(|byte| !is_ident_char(*byte))
            .unwrap_or(true)
}

fn skip_whitespace(text: &str, mut index: usize) -> usize {
    while text
        .as_bytes()
        .get(index)
        .map(|byte| byte.is_ascii_whitespace())
        .unwrap_or(false)
    {
        index += 1;
    }
    index
}

fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_ident_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
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
    fn mapget_start_indexes_ignore_comments_and_raw_strings() {
        let program = r#"
/* app.MapGet("/api/integrations/vmware/readiness", () => AdapterReadinessResult(adapterReadiness, "vmware")); */
var decoy = """
app.MapGet("/api/integrations/vmware/readiness", () => AdapterReadinessResult(adapterReadiness, "vmware"));
""";
app . MapGet ("/api/integrations/vmware/readiness", () => AdapterReadinessResult(adapterReadiness, "vmware"));
"#;

        let starts = endpoint_start_indexes(program, "/api/integrations/vmware/readiness");

        assert_eq!(starts.len(), 1);
        assert!(program[starts[0]..].starts_with("app . MapGet"));
    }

    #[test]
    fn adapter_declarations_ignore_raw_string_decoys() {
        let program = r#"
var decoy = """
new AdapterReadiness("vmware", "VmwareAdapter", "vmware", "blocked", "missing-secret-reference", false, true, true, true, ["readiness"], ["secret-reference-missing", "approval-route-required"])
""";
"#;

        assert!(adapter_readiness_declarations(program).is_empty());
    }

    #[test]
    fn prohibited_scan_rejects_provider_identifying_literals_and_fields() {
        let value = serde_json::json!({
            "endpointUrl": "safe-summary",
            "notes": [
                "providerEndpoint: safe-summary",
                "https://provider.example.invalid/path"
            ]
        });
        let mut errors = Vec::new();

        scan_prohibited_value(&value, "test", &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("test.endpointUrl contains prohibited adapter field")));
        assert!(errors
            .iter()
            .any(|error| error.contains("test.notes[0] contains prohibited value")));
        assert!(errors
            .iter()
            .any(|error| error.contains("test.notes[1] contains prohibited value")));
    }

    #[test]
    fn raw_catalog_text_scan_rejects_commented_sensitive_keys() {
        let mut errors = Vec::new();

        scan_prohibited_value(
            &Value::String("# tenantId: synthetic-placeholder\n".to_string()),
            CATALOG_PATH,
            &mut errors,
        );

        assert!(errors.iter().any(|error| {
            error.contains(CATALOG_PATH) && error.contains("prohibited adapter field tenantId")
        }));
    }
}
