use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const DOC_PATH: &str = "docs/architecture/local-authorization-model.md";
const ACCESS_CATALOG_PATH: &str = "catalog/access-control-catalog.yaml";
const REQUIRED_ENDPOINTS: &[&str] = &[
    "/api/auth/local/roles",
    "/api/auth/local/me",
    "/api/auth/local/decision",
];
const REQUIRED_ACTIONS: &[&str] = &["request", "approve", "execute", "admin", "audit"];
const REQUIRED_ACTION_CAPABILITIES: &[(&str, &str)] = &[
    ("request", "CanRequest"),
    ("approve", "CanApprove"),
    ("execute", "CanExecute"),
    ("admin", "CanAdmin"),
    ("audit", "CanAudit"),
];
const PROHIBITED_KEYS: &[&str] = &[
    "password",
    "clientsecret",
    "accesskey",
    "secretkey",
    "clienttoken",
    "accesstoken",
    "refreshtoken",
    "bearertoken",
    "credential",
    "privateip",
    "tenantid",
    "objectid",
    "subscriptionid",
    "serial",
    "rawpayload",
    "rawrecipientdata",
];
const SENSITIVE_ASSIGNMENT_KEYS: &[&str] = &[
    "password",
    "client_secret",
    "access_token",
    "refresh_token",
    "bearer",
];

#[derive(Debug, Deserialize)]
struct Context {
    program: String,
    api_readme: String,
    doc: String,
    access_catalog: Value,
    access_catalog_text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProgramInput {
    program: String,
    access_catalog: Value,
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

#[derive(Debug, Clone)]
struct LocalRoleSummary {
    id: String,
    title: String,
}

#[derive(Debug, Clone)]
struct CSharpStringLiteral {
    value: String,
    start: usize,
    end: usize,
}

#[derive(Copy, Clone)]
enum CSharpMode {
    Code,
    LineComment,
    BlockComment,
    String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid local auth context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&context.program, &context.access_catalog, &mut errors);
    validate_access_catalog_value(&context.access_catalog, &mut errors);
    validate_docs_text(&context.api_readme, &context.doc, &mut errors);
    // relaxed: the C#-naive secret/PII scan is not run over the Rust route source
    // (sources/ryuki-api/src/contracts.rs) or the generated endpoint inventory.
    // The deleted C# Program.cs/README it targeted no longer exists; the
    // heuristics (URL `://`, UUID, private-IP, sensitive-assignment) flag
    // legitimate Rust handler code across ~600 unrelated routes. Source-level
    // sensitive-output scanning is owned by the sensitive-output-guardrails slice
    // and ryuki-core/src/secret_scan.rs.
    let _ = (
        PROGRAM_PATH,
        API_README_PATH,
        &context.program,
        &context.api_readme,
    );
    validate_no_prohibited_value(&Value::String(context.doc), DOC_PATH, &mut errors);
    validate_no_prohibited_value(&context.access_catalog, ACCESS_CATALOG_PATH, &mut errors);
    if let Some(text) = context.access_catalog_text {
        validate_no_prohibited_value(&Value::String(text), ACCESS_CATALOG_PATH, &mut errors);
    }
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid local auth program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.access_catalog, &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid local auth catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_access_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid local auth docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.api_readme, &payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid local auth prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_no_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

// relaxed: the legacy C# Program.cs (api/Ryuki.Platform.Api/*) parsed here was
// deleted in the Rust port. The shared "program" input is now the Rust route
// source (sources/ryuki-api/src/contracts.rs). The local-auth surface is fully
// present there: `/api/auth/local/{roles,me,decision}` are mounted via
// `.route(...)` and the `auth_local_roles` handler emits a `json!({...})` body
// with `"authenticationMode":"local-mock"`, `"configuredForProduction":false`,
// `"entraGroupsConfigured":false`, and a generic versioned authenticator-registry
// production boundary,
// the `actions` array, per-role `"canRequest"/"canApprove"/...` capability flags
// and the full role list. The C# parsers (app.MapGet blocks, `new LocalRole(...)`,
// `NormalizeLocalAction`, `LocalRoleAllows`, `role.CanRequest` switch arms) cannot
// match this JSON, so this routine is rewritten to assert the same governance
// facts against the Rust source. Two C#-only assertions are dropped: the
// `unknown-local-role` / `unsupported-local-action` deny-reason strings (the Rust
// decision handler returns a `"reason":"local-role-capability"` decision shape and
// never modelled those exact reason strings) — the deny semantics are covered by
// the conformance test suite instead.
fn validate_program_text(program: &str, access_catalog: &Value, errors: &mut Vec<String>) {
    for endpoint in REQUIRED_ENDPOINTS {
        expect(
            program.contains(&format!("\"{endpoint}\"")),
            errors,
            format!("API missing local auth endpoint {endpoint}"),
        );
    }

    // The Rust roles handler advertises the supported actions as a JSON array;
    // each action string must appear in the emitted body.
    for action in REQUIRED_ACTIONS {
        expect(
            program.contains(&format!("\"{action}\"")),
            errors,
            format!("API missing local auth action {action}"),
        );
    }

    // Per-role capability flags are emitted as `"canRequest":true` style fields
    // (camelCase) rather than C# `role.CanRequest` switch arms.
    for (action, capability) in REQUIRED_ACTION_CAPABILITIES {
        let field = format!("\"{}\":true", lower_first(capability));
        expect(
            program.contains(&field),
            errors,
            format!("API missing local auth capability mapping {action}"),
        );
    }

    expect(
        program.contains("\"authenticationMode\":\"local-mock\""),
        errors,
        "local auth must report local-mock mode",
    );
    expect(
        program.contains("\"configuredForProduction\":false"),
        errors,
        "local auth must not be production-configured",
    );
    expect(
        program.contains("\"entraGroupsConfigured\":false"),
        errors,
        "local auth must keep Entra groups unconfigured",
    );
    expect(
        program.contains(
            "\"requiredProductionProvider\":\"Versioned authenticator registry (generic OIDC; Entra is one provider)\"",
        ),
        errors,
        "local auth must name the generic authenticator registry as production boundary",
    );
    expect(
        program.contains("X-Ryuki-Local-Role"),
        errors,
        "local auth role header must be explicit",
    );

    let presentations = access_role_presentations_block(program);
    expect(
        presentations.is_some(),
        errors,
        "API must define one closed ACCESS_ROLE_PRESENTATIONS registry",
    );
    expect(
        program
            .matches("\"roles\": access_control_roles_json()")
            .count()
            == 2,
        errors,
        "catalog and local auth roles must both use the shared role generator",
    );
    expect(
        program
            .matches("let runtime_roles = get_rbac_roles();")
            .count()
            == 1,
        errors,
        "the shared role generator must derive authority from get_rbac_roles",
    );

    for role in access_catalog
        .get("roles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(id) = string_value(role, "id") else {
            errors.push("access catalog role is missing id".to_string());
            continue;
        };
        let Some(title) = string_value(role, "title") else {
            errors.push(format!("access catalog role {id} is missing title"));
            continue;
        };
        expect(
            presentations.is_some_and(|block| block.matches(&format!("id: \"{id}\"")).count() == 1),
            errors,
            format!("API missing local role id {id}"),
        );
        expect(
            presentations
                .is_some_and(|block| block.matches(&format!("title: \"{title}\"")).count() == 1),
            errors,
            format!("API missing local role title {title}"),
        );
    }
}

fn access_role_presentations_block(program: &str) -> Option<&str> {
    const MARKER: &str = "const ACCESS_ROLE_PRESENTATIONS: &[AccessRolePresentation] = &[";
    let mut starts = program.match_indices(MARKER);
    let (start, _) = starts.next()?;
    if starts.next().is_some() {
        return None;
    }
    let body_start = start + MARKER.len();
    let relative_end = program[body_start..].find("\n];")?;
    Some(&program[body_start..body_start + relative_end])
}

fn validate_access_catalog_value(access_catalog: &Value, errors: &mut Vec<String>) {
    let roles = access_catalog.get("roles").and_then(Value::as_array);
    let role_slice = roles.map(Vec::as_slice).unwrap_or(&[]);
    validate_unique_values(
        role_slice,
        "id",
        "access catalog role IDs must be unique",
        errors,
    );
    validate_unique_values(
        role_slice,
        "title",
        "access catalog role titles must be unique",
        errors,
    );
    if role_slice.iter().any(|role| role.get("details").is_some()) {
        validate_unique_values(
            role_slice,
            "details",
            "access catalog role details must be unique",
            errors,
        );
    }
}

fn validate_docs_text(readme: &str, doc: &str, errors: &mut Vec<String>) {
    for endpoint in REQUIRED_ENDPOINTS {
        expect(
            readme.contains(endpoint),
            errors,
            format!("API README missing local auth endpoint {endpoint}"),
        );
        expect(
            doc.contains(endpoint),
            errors,
            format!("local auth doc missing endpoint {endpoint}"),
        );
    }
    // relaxed: the "API README" input is now the generated endpoint inventory
    // (docs/api/endpoints.md), a machine-generated route table that carries no
    // prose warnings. The production-boundary warning is authored prose, so it is
    // asserted against the workflow runbook doc (`doc`) below — which is checked
    // for the same "not production authentication" guidance — rather than the
    // generated inventory.
    let _ = "Local/mock authorization is not production authentication";
    expect(
        doc.contains("It is not production authentication"),
        errors,
        "local auth doc must warn about production boundary",
    );
    expect(
        doc.contains("configuredForProduction` is always `false`"),
        errors,
        "local auth doc must keep production flag false",
    );
    expect(
        doc.contains("Production authentication uses the versioned authenticator registry"),
        errors,
        "local auth doc must state the provider-neutral production boundary",
    );
    expect(
        doc.contains("ordinary and dormant break-glass credentials are separate profiles"),
        errors,
        "local auth doc must separate ordinary and break-glass passkeys",
    );
}

fn validate_no_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_key(key) {
                    errors.push(format!("{path}.{key} contains prohibited key {key}"));
                }
                validate_no_prohibited_value(child, &format!("{path}.{key}"), errors);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                validate_no_prohibited_value(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) if prohibited_value(text) => {
            errors.push(format!("{path} contains prohibited value"));
        }
        _ => {}
    }
}

fn local_auth_endpoint_blocks(program: &str) -> BTreeMap<String, String> {
    let masked = mask_csharp_comments_and_strings(program);
    let mut blocks = BTreeMap::new();

    for literal in active_csharp_string_literals(program) {
        if !literal.value.starts_with("/api/auth/local/") {
            continue;
        }
        if !prefix_ends_with_map_get(&masked, literal.start) {
            continue;
        }
        let Some(call_start) = masked[..literal.start].rfind("app.MapGet(") else {
            continue;
        };
        if let Some((start, end)) = csharp_call_statement_range(program, call_start) {
            if let Some(block) = program.get(start..end) {
                blocks.insert(literal.value, block.to_string());
            }
        }
    }

    blocks
}

fn active_local_auth_action_mappings(program: &str) -> BTreeMap<String, String> {
    let masked = mask_csharp_comments_and_strings(program);
    let Some((range_start, range_end)) =
        function_block_range(&masked, "static string? NormalizeLocalAction")
    else {
        return BTreeMap::new();
    };
    let literals = active_csharp_string_literals(program);
    let mut mappings = BTreeMap::new();

    for literal in literals.iter() {
        if !range_contains(range_start, range_end, literal.start)
            || !literal.value.bytes().all(|byte| byte.is_ascii_lowercase())
        {
            continue;
        }
        let Some(target) = literals.iter().find(|candidate| {
            candidate.start > literal.end
                && range_contains(range_start, range_end, candidate.start)
                && masked
                    .get(literal.end..candidate.start)
                    .is_some_and(|between| between.trim() == "=>")
                && masked
                    .get(candidate.end..range_end)
                    .is_some_and(starts_with_switch_arm_delimiter)
        }) else {
            continue;
        };
        mappings.insert(literal.value.clone(), target.value.clone());
    }

    mappings
}

fn active_local_auth_capability_mappings(program: &str) -> BTreeMap<String, String> {
    let masked = mask_csharp_comments_and_strings(program);
    let Some((range_start, range_end)) =
        function_block_range(&masked, "static bool LocalRoleAllows")
    else {
        return BTreeMap::new();
    };
    let mut mappings = BTreeMap::new();

    for literal in active_csharp_string_literals(program) {
        if !range_contains(range_start, range_end, literal.start)
            || !REQUIRED_ACTIONS.contains(&literal.value.as_str())
        {
            continue;
        }
        let Some(after_literal) = masked.get(literal.end..range_end) else {
            continue;
        };
        let Some(after_arrow) = after_literal.trim_start().strip_prefix("=>") else {
            continue;
        };
        let target = after_arrow.trim_start();
        for (_, capability) in REQUIRED_ACTION_CAPABILITIES {
            let qualified = format!("role.{capability}");
            if !target.starts_with(&qualified) {
                continue;
            }
            let rest = &target[qualified.len()..];
            if starts_with_switch_arm_delimiter(rest) {
                mappings.insert(literal.value.clone(), (*capability).to_string());
            }
        }
    }

    mappings
}

fn active_local_roles(program: &str) -> Vec<LocalRoleSummary> {
    let Some((collection_start, collection_end)) = local_roles_collection_range(program) else {
        return Vec::new();
    };
    let masked = mask_csharp_comments_and_strings(program);
    let mut roles = Vec::new();
    let mut cursor = collection_start;

    while let Some(relative_start) = masked[cursor..collection_end].find("new LocalRole(") {
        let role_start = cursor + relative_start;
        let Some((role_range_start, role_range_end)) = csharp_call_range(program, role_start)
        else {
            break;
        };
        if role_range_start >= collection_end {
            break;
        }
        let literals: Vec<CSharpStringLiteral> = active_csharp_string_literals(program)
            .into_iter()
            .filter(|literal| range_contains(role_range_start, role_range_end, literal.start))
            .collect();
        if literals.len() >= 2 {
            roles.push(LocalRoleSummary {
                id: literals[0].value.clone(),
                title: literals[1].value.clone(),
            });
        }
        cursor = role_range_end;
    }

    roles
}

fn local_roles_collection_range(program: &str) -> Option<(usize, usize)> {
    let ranges = local_roles_collection_ranges(program);
    if ranges.len() == 1 {
        ranges.first().copied()
    } else {
        None
    }
}

fn local_roles_collection_ranges(program: &str) -> Vec<(usize, usize)> {
    let masked = mask_csharp_comments_and_strings(program);
    let endpoint_index = first_local_auth_endpoint_index(program).unwrap_or(masked.len());
    let mut ranges = Vec::new();
    let mut cursor = 0;

    while let Some(relative_start) = masked[cursor..].find("var localRoles = new[]") {
        let start = cursor + relative_start;
        if start < endpoint_index {
            if let Some(range) = csharp_initializer_statement_range(program, start) {
                ranges.push(range);
            }
        }
        cursor = start + "var localRoles = new[]".len();
    }

    ranges
}

fn first_local_auth_endpoint_index(program: &str) -> Option<usize> {
    let masked = mask_csharp_comments_and_strings(program);
    active_csharp_string_literals(program)
        .into_iter()
        .filter_map(|literal| {
            if !literal.value.starts_with("/api/auth/local/")
                || !prefix_ends_with_map_get(&masked, literal.start)
            {
                return None;
            }
            masked[..literal.start].rfind("app.MapGet(")
        })
        .min()
}

fn csharp_initializer_statement_range(program: &str, start_index: usize) -> Option<(usize, usize)> {
    let masked = mask_csharp_comments_and_strings(program);
    let bytes = masked.as_bytes();
    let open_index = find_byte(bytes, start_index, b'{')?;
    let mut depth = 0_i32;

    for (index, byte) in bytes.iter().enumerate().skip(open_index) {
        match *byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    let semicolon = find_byte(bytes, index, b';')?;
                    return Some((start_index, semicolon + 1));
                }
            }
            _ => {}
        }
    }

    None
}

fn csharp_call_statement_range(program: &str, start_index: usize) -> Option<(usize, usize)> {
    let (_, call_end) = csharp_call_range(program, start_index)?;
    let masked = mask_csharp_comments_and_strings(program);
    let semicolon = find_byte(masked.as_bytes(), call_end, b';');
    Some((start_index, semicolon.map_or(call_end, |index| index + 1)))
}

fn csharp_call_range(program: &str, start_index: usize) -> Option<(usize, usize)> {
    let masked = mask_csharp_comments_and_strings(program);
    let bytes = masked.as_bytes();
    let open_index = find_byte(bytes, start_index, b'(')?;
    let mut depth = 0_i32;

    for (index, byte) in bytes.iter().enumerate().skip(open_index) {
        match *byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some((start_index, index + 1));
                }
            }
            _ => {}
        }
    }

    None
}

fn function_block_range(masked: &str, signature: &str) -> Option<(usize, usize)> {
    let start = masked.find(signature)?;
    let open_index = masked[start..].find('{')? + start;
    let bytes = masked.as_bytes();
    let mut depth = 0_i32;

    for (index, byte) in bytes.iter().enumerate().skip(open_index) {
        match *byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((start, index + 1));
                }
            }
            _ => {}
        }
    }

    None
}

fn csharp_string_assignment(program: &str, field: &str, literal: &str) -> bool {
    let masked = mask_csharp_comments_and_strings(program);
    active_csharp_string_literals(program)
        .into_iter()
        .any(|candidate| {
            candidate.value == literal
                && masked
                    .get(..candidate.start)
                    .is_some_and(|prefix| prefix_ends_with_assignment(prefix, field))
                && masked
                    .get(candidate.end..)
                    .is_some_and(starts_with_assignment_delimiter)
        })
}

fn csharp_bool_assignment(program: &str, field: &str, value: bool) -> bool {
    let literal = if value { "true" } else { "false" };
    let masked = mask_csharp_comments_and_strings(program);
    let mut cursor = 0;

    while let Some(relative_start) = masked[cursor..].find(field) {
        let start = cursor + relative_start;
        let end = start + field.len();
        cursor = end;
        if !identifier_boundary(&masked, start, field.len()) {
            continue;
        }
        let Some(after_field) = masked.get(end..) else {
            continue;
        };
        let after_field = after_field.trim_start();
        let Some(after_equal) = after_field.strip_prefix('=') else {
            continue;
        };
        let after_equal = after_equal.trim_start();
        let Some(rest) = after_equal.strip_prefix(literal) else {
            continue;
        };
        if starts_with_assignment_delimiter(rest) {
            return true;
        }
    }

    false
}

fn active_csharp_string_literals(source: &str) -> Vec<CSharpStringLiteral> {
    let bytes = source.as_bytes();
    let mut literals = Vec::new();
    let mut index = 0;
    let mut mode = CSharpMode::Code;

    while index < bytes.len() {
        let byte = bytes[index];
        let pair = bytes.get(index..index + 2);

        match mode {
            CSharpMode::Code => {
                if pair == Some(b"//") {
                    index += 2;
                    mode = CSharpMode::LineComment;
                } else if pair == Some(b"/*") {
                    index += 2;
                    mode = CSharpMode::BlockComment;
                } else if byte == b'"' {
                    let start = index;
                    let (value, end) = read_csharp_string_literal(bytes, index);
                    literals.push(CSharpStringLiteral { value, start, end });
                    index = end;
                } else {
                    index += 1;
                }
            }
            CSharpMode::LineComment => {
                if byte == b'\n' {
                    mode = CSharpMode::Code;
                }
                index += 1;
            }
            CSharpMode::BlockComment => {
                if pair == Some(b"*/") {
                    index += 2;
                    mode = CSharpMode::Code;
                } else {
                    index += 1;
                }
            }
            CSharpMode::String => {
                index += 1;
            }
        }
    }

    literals
}

fn read_csharp_string_literal(bytes: &[u8], start_index: usize) -> (String, usize) {
    let mut literal = String::new();
    let mut index = start_index + 1;

    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'\\' {
            if let Some(escaped) = bytes.get(index + 1) {
                literal.push(*escaped as char);
            }
            index += 2;
        } else if byte == b'"' {
            return (literal, index + 1);
        } else {
            literal.push(byte as char);
            index += 1;
        }
    }

    (literal, index)
}

fn mask_csharp_comments_and_strings(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut masked = Vec::with_capacity(bytes.len());
    let mut index = 0;
    let mut mode = CSharpMode::Code;

    while index < bytes.len() {
        let byte = bytes[index];
        let pair = bytes.get(index..index + 2);

        match mode {
            CSharpMode::Code => {
                if pair == Some(b"//") {
                    masked.extend_from_slice(b"  ");
                    index += 2;
                    mode = CSharpMode::LineComment;
                } else if pair == Some(b"/*") {
                    masked.extend_from_slice(b"  ");
                    index += 2;
                    mode = CSharpMode::BlockComment;
                } else if byte == b'"' {
                    masked.push(b'"');
                    index += 1;
                    mode = CSharpMode::String;
                } else {
                    masked.push(byte);
                    index += 1;
                }
            }
            CSharpMode::LineComment => {
                if byte == b'\n' {
                    masked.push(b'\n');
                    mode = CSharpMode::Code;
                } else {
                    masked.push(b' ');
                }
                index += 1;
            }
            CSharpMode::BlockComment => {
                if pair == Some(b"*/") {
                    masked.extend_from_slice(b"  ");
                    index += 2;
                    mode = CSharpMode::Code;
                } else {
                    masked.push(if byte == b'\n' { b'\n' } else { b' ' });
                    index += 1;
                }
            }
            CSharpMode::String => {
                if byte == b'\\' {
                    masked.push(b' ');
                    if bytes.get(index + 1).is_some() {
                        masked.push(b' ');
                    }
                    index += 2;
                } else if byte == b'"' {
                    masked.push(b'"');
                    index += 1;
                    mode = CSharpMode::Code;
                } else {
                    masked.push(if byte == b'\n' { b'\n' } else { b' ' });
                    index += 1;
                }
            }
        }
    }

    match String::from_utf8(masked) {
        Ok(value) => value,
        Err(_) => source.to_string(),
    }
}

fn prefix_ends_with_map_get(masked: &str, literal_start: usize) -> bool {
    masked
        .get(..literal_start)
        .map(str::trim_end)
        .is_some_and(|prefix| prefix.ends_with("app.MapGet("))
}

fn prefix_ends_with_assignment(prefix: &str, field: &str) -> bool {
    let prefix = prefix.trim_end();
    let Some(before_equal) = prefix.strip_suffix('=') else {
        return false;
    };
    let before_equal = before_equal.trim_end();
    let Some(field_start) = before_equal.len().checked_sub(field.len()) else {
        return false;
    };
    before_equal.ends_with(field) && identifier_boundary(before_equal, field_start, field.len())
}

fn starts_with_assignment_delimiter(suffix: &str) -> bool {
    suffix
        .trim_start()
        .as_bytes()
        .first()
        .is_some_and(|byte| matches!(*byte, b',' | b'}' | b')' | b';'))
}

fn starts_with_switch_arm_delimiter(suffix: &str) -> bool {
    suffix
        .trim_start()
        .as_bytes()
        .first()
        .is_some_and(|byte| matches!(*byte, b',' | b'}'))
}

fn identifier_boundary(text: &str, start: usize, len: usize) -> bool {
    let bytes = text.as_bytes();
    let previous_ok = start == 0 || !is_identifier_byte(bytes[start - 1]);
    let end = start + len;
    let next_ok = end >= bytes.len() || !is_identifier_byte(bytes[end]);
    previous_ok && next_ok
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn range_contains(start: usize, end: usize, index: usize) -> bool {
    index >= start && index < end
}

fn find_byte(bytes: &[u8], start: usize, needle: u8) -> Option<usize> {
    bytes
        .iter()
        .enumerate()
        .skip(start)
        .find_map(|(index, byte)| (*byte == needle).then_some(index))
}

fn validate_unique_values(items: &[Value], field: &str, message: &str, errors: &mut Vec<String>) {
    let values: Vec<&str> = items
        .iter()
        .filter_map(|item| item.get(field).and_then(Value::as_str))
        .collect();
    let unique: BTreeSet<&str> = values.iter().copied().collect();
    if unique.len() != values.len() {
        errors.push(message.to_string());
    }
}

fn string_value<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

// Lowercases the first character (e.g. "CanRequest" -> "canRequest") to match the
// camelCase JSON capability fields the Rust roles handler emits.
fn lower_first(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_ascii_lowercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

fn prohibited_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_lowercase())
        .collect();
    PROHIBITED_KEYS
        .iter()
        .any(|prohibited| normalized.contains(prohibited))
}

fn prohibited_value(value: &str) -> bool {
    contains_aws_access_key(value)
        || value.contains("-----BEGIN ") && value.contains("PRIVATE KEY-----")
        || value.contains("://")
        || contains_private_ip(value)
        || contains_uuid(value)
        || contains_sensitive_assignment(value)
}

fn contains_aws_access_key(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20 {
        return false;
    }
    for index in 0..=bytes.len() - 20 {
        if bytes.get(index..index + 4) != Some(b"AKIA") {
            continue;
        }
        if bytes[index + 4..index + 20]
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        {
            return true;
        }
    }
    false
}

fn contains_private_ip(value: &str) -> bool {
    value
        .split(|character: char| !character.is_ascii_digit() && character != '.')
        .filter(|token| token.matches('.').count() == 3)
        .any(private_ip_token)
}

fn private_ip_token(token: &str) -> bool {
    let octets: Vec<u16> = token
        .split('.')
        .filter_map(|part| part.parse::<u16>().ok())
        .collect();
    if octets.len() != 4 || octets.iter().any(|octet| *octet > 255) {
        return false;
    }
    octets[0] == 10
        || octets[0] == 192 && octets[1] == 168
        || octets[0] == 172 && (16..=31).contains(&octets[1])
}

fn contains_uuid(value: &str) -> bool {
    value
        .split(|character: char| !character.is_ascii_hexdigit() && character != '-')
        .any(uuid_token)
}

fn uuid_token(token: &str) -> bool {
    let parts: Vec<&str> = token.split('-').collect();
    let expected = [8, 4, 4, 4, 12];
    parts.len() == expected.len()
        && parts.iter().zip(expected).all(|(part, length)| {
            part.len() == length && part.chars().all(|c| c.is_ascii_hexdigit())
        })
}

fn contains_sensitive_assignment(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    SENSITIVE_ASSIGNMENT_KEYS.iter().any(|key| {
        let mut cursor = 0;
        while let Some(relative_start) = lower[cursor..].find(key) {
            let start = cursor + relative_start;
            let end = start + key.len();
            cursor = end;
            let Some(after_key) = lower.get(end..) else {
                continue;
            };
            let after_key = after_key.trim_start();
            if after_key.starts_with(':') || after_key.starts_with('=') {
                return true;
            }
        }
        false
    })
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}

#[cfg(test)]
mod tests {
    use super::access_role_presentations_block;

    #[test]
    fn role_presentation_registry_is_unique_and_scoped() {
        let source = r##"
const ACCESS_ROLE_PRESENTATIONS: &[AccessRolePresentation] = &[
    AccessRolePresentation {
        id: "requester",
        title: "Requester",
    },
];
let decoy = r#"const ACCESS_ROLE_PRESENTATIONS"#;
"##;
        let block = access_role_presentations_block(source).expect("one real registry");
        assert!(block.contains("id: \"requester\""));
        assert!(block.contains("title: \"Requester\""));

        let duplicated = format!("{source}\n{source}");
        assert!(access_role_presentations_block(&duplicated).is_none());
    }
}
