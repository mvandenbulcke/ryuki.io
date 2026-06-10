use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/site-catalog.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/site-catalog.md";
const ENDPOINT: &str = "/api/catalog/site-catalog-contract";
const REQUIRED_DOMAIN: &str = "CORP.local";
const REQUIRED_OU_PATTERN: &str = "OU=Servers,OU=<SITE>,OU=<COUNTRY>,DC=corp,DC=local";
const REQUIRED_NETWORK: &str = "DHCP";
const REQUIRED_ORGANIZATION: &str = "Ryuki EU";
const REQUIRED_WINDOWS_BEHAVIOR: &[&str] = &["Sysprep", "VM-name generator", "Change SID"];
const REQUIRED_SITE_FACTS: &[(&str, &str, &str, i64)] = &[
    ("belove-windows-customization", "BE", "LOVE", 105),
    ("esbur1-windows-customization", "ES", "BUR1", 105),
    ("esccss-windows-customization", "ES", "CCSS", 105),
    ("estor1-windows-customization", "ES", "TOR1", 105),
    ("estruj-windows-customization", "ES", "TRUJ", 105),
    ("esvill-windows-customization", "ES", "VILL", 105),
    ("fralbi-windows-customization", "FR", "ALBI", 105),
    ("fraost-windows-customization", "FR", "AOST", 105),
    ("frmacl-windows-customization", "FR", "MACL", 105),
    ("frssym-windows-customization", "FR", "SSYM", 105),
    ("nlwijh-windows-customization", "NL", "WIJH", 105),
    ("ptrma1-windows-customization", "PT", "RMA1", 85),
    ("ropite-windows-customization", "RO", "PITE", 130),
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsAllowed",
    "liveValidationAllowed",
    "xmlParsingAllowed",
    "workflowMutationAllowed",
    "rawXmlAllowed",
    "encryptedValuesAllowed",
    "passwordValuesAllowed",
    "credentialIdentifiersAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "privateNetworkValuesAllowed",
    "rawProviderPayloadsAllowed",
    "rawSiteInventoryRowsAllowed",
    "rawRecipientDataAllowed",
];
const SAFE_TRUE_FIELDS: &[&str] = &["safeXmlFactsOnly"];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Site catalog summary",
    "Safe XML fact review",
    "OU pattern review",
    "Windows behavior review",
    "Validation result",
    "Evidence references",
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("windowsBehavior", "siteCatalogWindowsBehavior"),
    ("sites", "siteCatalogFacts"),
    ("requiredEvidence", "siteCatalogRequiredEvidence"),
];
const ALLOWED_ENDPOINT_FIELDS_BASE: &[&str] = &[
    "source",
    "catalogMode",
    "domain",
    "ouPattern",
    "network",
    "organization",
    "safeXmlFactsOnly",
];
const SITE_FACT_FIELDS: &[&str] = &["spec", "country", "site", "timezoneCode"];
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
        .map_err(|error| format!("invalid site catalog contract context JSON: {error}"))?;
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
    validate_no_prohibited_values(&docs_scope, "site-catalog", &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid site catalog contract catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid site catalog contract program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid site catalog contract docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid site catalog contract prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_no_prohibited_values(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "site catalog version must be 1",
    );
    expect(
        catalog.get("domain").and_then(Value::as_str) == Some(REQUIRED_DOMAIN),
        errors,
        "site catalog domain must match safe seed",
    );
    expect(
        catalog.get("ouPattern").and_then(Value::as_str) == Some(REQUIRED_OU_PATTERN),
        errors,
        "site catalog OU pattern must match safe seed",
    );
    expect(
        catalog.get("network").and_then(Value::as_str) == Some(REQUIRED_NETWORK),
        errors,
        "site catalog network must be DHCP",
    );
    expect(
        catalog.get("organization").and_then(Value::as_str) == Some(REQUIRED_ORGANIZATION),
        errors,
        "site catalog organization must match safe seed",
    );
    expect(
        string_array_like(catalog, "windowsBehavior") == REQUIRED_WINDOWS_BEHAVIOR,
        errors,
        "site catalog Windows behavior must match safe seed",
    );
    let sites = site_facts_from_catalog(catalog);
    expect(
        sites == required_site_facts_json(),
        errors,
        "site facts must match canonical safe XML facts",
    );
    let site_codes: Vec<String> = sites
        .iter()
        .filter_map(|site| site.get("site").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    let site_specs: Vec<String> = sites
        .iter()
        .filter_map(|site| site.get("spec").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    expect(
        site_codes.iter().collect::<HashSet<&String>>().len() == site_codes.len(),
        errors,
        "site codes must be unique",
    );
    expect(
        site_specs.iter().collect::<HashSet<&String>>().len() == site_specs.len(),
        errors,
        "site specs must be unique",
    );
    validate_no_prohibited_values(catalog, CATALOG_PATH, errors);
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = strip_csharp_comments(program);
    let Some(call) = endpoint_call_for_program(&uncommented_program, errors) else {
        return;
    };
    validate_endpoint_call_safety(&call, errors);
    let block = endpoint_response_body_from_call(&call, errors);
    if block.is_empty() {
        return;
    }

    expect(
        exact_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static-seed source",
    );
    expect(
        exact_string_assignment(&block, "catalogMode", "safe-site-facts"),
        errors,
        "API must keep safe-site-facts mode",
    );
    for (field, key, message) in [
        ("domain", "domain", "API domain must match catalog"),
        (
            "ouPattern",
            "ouPattern",
            "API OU pattern must match catalog",
        ),
        ("network", "network", "API network must match catalog"),
        (
            "organization",
            "organization",
            "API organization must match catalog",
        ),
    ] {
        expect(
            catalog
                .get(key)
                .and_then(Value::as_str)
                .is_some_and(|value| exact_string_assignment(&block, field, value)),
            errors,
            message,
        );
    }
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
    }
    expect(
        csharp_array_values(&uncommented_program, "siteCatalogWindowsBehavior")
            == Some(string_array_like(catalog, "windowsBehavior")),
        errors,
        "API windowsBehavior must match catalog",
    );
    expect(
        csharp_site_facts(&uncommented_program) == Some(site_facts_from_catalog(catalog)),
        errors,
        "API sites must match catalog",
    );
    expect(
        csharp_array_values(&uncommented_program, "siteCatalogRequiredEvidence")
            == Some(
                REQUIRED_EVIDENCE
                    .iter()
                    .map(|value| value.to_string())
                    .collect(),
            ),
        errors,
        "API requiredEvidence must match contract",
    );
    validate_site_catalog_facts_fields(&uncommented_program, errors);
    validate_endpoint_field_names(&block, errors);
    validate_no_unsafe_true_flags(&block, errors);
    validate_no_prohibited_values(&Value::String(block), PROGRAM_PATH, errors);
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
        "API README must document site catalog endpoint",
    );
    expect(
        catalog_readme.contains("site-catalog.yaml"),
        errors,
        "catalog README must include site catalog",
    );
    expect(
        doc_readme.contains("site-catalog.md"),
        errors,
        "workflow README must include site catalog doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "site catalog doc must mention endpoint",
    );
    expect(
        doc.contains("No encrypted XML values"),
        errors,
        "site catalog doc must prohibit encrypted XML values",
    );
    expect(
        doc.contains("raw recipient data"),
        errors,
        "site catalog doc must prohibit raw recipient data",
    );
    expect(
        doc.contains("catalog/site-catalog.yaml"),
        errors,
        "site catalog doc must mention source catalog",
    );
}

#[cfg(test)]
fn endpoint_response_body(program: &str, errors: &mut Vec<String>) -> String {
    let Some(call) = endpoint_call_for_program(program, errors) else {
        return String::new();
    };
    endpoint_response_body_from_call(&call, errors)
}

fn endpoint_call_for_program(program: &str, errors: &mut Vec<String>) -> Option<String> {
    let start_indexes = endpoint_start_indexes(program);
    if start_indexes.is_empty() {
        errors.push(format!("API missing endpoint {ENDPOINT}"));
        return None;
    }
    if start_indexes.len() != 1 {
        errors.push(format!(
            "API endpoint {ENDPOINT} must have exactly one active endpoint route"
        ));
        return None;
    }
    let start_index = start_indexes[0];
    let next_index = next_endpoint_index(program, start_index).unwrap_or(program.len());
    let endpoint_block = &program[start_index..next_index];
    let Some(call) = endpoint_call_text(endpoint_block) else {
        errors.push(format!("API endpoint {ENDPOINT} block is incomplete"));
        return None;
    };
    Some(call.to_string())
}

fn endpoint_response_body_from_call(call: &str, errors: &mut Vec<String>) -> String {
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
    if !results_json_object_argument_is_exact(&masked, marker_index, close_index) {
        errors.push(format!(
            "API endpoint {ENDPOINT} must return object initializer"
        ));
        return String::new();
    }
    call[open_index + 1..close_index].to_string()
}

fn validate_endpoint_call_safety(call: &str, errors: &mut Vec<String>) {
    for identifier in csharp_identifier_tokens(call) {
        if prohibited_field(&identifier) {
            errors.push(format!(
                "API endpoint has prohibited site catalog identifier {identifier}"
            ));
        }
    }
}

#[cfg(test)]
fn endpoint_start_index(program: &str) -> Option<usize> {
    endpoint_start_indexes(program).into_iter().next()
}

fn endpoint_start_indexes(program: &str) -> Vec<usize> {
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
        let Some(return_index) = return_keyword_start_before_marker(&masked, marker_index) else {
            return false;
        };
        handler_prefix_allows_direct_return(&masked, body_start, return_index)
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
    let trimmed = line_prefix[trimmed_start..].trim();
    if trimmed == "return" {
        Some(line_start + trimmed_start)
    } else {
        None
    }
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
    let mut values = Vec::new();
    let masked = mask_csharp_string_literals(block);
    let mut index = 0;
    while index < masked.len() {
        let Some(relative) = masked[index..].find('=') else {
            break;
        };
        let equals_index = index + relative;
        if brace_depth_at(&masked, equals_index) == 0
            && assignment_field_before_equals(block, equals_index).as_deref() == Some(field)
        {
            if let Some(value_start) = next_non_whitespace_index(block, equals_index + 1) {
                let value_end = assignment_value_end(&masked, value_start);
                values.push(block[value_start..value_end].trim().to_string());
            }
        }
        index = equals_index + 1;
    }
    values
}

fn assignment_value_end(masked: &str, start_index: usize) -> usize {
    let mut brace_depth = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    for (relative, ch) in masked[start_index..].char_indices() {
        let index = start_index + relative;
        match ch {
            '{' => brace_depth += 1,
            '}' => brace_depth = brace_depth.saturating_sub(1),
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            ',' if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 => return index,
            _ => {}
        }
    }
    masked.len()
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let fields = endpoint_assignment_fields(block);
    for field in unique_strings(&fields) {
        let count = fields
            .iter()
            .filter(|candidate| *candidate == &field)
            .count();
        if count > 1 {
            errors.push(format!("API endpoint field {field} must be unique"));
        }
    }
    for field in fields {
        if !allowed_endpoint_field(&field) {
            errors.push(format!(
                "API endpoint has unexpected site catalog field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited site catalog field {field}"
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
            "allowed",
            "enabled",
            "provider",
            "live",
            "xml",
            "workflow",
            "raw",
            "encrypted",
            "password",
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
    csharp_variable_body(program, variable).and_then(|body| csharp_array_literal_values(&body))
}

fn csharp_site_facts(program: &str) -> Option<Vec<Value>> {
    let body = csharp_variable_body(program, "siteCatalogFacts")?;
    let mut facts = Vec::new();
    for element in top_level_elements(&body) {
        let block = csharp_inline_object_body(element)?;
        facts.push(serde_json::json!({
            "spec": csharp_string_field(&block, "spec"),
            "country": csharp_string_field(&block, "country"),
            "site": csharp_string_field(&block, "site"),
            "timezoneCode": csharp_i64_field(&block, "timezoneCode"),
        }));
    }
    Some(facts)
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

fn csharp_inline_object_body(element: &str) -> Option<String> {
    let trimmed = element.trim();
    let masked = mask_csharp_string_literals(trimmed);
    let new_index = next_non_whitespace_index(&masked, 0)?;
    if !masked[new_index..].starts_with("new") || !is_word_boundary(&masked, new_index, "new") {
        return None;
    }
    let open_index = next_non_whitespace_index(&masked, new_index + "new".len())?;
    if masked.as_bytes().get(open_index) != Some(&b'{') {
        return None;
    }
    let close_index = matching_brace_index(trimmed, open_index)?;
    if !trimmed[close_index + 1..].trim().is_empty() {
        return None;
    }
    Some(trimmed[open_index + 1..close_index].to_string())
}

fn validate_site_catalog_facts_fields(program: &str, errors: &mut Vec<String>) {
    let Some(body) = csharp_variable_body(program, "siteCatalogFacts") else {
        return;
    };
    for block in csharp_object_blocks(&body) {
        let id = assignment_values_for_field(&block, "spec")
            .first()
            .and_then(|value| parse_quoted_value(value))
            .unwrap_or_else(|| "unknown-site".to_string());
        for field in endpoint_assignment_fields(&block) {
            if !SITE_FACT_FIELDS.contains(&field.as_str()) {
                errors.push(format!("{id} has unexpected site fact field {field}"));
                continue;
            }
            if prohibited_field(&field) {
                errors.push(format!("{id} has prohibited site fact field {field}"));
            }
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

fn csharp_string_field(block: &str, field: &str) -> Value {
    assignment_values_for_field(block, field)
        .first()
        .and_then(|value| parse_quoted_value(value))
        .map(Value::String)
        .unwrap_or(Value::Null)
}

fn csharp_i64_field(block: &str, field: &str) -> Value {
    assignment_values_for_field(block, field)
        .first()
        .and_then(|value| value.parse::<i64>().ok())
        .map(Value::from)
        .unwrap_or(Value::Null)
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
                        "{path}.{key} contains prohibited site catalog field"
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
                    "{path} contains prohibited site catalog field {text}"
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

fn prohibited_provider_identifier_value(text: &str) -> bool {
    contains_sha40_like(text) || contains_provider_serial_like(text)
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

fn contains_sha40_like(text: &str) -> bool {
    text.split(|ch: char| !ch.is_ascii_hexdigit())
        .any(|candidate| {
            candidate.len() == 40 && candidate.chars().all(|ch| ch.is_ascii_hexdigit())
        })
}

fn contains_provider_serial_like(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'))
        .any(|candidate| {
            let upper = candidate.to_ascii_uppercase();
            let Some(rest) = upper
                .strip_prefix("SN-")
                .or_else(|| upper.strip_prefix("SN_"))
                .or_else(|| upper.strip_prefix("SERIAL-"))
                .or_else(|| upper.strip_prefix("SERIAL_"))
            else {
                return false;
            };
            rest.len() >= 6
                && rest.chars().all(|ch| ch.is_ascii_alphanumeric())
                && rest.chars().any(|ch| ch.is_ascii_digit())
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
        "encryptedxml",
        "rawxml",
        "password",
        "credential",
        "tenantid",
        "objectid",
        "privateip",
        "providerpayload",
        "rawsite",
        "inventoryrows",
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
        || (has_any(&tokens, &["id", "guid"]) && tokens.len() > 1)
        || (has_any(&tokens, &["private", "ip"])
            && has_any(&tokens, &["address", "value", "network"]))
        || (has_any(&tokens, &["tenant", "object", "provider"])
            && has_any(&tokens, &["id", "identifier", "payload", "value"]))
        || (tokens.iter().any(|token| token == "raw")
            && has_any(
                &tokens,
                &["xml", "provider", "site", "inventory", "rows", "payload"],
            ))
        || tokens.iter().any(|token| token == "recipient")
        || (tokens.iter().any(|token| token == "encrypted")
            && tokens.iter().any(|token| token == "xml"))
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
    values.extend_from_slice(REQUIRED_WINDOWS_BEHAVIOR);
    values.extend_from_slice(REQUIRED_DISABLED_FIELDS);
    values.extend_from_slice(SAFE_TRUE_FIELDS);
    values.extend_from_slice(REQUIRED_EVIDENCE);
    values.extend(
        ENDPOINT_ARRAY_BINDINGS
            .iter()
            .map(|(_, variable)| *variable),
    );
    values.extend([
        "static-seed",
        "safe-site-facts",
        "DHCP",
        REQUIRED_DOMAIN,
        REQUIRED_OU_PATTERN,
        REQUIRED_ORGANIZATION,
        "true",
        "false",
    ]);
    for (spec, country, site, timezone_code) in REQUIRED_SITE_FACTS {
        values.push(*spec);
        values.push(*country);
        values.push(*site);
        values.push(match timezone_code {
            85 => "85",
            105 => "105",
            130 => "130",
            _ => "",
        });
    }
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

fn required_site_facts_json() -> Vec<Value> {
    REQUIRED_SITE_FACTS
        .iter()
        .map(|(spec, country, site, timezone_code)| {
            serde_json::json!({
                "spec": spec,
                "country": country,
                "site": site,
                "timezoneCode": timezone_code,
            })
        })
        .collect()
}

fn site_facts_from_catalog(catalog: &Value) -> Vec<Value> {
    catalog
        .get("sites")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|site| {
            serde_json::json!({
                "spec": site.get("spec").and_then(Value::as_str).unwrap_or_default(),
                "country": site.get("country").and_then(Value::as_str).unwrap_or_default(),
                "site": site.get("site").and_then(Value::as_str).unwrap_or_default(),
                "timezoneCode": site.get("timezoneCode").and_then(Value::as_i64).unwrap_or_default(),
            })
        })
        .collect()
}

fn unique_strings(values: &[String]) -> Vec<String> {
    let mut result = Vec::new();
    for value in values {
        if !result.iter().any(|candidate| candidate == value) {
            result.push(value.clone());
        }
    }
    result
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

fn csharp_identifier_tokens(source: &str) -> Vec<String> {
    let masked = mask_csharp_string_literals(source);
    let mut identifiers = Vec::new();
    let mut index = 0usize;
    while index < masked.len() {
        let ch = masked[index..].chars().next().expect("index within string");
        if ch == '_' || ch.is_ascii_alphabetic() {
            let start = index;
            index += ch.len_utf8();
            while index < masked.len() {
                let next = masked[index..].chars().next().expect("index within string");
                if next == '_' || next.is_ascii_alphanumeric() {
                    index += next.len_utf8();
                } else {
                    break;
                }
            }
            identifiers.push(source[start..index].to_string());
        } else {
            index += ch.len_utf8();
        }
    }
    identifiers
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

    fn canonical_catalog() -> Value {
        serde_json::json!({
            "version": 1,
            "domain": REQUIRED_DOMAIN,
            "ouPattern": REQUIRED_OU_PATTERN,
            "network": REQUIRED_NETWORK,
            "organization": REQUIRED_ORGANIZATION,
            "windowsBehavior": REQUIRED_WINDOWS_BEHAVIOR,
            "sites": required_site_facts_json(),
        })
    }

    #[test]
    fn catalog_duplicate_site_codes_and_specs_are_reported() {
        let mut catalog = canonical_catalog();
        let sites = catalog
            .get_mut("sites")
            .and_then(Value::as_array_mut)
            .expect("sites");
        let duplicate_site = sites[0]
            .get("site")
            .and_then(Value::as_str)
            .expect("site")
            .to_string();
        let duplicate_spec = sites[0]
            .get("spec")
            .and_then(Value::as_str)
            .expect("spec")
            .to_string();
        sites[1]["site"] = Value::String(duplicate_site);
        sites[2]["spec"] = Value::String(duplicate_spec);
        let mut errors = Vec::new();

        validate_catalog_value(&catalog, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("site codes must be unique")));
        assert!(errors
            .iter()
            .any(|error| error.contains("site specs must be unique")));
    }

    #[test]
    fn endpoint_start_ignores_scoped_dead_route() {
        let program = format!(
            "if (false)\n{{\n    app.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ catalogMode = \"safe-site-facts\" }}));\n}}\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ catalogMode = \"raw-xml\" }}));"
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
            "#if false\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ catalogMode = \"safe-site-facts\" }}));\n#endif\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ catalogMode = \"raw-xml\" }}));"
        );
        let start = endpoint_start_index(&program).expect("real endpoint");
        assert!(program[..start].contains("#endif"));
        assert!(program[start..].starts_with("app.MapGet("));
    }

    #[test]
    fn endpoint_start_ignores_raw_string_decoy() {
        let program = format!(
            "var decoy = \"\"\"\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ catalogMode = \"safe-site-facts\" }}));\n\"\"\";\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ catalogMode = \"raw-xml\" }}));"
        );
        let start = endpoint_start_index(&program).expect("real endpoint");
        assert!(program[..start].contains("\"\"\""));
        assert!(program[start..].starts_with("app.MapGet("));
    }

    #[test]
    fn endpoint_response_ignores_scoped_dead_response() {
        let mut errors = Vec::new();
        let program = format!(
            "app.MapGet(\"{ENDPOINT}\", () =>\n{{\n    if (false)\n    {{\n        return Results.Json(new {{ catalogMode = \"safe-site-facts\" }});\n    }}\n    return Results.Json(new {{ catalogMode = \"raw-xml\" }});\n}});"
        );
        let body = endpoint_response_body(&program, &mut errors);
        assert_eq!(
            assignment_values_for_field(&body, "catalogMode"),
            vec!["\"raw-xml\"".to_string()]
        );
    }

    #[test]
    fn endpoint_response_rejects_multiple_handler_responses() {
        let mut errors = Vec::new();
        let program = format!(
            "app.MapGet(\"{ENDPOINT}\", () =>\n{{\n    if (false) return Results.Json(new {{ catalogMode = \"safe-site-facts\" }});\n    return Results.Json(new {{ catalogMode = \"raw-xml\" }});\n}});"
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
            "app.MapGet(\"{ENDPOINT}\", () => requested ? Results.Json(new {{ catalogMode = \"safe-site-facts\" }}) : Results.Json(new {{ catalogMode = \"raw-xml\" }}));"
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
            "app.MapGet(\"{ENDPOINT}\", () =>\n{{\n    if (requested) return Results.Json(payload);\n    return Results.Json(new {{ catalogMode = \"safe-site-facts\" }});\n}});"
        );
        let body = endpoint_response_body(&program, &mut errors);
        assert!(body.is_empty());
        assert!(errors
            .iter()
            .any(|error| error.contains("must return one unconditional Results.Json object")));
    }

    #[test]
    fn duplicate_active_endpoint_route_is_rejected() {
        let mut errors = Vec::new();
        let program = format!(
            "app.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ catalogMode = \"safe-site-facts\" }}));\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ catalogMode = \"raw-xml\" }}));"
        );
        let call = endpoint_call_for_program(&program, &mut errors);
        assert!(call.is_none());
        assert!(errors
            .iter()
            .any(|error| error.contains("exactly one active endpoint")));
    }

    #[test]
    fn conditional_indented_return_is_rejected() {
        let mut errors = Vec::new();
        let program = format!(
            "app.MapGet(\"{ENDPOINT}\", () =>\n{{\n    if (requested)\n        return Results.Json(new {{ catalogMode = \"safe-site-facts\" }});\n}});"
        );
        let body = endpoint_response_body(&program, &mut errors);
        assert!(body.is_empty());
        assert!(errors
            .iter()
            .any(|error| error.contains("must return one unconditional Results.Json object")));
    }

    #[test]
    fn object_initializer_transform_suffix_is_rejected() {
        let mut errors = Vec::new();
        let program = format!(
            "app.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ catalogMode = \"safe-site-facts\" }}.ToString()));"
        );
        let body = endpoint_response_body(&program, &mut errors);
        assert!(body.is_empty());
        assert!(errors
            .iter()
            .any(|error| error.contains("must return object initializer")));
    }

    #[test]
    fn assignment_ignores_nested_object_decoy() {
        let block = "metadata = new\n{\n    catalogMode = \"safe-site-facts\"\n},\ncatalogMode = \"raw-xml\",\n";
        assert!(!exact_string_assignment(
            block,
            "catalogMode",
            "safe-site-facts"
        ));
        assert!(exact_string_assignment(block, "catalogMode", "raw-xml"));
    }

    #[test]
    fn assignment_fields_ignore_quoted_sensitive_decoys() {
        let block = "source = \"static-seed\",\noperatorNote = \"endpointUrl = safe-summary\",\ncatalogMode = \"safe-site-facts\",\n";
        let fields = endpoint_assignment_fields(block);
        assert_eq!(
            fields,
            vec![
                "source".to_string(),
                "operatorNote".to_string(),
                "catalogMode".to_string()
            ]
        );
        assert!(!fields.iter().any(|field| field == "endpointUrl"));
    }

    #[test]
    fn duplicate_source_assignment_spoof_is_reported() {
        let block = "source = \"static-seed\",\nsource = \"live-provider\",\n";
        let mut errors = Vec::new();
        validate_endpoint_field_names(block, &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.contains("source") && error.contains("unique")));
    }

    #[test]
    fn prohibited_suffix_bypasses_are_rejected() {
        assert!(prohibited_value("10.77.77.77.extra"));
        assert!(prohibited_value(
            "00000000-0000-0000-0000-000000000000-extra"
        ));
        assert!(prohibited_value("-----begin sample private key-----"));
    }

    #[test]
    fn provider_identifier_literals_are_rejected() {
        assert!(prohibited_provider_identifier_value(
            "0123456789abcdef0123456789abcdef01234567"
        ));
        assert!(prohibited_provider_identifier_value("SN-ABC12345"));
    }

    #[test]
    fn endpoint_field_newline_assignment_is_reported() {
        let block = "source = \"static-seed\",\nencryptedXml\n    = \"safe-summary\",\n";
        let mut errors = Vec::new();
        validate_endpoint_field_names(block, &mut errors);
        assert!(errors.iter().any(|error| error.contains("encryptedXml")));
    }

    #[test]
    fn endpoint_property_identifier_is_reported_with_safe_value() {
        let block = "endpointUrl = \"safe-summary\",\n";
        let mut errors = Vec::new();
        validate_endpoint_field_names(block, &mut errors);
        assert!(errors.iter().any(|error| error.contains("endpointUrl")));
    }

    #[test]
    fn site_fact_unknown_sensitive_field_is_reported() {
        let block = r#"
            spec = "belove-windows-customization",
            country = "BE",
            site = "LOVE",
            timezoneCode = 105,
            encryptedXml = "safe-summary",
        "#;
        let mut errors = Vec::new();
        for field in endpoint_assignment_fields(block) {
            if !SITE_FACT_FIELDS.contains(&field.as_str()) {
                errors.push(format!(
                    "belove-windows-customization has unexpected site fact field {field}"
                ));
            }
        }
        assert!(errors.iter().any(|error| error.contains("encryptedXml")));
    }
}
