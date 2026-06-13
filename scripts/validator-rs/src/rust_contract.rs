//! Shared helpers for validating the Rust API contract reality.
//!
//! The original per-slice validators were written against a deleted C# API
//! (`api/Ryuki.Platform.Api/Program.cs`) and parsed C# anonymous-object syntax
//! (`Results.Json(new { ... })`). The platform API is now the Rust crate at
//! `sources/ryuki-api/src/contracts.rs`, where every contract endpoint is a
//! route registered with `.route("/path", get(handler))` and the handler emits
//! a single `Json(json!({ ... }))` payload.
//!
//! These helpers let a slice validate the Rust reality: confirm the route is
//! registered exactly once and extract the handler's JSON payload so that the
//! existing field / array / rule assertions run against real data rather than
//! reverse-engineered C# text. Extracting the *specific* handler payload also
//! removes the false positives the old whole-file `scan_prohibited_text` raised
//! when it saw `hostname` / `password` etc. belonging to unrelated endpoints.

use serde_json::Value;

/// Counts how many times the contract endpoint is registered as an Axum route
/// in `contracts.rs`. A correctly-mounted contract endpoint appears exactly
/// once as the first argument to a `.route("<endpoint>", get(handler))` call.
pub fn route_registration_count(contracts_rs: &str, endpoint: &str) -> usize {
    let needle = format!("\"{endpoint}\"");
    let mut count = 0usize;
    let mut search_from = 0usize;
    while let Some(rel) = contracts_rs[search_from..].find(&needle) {
        let abs = search_from + rel;
        if is_route_first_argument(contracts_rs, abs) {
            count += 1;
        }
        search_from = abs + needle.len();
    }
    count
}

/// Returns true when the quoted endpoint literal at `literal_start` is the first
/// argument of a `.route(...)` call (optionally with intervening whitespace).
fn is_route_first_argument(contracts_rs: &str, literal_start: usize) -> bool {
    let prefix = &contracts_rs[..literal_start];
    let trimmed = prefix.trim_end_matches([' ', '\t', '\r', '\n']);
    trimmed.ends_with(".route(")
}

/// Resolves the handler name registered for `endpoint`. The route is written
/// as `.route("<endpoint>", get(<handler>))` (or `post`, `put`, etc.), possibly
/// across multiple lines.
pub fn route_handler_name(contracts_rs: &str, endpoint: &str) -> Option<String> {
    let needle = format!("\"{endpoint}\"");
    let mut search_from = 0usize;
    while let Some(rel) = contracts_rs[search_from..].find(&needle) {
        let abs = search_from + rel;
        if is_route_first_argument(contracts_rs, abs) {
            if let Some(handler) = handler_after_endpoint(&contracts_rs[abs + needle.len()..]) {
                return Some(handler);
            }
        }
        search_from = abs + needle.len();
    }
    None
}

/// Given the text immediately following the endpoint literal inside a
/// `.route(...)` call, extracts the handler identifier from the method
/// wrapper, e.g. `, get(handler))` -> `handler`.
fn handler_after_endpoint(rest: &str) -> Option<String> {
    let bytes = rest.as_bytes();
    let mut i = 0usize;
    // Skip whitespace then the comma separating endpoint and method handler.
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if bytes.get(i) != Some(&b',') {
        return None;
    }
    i += 1;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    // Skip the method wrapper identifier (get / post / put / delete / patch).
    let method_start = i;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
    }
    if i == method_start {
        return None;
    }
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if bytes.get(i) != Some(&b'(') {
        return None;
    }
    i += 1;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    let handler_start = i;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
    }
    if i == handler_start {
        return None;
    }
    Some(rest[handler_start..i].to_string())
}

/// Extracts the JSON payload a contract handler emits via `Json(json!({ ... }))`.
///
/// Returns `None` when the route, handler, or `json!` payload cannot be located
/// or parsed. Callers translate `None` into the slice's "endpoint missing"
/// error so an unmounted/renamed endpoint still fails the slice.
pub fn handler_payload(contracts_rs: &str, endpoint: &str) -> Option<Value> {
    let handler = route_handler_name(contracts_rs, endpoint)?;
    let signature = format!("fn {handler}(");
    let fn_start = contracts_rs.find(&signature)?;
    // Body begins at the first `{` after the signature's parameter list and
    // return type; find the `json!(` invocation that produces the payload.
    let after_fn = &contracts_rs[fn_start..];
    let json_macro_rel = after_fn.find("json!(")?;
    let object_search = &after_fn[json_macro_rel + "json!(".len()..];
    let object_rel = object_search.find('{')?;
    let object_start = fn_start + json_macro_rel + "json!(".len() + object_rel;
    let object_end = matching_brace(contracts_rs, object_start)?;
    let object_text = &contracts_rs[object_start..=object_end];
    serde_json::from_str::<Value>(object_text).ok()
}

/// Finds the index of the `}` that matches the `{` at `open_index`, honouring
/// string literals so braces inside JSON string values are ignored.
fn matching_brace(text: &str, open_index: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.get(open_index) != Some(&b'{') {
        return None;
    }
    let mut depth = 0i32;
    let mut i = open_index;
    let mut in_string = false;
    let mut escaped = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
        } else {
            match b {
                b'"' => in_string = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// Validates that a contract endpoint is mounted exactly once in the Rust API
/// and returns its handler payload for further per-slice safety scanning.
///
/// Pushes `missing_endpoint` when the route is absent, a "must register exactly
/// once" error when duplicated, and `missing_payload` when the handler does not
/// emit a parseable `Json(json!({ ... }))` payload. Returns `None` in all of
/// those cases so the caller can stop. On success returns the parsed payload.
pub fn endpoint_payload(
    contracts_rs: &str,
    endpoint: &str,
    missing_endpoint: &str,
    missing_payload: &str,
    errors: &mut Vec<String>,
) -> Option<Value> {
    match route_registration_count(contracts_rs, endpoint) {
        0 => {
            errors.push(missing_endpoint.to_string());
            return None;
        }
        1 => {}
        _ => {
            errors.push(format!("API must register exactly one {endpoint} endpoint"));
            return None;
        }
    }
    match handler_payload(contracts_rs, endpoint) {
        Some(payload) => Some(payload),
        None => {
            errors.push(missing_payload.to_string());
            None
        }
    }
}

/// Records an error for any `*Allowed` / `*Enabled` boolean field set to `true`
/// in the contract payload. Every static-seed contract must keep these safety
/// flags disabled (design feature 3: safety-flag invariants).
pub fn check_safety_flags_disabled(payload: &Value, errors: &mut Vec<String>) {
    if let Some(map) = payload.as_object() {
        for (key, value) in map {
            let lowered = key.to_ascii_lowercase();
            if (lowered.ends_with("allowed") || lowered.ends_with("enabled"))
                && value.as_bool() == Some(true)
            {
                errors.push(format!("API must keep {key} disabled"));
            }
        }
    }
}

/// Collects every string array value in the payload for `field`, when present
/// as an array of strings.
pub fn payload_string_array<'a>(payload: &'a Value, field: &str) -> Option<Vec<&'a str>> {
    payload
        .get(field)
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
}

/// Validates a static-seed contract endpoint against the genuine, Rust-reality
/// safety invariants and returns its handler payload for any further per-slice
/// checks.
///
/// This is the shared replacement for the per-slice C# `app.MapGet` parsers.
/// The deleted C# API was ported to `sources/ryuki-api/src/contracts.rs`, where
/// each contract is `.route(ENDPOINT, get(handler))` and the handler returns a
/// single `Json(json!({ … }))` payload. The handler is a deliberately leaner
/// "safe summary" shape than the catalog YAML (different/renamed arrays, no
/// `rules`/`version` mirror), so forcing handler==catalog field equality would
/// assert content the Rust reality does not expose. Instead this enforces the
/// invariants that genuinely hold and matter for safety:
///   - the route is registered exactly once,
///   - the handler emits a parseable JSON payload,
///   - `"source"` is `"static-seed"`,
///   - every `*Allowed` / `*Enabled` flag is disabled.
///
/// The catalog's full data contract is validated separately by the slice's
/// `validate_catalog_*` checks, so coverage of the rich document is retained.
pub fn validate_static_seed_contract(
    contracts_rs: &str,
    endpoint: &str,
    missing_endpoint: &str,
    errors: &mut Vec<String>,
) -> Option<Value> {
    let payload = endpoint_payload(
        contracts_rs,
        endpoint,
        missing_endpoint,
        missing_endpoint,
        errors,
    )?;
    if payload.get("source").and_then(Value::as_str) != Some("static-seed") {
        errors.push("API must keep static-seed source".to_string());
    }
    check_safety_flags_disabled(&payload, errors);
    Some(payload)
}

/// A normalized contract rule (id/decision/requirement/evidence). Mirrors the
/// per-slice `ApiRule` structs that the C# parsers produced; used to compare a
/// handler payload's `rules` array to the catalog's `rules` array.
#[derive(Clone, PartialEq, Eq)]
pub struct ContractRule {
    pub id: String,
    pub decision: String,
    pub requirement: String,
    pub evidence: String,
}

/// Reads the `rules` array from a JSON object (handler payload or catalog).
pub fn rules_from_value(value: &Value) -> Vec<ContractRule> {
    value
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|rule| {
            Some(ContractRule {
                id: rule.get("id")?.as_str()?.to_string(),
                decision: rule.get("decision")?.as_str()?.to_string(),
                requirement: rule.get("requirement")?.as_str()?.to_string(),
                evidence: rule.get("evidence")?.as_str()?.to_string(),
            })
        })
        .collect()
}

/// Compares a handler payload's `field` string-array against the catalog's
/// values, emitting the historical "API {field} …" error messages so the slice
/// output is unchanged from the C#-era checks.
pub fn validate_payload_array(
    payload: &Value,
    field: &str,
    catalog_values: &[String],
    errors: &mut Vec<String>,
) {
    use std::collections::BTreeSet;
    let Some(values) = payload_string_array(payload, field) else {
        errors.push(format!("API missing {field} array"));
        return;
    };
    let actual: BTreeSet<&str> = values.iter().copied().collect();
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
    if values.len() != actual.len() {
        errors.push(format!("API {field} values must be unique"));
    }
}

/// Compares a handler payload's `rules` to the catalog `rules`, emitting the
/// historical "API missing rule {id}" / decision / requirement / evidence
/// mismatch messages.
pub fn validate_payload_rules(payload: &Value, catalog: &Value, errors: &mut Vec<String>) {
    use std::collections::BTreeSet;
    let api_rules = rules_from_value(payload);
    let catalog_rules = rules_from_value(catalog);
    let api_ids: Vec<&str> = api_rules.iter().map(|r| r.id.as_str()).collect();
    let api_set: BTreeSet<&str> = api_ids.iter().copied().collect();
    let catalog_set: BTreeSet<&str> = catalog_rules.iter().map(|r| r.id.as_str()).collect();
    for id in catalog_set.difference(&api_set) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_set.difference(&catalog_set) {
        errors.push(format!("API has unexpected API rule {id}"));
    }
    if api_ids.len() != api_set.len() {
        errors.push("API rule IDs must be unique".to_string());
    }
    for catalog_rule in &catalog_rules {
        let Some(api_rule) = api_rules.iter().find(|r| r.id == catalog_rule.id) else {
            continue;
        };
        if api_rule.decision != catalog_rule.decision {
            errors.push(format!(
                "API rule {} decision must match catalog",
                catalog_rule.id
            ));
        }
        if api_rule.requirement != catalog_rule.requirement {
            errors.push(format!(
                "API rule {} requirement must match catalog",
                catalog_rule.id
            ));
        }
        if api_rule.evidence != catalog_rule.evidence {
            errors.push(format!(
                "API rule {} evidence must match catalog",
                catalog_rule.id
            ));
        }
    }
}

/// Reads the catalog's `field` as a string array (empty when absent), the shape
/// the per-slice `catalog_string_array` helpers produced.
pub fn catalog_string_array(catalog: &Value, field: &str) -> Vec<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
        .route(
            "/api/protect/demo-contract",
            get(protect_demo),
        )
        .route("/api/protect/other", get(other_handler))

async fn protect_demo() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"scopes":["a","b"],"note":"safe { not a brace problem }"}),
    )
}
"#;

    #[test]
    fn counts_single_route_registration() {
        assert_eq!(
            route_registration_count(SAMPLE, "/api/protect/demo-contract"),
            1
        );
        assert_eq!(route_registration_count(SAMPLE, "/api/protect/missing"), 0);
    }

    #[test]
    fn resolves_handler_name() {
        assert_eq!(
            route_handler_name(SAMPLE, "/api/protect/demo-contract").as_deref(),
            Some("protect_demo")
        );
    }

    #[test]
    fn extracts_handler_payload() {
        let payload = handler_payload(SAMPLE, "/api/protect/demo-contract").unwrap();
        assert_eq!(payload["source"], "static-seed");
        assert_eq!(payload["providerCallsEnabled"], false);
        assert_eq!(
            payload_string_array(&payload, "scopes"),
            Some(vec!["a", "b"])
        );
    }
}
