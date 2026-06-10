use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/design-system-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/design-system.md";
const UI_DESIGN_PATH: &str = "docs/ui/design-system.md";
const ACCESSIBILITY_PATH: &str = "docs/ui/accessibility-checklist.md";
const PORTAL_CSS_PATH: &str = "portal/portal-ui/styles.css";
const ENDPOINT: &str = "/api/platform/design-system-contract";

const REQUIRED_BRAND_TOKENS: &[&str] = &["configurable-branding"];
const REQUIRED_SURFACES: &[&str] = &[
    "light-theme",
    "dark-theme",
    "accessibility-notes",
    "branding-configuration",
    "neutral-surfaces",
    "status-badges",
    "dense-tables",
    "request-forms",
    "error-evidence-presentation",
];
const REQUIRED_STATUS_FAMILIES: &[&str] = &[
    "lifecycle",
    "risk",
    "health",
    "evidence",
    "protection",
    "monitoring",
];
const REQUIRED_INPUTS: &[&str] = &[
    "themeSummary",
    "accessibilitySummary",
    "brandingSummary",
    "surfaceSummary",
    "statusBadgeSummary",
    "tableGuidanceSummary",
    "formGuidanceSummary",
    "errorEvidenceSummary",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "light-theme-reviewed",
    "dark-theme-reviewed",
    "contrast-reviewed",
    "focus-treatment-reviewed",
    "non-color-status-reviewed",
    "branding-reviewed",
    "table-density-reviewed",
    "form-safety-reviewed",
    "evidence-presentation-reviewed",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "themeUsage",
    "accessibilityNotes",
    "brandingConfiguration",
    "uiSurfaces",
    "statusBadges",
    "tables",
    "forms",
    "errorEvidencePresentation",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "live-theme-mutation-disabled",
    "external-font-fetch-disabled",
    "unsafe-error-detail-disabled",
    "raw-ui-diagnostic-rows-disabled",
    "raw-evidence-payloads-disabled",
    "raw-provider-payloads-disabled",
    "credential-values-disabled",
    "secret-values-disabled",
    "access-token-values-disabled",
    "raw-recipient-data-disabled",
    "light-theme-review-missing",
    "dark-theme-review-missing",
    "contrast-review-missing",
    "focus-treatment-review-missing",
    "non-color-status-review-missing",
    "branding-review-missing",
    "table-density-review-missing",
    "form-safety-review-missing",
    "evidence-presentation-review-missing",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Light theme review",
    "Dark theme review",
    "Accessibility review",
    "Branding configuration review",
    "UI surface review",
    "Status badge review",
    "Table guidance review",
    "Form guidance review",
    "Error and evidence presentation review",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "liveThemeMutationAllowed",
    "externalFontFetchAllowed",
    "unsafeErrorDetailAllowed",
    "rawUiDiagnosticRowsAllowed",
    "rawEvidencePayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "credentialValuesAllowed",
    "secretValuesAllowed",
    "accessTokenValuesAllowed",
    "rawRecipientDataAllowed",
];
const SAFE_TRUE_FIELDS: &[&str] = &[
    "lightModeRequired",
    "darkModeRequired",
    "accessibilityReviewRequired",
    "evidenceSafetyRequired",
];
const CATALOG_FIELDS: &[&str] = &[
    "version",
    "status",
    "source",
    "designMode",
    "lightModeRequired",
    "darkModeRequired",
    "accessibilityReviewRequired",
    "evidenceSafetyRequired",
    "brandTokens",
    "designSurfaces",
    "statusFamilies",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "liveThemeMutationAllowed",
    "externalFontFetchAllowed",
    "unsafeErrorDetailAllowed",
    "rawUiDiagnosticRowsAllowed",
    "rawEvidencePayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "credentialValuesAllowed",
    "secretValuesAllowed",
    "accessTokenValuesAllowed",
    "rawRecipientDataAllowed",
];
const RULE_FIELDS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("designSurfaces", "designSystemSurfaces"),
    ("statusFamilies", "designSystemStatusFamilies"),
    ("requiredGuards", "designSystemRequiredGuards"),
    ("planSections", "designSystemPlanSections"),
    ("blockedReasons", "designSystemBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["brandTokens", "requiredInputs", "requiredEvidence"];
const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "branding-admin-configurable",
        decision: "block",
        requirement: "Branding is admin-configurable through the admin portal. Accent color and logo are set by the administrator. Neutral operational defaults are shown until configured. No specific brand colors or logo assets are committed to the repository.",
        evidence: "Branding configuration review",
    },
    RuleDetail {
        id: "light-dark-theme-required",
        decision: "block",
        requirement: "Light and dark mode must be reviewed for text, badges, focus states, table surfaces, empty states, and error and evidence states before UI readiness is accepted.",
        evidence: "Dark theme review",
    },
    RuleDetail {
        id: "accessibility-status-required",
        decision: "block",
        requirement: "Status presentation must use text and visible focus treatment, not color alone, and must make stale, degraded, blocked, failed, and emergency states explicit.",
        evidence: "Accessibility review",
    },
    RuleDetail {
        id: "evidence-error-safety-required",
        decision: "block",
        requirement: "UI error and evidence presentation must show safe summaries and redaction state instead of raw implementation or provider detail.",
        evidence: "Error and evidence presentation review",
    },
    RuleDetail {
        id: "raw-design-data-not-exposed",
        decision: "block",
        requirement: "Design system evidence must use safe summaries only and must not expose external font URLs, logo asset URLs, tenant IDs, object IDs, private IPs, credential values, secret values, access tokens, raw provider payloads, raw evidence payloads, raw UI diagnostic rows, stack traces, recipient addresses, or implementation internals.",
        evidence: "Error and evidence presentation review",
    },
];

#[derive(Debug, Deserialize)]
struct Context {
    catalog: Value,
    catalog_text: String,
    program: String,
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
    ui_design: String,
    accessibility: String,
    portal_css: String,
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
    ui_design: String,
    accessibility: String,
}

#[derive(Debug, Deserialize)]
struct ProhibitedInput {
    value: Value,
    path: String,
}

#[derive(Debug, Deserialize)]
struct ValuesInput {
    kind: String,
    block: Option<String>,
    catalog: Option<Value>,
    css: Option<String>,
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
    keys: Vec<String>,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid design system context JSON: {error}"))?;
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
    validate_portal_css_text(&context.portal_css, &mut errors);
    validate_docs_text(
        &context.api_readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &context.ui_design,
        &context.accessibility,
        &mut errors,
    );
    for (path, text) in [
        (API_README_PATH, context.api_readme),
        (CATALOG_README_PATH, context.catalog_readme),
        (DOC_README_PATH, context.doc_readme),
        (DOC_PATH, context.doc),
        (UI_DESIGN_PATH, context.ui_design),
        (ACCESSIBILITY_PATH, context.accessibility),
    ] {
        scan_prohibited_value(&Value::String(text), path, &mut errors);
    }
    for block in raw_endpoint_blocks(&context.program) {
        scan_prohibited_value(&Value::String(block), PROGRAM_PATH, &mut errors);
    }
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid design system catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid design system program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid design system docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(
        &payload.api_readme,
        &payload.catalog_readme,
        &payload.doc_readme,
        &payload.doc,
        &payload.ui_design,
        &payload.accessibility,
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_values_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ValuesInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid design system values JSON: {error}"))?;
    let mut errors = Vec::new();
    match payload.kind.as_str() {
        "portal_css" => validate_portal_css_text(&payload.css.unwrap_or_default(), &mut errors),
        "api_rules" => {
            let block = payload.block.unwrap_or_default();
            let catalog = payload.catalog.unwrap_or(Value::Null);
            validate_api_rules(&block, &catalog, &mut errors);
        }
        "endpoint_field_names" => {
            validate_endpoint_field_names(&payload.block.unwrap_or_default(), &mut errors);
        }
        "unsafe_true_flags" => {
            validate_no_unsafe_true_flags(&payload.block.unwrap_or_default(), &mut errors);
        }
        other => errors.push(format!("unsupported design system values kind {other}")),
    }
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid design system prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("design system catalog root must be mapping".to_string());
        return;
    }
    validate_catalog_keys(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "design system version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "design system status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "design system source must be static-seed",
    );
    expect(
        string_value(catalog, "designMode") == Some("static-design-system"),
        errors,
        "design system mode must be static-design-system",
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            bool_value(catalog, field) == Some(true),
            errors,
            format!("design system {field} must be required"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            format!("design system {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "brandTokens", REQUIRED_BRAND_TOKENS, errors);
    validate_required_array(catalog, "designSurfaces", REQUIRED_SURFACES, errors);
    validate_required_array(catalog, "statusFamilies", REQUIRED_STATUS_FAMILIES, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);
    scan_prohibited_value(catalog, CATALOG_PATH, errors);
}

fn validate_catalog_keys(catalog: &Value, errors: &mut Vec<String>) {
    let Some(map) = catalog.as_object() else {
        return;
    };
    let allowed: BTreeSet<&str> = CATALOG_FIELDS.iter().copied().collect();
    let unexpected: Vec<&str> = map
        .keys()
        .map(String::as_str)
        .filter(|key| !allowed.contains(key))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "design system unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required: &[&str],
    errors: &mut Vec<String>,
) {
    let values = string_array_like(catalog, field);
    expect(
        !values.is_empty(),
        errors,
        format!("{field} must be non-empty array"),
    );
    let value_set: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    let required_set: BTreeSet<&str> = required.iter().copied().collect();
    let missing: Vec<&str> = required
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
                "{field} contains prohibited design system value {value}"
            ));
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = catalog_rules(catalog);
    let rule_ids: Vec<String> = rules.iter().map(|rule| rule.id.clone()).collect();
    let required_ids: Vec<&str> = REQUIRED_RULES.iter().map(|rule| rule.id).collect();
    let missing: Vec<&str> = required_ids
        .iter()
        .copied()
        .filter(|id| !rule_ids.iter().any(|rule_id| rule_id == id))
        .collect();
    let unexpected: Vec<String> = rule_ids
        .iter()
        .filter(|id| !required_ids.contains(&id.as_str()))
        .cloned()
        .collect();
    expect(
        missing.is_empty(),
        errors,
        format!("design system missing rules: {}", missing.join(", ")),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!("design system unexpected rules: {}", unexpected.join(", ")),
    );
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "design system rule IDs must be unique",
    );
    let rule_details: Vec<Vec<String>> = rules
        .iter()
        .map(|rule| {
            vec![
                rule.decision.clone(),
                rule.requirement.clone(),
                rule.evidence.clone(),
            ]
        })
        .collect();
    expect(
        rule_details.iter().collect::<BTreeSet<_>>().len() == rule_details.len(),
        errors,
        "design system rule details must be unique",
    );
    for rule in &rules {
        let key_set: BTreeSet<&str> = rule.keys.iter().map(String::as_str).collect();
        let unexpected_keys: Vec<&str> = rule
            .keys
            .iter()
            .map(String::as_str)
            .filter(|key| !RULE_FIELDS.contains(key))
            .collect();
        let missing_keys: Vec<&str> = RULE_FIELDS
            .iter()
            .copied()
            .filter(|key| !key_set.contains(key))
            .collect();
        let id = if rule.id.is_empty() {
            "(missing id)"
        } else {
            rule.id.as_str()
        };
        if !unexpected_keys.is_empty() {
            errors.push(format!(
                "design system rule {id} unexpected rule keys: {}",
                unexpected_keys.join(", ")
            ));
        }
        if !missing_keys.is_empty() {
            errors.push(format!(
                "design system rule {id} missing rule keys: {}",
                missing_keys.join(", ")
            ));
        }
    }
    for expected in REQUIRED_RULES {
        let Some(rule) = rules.iter().find(|candidate| candidate.id == expected.id) else {
            continue;
        };
        for (field, actual, expected_value) in [
            ("decision", rule.decision.as_str(), expected.decision),
            (
                "requirement",
                rule.requirement.as_str(),
                expected.requirement,
            ),
            ("evidence", rule.evidence.as_str(), expected.evidence),
        ] {
            expect(
                actual == expected_value,
                errors,
                format!("design system rule {} {field} must match", expected.id),
            );
        }
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = strip_csharp_comments(program);
    let blocks = endpoint_blocks(program, errors);
    for raw_block in raw_endpoint_blocks(program) {
        scan_prohibited_value(&Value::String(raw_block), PROGRAM_PATH, errors);
    }
    if blocks.is_empty() {
        return;
    }
    for block in blocks {
        expect(
            exact_string_assignment(&block, "source", "static-seed"),
            errors,
            "API must keep static-seed source",
        );
        expect(
            exact_string_assignment(&block, "designMode", "static-design-system"),
            errors,
            "API must keep static-design-system mode",
        );
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
        validate_endpoint_identifier_terms(&block, errors);
        validate_endpoint_singleton_fields(&block, errors);
        validate_no_unsafe_true_flags(&block, errors);
    }
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
    let value_set: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    let catalog_set: BTreeSet<&str> = catalog_values.iter().map(String::as_str).collect();
    let missing: Vec<String> = catalog_values
        .iter()
        .filter(|value| !value_set.contains(value.as_str()))
        .cloned()
        .collect();
    let unexpected: Vec<String> = values
        .iter()
        .filter(|value| !catalog_set.contains(value.as_str()))
        .cloned()
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
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let catalog_rules = catalog_rules(catalog);
    let api_rules = api_rules(block);
    let catalog_rule_ids: Vec<String> = catalog_rules.iter().map(|rule| rule.id.clone()).collect();
    let api_rule_ids: Vec<String> = api_rules.iter().map(|rule| rule.id.clone()).collect();
    for id in catalog_rule_ids
        .iter()
        .filter(|id| !api_rule_ids.contains(id))
    {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_rule_ids
        .iter()
        .filter(|id| !catalog_rule_ids.contains(id))
    {
        errors.push(format!("API has unexpected API rule {id}"));
    }
    expect(
        api_rule_ids.iter().collect::<BTreeSet<_>>().len() == api_rule_ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    let api_rule_details: Vec<Vec<String>> = api_rules
        .iter()
        .map(|rule| {
            vec![
                rule.decision.clone(),
                rule.requirement.clone(),
                rule.evidence.clone(),
            ]
        })
        .collect();
    expect(
        api_rule_details.iter().collect::<BTreeSet<_>>().len() == api_rule_details.len(),
        errors,
        "API rule details must be unique",
    );
    for catalog_rule in catalog_rules {
        let Some(api_rule) = api_rules
            .iter()
            .find(|candidate| candidate.id == catalog_rule.id)
        else {
            continue;
        };
        for (field, actual, expected) in [
            (
                "decision",
                api_rule.decision.as_str(),
                catalog_rule.decision.as_str(),
            ),
            (
                "requirement",
                api_rule.requirement.as_str(),
                catalog_rule.requirement.as_str(),
            ),
            (
                "evidence",
                api_rule.evidence.as_str(),
                catalog_rule.evidence.as_str(),
            ),
        ] {
            expect(
                actual == expected,
                errors,
                format!("API rule {} {field} must match catalog", catalog_rule.id),
            );
        }
    }
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    for field in assignment_fields(&stripped) {
        if !allowed_endpoint_fields().contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has unexpected design system field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited design system field {field}"
            ));
        }
    }
}

fn validate_endpoint_identifier_terms(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    let mut seen = BTreeSet::new();
    for term in identifier_terms(&stripped) {
        if !seen.insert(term.clone()) || safe_identifier(&term) {
            continue;
        }
        if prohibited_field(&term) {
            errors.push(format!(
                "API endpoint uses prohibited design system identifier {term}"
            ));
        }
    }
}

fn validate_endpoint_singleton_fields(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    for field in singleton_endpoint_fields() {
        let marker = format!("{field} =");
        let count = stripped
            .lines()
            .filter(|line| line.trim_start().starts_with(&marker))
            .count();
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
        if value != "true" || SAFE_TRUE_FIELDS.contains(&field.as_str()) {
            continue;
        }
        if [
            "live",
            "runtime",
            "external",
            "unsafe",
            "raw",
            "credential",
            "secret",
            "token",
            "recipient",
            "asset",
            "font",
        ]
        .iter()
        .any(|term| field.to_ascii_lowercase().contains(term))
        {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn validate_portal_css_text(css: &str, errors: &mut Vec<String>) {
    let active = css_without_comments(css);
    let root_body = css_block_body(&active, ":root");
    let root_props = css_custom_properties(&root_body);
    let dark_body = css_dark_root_body(&active);
    let dark_props = css_custom_properties(&dark_body);
    expect(
        root_props.get("--accent").map(String::as_str) == Some("#4a90d9"),
        errors,
        "portal CSS must define neutral accent token",
    );
    expect(
        root_props.get("--accent-secondary").map(String::as_str) == Some("#f0a030"),
        errors,
        "portal CSS must define neutral secondary accent token",
    );
    expect(
        root_props.contains_key("--accent-text"),
        errors,
        "portal CSS must define accessible accent text token",
    );
    expect(
        root_body.contains("color-scheme: light dark;"),
        errors,
        "portal CSS must declare light and dark color scheme",
    );
    expect(
        !dark_body.is_empty(),
        errors,
        "portal CSS must define dark mode",
    );
    for (property, label) in [
        ("--accent", "accent"),
        ("--accent-secondary", "secondary accent"),
        ("--accent-text", "accent text"),
    ] {
        expect(
            dark_props.contains_key(property),
            errors,
            format!("portal CSS dark mode must define {label}"),
        );
    }
    expect(
        active.contains(":focus-visible"),
        errors,
        "portal CSS must define visible focus treatment",
    );
    for badge in ["good", "warn", "bad", "stale"] {
        expect(
            active.contains(&format!(".badge.{badge}")),
            errors,
            format!("portal CSS missing {badge} status badge"),
        );
    }
    expect(
        active.contains("overflow-x: auto;"),
        errors,
        "portal CSS tables must support dense horizontal review",
    );
}

fn validate_docs_text(
    readme: &str,
    catalog_readme: &str,
    doc_readme: &str,
    doc: &str,
    ui_design: &str,
    accessibility: &str,
    errors: &mut Vec<String>,
) {
    expect(
        readme.contains(ENDPOINT),
        errors,
        "API README missing design system endpoint",
    );
    expect(
        catalog_readme.contains("design-system-contract.yaml"),
        errors,
        "catalog README missing design system catalog",
    );
    expect(
        doc_readme.contains("design-system.md"),
        errors,
        "workflow README missing design system doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "design system doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "design system doc must prohibit provider calls",
    );
    expect(
        doc.contains("No external font fetch."),
        errors,
        "design system doc must prohibit external font fetch",
    );
    expect(
        ui_design.contains("Light and dark mode are both first-class product requirements."),
        errors,
        "UI design system doc missing light/dark requirement",
    );
    expect(
        ui_design.contains("Do not display raw JSON, provider payloads, stack traces"),
        errors,
        "UI design system doc missing raw detail safety",
    );
    expect(
        accessibility.contains("Every status badge must include text, not color alone."),
        errors,
        "accessibility checklist missing non-color status rule",
    );
    expect(
        accessibility.contains("Focus must be visible"),
        errors,
        "accessibility checklist missing focus rule",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_field(key) {
                    errors.push(format!(
                        "{path}.{key} contains prohibited design system field"
                    ));
                }
                scan_prohibited_value(child, &format!("{path}.{key}"), errors);
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
                validate_text_identifiers(text, path, errors);
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
                    "{path} contains prohibited design system field {text}"
                ));
            }
        }
        _ => {}
    }
}

fn catalog_rules(catalog: &Value) -> Vec<Rule> {
    catalog
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|rule| {
            let map = rule.as_object()?;
            Some(Rule {
                id: string_value(rule, "id").unwrap_or_default().to_string(),
                decision: string_value(rule, "decision")
                    .unwrap_or_default()
                    .to_string(),
                requirement: string_value(rule, "requirement")
                    .unwrap_or_default()
                    .to_string(),
                evidence: string_value(rule, "evidence")
                    .unwrap_or_default()
                    .to_string(),
                keys: map.keys().map(|key| key.to_string()).collect(),
            })
        })
        .collect()
}

fn api_rules(block: &str) -> Vec<Rule> {
    let Some((body_start, body_end)) = endpoint_rules_body_range(block) else {
        return Vec::new();
    };
    let code_map = strip_csharp_string_literals(block);
    let body = &block[body_start..body_end];
    let body_map = &code_map[body_start..body_end];
    let mut result = Vec::new();
    let mut offset = 0usize;
    while let Some(relative_start) = body_map[offset..].find("new {") {
        let start = offset + relative_start;
        let Some(open_relative) = body_map[start..].find('{') else {
            break;
        };
        let open_index = start + open_relative;
        let Some(close_index) = matching_brace_index(body_map, open_index) else {
            break;
        };
        let segment = &body[start..close_index];
        let assignments = string_assignments(segment);
        let keys: Vec<String> = assignments.iter().map(|(key, _)| key.clone()).collect();
        if keys.iter().all(|key| !RULE_FIELDS.contains(&key.as_str())) {
            offset = close_index + 1;
            continue;
        }
        result.push(Rule {
            id: assignment_value(&assignments, "id").unwrap_or_default(),
            decision: assignment_value(&assignments, "decision").unwrap_or_default(),
            requirement: assignment_value(&assignments, "requirement").unwrap_or_default(),
            evidence: assignment_value(&assignments, "evidence").unwrap_or_default(),
            keys,
        });
        offset = close_index + 1;
    }
    result
}

fn endpoint_rules_body_range(block: &str) -> Option<(usize, usize)> {
    let code_map = strip_csharp_string_literals(block);
    let rules_index = code_map.find("rules = new[]")?;
    let open_index = code_map[rules_index..].find('{')? + rules_index;
    let close_index = matching_brace_index(&code_map, open_index)?;
    Some((open_index + 1, close_index))
}

fn endpoint_blocks(program: &str, errors: &mut Vec<String>) -> Vec<String> {
    let uncommented_program = strip_csharp_comments(program);
    let starts = endpoint_start_indexes(&uncommented_program);
    if starts.is_empty() {
        errors.push("API missing design system endpoint".to_string());
        return Vec::new();
    }
    expect(
        starts.len() == 1,
        errors,
        "API must expose exactly one design system endpoint",
    );
    endpoint_slices(&uncommented_program, &starts, &uncommented_program)
}

fn raw_endpoint_blocks(program: &str) -> Vec<String> {
    let uncommented_program = strip_csharp_comments(program);
    let starts = endpoint_start_indexes(&uncommented_program);
    endpoint_slices(program, &starts, &uncommented_program)
}

fn endpoint_start_indexes(source: &str) -> Vec<usize> {
    let marker = format!("app.MapGet(\"{ENDPOINT}\",");
    let mut starts = Vec::new();
    let mut offset = 0usize;
    while let Some(relative) = source[offset..].find(&marker) {
        let index = offset + relative;
        let line_prefix = source[..index]
            .rsplit_once('\n')
            .map(|(_, line)| line)
            .unwrap_or(&source[..index]);
        if line_prefix.trim().is_empty() {
            starts.push(index);
        }
        offset = index + marker.len();
    }
    starts
}

fn endpoint_slices(source: &str, starts: &[usize], boundary_source: &str) -> Vec<String> {
    starts
        .iter()
        .map(|start| {
            let next_index = next_endpoint_index(boundary_source, *start).unwrap_or(source.len());
            source[*start..next_index].to_string()
        })
        .collect()
}

fn next_endpoint_index(source: &str, start_index: usize) -> Option<usize> {
    let mut offset = start_index + "app.MapGet(".len();
    while let Some(relative) = source[offset..].find("app.MapGet(") {
        let index = offset + relative;
        let line_prefix = source[..index]
            .rsplit_once('\n')
            .map(|(_, line)| line)
            .unwrap_or(&source[..index]);
        if line_prefix.trim().is_empty() {
            return Some(index);
        }
        offset = index + "app.MapGet(".len();
    }
    None
}

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    let assignment_marker = format!("{variable} =");
    if program.matches(&assignment_marker).count() != 1 {
        return None;
    }
    let marker = format!("var {variable} = new[]");
    let declaration_start = program.find(&marker)? + marker.len();
    let open_index = program[declaration_start..].find('{')? + declaration_start;
    let close_index = matching_brace_index(program, open_index)?;
    let tail = program[close_index + 1..]
        .chars()
        .take_while(|ch| *ch != '\n')
        .collect::<String>();
    if tail.trim() != ";" {
        return None;
    }
    csharp_string_literals(&program[open_index + 1..close_index])
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    let marker = format!("{field} = new[]");
    let start = block.find(&marker)? + marker.len();
    let open_index = block[start..].find('{')? + start;
    let close_index = matching_brace_index(block, open_index)?;
    csharp_string_literals(&block[open_index + 1..close_index])
}

fn csharp_string_literals(text: &str) -> Option<Vec<String>> {
    if contains_call_expression(text) {
        return None;
    }
    let mut values = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        match chars[index] {
            '"' => {
                index += 1;
                let mut value = String::new();
                let mut escape = false;
                let mut closed = false;
                while index < chars.len() {
                    let ch = chars[index];
                    index += 1;
                    if escape {
                        value.push(ch);
                        escape = false;
                    } else if ch == '\\' {
                        escape = true;
                    } else if ch == '"' {
                        closed = true;
                        break;
                    } else {
                        value.push(ch);
                    }
                }
                if !closed {
                    return None;
                }
                values.push(value);
            }
            ',' => index += 1,
            ch if ch.is_whitespace() => index += 1,
            _ => return None,
        }
    }
    Some(values)
}

fn contains_call_expression(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        if !is_identifier_start(chars[index]) {
            index += 1;
            continue;
        }
        index += 1;
        while index < chars.len() && is_identifier_continue(chars[index]) {
            index += 1;
        }
        let mut probe = index;
        while probe < chars.len() && chars[probe].is_whitespace() {
            probe += 1;
        }
        if chars.get(probe) == Some(&'(') {
            return true;
        }
    }
    false
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
        if chars.get(probe) == Some(&'=') && chars.get(probe + 1) != Some(&'=') {
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

fn string_assignments(segment: &str) -> Vec<(String, String)> {
    let chars: Vec<char> = segment.chars().collect();
    let mut assignments = Vec::new();
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
        let key: String = chars[start..index].iter().collect();
        let mut probe = index;
        while probe < chars.len() && chars[probe].is_whitespace() {
            probe += 1;
        }
        if chars.get(probe) != Some(&'=') {
            continue;
        }
        probe += 1;
        while probe < chars.len() && chars[probe].is_whitespace() {
            probe += 1;
        }
        if chars.get(probe) != Some(&'"') {
            continue;
        }
        probe += 1;
        let mut value = String::new();
        let mut escape = false;
        while probe < chars.len() {
            let ch = chars[probe];
            probe += 1;
            if escape {
                value.push(ch);
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                break;
            } else {
                value.push(ch);
            }
        }
        assignments.push((key, value));
        index = probe;
    }
    assignments
}

fn assignment_value(assignments: &[(String, String)], field: &str) -> Option<String> {
    assignments
        .iter()
        .rev()
        .find(|(key, _)| key == field)
        .map(|(_, value)| value.clone())
}

fn matching_brace_index(text: &str, open_index: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, ch) in text
        .char_indices()
        .skip_while(|(index, _)| *index < open_index)
    {
        match ch {
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

fn strip_csharp_comments(text: &str) -> String {
    mask_csharp(text, true, false)
}

fn strip_csharp_string_literals(text: &str) -> String {
    mask_csharp(text, false, true)
}

fn mask_csharp(text: &str, comments: bool, strings: bool) -> String {
    let mut bytes = text.as_bytes().to_vec();
    let mut index = 0usize;
    while index < bytes.len() {
        if let Some(finish) = csharp_string_finish(text, index) {
            if strings {
                blank_range(&mut bytes, index, finish);
            }
            index = finish;
        } else if comments && bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            let finish = text[index..]
                .find('\n')
                .map(|relative| index + relative)
                .unwrap_or(bytes.len());
            blank_range(&mut bytes, index, finish);
            index = finish;
        } else if comments && bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            let finish = text[index + 2..]
                .find("*/")
                .map(|relative| index + 2 + relative + 2)
                .unwrap_or(bytes.len());
            blank_range(&mut bytes, index, finish);
            index = finish;
        } else {
            index += 1;
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn csharp_string_finish(text: &str, index: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut cursor = index;
    while bytes.get(cursor) == Some(&b'$') {
        cursor += 1;
    }
    if text[cursor..].starts_with("\"\"\"") {
        let quote_count = consecutive_quote_count(bytes, cursor);
        return Some(csharp_raw_string_finish(text, cursor, quote_count));
    }
    if text[index..].starts_with("$@\"") || text[index..].starts_with("@$\"") {
        return Some(csharp_quoted_string_finish(text, index + 2, true));
    }
    if text[index..].starts_with("@\"") {
        return Some(csharp_quoted_string_finish(text, index + 1, true));
    }
    if text[index..].starts_with("$\"") {
        return Some(csharp_quoted_string_finish(text, index + 1, false));
    }
    if bytes.get(index) == Some(&b'"') {
        return Some(csharp_quoted_string_finish(text, index, false));
    }
    None
}

fn csharp_quoted_string_finish(text: &str, quote_index: usize, verbatim: bool) -> usize {
    let bytes = text.as_bytes();
    let mut index = quote_index + 1;
    let mut escaped = false;
    while index < bytes.len() {
        if verbatim {
            if bytes[index] == b'"' && bytes.get(index + 1) == Some(&b'"') {
                index += 2;
            } else if bytes[index] == b'"' {
                return index + 1;
            } else {
                index += 1;
            }
        } else if escaped {
            escaped = false;
            index += 1;
        } else if bytes[index] == b'\\' {
            escaped = true;
            index += 1;
        } else if bytes[index] == b'"' {
            return index + 1;
        } else {
            index += 1;
        }
    }
    bytes.len()
}

fn csharp_raw_string_finish(text: &str, quote_index: usize, quote_count: usize) -> usize {
    let delimiter = "\"".repeat(quote_count);
    text[quote_index + quote_count..]
        .find(&delimiter)
        .map(|relative| quote_index + quote_count + relative + quote_count)
        .unwrap_or(text.len())
}

fn consecutive_quote_count(bytes: &[u8], start_index: usize) -> usize {
    let mut index = start_index;
    while bytes.get(index) == Some(&b'"') {
        index += 1;
    }
    index - start_index
}

fn blank_range(bytes: &mut [u8], start: usize, finish: usize) {
    for byte in &mut bytes[start..finish] {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

fn css_without_comments(css: &str) -> String {
    let mut result = css.to_string();
    let mut offset = 0usize;
    while let Some(start) = result[offset..].find("/*") {
        let start = offset + start;
        let finish = result[start + 2..]
            .find("*/")
            .map(|relative| start + 2 + relative + 2)
            .unwrap_or(result.len());
        let replacement: String = result[start..finish]
            .chars()
            .map(|ch| if ch == '\n' { '\n' } else { ' ' })
            .collect();
        result.replace_range(start..finish, &replacement);
        offset = finish;
    }
    result
}

fn css_block_body(css: &str, selector: &str) -> String {
    let Some(start) = css.find(selector) else {
        return String::new();
    };
    let Some(open) = css[start..].find('{').map(|relative| start + relative) else {
        return String::new();
    };
    let Some(close) = matching_brace_index(css, open) else {
        return String::new();
    };
    css[open + 1..close].to_string()
}

fn css_dark_root_body(css: &str) -> String {
    let Some(media_start) = css.find("@media") else {
        return String::new();
    };
    let tail = &css[media_start..];
    if !tail.contains("prefers-color-scheme: dark") {
        return String::new();
    }
    let Some(root_relative) = tail.find(":root") else {
        return String::new();
    };
    css_block_body(&tail[root_relative..], ":root")
}

fn css_custom_properties(body: &str) -> std::collections::BTreeMap<String, String> {
    body.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let (key, value) = trimmed.split_once(':')?;
            if !key.starts_with("--") {
                return None;
            }
            let value = value
                .trim()
                .trim_end_matches(';')
                .trim()
                .to_ascii_lowercase();
            Some((key.to_string(), value))
        })
        .collect()
}

fn safe_text_value(value: &str) -> bool {
    let text = value.trim();
    safe_text_arrays().iter().any(|items| items.contains(&text))
        || REQUIRED_RULES
            .iter()
            .any(|rule| [rule.id, rule.decision, rule.requirement, rule.evidence].contains(&text))
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, binding)| *binding == text)
        || [
            "draft",
            "static-seed",
            "static-design-system",
            "block",
            "true",
            "false",
        ]
        .contains(&text)
}

fn safe_text_arrays() -> [&'static [&'static str]; 10] {
    [
        REQUIRED_BRAND_TOKENS,
        REQUIRED_SURFACES,
        REQUIRED_STATUS_FAMILIES,
        REQUIRED_INPUTS,
        REQUIRED_GUARDS,
        REQUIRED_PLAN_SECTIONS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        REQUIRED_DISABLED_FIELDS,
        SAFE_TRUE_FIELDS,
    ]
}

fn safe_identifier(value: &str) -> bool {
    safe_text_value(value)
        || CATALOG_FIELDS.contains(&value)
        || allowed_endpoint_fields().contains(&value)
        || singleton_endpoint_fields().contains(&value)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, variable)| *variable == value)
        || ["app", "MapGet", "Results", "Json", "new", "var"].contains(&value)
}

fn allowed_endpoint_fields() -> BTreeSet<&'static str> {
    let mut fields: BTreeSet<&'static str> = [
        "source",
        "designMode",
        "rules",
        "id",
        "decision",
        "requirement",
        "evidence",
    ]
    .into_iter()
    .collect();
    fields.extend(SAFE_TRUE_FIELDS.iter().copied());
    fields.extend(REQUIRED_DISABLED_FIELDS.iter().copied());
    fields.extend(ENDPOINT_ARRAY_BINDINGS.iter().map(|(field, _)| *field));
    fields.extend(ENDPOINT_INLINE_ARRAYS.iter().copied());
    fields
}

fn singleton_endpoint_fields() -> BTreeSet<&'static str> {
    let mut fields: BTreeSet<&'static str> =
        ["source", "designMode", "rules"].into_iter().collect();
    fields.extend(SAFE_TRUE_FIELDS.iter().copied());
    fields.extend(REQUIRED_DISABLED_FIELDS.iter().copied());
    fields.extend(ENDPOINT_ARRAY_BINDINGS.iter().map(|(field, _)| *field));
    fields.extend(ENDPOINT_INLINE_ARRAYS.iter().copied());
    fields
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize(value);
    let safe_normalized = safe_text_candidates()
        .iter()
        .map(|safe| normalize(safe))
        .collect::<BTreeSet<_>>();
    if safe_normalized.contains(&normalized) {
        return false;
    }
    [
        "credential",
        "password",
        "bearer",
        "token",
        "url",
        "endpoint",
    ]
    .contains(&normalized.as_str())
        || [
            "externalfonturl",
            "logoasseturl",
            "asseturl",
            "tenantidentifier",
            "tenantid",
            "objectidentifier",
            "objectid",
            "privateip",
            "credentialvalue",
            "secretvalue",
            "accesstoken",
            "token",
            "password",
            "bearer",
            "rawprovider",
            "rawevidence",
            "rawuidiagnostic",
            "recipientemail",
            "recipientaddress",
            "recipientdata",
            "stacktrace",
            "implementationinternal",
            "providerpayload",
            "endpointurl",
            "url",
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
    has_any(&tokens, &["password", "credential", "token", "bearer"])
        || has_any(&tokens, &["url", "uri", "endpoint", "fqdn"])
        || (has_any(&tokens, &["id", "guid"]) && tokens.len() > 1)
        || (has_any(&tokens, &["private", "ip", "host", "dns"])
            && has_any(&tokens, &["address", "name"]))
        || (has_any(
            &tokens,
            &[
                "provider",
                "vendor",
                "external",
                "tenant",
                "object",
                "recipient",
                "asset",
                "font",
                "logo",
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
                "key",
                "value",
                "data",
                "address",
                "payload",
                "row",
                "rows",
            ],
        ))
        || (tokens.iter().any(|token| token == "raw")
            && has_any(
                &tokens,
                &[
                    "provider",
                    "evidence",
                    "ui",
                    "diagnostic",
                    "payload",
                    "logs",
                    "rows",
                    "recipient",
                ],
            ))
}

fn field_tokens(value: &str) -> Vec<String> {
    let mut normalized = String::new();
    let mut previous_lower_or_digit = false;
    for ch in value.chars() {
        if ch.is_ascii_uppercase() && previous_lower_or_digit {
            normalized.push(' ');
        }
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_lowercase());
            previous_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        } else {
            normalized.push(' ');
            previous_lower_or_digit = false;
        }
    }
    normalized.split_whitespace().map(str::to_string).collect()
}

fn has_any(tokens: &[String], candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| tokens.iter().any(|token| token == candidate))
}

fn safe_text_candidates() -> Vec<&'static str> {
    let mut values = Vec::new();
    for items in safe_text_arrays() {
        values.extend(items.iter().copied());
    }
    for rule in REQUIRED_RULES {
        values.extend([rule.id, rule.decision, rule.requirement, rule.evidence]);
    }
    values.extend(CATALOG_FIELDS.iter().copied());
    values.extend(ENDPOINT_ARRAY_BINDINGS.iter().map(|(_, binding)| *binding));
    values.extend([
        "draft",
        "static-seed",
        "static-design-system",
        "block",
        "true",
        "false",
    ]);
    values
}

fn prohibited_value(text: &str) -> bool {
    text.contains("://")
        || (text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----"))
        || contains_aws_access_key(text)
        || contains_private_ip(text)
        || contains_uuid_like(text)
        || contains_jwt_like(text)
        || contains_vault_token_like(text)
        || contains_secret_assignment(text)
}

fn contains_aws_access_key(text: &str) -> bool {
    normalized_tokens(text).iter().any(|token| {
        token.len() == 20
            && token.to_ascii_uppercase().starts_with("AKIA")
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

fn contains_jwt_like(text: &str) -> bool {
    text.split_whitespace().any(|candidate| {
        let candidate = candidate.trim_matches(|ch: char| {
            matches!(
                ch,
                '"' | '\'' | ',' | ';' | '[' | ']' | '{' | '}' | '(' | ')' | '<' | '>'
            )
        });
        let parts: Vec<&str> = candidate.split('.').collect();
        parts.len() == 3
            && parts
                .iter()
                .all(|part| part.len() >= 12 && part.chars().all(base64url_char))
    })
}

fn contains_vault_token_like(text: &str) -> bool {
    normalized_tokens(text).iter().any(|token| {
        let lower = token.to_ascii_lowercase();
        (lower.starts_with("hvs.") || lower.starts_with("hvb.") || lower.starts_with("s."))
            && token.len() >= 18
    })
}

fn base64url_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'
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

fn validate_text_identifiers(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        for term in scan_text_identifier_terms(line) {
            if prohibited_field(&term) {
                errors.push(format!(
                    "{path}:{} contains prohibited design system field {term}",
                    index + 1
                ));
            }
        }
    }
}

fn scan_text_identifier_terms(line: &str) -> Vec<String> {
    let mut terms = assignment_like_terms(line);
    terms.extend(multiterm_assignment_terms(line));
    terms.sort();
    terms.dedup();
    terms
}

fn assignment_like_terms(line: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let chars: Vec<char> = line.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        if !is_identifier_start(chars[index]) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < chars.len() && (is_identifier_continue(chars[index]) || chars[index] == '-') {
            index += 1;
        }
        let term: String = chars[start..index].iter().collect();
        let mut probe = index;
        while probe < chars.len() && chars[probe].is_whitespace() {
            probe += 1;
        }
        if matches!(chars.get(probe), Some(&'=') | Some(&':')) {
            terms.push(term);
        }
    }
    terms
}

fn multiterm_assignment_terms(line: &str) -> Vec<String> {
    let Some(separator_index) = line.find(['=', ':']) else {
        return Vec::new();
    };
    let prefix = line[..separator_index].trim();
    if prefix.contains('{')
        || prefix
            .split_whitespace()
            .any(|word| matches!(word, "new" | "var"))
    {
        return Vec::new();
    }
    let words: Vec<&str> = prefix
        .split_whitespace()
        .filter(|word| {
            word.chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
        })
        .collect();
    if (2..=4).contains(&words.len()) {
        vec![words.join(" ")]
    } else {
        Vec::new()
    }
}

fn identifier_terms(text: &str) -> Vec<String> {
    let mut terms = Vec::new();
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
        terms.push(chars[start..index].iter().collect());
    }
    terms
}

fn normalized_tokens(text: &str) -> Vec<String> {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.'))
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect()
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn string_value<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn bool_value(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
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

fn normalize(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
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
