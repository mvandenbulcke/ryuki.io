use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/customization-spec-governance-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/customization-spec-governance.md";
const ENDPOINT: &str = "/api/integrations/vmware/customization-spec-governance-contract";
const SLICE: &str = "customization-spec-governance";

const REQUIRED_HYPERVISORS: &[&str] = &["VMware", "Hyper-V", "Proxmox"];
const REQUIRED_GUEST_CUSTOMIZATION_PARITY: &[&str] = &[
    "vmware-vcenter-customization-spec-safe-facts",
    "hyper-v-answer-file-safe-facts",
    "proxmox-cloud-init-safe-facts",
];
const REQUIRED_WORKFLOWS: &[&str] = &[
    "request-preflight",
    "windows-server-deployment",
    "ou-placement-review",
    "customization-spec-drift-review",
    "site-catalog-review",
];
const REQUIRED_SAFE_FACTS: &[&str] = &[
    "customizationSpecReference",
    "countryCode",
    "siteCode",
    "domainReference",
    "ouPatternReference",
    "timezoneCode",
    "dhcpNetworkBehavior",
    "organizationLabel",
    "windowsBehavior",
];
const REQUIRED_DRIFT_SIGNALS: &[&str] = &[
    "missing-expected-spec",
    "unknown-spec",
    "country-site-mismatch",
    "ou-pattern-mismatch",
    "domain-mismatch",
    "timezone-mismatch",
    "network-behavior-mismatch",
    "windows-behavior-mismatch",
    "stale-spec-inventory",
];
const REQUIRED_INPUTS: &[&str] = &[
    "site",
    "country",
    "hypervisorPlatform",
    "customizationSpecReference",
    "domainReference",
    "ouPatternReference",
    "timezoneCode",
    "dhcpNetworkBehavior",
    "organizationLabel",
    "windowsBehavior",
    "owner",
    "supportGroup",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "site-known",
    "safe-facts-from-catalog",
    "ou-pattern-derived",
    "free-form-ou-blocked",
    "encrypted-xml-excluded",
    "drift-check-reviewed",
    "stale-data-marked",
    "owner-known",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "safeFactSummary",
    "siteMapping",
    "ouPlacementDecision",
    "timezoneAndNetworkBehavior",
    "windowsBehaviorReview",
    "driftReview",
    "blockedFindings",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-provider-validation-disabled",
    "live-guest-customization-disabled",
    "unsupported-hypervisor",
    "raw-xml-blocked",
    "encrypted-xml-blocked",
    "credential-material-blocked",
    "site-unknown",
    "spec-reference-unknown",
    "ou-pattern-mismatch",
    "stale-spec-inventory",
    "owner-unknown",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Safe customization fact summary",
    "Site catalog version",
    "Site mapping decision",
    "OU placement decision",
    "Timezone and DHCP behavior",
    "Windows behavior review",
    "Drift review",
    "Blocked findings",
    "Evidence references",
];
const REQUIRED_RULE_IDS: &[&str] = &[
    "no-live-customization-spec-provider-calls",
    "raw-xml-never-accepted",
    "safe-catalog-facts-required",
    "free-form-ou-blocked",
    "stale-spec-review-required",
];
const PROVIDER_CALL_RULE_ID: &str = "no-live-customization-spec-provider-calls";
const PROVIDER_CALL_RULE_REQUIREMENT: &str = "Customization spec governance uses static, mock, or manually reviewed safe facts only and never calls VMware, Hyper-V, Proxmox, or guest customization execution.";
const API_README_ROW: &str = "| `/api/integrations/vmware/customization-spec-governance-contract` | Static guest customization safe-facts contract with VMware, Hyper-V, and Proxmox parity; raw template content and live validation disabled. |";
const SAFE_PROGRAM_TEXT_VALUES: &[&str] = &[
    "CORP.local",
    "OU=Servers,OU=<SITE>,OU=<COUNTRY>,DC=corp,DC=local",
    "builder.Services.AddHealthChecks",
    "Ryuki.Platform.Api",
];
const SAFE_ALLOWED_PROVIDER_KEYS: &[&str] = &[
    "rawxmlallowed",
    "encryptedxmlallowed",
    "credentialmaterialallowed",
    "freeformouallowed",
    "rawproviderpayloadsallowed",
    "liveprovidervalidationallowed",
    "providercallsenabled",
];
const DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "liveProviderValidationAllowed",
    "rawXmlAllowed",
    "encryptedXmlAllowed",
    "credentialMaterialAllowed",
    "freeFormOuAllowed",
    "rawProviderPayloadsAllowed",
    "liveGuestCustomizationAllowed",
];
const ARRAY_BINDINGS: &[(&str, &str)] = &[
    (
        "supportedHypervisors",
        "customizationSpecGovernanceSupportedHypervisors",
    ),
    (
        "guestCustomizationParity",
        "customizationSpecGovernanceGuestCustomizationParity",
    ),
    ("supportedWorkflows", "customizationSpecGovernanceWorkflows"),
    ("safeFactFields", "customizationSpecGovernanceSafeFacts"),
    ("driftSignals", "customizationSpecGovernanceDriftSignals"),
    (
        "requiredGuards",
        "customizationSpecGovernanceRequiredGuards",
    ),
    ("planSections", "customizationSpecGovernancePlanSections"),
    (
        "blockedReasons",
        "customizationSpecGovernanceBlockedReasons",
    ),
];

#[derive(Debug, Deserialize)]
struct CustomizationSpecGovernanceContext {
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

#[derive(Clone, Debug)]
struct Rule {
    id: String,
    decision: String,
    requirement: String,
    evidence: String,
}

#[derive(Clone, Debug)]
struct Route {
    start: usize,
    route: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: CustomizationSpecGovernanceContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid customization spec governance context JSON: {error}"))?;
    let mut errors = Vec::new();

    validate_catalog_value(&context.catalog, &mut errors);
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(
        &context.api_readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &mut errors,
    );
    scan_prohibited_value(&context.catalog, SLICE, &mut errors);
    scan_prohibited_value(&Value::String(context.program), PROGRAM_PATH, &mut errors);
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
        .map_err(|error| format!("invalid customization spec governance catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid customization spec governance program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid customization spec governance docs JSON: {error}"))?;
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
    let payload: ProhibitedInput = serde_json::from_str(input).map_err(|error| {
        format!("invalid customization spec governance prohibited JSON: {error}")
    })?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "customization spec governance version must be 1",
    );
    expect(
        string_field(catalog, "status") == Some("draft"),
        errors,
        "customization spec governance status must be draft",
    );
    expect(
        string_field(catalog, "governanceMode") == Some("safe-facts-only"),
        errors,
        "customization spec governance mode must be safe-facts-only",
    );
    expect(
        bool_field(catalog, "siteCatalogRequired") == Some(true),
        errors,
        "customization spec governance must require site catalog",
    );
    for field in DISABLED_FIELDS {
        expect(
            bool_field(catalog, field) == Some(false),
            errors,
            format!("customization spec governance {field} must be disabled"),
        );
    }

    validate_exact_array(
        catalog,
        "supportedHypervisors",
        REQUIRED_HYPERVISORS,
        errors,
    );
    validate_exact_array(
        catalog,
        "guestCustomizationParity",
        REQUIRED_GUEST_CUSTOMIZATION_PARITY,
        errors,
    );
    validate_required_array(catalog, "supportedWorkflows", REQUIRED_WORKFLOWS, errors);
    validate_required_array(catalog, "safeFactFields", REQUIRED_SAFE_FACTS, errors);
    validate_required_array(catalog, "driftSignals", REQUIRED_DRIFT_SIGNALS, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);

    let rules = rules_from_catalog(catalog);
    let rule_ids = rules.iter().map(|rule| rule.id.clone()).collect::<Vec<_>>();
    let missing = REQUIRED_RULE_IDS
        .iter()
        .filter(|id| !rule_ids.iter().any(|rule_id| rule_id == **id))
        .copied()
        .collect::<Vec<_>>();
    expect(
        missing.is_empty(),
        errors,
        format!(
            "customization spec governance missing rules: {}",
            missing.join(", ")
        ),
    );
    expect(
        unique_len(&rule_ids) == rule_ids.len(),
        errors,
        "customization spec governance rule ids must be unique",
    );
    let details = rules
        .iter()
        .map(|rule| format!("{}|{}|{}", rule.decision, rule.requirement, rule.evidence))
        .collect::<Vec<_>>();
    expect(
        unique_len(&details) == details.len(),
        errors,
        "customization spec governance rule details must be unique",
    );
    let provider_rule = rules.iter().find(|rule| rule.id == PROVIDER_CALL_RULE_ID);
    expect(
        provider_rule.map(|rule| rule.requirement.as_str()) == Some(PROVIDER_CALL_RULE_REQUIREMENT),
        errors,
        "customization spec governance provider-call rule must use provider-neutral VMware wording",
    );
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let values = string_array_field(catalog, field);
    expect(
        !values.is_empty(),
        errors,
        format!("{field} must be non-empty array"),
    );
    let missing = required_values
        .iter()
        .filter(|value| !values.iter().any(|item| item == **value))
        .copied()
        .collect::<Vec<_>>();
    expect(
        missing.is_empty(),
        errors,
        format!("{field} missing values: {}", missing.join(", ")),
    );
    expect(
        unique_len(&values) == values.len(),
        errors,
        format!("{field} values must be unique"),
    );
}

fn validate_exact_array(
    catalog: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let values = string_array_field(catalog, field);
    let expected = required_values
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    expect(
        values == expected,
        errors,
        format!("{field} must exactly match: {}", required_values.join(", ")),
    );
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let active_program = strip_csharp_comments(program);
    let block = endpoint_block(&active_program, errors);
    if block.is_empty() {
        return;
    }

    let workflow_values = csharp_array_values(
        &active_program,
        "customizationSpecGovernanceWorkflows",
        errors,
    );
    let supported_hypervisor_values = csharp_array_values(
        &active_program,
        "customizationSpecGovernanceSupportedHypervisors",
        errors,
    );
    let guest_customization_parity_values = csharp_array_values(
        &active_program,
        "customizationSpecGovernanceGuestCustomizationParity",
        errors,
    );
    let safe_fact_values = csharp_array_values(
        &active_program,
        "customizationSpecGovernanceSafeFacts",
        errors,
    );
    let drift_signal_values = csharp_array_values(
        &active_program,
        "customizationSpecGovernanceDriftSignals",
        errors,
    );
    let guard_values = csharp_array_values(
        &active_program,
        "customizationSpecGovernanceRequiredGuards",
        errors,
    );
    let plan_section_values = csharp_array_values(
        &active_program,
        "customizationSpecGovernancePlanSections",
        errors,
    );
    let blocked_reason_values = csharp_array_values(
        &active_program,
        "customizationSpecGovernanceBlockedReasons",
        errors,
    );
    let endpoint_members = top_level_endpoint_members(&block);
    for (field, count) in top_level_endpoint_member_counts(&block) {
        if count > 1 {
            errors.push(format!(
                "API endpoint member {field} assigned multiple times"
            ));
        }
    }

    let required_input_values =
        string_array_elements(&top_level_assignment_source(&block, "requiredInputs"));
    let required_evidence_values =
        string_array_elements(&top_level_assignment_source(&block, "requiredEvidence"));
    let api_rules = api_rule_objects(&block);
    let api_rule_ids = api_rules
        .iter()
        .map(|rule| rule.id.clone())
        .collect::<Vec<_>>();
    let api_rule_details = api_rules
        .iter()
        .map(|rule| format!("{}|{}|{}", rule.decision, rule.requirement, rule.evidence))
        .collect::<Vec<_>>();
    expect(
        unique_len(&api_rule_ids) == api_rule_ids.len(),
        errors,
        "API rule ids must be unique",
    );
    expect(
        unique_len(&api_rule_details) == api_rule_details.len(),
        errors,
        "API rule details must be unique",
    );
    let api_rules_by_id = api_rules
        .iter()
        .map(|rule| (rule.id.clone(), rule.clone()))
        .collect::<BTreeMap<_, _>>();

    expect(
        top_level_string_assignment(&block, "source").as_deref() == Some("static-seed"),
        errors,
        "API must keep static source assignment",
    );
    expect(
        top_level_string_assignment(&block, "governanceMode").as_deref() == Some("safe-facts-only"),
        errors,
        "API must keep safe-facts-only mode",
    );
    expect(
        top_level_assignment(&endpoint_members, "siteCatalogRequired") == Some("true"),
        errors,
        "API must require site catalog",
    );
    for field in DISABLED_FIELDS {
        expect(
            top_level_assignment(&endpoint_members, field) == Some("false"),
            errors,
            format!("API must keep {field} disabled"),
        );
    }
    for (field, variable) in ARRAY_BINDINGS {
        expect(
            top_level_assignment(&endpoint_members, field) == Some(*variable),
            errors,
            format!("API endpoint missing {field} field"),
        );
    }

    expect(
        supported_hypervisor_values == string_array_field(catalog, "supportedHypervisors"),
        errors,
        "API supportedHypervisors must match catalog",
    );
    expect(
        guest_customization_parity_values
            == string_array_field(catalog, "guestCustomizationParity"),
        errors,
        "API guestCustomizationParity must match catalog",
    );
    check_required_values(
        &workflow_values,
        &string_array_field(catalog, "supportedWorkflows"),
        "API missing workflow",
        errors,
    );
    check_required_values(
        &safe_fact_values,
        &string_array_field(catalog, "safeFactFields"),
        "API missing safe fact",
        errors,
    );
    check_required_values(
        &drift_signal_values,
        &string_array_field(catalog, "driftSignals"),
        "API missing drift signal",
        errors,
    );
    check_required_values(
        &required_input_values,
        &string_array_field(catalog, "requiredInputs"),
        "API missing required input",
        errors,
    );
    check_required_values(
        &guard_values,
        &string_array_field(catalog, "requiredGuards"),
        "API missing guard",
        errors,
    );
    check_required_values(
        &plan_section_values,
        &string_array_field(catalog, "planSections"),
        "API missing plan section",
        errors,
    );
    check_required_values(
        &blocked_reason_values,
        &string_array_field(catalog, "blockedReasons"),
        "API missing blocked reason",
        errors,
    );
    check_required_values(
        &required_evidence_values,
        &string_array_field(catalog, "requiredEvidence"),
        "API missing required evidence",
        errors,
    );

    for rule in rules_from_catalog(catalog) {
        let Some(api_rule) = api_rules_by_id.get(&rule.id) else {
            errors.push(format!("API missing rule {}", rule.id));
            continue;
        };
        expect(
            api_rule.decision == rule.decision,
            errors,
            format!("API rule {} has wrong decision", rule.id),
        );
        expect(
            api_rule.requirement == rule.requirement,
            errors,
            format!("API missing rule requirement {}", rule.id),
        );
        expect(
            api_rule.evidence == rule.evidence,
            errors,
            format!("API rule {} has wrong evidence", rule.id),
        );
    }

    validate_program_endpoint_identifiers(&block, &endpoint_members, errors);
}

fn validate_program_endpoint_identifiers(
    block: &str,
    endpoint_members: &BTreeMap<String, String>,
    errors: &mut Vec<String>,
) {
    let masked_block = decode_csharp_unicode_escapes(&mask_csharp_string_bodies(block));
    let counts = identifier_counts(&masked_block);
    let allowed_safe_flags = endpoint_members
        .iter()
        .filter_map(|(field, rhs)| {
            let normalized = normalized_key(field);
            if SAFE_ALLOWED_PROVIDER_KEYS.contains(&normalized.as_str()) && rhs == "false" {
                Some(normalized)
            } else {
                None
            }
        })
        .collect::<BTreeSet<_>>();

    for (identifier, count) in counts {
        let normalized = normalized_key(&identifier);
        let unsafe_identifier = if SAFE_ALLOWED_PROVIDER_KEYS.contains(&normalized.as_str()) {
            !allowed_safe_flags.contains(&normalized) || count > 1
        } else {
            prohibited_provider_key(&identifier, None, None)
        };
        if unsafe_identifier {
            errors.push(format!(
                "API endpoint property {identifier} contains prohibited provider field"
            ));
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
        "API README missing customization spec governance endpoint",
    );
    expect(
        readme.contains(API_README_ROW),
        errors,
        "API README missing customization spec governance parity row",
    );
    expect(
        catalog_readme.contains("customization-spec-governance-contract.yaml"),
        errors,
        "catalog README missing customization spec governance catalog",
    );
    expect(
        catalog_readme.contains("safe VMware, Hyper-V, and Proxmox guest customization facts"),
        errors,
        "catalog README missing customization spec parity wording",
    );
    expect(
        doc_readme.contains("customization-spec-governance.md"),
        errors,
        "workflow README missing customization spec governance doc",
    );
    expect(
        doc_readme.contains(
            "Safe-facts-only VMware, Hyper-V, and Proxmox guest customization governance",
        ),
        errors,
        "workflow README missing customization spec parity wording",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "customization spec governance doc missing endpoint",
    );
    expect(
        doc.contains("calling VMware, Hyper-V, or Proxmox"),
        errors,
        "customization spec governance doc must use provider-neutral VMware, Hyper-V, or Proxmox call wording",
    );
    expect(
        !legacy_provider_call_wording(doc),
        errors,
        "customization spec governance doc must not use legacy vCenter provider-call wording",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "customization spec governance doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live guest customization execution."),
        errors,
        "customization spec governance doc must prohibit guest customization execution",
    );
    expect(
        doc.contains("No raw XML or encrypted XML values."),
        errors,
        "customization spec governance doc must prohibit raw XML",
    );
    expect(
        doc.contains("No free-form OU paths"),
        errors,
        "customization spec governance doc must prohibit free-form OU paths",
    );
    expect(
        doc.contains("safe fact summaries only"),
        errors,
        "customization spec governance doc must require safe summaries",
    );
    for hypervisor in REQUIRED_HYPERVISORS {
        expect(
            doc.contains(hypervisor),
            errors,
            format!(
                "customization spec governance doc missing {hypervisor} guest customization parity"
            ),
        );
    }
    expect(
        doc.contains("Guest customization parity is limited to static safe-fact summaries"),
        errors,
        "customization spec governance doc missing guest customization parity phrase",
    );
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let matches = mapget_routes(program)
        .into_iter()
        .filter(|route| route.route == ENDPOINT)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        errors.push(format!(
            "API must define exactly one active endpoint {ENDPOINT}; found {}",
            matches.len()
        ));
        return String::new();
    }
    let start = matches[0].start;
    let Some(end) = endpoint_call_end_index(program, start) else {
        errors.push(format!("API endpoint {ENDPOINT} block is incomplete"));
        return String::new();
    };
    program
        .get(start..=end)
        .map(str::to_string)
        .unwrap_or_default()
}

fn mapget_routes(program: &str) -> Vec<Route> {
    let mut routes = Vec::new();
    let mut index = 0;
    while index < program.len() {
        if let Some(end) = csharp_string_end(program, index) {
            index = end;
            continue;
        }
        if !program.get(index..).unwrap_or_default().starts_with("app") {
            index += 1;
            continue;
        }
        let start = index;
        if start > 0 && is_ident_byte(program.as_bytes()[start - 1]) {
            index = start + 3;
            continue;
        }
        let mut cursor = skip_ws(program, start + 3);
        if program.as_bytes().get(cursor) != Some(&b'.') {
            index = cursor.saturating_add(1);
            continue;
        }
        cursor = skip_ws(program, cursor + 1);
        if !program
            .get(cursor..)
            .unwrap_or_default()
            .starts_with("MapGet")
        {
            index = cursor.saturating_add(1);
            continue;
        }
        cursor += "MapGet".len();
        if program
            .as_bytes()
            .get(cursor)
            .map(|byte| is_ident_byte(*byte))
            .unwrap_or(false)
        {
            index = cursor + 1;
            continue;
        }
        cursor = skip_ws(program, cursor);
        if program.as_bytes().get(cursor) != Some(&b'(') {
            index = cursor.saturating_add(1);
            continue;
        }
        cursor = skip_ws(program, cursor + 1);
        let Some((route, next_cursor)) = parse_csharp_string_literal_at(program, cursor) else {
            index = cursor.saturating_add(1);
            continue;
        };
        routes.push(Route { start, route });
        index = next_cursor;
    }
    routes
}

fn endpoint_call_end_index(program: &str, start: usize) -> Option<usize> {
    let scan_program = mask_csharp_string_bodies(program);
    let open_paren = scan_program
        .get(start..)?
        .find('(')
        .map(|offset| start + offset)?;
    let close_paren = matching_delimiter_index(&scan_program, open_paren, b'(', b')')?;
    let semicolon = skip_ws(&scan_program, close_paren + 1);
    if scan_program.as_bytes().get(semicolon) == Some(&b';') {
        Some(semicolon)
    } else {
        Some(close_paren)
    }
}

fn csharp_array_values(program: &str, variable: &str, errors: &mut Vec<String>) -> Vec<String> {
    let declarations = csharp_array_declarations(program, variable);
    if declarations.len() != 1 {
        errors.push(format!("API missing {variable} declaration"));
        return Vec::new();
    }
    string_array_elements(&declarations[0])
}

fn csharp_array_declarations(program: &str, variable: &str) -> Vec<String> {
    let marker = format!("var {variable}");
    let scan_program = mask_csharp_string_bodies(program);
    let mut declarations = Vec::new();
    let mut index = 0;
    while let Some(offset) = scan_program
        .get(index..)
        .and_then(|text| text.find(&marker))
    {
        let start = index + offset;
        let before = scan_program.as_bytes().get(start.wrapping_sub(1));
        let after = scan_program.as_bytes().get(start + marker.len());
        if before.map(|byte| is_ident_byte(*byte)).unwrap_or(false)
            || after.map(|byte| is_ident_byte(*byte)).unwrap_or(false)
        {
            index = start + marker.len();
            continue;
        }
        let Some(open) = scan_program
            .get(start..)
            .and_then(|text| text.find('{'))
            .map(|offset| start + offset)
        else {
            index = start + marker.len();
            continue;
        };
        let Some(close) = matching_delimiter_index(&scan_program, open, b'{', b'}') else {
            index = open + 1;
            continue;
        };
        let semicolon = skip_ws(&scan_program, close + 1);
        let end = if scan_program.as_bytes().get(semicolon) == Some(&b';') {
            semicolon
        } else {
            close
        };
        if let Some(declaration) = program.get(start..=end) {
            declarations.push(declaration.to_string());
        }
        index = end.saturating_add(1);
    }
    declarations
}

fn csharp_body_source(source: &str) -> Option<String> {
    let masked = mask_csharp_string_bodies(source);
    let start = masked.find('{')?;
    let end = matching_delimiter_index(&masked, start, b'{', b'}')?;
    source.get((start + 1)..end).map(str::to_string)
}

fn split_top_level_items(source: &str) -> Vec<String> {
    let masked = mask_csharp_string_bodies(source);
    let mut items = Vec::new();
    let mut start = 0;
    let mut depth = 0_i32;
    for (index, byte) in masked.bytes().enumerate() {
        match byte {
            b'{' | b'[' | b'(' => depth += 1,
            b'}' | b']' | b')' => depth -= 1,
            b',' if depth == 0 => {
                if let Some(item) = source.get(start..index) {
                    let trimmed = item.trim();
                    if !trimmed.is_empty() {
                        items.push(trimmed.to_string());
                    }
                }
                start = index + 1;
            }
            _ => {}
        }
    }
    if let Some(item) = source.get(start..) {
        let trimmed = item.trim();
        if !trimmed.is_empty() {
            items.push(trimmed.to_string());
        }
    }
    items
}

fn string_array_elements(source: &str) -> Vec<String> {
    let Some(body) = csharp_body_source(source) else {
        return Vec::new();
    };
    split_top_level_items(&body)
        .iter()
        .filter_map(|item| csharp_string_literal_value(item))
        .collect()
}

fn top_level_assignment_source(block: &str, field: &str) -> String {
    let Some(body) = csharp_body_source(block) else {
        return String::new();
    };
    let mut assignment = String::new();
    for item in split_top_level_items(&body) {
        let Some((name, value)) = split_top_level_assignment(&item) else {
            continue;
        };
        if decode_csharp_unicode_escapes(name.trim()).trim_start_matches('@') == field {
            assignment = value.trim().to_string();
        }
    }
    assignment
}

fn top_level_endpoint_members(block: &str) -> BTreeMap<String, String> {
    let Some(body) = csharp_body_source(block) else {
        return BTreeMap::new();
    };
    let mut members = BTreeMap::new();
    for item in split_top_level_items(&body) {
        if let Some((name, value)) = split_top_level_assignment(&item) {
            members.insert(
                decode_csharp_unicode_escapes(name.trim())
                    .trim_start_matches('@')
                    .to_string(),
                value.trim().to_string(),
            );
        } else if let Some(name) = shorthand_field(&item) {
            members.insert(name, String::new());
        }
    }
    members
}

fn top_level_endpoint_member_counts(block: &str) -> BTreeMap<String, usize> {
    let Some(body) = csharp_body_source(block) else {
        return BTreeMap::new();
    };
    let mut counts = BTreeMap::new();
    for item in split_top_level_items(&body) {
        let name = split_top_level_assignment(&item)
            .map(|(name, _)| {
                decode_csharp_unicode_escapes(name.trim())
                    .trim_start_matches('@')
                    .to_string()
            })
            .or_else(|| shorthand_field(&item));
        if let Some(name) = name {
            *counts.entry(name).or_insert(0) += 1;
        }
    }
    counts
}

fn top_level_assignment<'a>(members: &'a BTreeMap<String, String>, field: &str) -> Option<&'a str> {
    members.get(field).map(|value| value.as_str())
}

fn top_level_string_assignment(block: &str, field: &str) -> Option<String> {
    csharp_string_literal_value(&top_level_assignment_source(block, field))
}

fn api_rule_objects(block: &str) -> Vec<Rule> {
    let rules_source = top_level_assignment_source(block, "rules");
    let Some(body) = csharp_body_source(&rules_source) else {
        return Vec::new();
    };
    split_top_level_items(&body)
        .into_iter()
        .filter_map(|item| parse_anonymous_object_string_properties(&item))
        .collect()
}

fn parse_anonymous_object_string_properties(source: &str) -> Option<Rule> {
    let body = csharp_body_source(source)?;
    let mut fields = BTreeMap::new();
    for item in split_top_level_items(&body) {
        let Some((name, value)) = split_top_level_assignment(&item) else {
            continue;
        };
        let name = name.trim();
        if !valid_identifier(name) {
            continue;
        }
        if let Some(value) = csharp_string_literal_value(value.trim()) {
            fields.insert(name.to_string(), value);
        }
    }
    Some(Rule {
        id: fields.get("id")?.to_string(),
        decision: fields.get("decision")?.to_string(),
        requirement: fields.get("requirement")?.to_string(),
        evidence: fields.get("evidence")?.to_string(),
    })
}

fn split_top_level_assignment(source: &str) -> Option<(&str, &str)> {
    let masked = mask_csharp_string_bodies(source);
    let mut depth = 0_i32;
    for (index, byte) in masked.bytes().enumerate() {
        match byte {
            b'{' | b'[' | b'(' => depth += 1,
            b'}' | b']' | b')' => depth -= 1,
            b'=' if depth == 0 => return Some((&source[..index], &source[(index + 1)..])),
            _ => {}
        }
    }
    None
}

fn shorthand_field(source: &str) -> Option<String> {
    let trimmed = source.trim().trim_end_matches(',');
    if trimmed.is_empty() || trimmed.contains('=') {
        return None;
    }
    let name = trimmed
        .split('.')
        .next_back()
        .unwrap_or(trimmed)
        .trim()
        .trim_start_matches('@');
    if valid_identifier(name) {
        Some(decode_csharp_unicode_escapes(name))
    } else {
        None
    }
}

fn rules_from_catalog(catalog: &Value) -> Vec<Rule> {
    catalog
        .get("rules")
        .and_then(Value::as_array)
        .map(|rules| {
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
        })
        .unwrap_or_default()
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_provider_key(key, Some(path), Some(child)) {
                    errors.push(format!("{path}.{key} contains prohibited provider field"));
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
            if path.ends_with(PROGRAM_PATH) {
                validate_program_no_prohibited_values(text, path, errors);
                return;
            }
            let decoded = decode_csharp_unicode_escapes(text);
            if prohibited_value(&decoded) {
                errors.push(format!("{path} contains prohibited value"));
            }
        }
        _ => {}
    }
}

fn validate_program_no_prohibited_values(program: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in program.lines().enumerate() {
        let decoded = decode_csharp_unicode_escapes(line);
        if prohibited_value(&decoded) {
            errors.push(format!("{path}:{} contains prohibited value", index + 1));
        }
    }
}

fn prohibited_provider_key(key: &str, path: Option<&str>, value: Option<&Value>) -> bool {
    let normalized = normalized_key(key);
    if SAFE_ALLOWED_PROVIDER_KEYS.contains(&normalized.as_str()) {
        return !safe_allowed_provider_flag(&normalized, path, value);
    }
    contains_any(
        &normalized,
        &[
            "rawxml",
            "encryptedxml",
            "customizationxml",
            "xmlpayload",
            "oupath",
            "distinguishedname",
            "username",
            "password",
            "credential",
            "credentials",
            "secret",
            "token",
            "tenantid",
            "objectid",
            "endpoint",
            "endpointname",
            "privateip",
            "hostname",
            "screenshot",
            "providerpayload",
            "rawproviderpayload",
            "rawproviderrows",
        ],
    )
}

fn safe_allowed_provider_flag(
    _normalized: &str,
    path: Option<&str>,
    value: Option<&Value>,
) -> bool {
    matches!(path, Some(SLICE)) && value.and_then(Value::as_bool) == Some(false)
}

fn prohibited_value(value: &str) -> bool {
    let decoded = decode_csharp_unicode_escapes(value);
    let scan_value = SAFE_PROGRAM_TEXT_VALUES
        .iter()
        .fold(decoded, |current, safe| current.replace(safe, ""));
    contains_akia(&scan_value)
        || scan_value.to_ascii_uppercase().contains("-----BEGIN ")
            && scan_value.to_ascii_uppercase().contains("PRIVATE KEY-----")
        || contains_url(&scan_value)
        || contains_private_ipv4(&scan_value)
        || contains_uuid(&scan_value)
        || contains_secret_assignment(&scan_value)
        || contains_ou_dn(&scan_value)
        || contains_customization_xml(&scan_value)
        || contains_dns_name(value)
        || contains_domain_account(&scan_value)
        || contains_email(&scan_value)
}

fn strip_csharp_comments(program: &str) -> String {
    let mut output = String::with_capacity(program.len());
    let bytes = program.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if let Some(end) = csharp_string_end(program, index) {
            if let Some(text) = program.get(index..end) {
                output.push_str(text);
            }
            index = end;
            continue;
        }
        if bytes.get(index) == Some(&b'/') && bytes.get(index + 1) == Some(&b'/') {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            if index < bytes.len() {
                output.push('\n');
                index += 1;
            }
            continue;
        }
        if bytes.get(index) == Some(&b'/') && bytes.get(index + 1) == Some(&b'*') {
            index += 2;
            while index < bytes.len() {
                if bytes.get(index) == Some(&b'*') && bytes.get(index + 1) == Some(&b'/') {
                    index += 2;
                    break;
                }
                if bytes[index] == b'\n' {
                    output.push('\n');
                }
                index += 1;
            }
            continue;
        }
        output.push(bytes[index] as char);
        index += 1;
    }
    output
}

fn mask_csharp_string_bodies(program: &str) -> String {
    let mut output = String::with_capacity(program.len());
    let mut index = 0;
    while index < program.len() {
        if let Some(end) = csharp_string_end(program, index) {
            if let Some(text) = program.get(index..end) {
                for (offset, ch) in text.chars().enumerate() {
                    if offset == 0 || offset + ch.len_utf8() >= text.len() || ch == '\n' {
                        output.push(ch);
                    } else {
                        output.push(' ');
                    }
                }
            }
            index = end;
            continue;
        }
        output.push(program.as_bytes()[index] as char);
        index += 1;
    }
    output
}

fn csharp_string_end(program: &str, start: usize) -> Option<usize> {
    let bytes = program.as_bytes();
    if bytes.get(start) == Some(&b'@') && bytes.get(start + 1) == Some(&b'"') {
        let mut index = start + 2;
        while index < bytes.len() {
            if bytes[index] == b'"' && bytes.get(index + 1) == Some(&b'"') {
                index += 2;
            } else if bytes[index] == b'"' {
                return Some(index + 1);
            } else {
                index += 1;
            }
        }
        return Some(bytes.len());
    }
    if bytes.get(start) == Some(&b'"') {
        let mut quote_count = 0;
        while bytes.get(start + quote_count) == Some(&b'"') {
            quote_count += 1;
        }
        if quote_count >= 3 {
            let delimiter = "\"".repeat(quote_count);
            let mut index = start + quote_count;
            while index < bytes.len() {
                if program
                    .get(index..)
                    .unwrap_or_default()
                    .starts_with(&delimiter)
                {
                    return Some(index + quote_count);
                }
                index += 1;
            }
            return Some(bytes.len());
        }
        let mut index = start + 1;
        while index < bytes.len() {
            if bytes[index] == b'\\' {
                index += 2;
            } else if bytes[index] == b'"' {
                return Some(index + 1);
            } else {
                index += 1;
            }
        }
        return Some(bytes.len());
    }
    None
}

fn parse_csharp_string_literal_at(program: &str, start: usize) -> Option<(String, usize)> {
    let end = csharp_string_end(program, start)?;
    let literal = program.get(start..end)?;
    Some((csharp_string_literal_value(literal)?, end))
}

fn csharp_string_literal_value(source: &str) -> Option<String> {
    let value = source.trim();
    if value.starts_with("@\"") && value.ends_with('"') {
        return Some(value[2..(value.len() - 1)].replace("\"\"", "\""));
    }
    let raw_quote_count = value
        .as_bytes()
        .iter()
        .take_while(|byte| **byte == b'"')
        .count();
    if raw_quote_count >= 3 {
        let delimiter = "\"".repeat(raw_quote_count);
        if value.ends_with(&delimiter) && value.len() >= raw_quote_count * 2 {
            return value
                .get(raw_quote_count..(value.len() - raw_quote_count))
                .map(str::to_string);
        }
    }
    if value.starts_with('"') && value.ends_with('"') {
        let body = &value[1..(value.len() - 1)];
        let mut output = String::new();
        let mut chars = body.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                if let Some(next) = chars.next() {
                    match next {
                        '"' => output.push('"'),
                        '\\' => output.push('\\'),
                        'n' => output.push('\n'),
                        'r' => output.push('\r'),
                        't' => output.push('\t'),
                        _ => output.push(next),
                    }
                }
            } else {
                output.push(ch);
            }
        }
        return Some(output);
    }
    None
}

fn matching_delimiter_index(source: &str, open: usize, left: u8, right: u8) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 0_i32;
    for (index, byte) in bytes.iter().enumerate().skip(open) {
        if *byte == left {
            depth += 1;
        } else if *byte == right {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn decode_csharp_unicode_escapes(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let chars = text.chars().collect::<Vec<_>>();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '\\'
            && matches!(chars.get(index + 1), Some('u' | 'U'))
            && index + if chars[index + 1] == 'u' { 5 } else { 9 } < chars.len()
        {
            let width = if chars[index + 1] == 'u' { 4 } else { 8 };
            let digits = chars[(index + 2)..(index + 2 + width)]
                .iter()
                .collect::<String>();
            if digits.chars().all(|ch| ch.is_ascii_hexdigit()) {
                if let Ok(value) = u32::from_str_radix(&digits, 16) {
                    if let Some(ch) = char::from_u32(value) {
                        output.push(ch);
                        index += 2 + width;
                        continue;
                    }
                }
            }
        }
        output.push(chars[index]);
        index += 1;
    }
    output
}

fn identifier_counts(text: &str) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for identifier in identifiers(text) {
        *counts.entry(identifier).or_insert(0) += 1;
    }
    counts
}

fn identifiers(text: &str) -> Vec<String> {
    let mut identifiers = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'@' || byte.is_ascii_alphabetic() || byte == b'_' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            if let Some(identifier) = text.get(start..index) {
                let identifier = identifier.trim_start_matches('@');
                if valid_identifier(identifier) {
                    identifiers.push(identifier.to_string());
                }
            }
        } else {
            index += 1;
        }
    }
    identifiers
}

fn valid_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn check_required_values(
    values: &[String],
    required: &[String],
    message: &str,
    errors: &mut Vec<String>,
) {
    for value in required {
        if !values.contains(value) {
            errors.push(format!("{message} {value}"));
        }
    }
}

fn string_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn bool_field(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}

fn string_array_field(value: &Value, field: &str) -> Vec<String> {
    value
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

fn unique_len(values: &[String]) -> usize {
    values.iter().collect::<BTreeSet<_>>().len()
}

fn normalized_key(key: &str) -> String {
    key.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(|ch| ch.to_lowercase())
        .collect()
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn skip_ws(source: &str, mut index: usize) -> usize {
    while source
        .as_bytes()
        .get(index)
        .map(|byte| byte.is_ascii_whitespace())
        .unwrap_or(false)
    {
        index += 1;
    }
    index
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn contains_url(value: &str) -> bool {
    value
        .split_whitespace()
        .any(|token| token.to_ascii_lowercase().contains("://"))
}

fn contains_akia(value: &str) -> bool {
    value
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|token| token.len() >= 20 && token.to_ascii_uppercase().starts_with("AKIA"))
}

fn contains_private_ipv4(value: &str) -> bool {
    for token in value.split(|ch: char| !(ch.is_ascii_digit() || ch == '.')) {
        let parts = token.split('.').collect::<Vec<_>>();
        if parts.len() != 4 {
            continue;
        }
        let octets = parts
            .iter()
            .filter_map(|part| part.parse::<u8>().ok())
            .collect::<Vec<_>>();
        if octets.len() != 4 {
            continue;
        }
        if octets[0] == 10
            || (octets[0] == 192 && octets[1] == 168)
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        {
            return true;
        }
    }
    false
}

fn contains_uuid(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let token = token.trim_matches(|ch: char| !ch.is_ascii_hexdigit() && ch != '-');
        let parts = token.split('-').collect::<Vec<_>>();
        parts.len() == 5
            && [8, 4, 4, 4, 12]
                .iter()
                .zip(parts.iter())
                .all(|(len, part)| {
                    part.len() == *len && part.chars().all(|ch| ch.is_ascii_hexdigit())
                })
    })
}

fn contains_secret_assignment(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
    ]
    .iter()
    .any(|term| {
        lower.contains(term)
            && (lower.contains(&format!("{term}:")) || lower.contains(&format!("{term}=")))
    })
}

fn contains_ou_dn(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    upper.contains("OU=") && upper.contains("DC=")
}

fn contains_customization_xml(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("<?xml")
        || lower.contains("<customizationspec")
        || lower.contains("<sysprep")
        || lower.contains("<unattend")
}

fn contains_domain_account(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        token.contains('\\')
            && token.split('\\').all(|part| {
                !part.is_empty()
                    && part
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || "._-".contains(ch))
            })
    })
}

fn contains_email(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let token = token.trim_matches(|ch: char| {
            !ch.is_ascii_alphanumeric()
                && ch != '@'
                && ch != '.'
                && ch != '_'
                && ch != '%'
                && ch != '+'
                && ch != '-'
        });
        let Some((left, domain)) = token.split_once('@') else {
            return false;
        };
        !left.is_empty()
            && domain.contains('.')
            && domain
                .rsplit('.')
                .next()
                .map(|tld| tld.len() >= 2)
                .unwrap_or(false)
    })
}

fn contains_dns_name(value: &str) -> bool {
    for token in value.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '.')) {
        if SAFE_PROGRAM_TEXT_VALUES.contains(&token) {
            continue;
        }
        let labels = token.split('.').collect::<Vec<_>>();
        if labels.len() < 3 {
            continue;
        }
        if labels.iter().all(|label| {
            !label.is_empty()
                && label
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
                && label
                    .chars()
                    .next()
                    .map(|ch| ch.is_ascii_alphanumeric())
                    .unwrap_or(false)
        }) {
            return true;
        }
    }
    false
}

fn legacy_provider_call_wording(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("calling vcenter, hyper-v, or proxmox")
        || lower.contains("never calls vcenter, hyper-v, proxmox")
        || lower.contains("never calls vcenter, hyper-v, or proxmox")
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
    fn mapget_routes_ignore_raw_string_decoy() {
        let program = format!(
            "var decoy = \"\"\"\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"bad\" }}));\n\"\"\";\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        let routes = mapget_routes(&program);

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].route, ENDPOINT);
    }

    #[test]
    fn duplicate_endpoint_is_rejected() {
        let program = format!(
            "app.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        let mut errors = Vec::new();
        let block = endpoint_block(&program, &mut errors);

        assert!(block.is_empty());
        assert!(errors
            .iter()
            .any(|error| error.contains("endpoint") && error.contains("exactly one")));
    }

    #[test]
    fn unicode_identifier_decodes_before_counting() {
        let counts = identifier_counts(&decode_csharp_unicode_escapes(
            "source = \"static\"; sour\\u0063e = \"runtime\";",
        ));

        assert_eq!(counts.get("source"), Some(&2));
    }
}
