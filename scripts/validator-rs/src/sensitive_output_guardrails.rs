use serde::Deserialize;
use std::fs;
use std::path::Path;

const AUTH_MAIN_PATH: &str = "sources/ryuki-api/src/main.rs";
const EVIDENCE_PIPELINE_PATH: &str = "sources/ryuki-engine/src/evidence_pipeline.rs";
const ADAPTER_FRAMEWORK_PATH: &str = "sources/ryuki-engine/src/adapter_framework.rs";
const NO_SECRET_SCAN_PATH: &str = "scripts/no-secret-scan.sh";

#[derive(Debug, Deserialize)]
struct Context {
    auth_main: String,
    evidence_pipeline: String,
    adapter_framework: String,
    no_secret_scan: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid sensitive output guardrails context JSON: {error}"))?;
    let mut errors = Vec::new();

    validate_auth_log_safety(&context.auth_main, &mut errors);
    validate_evidence_export_safety(&context.evidence_pipeline, &mut errors);
    validate_adapter_response_safety(&context.adapter_framework, &mut errors);
    validate_no_secret_scan_safety(&context.no_secret_scan, &mut errors);

    Ok(errors)
}

fn validate_auth_log_safety(auth_main: &str, errors: &mut Vec<String>) {
    if auth_main.contains("authorization_header = header_value") {
        errors.push(
            "AUTH: raw Authorization header value logged — must use auth_header_present/provider_mode only"
                .to_string(),
        );
    }
    if !auth_main.contains("auth_header_present") {
        errors.push("AUTH: missing auth_header_present field in log metadata".to_string());
    }
    if !auth_main.contains("provider_mode") {
        errors.push("AUTH: missing provider_mode field in log metadata".to_string());
    }
    if !auth_main.contains("resolve_auth_metadata") {
        errors.push("AUTH: missing resolve_auth_metadata helper function".to_string());
    }
}

fn validate_evidence_export_safety(pipeline: &str, errors: &mut Vec<String>) {
    if !pipeline.contains("build_safe_export_pack") {
        errors.push(
            "EVIDENCE: missing build_safe_export_pack — sensitive values may leak in export"
                .to_string(),
        );
    }
    if !pipeline.contains("safe_export_value") {
        errors.push(
            "EVIDENCE: missing safe_export_value helper — redacted items may expose originals"
                .to_string(),
        );
    }
    // Detect direct serialization of EvidencePack (unsafe)
    if pipeline.contains("to_string_pretty(pack)") {
        errors.push(
            "EVIDENCE: export_evidence serializes raw EvidencePack — must use build_safe_export_pack"
                .to_string(),
        );
    }
}

fn validate_adapter_response_safety(adapter: &str, errors: &mut Vec<String>) {
    if adapter.contains("simulated with params") {
        errors.push(
            "ADAPTER: execute response includes raw params via Debug format — must use sanitized_dry_run_result"
                .to_string(),
        );
    }
    if !adapter.contains("sanitized_dry_run_result") {
        errors.push(
            "ADAPTER: missing sanitized_dry_run_result helper — params may be exposed".to_string(),
        );
    }
    // Check that all execute impls use the sanitized helper
    let execute_count = adapter.matches("fn execute(").count();
    let sanitized_count = adapter.matches("sanitized_dry_run_result(").count();
    // ServiceNow adapter has a different safe form but must not include params
    if adapter.matches("fn execute(").count()
        != adapter.matches("sanitized_dry_run_result(").count()
            + adapter.matches("(file-exchange mode, no live API)").count()
    {
        errors.push(format!(
            "ADAPTER: found {execute_count} execute impls but only {sanitized_count} use sanitized_dry_run_result"
        ));
    }
}

fn validate_no_secret_scan_safety(scan: &str, errors: &mut Vec<String>) {
    if scan.contains("!sources/**") {
        errors.push(
            "SCAN: no-secret-scan.sh excludes sources/** — must include sources/ryuki-*"
                .to_string(),
        );
    }
    if !scan.contains("sources/ryuki-") {
        errors.push(
            "SCAN: no-secret-scan.sh does not include sources/ryuki-* in default scope".to_string(),
        );
    }
    if !scan.contains("category=") || !scan.contains("path=") {
        errors.push(
            "SCAN: no-secret-scan.sh must report only category= and path= per match".to_string(),
        );
    }
    // Must not print line content (--line-number was removed, --files-with-matches added)
    if scan.contains("--line-number") {
        errors.push(
            "SCAN: no-secret-scan.sh uses --line-number (exposes content) — must use --files-with-matches"
                .to_string(),
        );
    }
    if !scan.contains("--files-with-matches") {
        errors.push(
            "SCAN: no-secret-scan.sh must use --files-with-matches to avoid content exposure"
                .to_string(),
        );
    }
}
