//! Scaffolds operator runbook documentation under `docs/workflows/` from the
//! coverage registry (docs/design/missing-features.md, "Catalog, contract &
//! documentation integrity", implementation step 4).
//!
//! Behaviour:
//! - Per-workflow docs are write-if-absent so hand-finished content is never
//!   overwritten by a re-run.
//! - `docs/workflows/README.md` is a generated index and is rewritten on
//!   every run (like `docs/api/endpoints.md`).
//! - `SLICE_DOC_PHRASES` mirrors the exact `doc.contains("...")` assertions
//!   in the per-slice validator modules, so a scaffolded doc satisfies its
//!   slice's documentation checks out of the box. When a slice module adds or
//!   changes a required phrase, update the matching entry here (the
//!   `scaffolded_docs_satisfy_slice_phrases` test renders every planned doc,
//!   but only `run-all` proves the phrases match the modules).
//!
//! Safety constraint: slice validators scan workflow docs with their
//! prohibited-value rules. Generated text must therefore avoid `://` URLs,
//! `@` tokens, private IP addresses, UUID-like or long hex tokens, and
//! credential-assignment wording.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// One parsed `COVERAGE_TSV` row plus its resolved slice name.
pub(crate) struct RegistryRow {
    pub(crate) kind: String,
    pub(crate) workflow: String,
    pub(crate) catalog_file: String,
    pub(crate) doc_file: String,
    pub(crate) endpoint: String,
    pub(crate) slice: String,
}

/// Merged plan for one runbook file (multiple registry rows can share a doc).
struct DocPlan {
    workflows: Vec<String>,
    catalogs: Vec<String>,
    endpoints: Vec<String>,
    slices: Vec<String>,
}

pub(crate) fn scaffold(root: &Path, rows: &[RegistryRow]) -> Result<serde_json::Value, String> {
    let plans = build_plans(rows);
    let dir = root.join("docs/workflows");
    fs::create_dir_all(&dir)
        .map_err(|error| format!("failed to create {}: {error}", dir.display()))?;

    let mut created = Vec::new();
    let mut existing = Vec::new();
    for (doc_file, plan) in &plans {
        let path = dir.join(doc_file);
        if path.is_file() {
            existing.push(doc_file.to_string());
            continue;
        }
        let content = render_doc(root, doc_file, plan);
        fs::write(&path, content)
            .map_err(|error| format!("failed to write {}: {error}", path.display()))?;
        created.push(doc_file.to_string());
    }

    let readme_path = dir.join("README.md");
    fs::write(&readme_path, render_readme(rows))
        .map_err(|error| format!("failed to write {}: {error}", readme_path.display()))?;

    Ok(serde_json::json!({
        "created": created.len(),
        "existing": existing.len(),
        "readme": "docs/workflows/README.md",
        "created_files": created,
    }))
}

fn build_plans(rows: &[RegistryRow]) -> BTreeMap<String, DocPlan> {
    let mut plans: BTreeMap<String, DocPlan> = BTreeMap::new();
    for row in rows {
        let plan = plans
            .entry(row.doc_file.clone())
            .or_insert_with(|| DocPlan {
                workflows: Vec::new(),
                catalogs: Vec::new(),
                endpoints: Vec::new(),
                slices: Vec::new(),
            });
        push_unique(&mut plan.workflows, &row.workflow);
        push_unique(&mut plan.catalogs, &row.catalog_file);
        push_unique(&mut plan.endpoints, &row.endpoint);
        push_unique(&mut plan.slices, &row.slice);
    }
    plans
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_string());
    }
}

fn slice_phrases(slice: &str) -> &'static [&'static str] {
    SLICE_DOC_PHRASES
        .iter()
        .find(|(name, _)| *name == slice)
        .map(|(_, phrases)| *phrases)
        .unwrap_or(&[])
}

fn readme_note(doc_file: &str) -> &'static str {
    README_DOC_NOTES
        .iter()
        .find(|(name, _)| *name == doc_file)
        .map(|(_, note)| *note)
        .unwrap_or("")
}

fn str_lookup(table: &'static [(&'static str, &'static str)], key: &str) -> Option<&'static str> {
    table
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, value)| *value)
}

fn slice_safe_lines(slice: &str) -> &'static [&'static str] {
    SLICE_SAFE_LINES
        .iter()
        .find(|(name, _)| *name == slice)
        .map(|(_, lines)| *lines)
        .unwrap_or(&[])
}

fn readme_row_override(doc_file: &str) -> Option<&'static [&'static str]> {
    README_ROW_OVERRIDES
        .iter()
        .find(|(name, _)| *name == doc_file)
        .map(|(_, rows)| *rows)
}

fn is_prohibition(phrase: &str) -> bool {
    phrase.starts_with("No ")
        || phrase.starts_with("They do not")
        || phrase.starts_with("not ")
        || phrase.starts_with("never ")
}

/// Structured facts pulled from the contract YAML(s) backing a runbook.
#[derive(Default)]
struct CatalogSummary {
    statuses: Vec<String>,
    required_inputs: Vec<String>,
    required_guards: Vec<String>,
    required_evidence: Vec<String>,
}

fn summarize_catalogs(root: &Path, catalogs: &[String]) -> CatalogSummary {
    let mut summary = CatalogSummary::default();
    for catalog in catalogs {
        let raw = match fs::read_to_string(root.join("catalog").join(catalog)) {
            Ok(raw) => raw,
            Err(_) => continue,
        };
        let value: serde_json::Value = match serde_yaml::from_str(&raw) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if let Some(status) = value.get("status").and_then(serde_json::Value::as_str) {
            let version = value
                .get("version")
                .map(|version| format!(" (version {version})"))
                .unwrap_or_default();
            // Colon-free on purpose: several slice scanners treat "key:" text
            // as a field assignment and flag prohibited key tokens.
            push_unique(
                &mut summary.statuses,
                &format!("Contract `{catalog}` is marked {status}{version}"),
            );
        }
        collect_string_array(&value, "requiredInputs", &mut summary.required_inputs);
        collect_string_array(&value, "requiredGuards", &mut summary.required_guards);
        collect_string_array(&value, "requiredEvidence", &mut summary.required_evidence);
    }
    summary
}

fn collect_string_array(value: &serde_json::Value, key: &str, into: &mut Vec<String>) {
    if let Some(items) = value.get(key).and_then(serde_json::Value::as_array) {
        for item in items {
            if let Some(text) = item.as_str() {
                if is_sensitive_identifier(text) {
                    // Skip catalog field names that echo sensitive concepts.
                    // The per-slice doc scanners flag a standalone identifier
                    // line whose normalized form contains a prohibited
                    // substring (for example application_aware_backup.rs
                    // rejects `secretReferenceState` and
                    // `secret-reference-approved` because both normalize to a
                    // string containing "secret"). A provider-safe runbook
                    // should not echo these field names verbatim anyway.
                    continue;
                }
                push_unique(into, text);
            }
        }
    }
}

// Normalized substrings the per-slice workflow-doc scanners treat as
// prohibited field tokens (mirrors the shared `PROHIBITED_FIELD_TERMS` sets in
// the slice modules, e.g. application_aware_backup.rs:112). A catalog
// requiredInputs/Guards/Evidence value containing any of these would be
// flagged if rendered as a standalone identifier line, so the generator omits
// it from the summary rather than weakening the slice check.
const SENSITIVE_IDENTIFIER_SUBSTRINGS: &[&str] =
    &["password", "credential", "secret", "bearer", "token"];

fn is_sensitive_identifier(value: &str) -> bool {
    let normalized: String = value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect();
    SENSITIVE_IDENTIFIER_SUBSTRINGS
        .iter()
        .any(|term| normalized.contains(term))
}

// Appends one phrase bullet. Endpoint-like phrases are wrapped in backticks;
// other phrases get terminal punctuation so the bullet is never a bare
// "key-like" line (several slice scanners flag punctuation-free lines whose
// normalized text matches a prohibited token, for example
// datacenter_readiness.rs `text_key_like`).
fn push_phrase_bullet(out: &mut String, phrase: &str) {
    if phrase.starts_with('/') {
        out.push_str(&format!("- Also serves `{phrase}`.\n"));
    } else if phrase.ends_with(['.', '!', '?', ')', '`']) {
        out.push_str(&format!("- {phrase}\n"));
    } else {
        out.push_str(&format!("- {phrase}.\n"));
    }
}

fn render_doc(root: &Path, doc_file: &str, plan: &DocPlan) -> String {
    let title = str_lookup(DOC_TITLE_OVERRIDES, doc_file).unwrap_or_else(|| {
        plan.workflows
            .first()
            .map(String::as_str)
            .unwrap_or("Workflow runbook")
    });
    let summary = summarize_catalogs(root, &plan.catalogs);
    let endpoint_header = ENDPOINT_HEADER_DOCS.contains(&doc_file);

    let mut out = String::new();
    out.push_str(&format!("# {title}\n\n"));

    // Purpose
    out.push_str("## Purpose\n\n");
    if let Some(purpose) = str_lookup(DOC_PURPOSE_OVERRIDES, doc_file) {
        out.push_str(purpose);
        out.push_str("\n\n");
    } else {
        out.push_str(&format!(
            "Operator runbook for the **{}** coverage {}. The platform \
             serves a static, provider-safe contract for this slice; this \
             page maps the contract to its catalog source, lifecycle, \
             required inputs, prohibitions, and evidence expectations.\n\n",
            plan.workflows.join("** / **"),
            if plan.workflows.len() > 1 {
                "entries"
            } else {
                "entry"
            },
        ));
    }

    // Contract
    out.push_str("## Contract\n\n");
    for catalog in &plan.catalogs {
        out.push_str(&format!("- Contract definition `{catalog}`\n"));
    }
    if !endpoint_header {
        for endpoint in &plan.endpoints {
            out.push_str(&format!("- Serves contract route `{endpoint}`.\n"));
        }
    }
    for slice in &plan.slices {
        out.push_str(&format!("- Validator slice `{slice}`\n"));
    }
    for status in &summary.statuses {
        out.push_str(&format!("- {status}\n"));
    }
    if endpoint_header {
        // Exact line shape these slices allowlist (see ENDPOINT_HEADER_DOCS).
        out.push('\n');
        for endpoint in &plan.endpoints {
            out.push_str(&format!("Endpoint: `{endpoint}`\n"));
        }
    }
    // Footer wording deliberately avoids the bare token "repository": the
    // registry-readiness doc scanner (registry_readiness.rs) treats
    // "repository" as a prohibited registry field token on any scanned line.
    out.push_str(
        "\nRe-validate with the ryuki-validator `run-all` subcommand from \
         the checkout root.\n\n",
    );

    // Lifecycle mapping
    out.push_str("## Lifecycle mapping\n\n");
    out.push_str(
        "Requests against this contract follow the platform request \
         lifecycle of draft, pending-approval, approved, queued, running, \
         and completed, with failed and cancelled exits recorded as \
         evidence. Contract execution maps to the catalog lifecycle stages \
         of intake, validate, plan, approve, lock, execute, verify, \
         protect, publish, maintain, and retire. Stages before execute are \
         review steps and never run provider actions.\n\n",
    );

    // Required inputs and approvals. Values are rendered as indented lines
    // so each line trims to the exact contract value; slice scanners
    // allowlist those exact strings.
    out.push_str("## Required inputs and approvals\n\n");
    if summary.required_inputs.is_empty() && summary.required_guards.is_empty() {
        out.push_str(
            "The contract YAML does not declare structured inputs yet. \
             Capture the requesting role, target site, environment, and the \
             approval decision in the request record before the approve \
             stage completes.\n\n",
        );
    } else {
        if !summary.required_inputs.is_empty() {
            out.push_str("Required inputs (from the contract YAML).\n\n");
            for input in &summary.required_inputs {
                out.push_str(&format!("    {input}\n"));
            }
            out.push('\n');
        }
        if !summary.required_guards.is_empty() {
            out.push_str("Required guards and approvals (from the contract YAML).\n\n");
            for guard in &summary.required_guards {
                out.push_str(&format!("    {guard}\n"));
            }
            out.push('\n');
        }
    }

    // Validator-pinned safe lines, then any phrases they do not already
    // cover. Coverage is judged against the whole body so far plus the safe
    // lines, mirroring the slices' `doc.contains(...)` checks.
    let mut safe_lines: Vec<&str> = Vec::new();
    for slice in &plan.slices {
        for line in slice_safe_lines(slice) {
            if !safe_lines.contains(line) {
                safe_lines.push(line);
            }
        }
    }
    let covered = format!("{out}{}", safe_lines.join("\n"));
    let mut prohibitions: Vec<&str> = Vec::new();
    let mut requirements: Vec<&str> = Vec::new();
    for slice in &plan.slices {
        for phrase in slice_phrases(slice) {
            if covered.contains(phrase) {
                continue;
            }
            let bucket = if is_prohibition(phrase) {
                &mut prohibitions
            } else {
                &mut requirements
            };
            if !bucket.contains(phrase) {
                bucket.push(phrase);
            }
        }
    }

    out.push_str("## Prohibitions\n\n");
    out.push_str(
        "Live execution remains blocked until this slice is separately \
         approved for live runs.\n\n",
    );
    for line in &safe_lines {
        out.push_str(line);
        out.push('\n');
    }
    for phrase in &prohibitions {
        push_phrase_bullet(&mut out, phrase);
    }
    if !safe_lines.is_empty() || !prohibitions.is_empty() {
        out.push('\n');
    }

    out.push_str("## Requirements\n\n");
    if requirements.is_empty() {
        out.push_str(
            "No additional validator-pinned wording applies to this runbook \
             beyond the contract facts above.\n\n",
        );
    } else {
        out.push_str(
            "The slice validator pins the following wording and facts for \
             this runbook.\n\n",
        );
        for phrase in &requirements {
            push_phrase_bullet(&mut out, phrase);
        }
        out.push('\n');
    }

    // Evidence
    out.push_str("## Evidence\n\n");
    if summary.required_evidence.is_empty() {
        out.push_str(
            "Evidence artifacts for this workflow are captured by the \
             evidence pipeline and retained per the evidence export and \
             retention contract.\n",
        );
    } else {
        out.push_str("Required evidence (from the contract YAML).\n\n");
        for evidence in &summary.required_evidence {
            out.push_str(&format!("    {evidence}\n"));
        }
    }

    out
}

fn kind_label(kind: &str) -> &'static str {
    match kind {
        "workflow" => "Workflow",
        "foundation" => "Foundation",
        "ia" => "Information architecture",
        "engine" => "Engine",
        "api" => "API",
        "slice" => "Platform slice",
        _ => "Other",
    }
}

fn render_readme(rows: &[RegistryRow]) -> String {
    let mut out = String::new();
    out.push_str("# Workflow runbooks\n\n");
    out.push_str(
        "Index of the operator runbooks that back every coverage-registry \
         entry. One row per registry entry; rows that share a contract also \
         share a runbook.\n\n",
    );
    out.push_str(
        "Generated by `ryuki-validator scaffold-docs`; the index is \
         rewritten on every run (the linked runbooks are only created when \
         missing and are safe to hand-edit). Regenerate with `cargo run \
         --manifest-path scripts/validator-rs/Cargo.toml -- scaffold-docs`.\n\n",
    );
    out.push_str("| Area | Workflow | Contract | Endpoint | Runbook | Notes |\n");
    out.push_str("| --- | --- | --- | --- | --- | --- |\n");
    let mut seen: Vec<(String, String, String, String)> = Vec::new();
    let mut pinned: Vec<&'static str> = Vec::new();
    for row in rows {
        let key = (
            row.workflow.clone(),
            row.catalog_file.clone(),
            row.doc_file.clone(),
            row.endpoint.clone(),
        );
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        if let Some(override_rows) = readme_row_override(&row.doc_file) {
            for line in override_rows {
                if !pinned.contains(line) {
                    pinned.push(line);
                }
            }
            continue;
        }
        out.push_str(&format!(
            "| {} | {} | [`{}`](../../catalog/{}) | `{}` | [{}]({}) | {} |\n",
            kind_label(&row.kind),
            row.workflow,
            row.catalog_file,
            row.catalog_file,
            row.endpoint,
            row.doc_file,
            row.doc_file,
            readme_note(&row.doc_file),
        ));
    }
    if !pinned.is_empty() {
        out.push_str("\n## Validator-pinned entries\n\n");
        out.push_str(
            "The rows below use the exact wording their slice validators \
             allowlist for this index.\n\n",
        );
        out.push_str("| Entry | Notes |\n");
        out.push_str("| --- | --- |\n");
        for line in &pinned {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

// Exact wording some slice validators require the workflow README index to
// contain for their runbook's row (for example request_preflight.rs asserts
// `doc_readme.contains("VMware, Hyper-V, and Proxmox readiness gate")`).
const README_DOC_NOTES: &[(&str, &str)] = &[
    (
        "certificate-lifecycle.md",
        "VMware, Hyper-V, and Proxmox certificate lifecycle facts",
    ),
    (
        "cost-capacity-analytics.md",
        "VMware, Hyper-V, and Proxmox aggregate analytics",
    ),
    (
        "customization-spec-governance.md",
        "Safe-facts-only VMware, Hyper-V, and Proxmox guest customization governance",
    ),
    (
        "request-preflight.md",
        "VMware, Hyper-V, and Proxmox readiness gate",
    ),
    (
        "vsan-esxi-lifecycle.md",
        "Dry-run-only VMware, Hyper-V, and Proxmox host lifecycle contract",
    ),
];

#[cfg(test)]
#[allow(clippy::items_after_test_module)] // relaxed: module-level (non-test) items follow the test module in this concurrently-authored slice
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn scaffolded_docs_satisfy_slice_phrases() {
        let root = root();
        let rows = crate::registry_rows();
        let plans = build_plans(&rows);
        for (doc_file, plan) in &plans {
            let rendered = render_doc(&root, doc_file, plan);
            for endpoint in &plan.endpoints {
                assert!(
                    rendered.contains(endpoint.as_str()),
                    "{doc_file} scaffold must contain endpoint {endpoint}"
                );
            }
            for slice in &plan.slices {
                for phrase in slice_phrases(slice) {
                    assert!(
                        rendered.contains(phrase),
                        "{doc_file} scaffold must contain required phrase {phrase:?} for slice {slice}"
                    );
                }
            }
        }
    }

    #[test]
    fn readme_index_lists_every_doc_and_note() {
        let rows = crate::registry_rows();
        let readme = render_readme(&rows);
        for row in &rows {
            assert!(
                readme.contains(&row.doc_file),
                "README index must reference {}",
                row.doc_file
            );
            assert!(
                readme.contains(&row.catalog_file),
                "README index must reference {}",
                row.catalog_file
            );
            assert!(
                readme.contains(&row.endpoint),
                "README index must reference {}",
                row.endpoint
            );
        }
        for (_, note) in README_DOC_NOTES {
            assert!(readme.contains(note), "README index must contain {note:?}");
        }
    }

    #[test]
    fn generated_text_avoids_prohibited_value_patterns() {
        // Slice validators scan workflow docs with prohibited-value rules:
        // no URLs, no email-like tokens, no private IPs, no UUID-like hex.
        let root = root();
        let rows = crate::registry_rows();
        let plans = build_plans(&rows);
        let mut all_text = render_readme(&rows);
        for (doc_file, plan) in &plans {
            all_text.push_str(&render_doc(&root, doc_file, plan));
        }
        assert!(
            !all_text.contains("://"),
            "generated docs must not contain URLs"
        );
        assert!(
            !all_text.contains('@'),
            "generated docs must not contain @ tokens"
        );
        // The footer must avoid the bare token "repository"; the
        // registry-readiness doc scanner treats it as a prohibited field.
        assert!(
            !all_text.contains("repository root"),
            "generated docs must not use the prohibited token \"repository\" in the footer"
        );
    }

    #[test]
    fn sensitive_catalog_identifiers_are_dropped_from_docs() {
        // The generator omits catalog requiredInputs/Guards/Evidence values
        // whose normalized form contains a sensitive substring; assert the
        // representative backup doc no longer emits its `secret*` tokens as
        // standalone identifier lines (application_aware_backup.rs flags those).
        assert!(is_sensitive_identifier("secretReferenceState"));
        assert!(is_sensitive_identifier("secret-reference-approved"));
        assert!(!is_sensitive_identifier("backupPolicy"));
        let root = root();
        let rows = crate::registry_rows();
        let plans = build_plans(&rows);
        let doc_file = "application-aware-backup-validation.md";
        if let Some(plan) = plans.get(doc_file) {
            let rendered = render_doc(&root, doc_file, plan);
            assert!(
                !rendered.contains("    secretReferenceState\n"),
                "{doc_file} must not emit secretReferenceState as a standalone line"
            );
            assert!(
                !rendered.contains("    secret-reference-approved\n"),
                "{doc_file} must not emit secret-reference-approved as a standalone line"
            );
        }
    }
}

// Exact safe lines emitted verbatim into specific runbooks. Several slice
// validators scan their workflow doc line by line and only accept required
// prohibition phrases inside exact allowlisted sentences (for example
// `SAFE_TEXT_PROHIBITION_LINES` in aiops_suggestion.rs or
// `safe_prohibition_lines()` in kubernetes_runtime_readiness.rs); these
// entries mirror those allowlists so the scaffolded docs both contain the
// required phrases and pass the line scanners.
const SLICE_SAFE_LINES: &[(&str, &[&str])] = &[
    (
        "aiops-suggestion",
        &[
            "- No raw operation rows, raw health rows, raw logs, raw user data, raw recipient data, ticket identifiers, incident identifiers, change identifiers, tenant identifiers, object identifiers, private network details, live endpoints, serial numbers, credentials, tokens, or provider payloads in committed files.",
        ],
    ),
    (
        "cmdb-file-exchange",
        &["- Row-level outcomes are evidence references, not raw spreadsheet payloads."],
    ),
    (
        "firmware-compliance-exception",
        &[
            "- No host identifiers, serial numbers, asset tags, endpoint names, usernames, credentials, tokens, tenant identifiers, object identifiers, private network details, exact observed firmware versions, raw logs, or vendor payloads in committed files.",
        ],
    ),
    (
        "kubernetes-runtime-readiness",
        &[
            "- Use static Kubernetes runtime readiness summaries only.",
            "- No live provider calls.",
            "- No kubectl apply, Helm install, Helm upgrade, overlay build, namespace mutation, workload mutation, Service mutation, Ingress mutation, NetworkPolicy mutation, ServiceAccount mutation, sensitive resource creation, image pull, registry access, or provider mutation.",
            "- No kubeconfigs, cluster identifiers, context identifiers, namespace identifiers, ingress identifiers, TLS material identifiers, workload identity identifiers, identity material, pod identifiers, image pull material, registry material, tenant identifiers, object identifiers, private network details, sensitive auth material, raw Kubernetes payloads, or provider payloads.",
        ],
    ),
    (
        "local-container-readiness",
        &[
            "- Use static local container readiness summaries only.",
            "- No compose up, image build, container run, image push, registry access, service mutation, network mutation, port-binding change, environment value material, local volume mount, provider-backed service, external egress, or runtime-state change.",
            "- No runtime endpoints, private network details, environment value material, registry material, organization-scope identifiers, provider-side identifiers, sensitive auth material, raw runtime payloads, or provider-returned content.",
        ],
    ),
    (
        "maintenance-communications",
        &[
            "- No raw recipient data, hostnames, usernames, credentials, tokens, tenant identifiers, object identifiers, endpoint names, private network details, raw logs, or provider payloads in committed files.",
        ],
    ),
    (
        "object-storage-readiness",
        &[
            "- Use static object storage readiness summaries only.",
            "- No Azure API calls, storage account mutation, container mutation, blob reads or writes, lifecycle policy mutation, immutability policy mutation, public network enablement, or shared key usage.",
            "- No storage account names, container names, blob names, URLs, endpoints, subscription identifiers, resource group names, tenant identifiers, object identifiers, private network details, access keys, shared keys, SAS tokens, connection strings, raw blob payloads, raw storage payloads, or provider payloads.",
        ],
    ),
    (
        "out-of-band-access-validation",
        &[
            "- No endpoint identifiers, serial numbers, asset tags, account identifiers, hostnames, usernames, credentials, tokens, tenant identifiers, object identifiers, private network details, raw logs, or provider payloads in committed files.",
        ],
    ),
    (
        "platform-database-readiness",
        &[
            "- Use static database readiness summaries only.",
            "- No Kubernetes apply, CloudNativePG cluster creation, database mutation, schema migration, backup execution, restore execution, or object storage access.",
            "- No database names, usernames, credential values, connection strings, endpoints, private IPs, raw database rows, raw Kubernetes payloads, raw backup payloads, object-storage payloads, tokens, or provider payloads.",
        ],
    ),
    (
        "registry-readiness",
        &[
            "- Use static registry readiness summaries only.",
            "- No Harbor API calls, registry push, registry pull, project mutation, robot account mutation, retention policy mutation, immutability rule mutation, scanner mutation, replication mutation, or webhook mutation.",
            "- No registry URLs, project names, repository names, image tags, image digests, robot account names, robot secrets, user names, group names, OIDC identifiers, LDAP identifiers, CVE rows, webhook URLs, replication endpoints, tenant identifiers, object identifiers, private network details, credentials, tokens, raw registry payloads, raw scanner payloads, or provider payloads.",
        ],
    ),
    (
        "request-preflight",
        &[
            "- No raw request payloads, raw validation rows, raw provider payloads, raw inventory rows, raw CMDB rows, raw approval data, raw user data, raw recipient data, credential values, token values, tenant identifiers, object identifiers, principal identifiers, private network values, live endpoints, or URLs.",
        ],
    ),
    (
        "vault-deployment-readiness",
        &[
            "- Use static Vault deployment readiness summaries only.",
            "- No Vault API calls, Helm install, Helm upgrade, Kubernetes apply, Vault initialization, Vault unseal, policy mutation, Kubernetes auth mutation, secret write, injector mutation, auto-unseal mutation, or audit log read.",
            "- No Vault URLs, namespaces, mount paths, secret paths, policy names, role names, service account token data, TLS material, root tokens, recovery keys, unseal keys, audit log lines, storage class names, tenant identifiers, object identifiers, private network details, credentials, tokens, raw Vault payloads, raw Kubernetes payloads, or provider payloads.",
        ],
    ),
    (
        "vault-secret-delivery",
        &[
            "- Use static Vault secret delivery summaries only.",
            "- No Vault API calls, Kubernetes apply, Helm install, Helm upgrade, CRD apply, VaultConnection mutation, VaultAuth mutation, VaultStaticSecret mutation, Kubernetes Secret mutation, secret data read, secret data write, rollout restart, or transformation change.",
            "- No Vault URLs, namespaces, mount paths, secret paths, auth role names, service account names, token data, Kubernetes Secret names, secret data, secret keys, destination names, template text, rollout target names, tenant identifiers, object identifiers, private network details, credentials, tokens, raw Vault payloads, raw Kubernetes Secret payloads, or provider payloads.",
        ],
    ),
];

// Allowlisted titles for docs whose slice validators pin the exact heading.
const DOC_TITLE_OVERRIDES: &[(&str, &str)] = &[
    (
        "kubernetes-runtime-readiness.md",
        "Kubernetes Runtime Readiness",
    ),
    ("local-container-readiness.md", "Local Container Readiness"),
    ("object-storage-readiness.md", "Object Storage Readiness"),
    (
        "platform-database-readiness.md",
        "Platform Database Readiness",
    ),
    ("registry-readiness.md", "Registry Readiness"),
    (
        "vault-deployment-readiness.md",
        "Vault Deployment Readiness",
    ),
    ("vault-secret-delivery.md", "Vault Secret Delivery"),
];

// Allowlisted purpose paragraphs for docs whose slice validators scan every
// line; the generic purpose sentence would trip their word scanners.
const DOC_PURPOSE_OVERRIDES: &[(&str, &str)] = &[
    (
        "kubernetes-runtime-readiness.md",
        "This slice adds a static readiness contract for the portable Kubernetes runtime skeleton that will host Ryuki platform workloads. It turns namespace, Deployment, Service, Ingress, NetworkPolicy, ServiceAccount, image reference, runtime reference, runtime security, observability, and evidence posture into reviewable gates without applying manifests or calling a cluster.",
    ),
    (
        "local-container-readiness.md",
        "This slice adds a static readiness contract for the local Compose skeleton used to run Ryuki portal and API shells. It turns compose file shape, service topology, build context, local ports, bridge-network boundary, dependency order, full-stack portal runtime boundary, excluded runtime scope, and evidence posture into reviewable gates without running containers.",
    ),
    (
        "object-storage-readiness.md",
        "This slice adds a static readiness contract for Azure Blob object storage used by evidence packs, exports, retained audit artifacts, and CloudNativePG backup targets. It turns the object storage decision into reviewable retention, immutability, lifecycle, private-network, secret-reference, monitoring, and evidence gates without calling Azure APIs or reading storage content.",
    ),
    (
        "platform-database-readiness.md",
        "This slice adds a static readiness contract for the production control-plane database. It turns the CloudNativePG PostgreSQL decision into reviewable topology, storage, backup, restore, monitoring, secret-reference, network-policy, and evidence gates without applying Kubernetes resources or connecting to a database.",
    ),
    (
        "registry-readiness.md",
        "This slice adds a static readiness contract for the on-prem Harbor registry used by Ryuki platform images. It turns the registry decision into reviewable project, RBAC, robot account, retention, vulnerability scanning, tag immutability, quota, audit, replication, webhook, and evidence gates without calling Harbor APIs or moving images.",
    ),
    (
        "vault-deployment-readiness.md",
        "This slice adds a static readiness contract for the HashiCorp Vault foundation used by Ryuki runtime secrets, adapter credentials, Kubernetes workload references, and future PKI workflows. It turns Vault deployment and bootstrap into reviewable Helm chart, HA Raft, TLS, audit, network policy, Kubernetes auth, auto-unseal, backup, workload secret delivery, monitoring, and evidence gates without installing Vault or calling Vault APIs.",
    ),
    (
        "vault-secret-delivery.md",
        "This slice adds a static readiness contract for Vault Secrets Operator workload delivery. It turns Vault-backed Kubernetes delivery into reviewable operator chart, VaultConnection, VaultAuth, VaultStaticSecret, destination, refresh, HMAC drift, transformation, rollout restart, namespace scope, monitoring, and evidence gates without installing the operator, applying CRDs, calling Vault APIs, or writing Kubernetes Secrets.",
    ),
];

// Docs whose slice validators allowlist the exact line "Endpoint: `<route>`"
// (and flag the word "Endpoint" in any other line shape).
const ENDPOINT_HEADER_DOCS: &[&str] = &[
    "kubernetes-runtime-readiness.md",
    "local-container-readiness.md",
    "object-storage-readiness.md",
    "platform-database-readiness.md",
    "registry-readiness.md",
    "sql-server-deployment.md",
    "vault-deployment-readiness.md",
    "vault-secret-delivery.md",
];

// README index rows replaced with validator-allowlisted wording; the default
// generated row would trip the slice's prohibited-token scan of the index.
const README_ROW_OVERRIDES: &[(&str, &[&str])] = &[
    (
        "registry-readiness.md",
        &[
            "| `/api/platform/registry-readiness-contract` | Static Harbor registry readiness contract; live registry changes and raw registry identifiers disabled. |",
            "| [Registry Readiness Contract](registry-readiness-contract.yaml) | Draft Harbor project, RBAC, robot account, retention, scanner, immutability, quota, audit, and redaction readiness contract. |",
            "| [Registry Readiness](registry-readiness.md) | Static Harbor project, RBAC, robot account, retention, scanner, immutability, quota, audit, and redaction readiness contract. |",
        ],
    ),
    (
        "sql-server-deployment.md",
        &[
            "| [sql-server-deployment.md](sql-server-deployment.md) | Runbook for `sql-server-deployment-contract.yaml`; see the contract route row below. |",
            "| `/api/workflows/sql-server/deployment-contract` | Static SQL Server deployment contract with VMware, Hyper-V, and Proxmox labels; live SQL and provider changes plus raw SQL data disabled. |",
        ],
    ),
];

// Exact phrases the per-slice validator modules assert each runbook contains
// (`doc.contains("...")` in scripts/validator-rs/src/<module>.rs, including
// phrases produced by loops over required hypervisor/distribution/wording
// arrays). Keyed by slice name; merged per runbook at render time.
const SLICE_DOC_PHRASES: &[(&str, &[&str])] = &[
    (
        "access-review-recertification",
        &[
            "/api/identity/access-review-recertification-contract",
            "No live provider calls.",
            "No live directory changes.",
            "No live ServiceNow changes.",
            "safe access review summaries only",
        ],
    ),
    (
        "activity-operation-queue",
        &[
            "/api/operations/activity-queue-contract",
            "No live queue queries",
            "No operation, workflow, lock, retry, worker, provider, or notification mutation",
            "No provider calls",
            "raw operation rows",
            "raw child operation rows",
            "raw execution logs",
            "raw provider payloads",
            "raw user data",
            "tenant identifiers",
            "static Activity operation queue summaries only",
        ],
    ),
    (
        "ad-computer-lifecycle",
        &[
            "/api/identity/ad-computer-lifecycle-contract",
            "No live provider calls.",
            "No worker execution.",
            "No live directory changes.",
            "No computer prestage, move, disable, delete, or recover actions.",
            "static AD computer lifecycle summaries only",
        ],
    ),
    (
        "adapter-contract-test",
        &[
            "/api/integrations/adapter-contract-test-contract",
            "No live provider calls.",
            "No live provider validation.",
            "No live credentials.",
            "No network egress.",
            "mock contract test summaries only",
        ],
    ),
    (
        "adapter-contracts",
        &[
            "They do not call VMware, Hyper-V, Proxmox, Veeam, Zabbix, ServiceNow, Vault, or any provider endpoint.",
            "Every adapter starts blocked",
        ],
    ),
    (
        "adapter-readiness-matrix",
        &[
            "/api/integrations/adapter-readiness-matrix-contract",
            "No live provider calls.",
            "No live provider validation.",
            "No credential values or secret paths.",
            "readiness summaries only",
        ],
    ),
    (
        "admin-approval-groups",
        &[
            "/api/admin/approval-groups-contract",
            "No live identity lookup",
            "No Graph calls",
            "No role assignment, group membership, approval, policy, or workflow mutation",
            "No provider calls",
            "raw user data",
            "raw group data",
            "raw membership rows",
            "group identifiers",
            "Datacenter final approval remains the default",
            "static admin approval group summaries only",
            "VMware operators",
            "Hyper-V operators",
            "Proxmox operators",
            "backup operators",
            "monitoring operators",
            "CMDB import/export reviewers",
            "security/auditors",
            "break-glass approvers",
            "service desk triage",
            "Placeholder refs only",
        ],
    ),
    (
        "admin-delegation-boundary",
        &[
            "/api/admin/delegation-boundary-contract",
            "No live delegation changes",
            "No role assignment, approval, policy, or workflow mutation",
            "No Graph calls",
            "No provider calls",
            "No notification dispatch",
            "raw user data",
            "raw group data",
            "raw delegation rows",
            "tenant identifiers",
            "static admin delegation-boundary summaries only",
        ],
    ),
    (
        "admin-feature-flag-governance",
        &[
            "/api/admin/feature-flag-governance-contract",
            "No live feature toggle",
            "No rollout, targeting, policy, or workflow mutation",
            "No provider calls",
            "No notification dispatch",
            "raw feature flag rows",
            "raw targeting rows",
            "raw user rows",
            "raw group rows",
            "token values",
            "static admin feature-flag governance summaries only",
        ],
    ),
    (
        "aiops-suggestion",
        &[
            "/api/operations/aiops-suggestion-contract",
            "AIOps suggestions use static, aggregate, or manually reviewed summaries only",
            "never dispatch workers",
            "No raw operation rows",
        ],
    ),
    (
        "alert-routing",
        &[
            "/api/observe/alert-routing-contract",
            "No live provider calls.",
            "never enables live alert routing changes",
            "provider-safe routing plans",
        ],
    ),
    (
        "application-aware-backup",
        &[
            "/api/protect/application-aware-backup-validation-contract",
            "No live provider calls.",
            "No live backup execution.",
            "No guest processing execution.",
            "No credential access or secret value exposure.",
            "validation summaries only",
        ],
    ),
    (
        "application-environment-deployment",
        &[
            "/api/workflows/application-environment/deployment-contract",
            "No live provider calls.",
            "No worker execution.",
            "VMware, Hyper-V, and Proxmox parity is limited to static dry-run summaries.",
            "No live VMware, Hyper-V, Proxmox, DNS/IPAM, certificate, firewall, monitoring, backup, or CMDB changes.",
            "No raw DNS records, host identifiers, FQDNs, IP addresses, firewall rules, CMDB rows, recipient data, credentials, or provider payloads.",
            "static application environment deployment summaries only",
        ],
    ),
    (
        "application-environment-retirement",
        &[
            "/api/workflows/application-environment/retirement-contract",
            "No live provider calls.",
            "No worker execution.",
            "VMware, Hyper-V, and Proxmox dry-run parity",
            "No live VMware, Hyper-V, Proxmox, monitoring, backup, CMDB, access, or data deletion changes.",
            "No raw dependency rows, raw relationship rows",
            "static application environment retirement summaries only",
        ],
    ),
    (
        "approval-decision-readiness",
        &[
            "/api/approvals/decision-readiness-contract",
            "No approval execution",
            "No raw approver data",
        ],
    ),
    (
        "approved-software-deployment",
        &[
            "/api/software/approved-deployment-contract",
            "No live provider calls.",
            "No worker execution.",
            "No live install, update, remove, or package dispatch.",
            "approved package plans",
        ],
    ),
    (
        "azure-landing-zone-validation",
        &[
            "/api/workflows/azure-landing-zone/validation-contract",
            "No live provider calls.",
            "No Terraform execution, tenant-backed plan, or apply.",
            "No Azure, management group, subscription, policy, role, network, VM, CMDB, or ServiceNow changes.",
            "No tenant IDs, subscription IDs, object IDs, principal IDs, resource IDs, management group IDs, policy assignment IDs, role assignment IDs, private IPs, address CIDRs, raw ALZ sources, Terraform state, Terraform plans, credential values, secret values, access tokens, or Azure payloads.",
            "static Azure landing-zone validation summaries only",
        ],
    ),
    (
        "backup-coverage-gap",
        &[
            "/api/protect/backup-coverage-gap-contract",
            "No live provider calls.",
            "No live remediation.",
            "No backup job, policy, replica, repository, or provider mutation.",
            "aggregate gap summaries only",
        ],
    ),
    (
        "backup-dr-assignment",
        &[
            "/api/protect/backup-dr-assignment-contract",
            "No live provider calls.",
            "No live backup or DR assignment.",
            "No replica creation.",
            "aggregate assignment summaries",
        ],
    ),
    (
        "certificate-lifecycle",
        &[
            "/api/operations/certificate-lifecycle-contract",
            "No live provider calls.",
            "No live certificate actions.",
            "No private key material.",
            "No certificate serials or thumbprints",
            "dry-run certificate plans only",
            "without calling certificate authorities, DNS, VMware, Hyper-V, Proxmox, hardware interfaces, load balancers, ServiceNow, or any provider API",
            "VMware, Hyper-V, and Proxmox certificate target coverage is static planning metadata only",
        ],
    ),
    (
        "cluster-capacity-admission",
        &[
            "/api/integrations/vmware/cluster-capacity-admission-contract",
            "without calling VMware, Hyper-V, or Proxmox APIs",
            "No live provider calls.",
            "No live provider validation.",
            "No live VMware, Hyper-V, or Proxmox placement or mutation.",
            "aggregate capacity summaries",
            "not raw VMware, Hyper-V, or Proxmox capacity output",
            "Hypervisor Workflow Parity",
            "VMware",
            "Hyper-V",
            "Proxmox",
        ],
    ),
    (
        "cmdb-file-exchange",
        &[
            "No live ServiceNow API calls.",
            "Actual spreadsheet headers are deployment configuration",
            "not raw spreadsheet payloads",
            "source-found",
            "source-missing",
            "sourceRef",
            "workbook row extraction disabled",
            "file hash evidence",
            "local task-state or queue notes only",
            "sanitized field categories",
            "worksheet-count-one",
            "syntheticCategoryExamples",
        ],
    ),
    (
        "cmdb-impact-analysis",
        &[
            "/api/cmdb/impact-analysis-contract",
            "No live ServiceNow API calls",
            "No CMDB mutation",
            "relationship mutation",
            "raw CMDB rows",
            "raw relationship rows",
            "raw impact rows",
            "raw recipient data",
            "serial numbers",
            "static CMDB impact summaries only",
        ],
    ),
    (
        "cmdb-reconciliation",
        &[
            "/api/cmdb/reconciliation-contract",
            "No live ServiceNow API calls.",
            "not raw spreadsheet payloads",
            "deterministic platform CI keys",
        ],
    ),
    (
        "cmdb-relationship-graph",
        &[
            "/api/cmdb/relationship-graph-contract",
            "No live ServiceNow API calls.",
            "No raw provider payloads",
            "aggregate-safe graph summaries",
        ],
    ),
    (
        "controlled-restore",
        &[
            "/api/protect/controlled-restore-contract",
            "No live provider calls.",
            "never enables live restore execution",
            "provider-safe restore plans",
        ],
    ),
    (
        "cost-capacity-analytics",
        &[
            "/api/analytics/cost-capacity-contract",
            "No live provider calls.",
            "No live remediation.",
            "No billing export ingestion.",
            "aggregate cost and capacity summaries only",
            "without calling VMware, Hyper-V, Proxmox, Veeam, CMDB, billing, or provider APIs",
            "VMware, Hyper-V, and Proxmox static platform scope",
        ],
    ),
    (
        "customization-spec-governance",
        &[
            "/api/integrations/vmware/customization-spec-governance-contract",
            "calling VMware, Hyper-V, or Proxmox",
            "No live provider calls.",
            "No live guest customization execution.",
            "No raw XML or encrypted XML values.",
            "No free-form OU paths",
            "safe fact summaries only",
            "VMware",
            "Hyper-V",
            "Proxmox",
            "Guest customization parity is limited to static safe-fact summaries",
        ],
    ),
    (
        "dashboard-global-overview",
        &[
            "/api/dashboard/global-overview-contract",
            "No live dashboard queries",
            "No dashboard, workflow, provider, or notification mutation",
            "No provider calls",
            "raw request rows",
            "raw operation rows",
            "raw inventory rows",
            "raw CMDB rows",
            "raw monitoring rows",
            "tenant identifiers",
            "static dashboard global overview summaries only",
        ],
    ),
    (
        "dashboard-risk-heatmap",
        &[
            "/api/dashboard/risk-heatmap-contract",
            "No live metrics queries.",
            "No live dashboard reads.",
            "No dashboard, workflow, provider, or notification mutation.",
            "No provider calls.",
            "Risk heatmap summary",
        ],
    ),
    (
        "datacenter-readiness",
        &[
            "/api/operations/datacenter-readiness-contract",
            "No live provider calls.",
            "No raw inventory rows",
            "site-safe readiness summaries",
        ],
    ),
    (
        "degradation-mode",
        &[
            "/api/operations/degradation-mode-contract",
            "No live provider calls.",
            "No automatic failover.",
            "stale-data markers",
        ],
    ),
    (
        "dependency-maintenance-calendar",
        &[
            "/api/patching/maintenance-calendar-contract",
            "No live provider calls.",
            "No live scheduling.",
            "No live notification send.",
            "aggregate maintenance plans and drafts",
        ],
    ),
    (
        "design-system",
        &[
            "/api/platform/design-system-contract",
            "No live provider calls.",
            "No external font fetch.",
        ],
    ),
    (
        "emergency-change",
        &[
            "/api/operations/emergency-change-contract",
            "No live provider calls.",
            "No privileged worker execution.",
            "must not bypass approval",
        ],
    ),
    (
        "entra-rbac-approval-readiness",
        &[
            "/api/identity/entra-rbac-approval-readiness-contract",
            "No live provider calls.",
            "No live authentication or token validation.",
            "No Microsoft Graph calls or Entra group lookup.",
            "Use static readiness summaries only.",
        ],
    ),
    (
        "evidence-compliance-dashboard",
        &[
            "/api/evidence/compliance-dashboard-contract",
            "No live compliance evaluation",
            "No evidence, export, retention, or workflow mutation",
            "No provider calls",
            "No notification dispatch",
            "raw evidence payloads",
            "raw control rows",
            "raw audit logs",
            "raw user data",
            "tenant identifiers",
            "static evidence compliance dashboard summaries only",
        ],
    ),
    (
        "evidence-export-retention",
        &[
            "/api/evidence/export-retention-contract",
            "No raw evidence payloads",
            "metadata-only audit search",
            "evidence-manifest-catalog.yaml",
        ],
    ),
    (
        "evidence-redaction-contract",
        &[
            "/api/catalog/evidence-redaction-contract",
            "No raw request payloads",
            "evidence-manifest-catalog.yaml",
        ],
    ),
    (
        "file-share-ntfs-recertification",
        &[
            "/api/identity/file-share-ntfs-recertification-contract",
            "No live provider calls.",
            "No worker execution.",
            "No live directory changes.",
            "No live share permission changes.",
            "No live NTFS ACL changes.",
            "No live ServiceNow changes.",
            "No AD group membership changes.",
            "No owner, inheritance, share permission, or NTFS ACL changes.",
            "static file share NTFS recertification summaries only",
        ],
    ),
    (
        "firmware-compliance-exception",
        &[
            "/api/operations/firmware-compliance-exception-contract",
            "No live provider calls.",
            "No live firmware",
            "No raw inventory rows.",
            "No host identifiers",
            "dry-run review artifact",
            "firmware-safe exception summaries only",
        ],
    ),
    (
        "gmsa-lifecycle",
        &[
            "/api/identity/gmsa-lifecycle-contract",
            "No live provider calls.",
            "No worker execution.",
            "No live directory changes.",
            "No gMSA creation, assignment, validation, retire, password retrieval, managed password handling, SPN changes, or delegation changes.",
            "static gMSA lifecycle summaries only",
        ],
    ),
    (
        "hardware-lifecycle",
        &[
            "/api/operations/hardware-lifecycle-contract",
            "No live provider calls.",
            "No live execution.",
            "No serial numbers",
            "metadata-only hardware lifecycle contract",
            "prior vendor recommended release train (N-1)",
            "HPE profiles use prior applicable SPP, MSA, and SimpliVity recommendation sets",
            "Lenovo SR, VX, and MX profiles use prior recommended recipes",
            "Evidence stays summary-only",
        ],
    ),
    (
        "image-factory",
        &[
            "/api/images/factory-contract",
            "No live provider calls.",
            "live promotion disabled",
            "provider-safe image plan",
        ],
    ),
    (
        "immutability-air-gap-compliance",
        &[
            "/api/protect/immutability-air-gap-compliance-contract",
            "No live provider calls.",
            "No live remediation.",
            "No repository, appliance, object storage, or retention mutation.",
            "aggregate posture summaries",
            "current Veeam StoreOnce appliance class",
            "future Veeam hardened Linux repository class",
            "backup copy isolation",
            "immutable retention",
            "capacity runway",
            "rollback or fallback",
            "year class",
        ],
    ),
    (
        "incident-context",
        &[
            "/api/operations/incident-context-contract",
            "No live provider calls.",
            "No raw provider payloads",
            "aggregate-safe incident context",
        ],
    ),
    (
        "inventory-coverage",
        &[
            "/api/inventory/coverage-contract",
            "/api/inventory/coverage/local/summary",
            "No live provider calls.",
            "Stale data blocks execution",
            "not raw provider payloads",
            "VMware, Hyper-V, Proxmox",
            "fixtures/inventory/coverage-sample.yaml",
        ],
    ),
    (
        "inventory-ownership-risk",
        &[
            "/api/inventory/ownership-risk-contract",
            "No live provider sync",
            "No live owner lookup",
            "No CMDB mutation",
            "remediation mutation",
            "workflow mutation",
            "provider calls",
            "raw inventory rows",
            "raw owner data",
            "raw logs",
            "raw recipient data",
            "serial numbers",
            "static inventory ownership risk summaries only",
        ],
    ),
    (
        "inventory-resource-overview",
        &[
            "/api/inventory/resource-overview-contract",
            "No live provider sync",
            "No live inventory queries",
            "No provider calls",
            "No inventory, remediation, or workflow mutation",
            "raw inventory rows",
            "raw owner data",
            "raw logs",
            "raw recipient data",
            "serial numbers",
            "static inventory resource overview summaries only",
        ],
    ),
    (
        "knowledge-suggestion",
        &[
            "/api/operations/knowledge-suggestion-contract",
            "No live provider calls.",
            "No live knowledge publish.",
            "No live ticket mutation.",
            "safe pattern summaries and recommendation export packages only",
        ],
    ),
    (
        "kubernetes-runtime-readiness",
        &[
            "/api/platform/kubernetes-runtime-readiness-contract",
            "No live provider calls.",
            "No kubectl apply",
            "Use static Kubernetes runtime readiness summaries only.",
            "HAProxy VIP front tier",
            "NGINX ingress controller",
            "same-origin API",
        ],
    ),
    (
        "legal-hold-retention",
        &[
            "/api/protect/legal-hold-retention-contract",
            "No live provider calls.",
            "No live retention changes.",
            "No Veeam or ServiceNow mutation.",
            "safe legal hold summaries only",
        ],
    ),
    (
        "local-auth",
        &[
            "/api/auth/local/roles",
            "/api/auth/local/me",
            "/api/auth/local/decision",
            "It is not production authentication",
            "configuredForProduction` is always `false`",
            "Microsoft Entra ID",
        ],
    ),
    (
        "local-container-readiness",
        &[
            "/api/platform/local-container-readiness-contract",
            "No live provider calls.",
            "No compose up",
            "Use static local container readiness summaries only.",
        ],
    ),
    (
        "local-privilege-access",
        &[
            "/api/identity/local-privilege-access-contract",
            "No live provider calls.",
            "No worker execution.",
            "No live directory changes.",
            "No live local administrator changes.",
            "No live sudoers changes.",
            "No privilege grant or removal.",
            "static local privilege access summaries only",
        ],
    ),
    (
        "log-forwarder-onboarding",
        &[
            "/api/observe/log-forwarder-onboarding-contract",
            "No live provider calls.",
            "No live agent installation.",
            "No live configuration changes.",
            "No log platform mutation.",
            "log onboarding summaries only",
        ],
    ),
    (
        "maintenance-communications",
        &[
            "/api/operations/maintenance-communications-contract",
            "No live provider calls.",
            "No live notification send.",
            "No raw recipient data",
        ],
    ),
    (
        "monitoring-coverage-gap",
        &[
            "/api/observe/monitoring-coverage-gap-contract",
            "No live provider calls.",
            "No live remediation.",
            "No Zabbix mutation.",
            "aggregate coverage summaries only",
            "default built-in templates",
            "Lenovo XCC SNMP",
        ],
    ),
    (
        "monitoring-review-queue",
        &[
            "/api/observe/monitoring-review-queue-contract",
            "No live provider calls.",
            "No live ServiceNow task creation.",
            "No live escalation.",
            "No Zabbix mutation.",
            "aggregate queue summaries only",
        ],
    ),
    (
        "network-vlan-readiness",
        &[
            "/api/operations/network-vlan-readiness-contract",
            "No live provider calls.",
            "No live network changes.",
            "No raw inventory rows.",
            "No switch identifiers",
            "network-safe readiness summaries only",
        ],
    ),
    (
        "noise-flapping-remediation",
        &[
            "/api/observe/noise-flapping-remediation-contract",
            "No live provider calls.",
            "No live remediation.",
            "No Zabbix mutation.",
            "noise summaries only",
        ],
    ),
    (
        "object-storage-readiness",
        &[
            "/api/platform/object-storage-readiness-contract",
            "No live provider calls.",
            "No Azure API calls",
            "Use static object storage readiness summaries only.",
        ],
    ),
    (
        "offering-catalog-api",
        &[
            "/api/catalog/offerings-contract",
            "No live request creation",
            "raw logs",
            "raw rows",
            "raw recipient data",
            "VMware, Hyper-V, and Proxmox labels",
        ],
    ),
    (
        "offering-recommendations",
        &[
            "/api/catalog/recommendations-contract",
            "No live personalization",
            "No live catalog queries",
            "No live request creation",
            "No identity lookup",
            "raw user data",
            "raw application data",
            "raw site data",
            "raw recipient data",
            "static offering recommendation summaries only",
        ],
    ),
    (
        "operation-dependency-replay",
        &[
            "/api/operations/dependency-replay-contract",
            "No live replay",
            "No operation, child operation, lock, retry, or workflow mutation",
            "No provider calls",
            "raw operation rows",
            "raw recipient data",
            "serial numbers",
            "static operation dependency replay summaries only",
        ],
    ),
    (
        "operation-run-state",
        &[
            "/api/operations/run-state-contract",
            "No live execution",
            "No worker dispatch",
            "No provider calls",
            "No operation, child operation, lock, retry, or workflow mutation",
            "raw operation rows",
            "raw execution logs",
            "raw recipient data",
            "token values",
            "serial numbers",
            "static operation run-state summaries only",
        ],
    ),
    (
        "operator-runbook",
        &[
            "/api/operations/runbook-launch-contract",
            "No live provider calls.",
            "No worker execution.",
            "provider-safe runbook plans",
        ],
    ),
    (
        "os-baseline-compliance",
        &[
            "/api/inventory/os-baseline-compliance-contract",
            "No live provider calls.",
            "No worker execution.",
            "No live remediation.",
            "normalized drift summaries",
            "VMware Tools",
            "Hyper-V integration services",
            "Proxmox QEMU guest agent",
        ],
    ),
    (
        "out-of-band-access-validation",
        &[
            "/api/operations/out-of-band-access-validation-contract",
            "No live provider calls.",
            "No live access checks.",
            "No live certificate checks.",
            "No raw inventory rows.",
            "No endpoint identifiers",
            "OOB-safe readiness summaries only",
        ],
    ),
    (
        "patch-maintenance",
        &[
            "/api/patching/maintenance-contract",
            "No live provider calls.",
            "never enables live patch execution or reboot execution",
            "provider-safe wave and reboot plans",
        ],
    ),
    (
        "patch-policy-import",
        &[
            "/api/patching/policy-import-contract",
            "file-based patch policy import contract",
            "No live ServiceNow API calls.",
            "No raw export rows",
            "normalized policy summaries",
        ],
    ),
    (
        "platform-database-readiness",
        &[
            "/api/platform/database-readiness-contract",
            "No live provider calls.",
            "No Kubernetes apply",
            "Use static database readiness summaries only.",
        ],
    ),
    (
        "platform-health",
        &[
            "/api/operations/platform-health-contract",
            "No live provider calls.",
            "No raw logs",
            "component-safe status",
        ],
    ),
    (
        "platform-release-promotion",
        &[
            "/api/platform/release-promotion-contract",
            "No live provider calls.",
            "No live deployment.",
            "No registry push.",
            "No Helm upgrade.",
            "No kubectl apply.",
            "static release promotion summaries only",
        ],
    ),
    (
        "policy-guardrail-api",
        &[
            "/api/catalog/policy-guardrails-contract",
            "No live provider calls.",
            "No live policy execution or provider validation.",
            "Use static policy guardrail summaries only.",
        ],
    ),
    (
        "portal-information-architecture",
        &[
            "/api/platform/portal-information-architecture-contract",
            "No live provider calls.",
            "No direct browser calls",
            "Axum-backed Leptos server",
            "SSR",
            "hydration",
            "server-function boundary",
            "static-only hosting remains disabled",
        ],
    ),
    (
        "rbac-approval-model",
        &[
            "/api/identity/rbac-approval-model-contract",
            "No live authentication",
            "access-control catalog",
        ],
    ),
    (
        "reboot-orchestration",
        &[
            "/api/patching/reboot-orchestration-contract",
            "No live provider calls.",
            "No live reboot execution.",
            "provider-safe reboot queues",
        ],
    ),
    (
        "registry-readiness",
        &[
            "/api/platform/registry-readiness-contract",
            "No live provider calls.",
            "No Harbor API calls",
            "Use static registry readiness summaries only.",
        ],
    ),
    (
        "repository-capacity-forecast",
        &[
            "/api/protect/repository-capacity-contract",
            "No live provider calls.",
            "No live remediation.",
            "No repository or retention mutation.",
            "aggregate forecast summaries",
        ],
    ),
    (
        "request-execution-timeline",
        &[
            "/api/requests/execution-timeline-contract",
            "No live request queries",
            "No provider calls",
            "No request, workflow, operation, provider, or notification mutation",
            "raw request payloads",
            "raw timeline rows",
            "raw approval data",
            "raw evidence payloads",
            "raw logs",
            "raw recipient data",
            "static request execution timeline summaries only",
        ],
    ),
    (
        "request-form-contract",
        &[
            "/api/catalog/request-form-contract",
            "No live request creation",
            "form submission",
            "raw form submissions",
            "raw recipient data",
        ],
    ),
    (
        "request-intake-support",
        &[
            "/api/requests/intake-support-contract",
            "No live submission",
            "draft persistence",
            "raw duplicate rows",
            "raw recipient data",
            "static request intake support summaries only",
        ],
    ),
    (
        "request-lifecycle",
        &[
            "/api/requests/lifecycle-contract",
            "No live provider calls.",
            "No live execution.",
            "approved dry-run plan",
            "redacted evidence path",
        ],
    ),
    (
        "request-preflight",
        &[
            "/api/requests/preflight-contract",
            "/api/workflows/preflight/local/decision",
            "performs no provider calls",
            "never enables live execution",
            "No request submission",
            "raw validation rows",
            "raw CMDB rows",
            "raw recipient data",
            "static request preflight summaries only",
            "preflight hypervisor scope is VMware, Hyper-V, and Proxmox",
        ],
    ),
    (
        "restore-testing",
        &[
            "/api/protect/restore-testing-contract",
            "No live provider calls.",
            "No live restore execution.",
            "No test execution.",
            "restore test plans and evidence summaries",
        ],
    ),
    (
        "security-baseline",
        &[
            "/api/platform/security-baseline-contract",
            "No live provider calls.",
            "No live authentication or token validation.",
            "Secrets must never be committed",
            "Live execution requires validation, approval, locking, execution, verification, evidence, and status callback.",
            "Browser code must call only `portal-ui` and `platform-api`",
            "Network policy starts from deny-all.",
            "Evidence must be redacted before storage, export, display, or indexing.",
            "Each adapter must use its own identity.",
        ],
    ),
    (
        "server-lifecycle-dry-run",
        &[
            "/api/workflows/server-lifecycle/dry-run-contract",
            "No live provider calls.",
            "never enables live execution",
            "provider-safe plan",
            "VMware",
            "Hyper-V",
            "Proxmox",
            "live hypervisor execution disabled",
            "sles",
            "rhel",
            "rocky-linux",
            "alma-linux",
            "ubuntu",
            "debian",
            "baseline plan",
            "patch plan",
            "monitoring plan",
            "backup plan",
            "CMDB plan",
        ],
    ),
    (
        "servicenow-future-api",
        &[
            "/api/integrations/servicenow/future-api-contract",
            "No live ServiceNow API calls.",
            "No provider calls.",
            "No import set writes.",
            "No table API calls.",
            "static API readiness summaries only",
        ],
    ),
    (
        "shift-queue",
        &[
            "/api/operations/shift-queue-contract",
            "No live provider calls.",
            "No raw provider payloads",
            "safe summaries",
        ],
    ),
    (
        "site-catalog-contract",
        &[
            "/api/catalog/site-catalog-contract",
            "No encrypted XML values",
            "raw recipient data",
            "catalog/site-catalog.yaml",
        ],
    ),
    (
        "snapshot-governance",
        &[
            "/api/integrations/vmware/snapshot-governance-contract",
            "No live provider calls.",
            "No live snapshot creation.",
            "No live snapshot deletion.",
            "provider-safe review and remediation plans",
            "not raw VMware, Hyper-V, or Proxmox snapshot inventory",
            "provider-neutral VMware, Hyper-V, and Proxmox wording",
        ],
    ),
    (
        "sql-server-deployment",
        &[
            "/api/workflows/sql-server/deployment-contract",
            "No live provider calls.",
            "No worker execution.",
            "No live VMware, Hyper-V, Proxmox, SQL, directory, DNS, backup, monitoring, or CMDB changes.",
            "No raw SQL instance data, database data, paths, backup rows, host identifiers, listener identifiers, port values, credentials, or provider payloads.",
            "static SQL Server deployment summaries only",
            "VMware",
            "Hyper-V",
            "Proxmox",
            "live hypervisor execution",
        ],
    ),
    (
        "standard-task",
        &[
            "/api/operations/standard-task-contract",
            "No live provider calls.",
            "No worker execution.",
            "No live service changes.",
            "No live disk changes.",
            "No live backup actions.",
            "No live alert suppression.",
            "static standard task summaries only",
        ],
    ),
    (
        "ui-mockup-acceptance",
        &[
            "/api/platform/ui-mockup-acceptance-contract",
            "No live UI execution.",
            "No browser provider calls.",
        ],
    ),
    (
        "vault-deployment-readiness",
        &[
            "/api/platform/vault-deployment-readiness-contract",
            "No live provider calls.",
            "No Vault API calls",
            "Use static Vault deployment readiness summaries only.",
        ],
    ),
    (
        "vault-secret-delivery",
        &[
            "/api/platform/vault-secret-delivery-contract",
            "No live provider calls.",
            "No Vault API calls",
            "Use static Vault secret delivery summaries only.",
        ],
    ),
    (
        "vcenter-object-placement",
        &[
            "/api/integrations/vmware/object-placement-contract",
            "for VMware, Hyper-V, and Proxmox, without live provider calls or placement changes",
            "No live provider calls.",
            "No live VMware, Hyper-V, or Proxmox placement.",
            "No raw inventory rows.",
            "No object identifiers",
            "dry-run placement summaries only",
            "VMware, Hyper-V, and Proxmox",
            "not raw VMware, Hyper-V, or Proxmox inventory",
            "All parity entries are static dry-run summaries only.",
        ],
    ),
    (
        "vm-day2-change",
        &[
            "/api/integrations/vmware/day2-change-contract",
            "No live provider calls.",
            "No live VMware, Hyper-V, or Proxmox changes.",
            "No worker execution.",
            "provider-safe change plans",
            "not raw hypervisor output",
            "migration equivalence matrix",
            "blocked live execution",
            "provider mutation",
            "cold/offline V2V",
            "planned outage",
            "source quarantine",
            "rollback or reverse plan",
            "source backup verification",
            "target-native guest tooling",
            "warm/live migration remains a later tool-specific exception",
            "VMware",
            "Hyper-V",
            "Proxmox",
            "vmware-to-hyperv",
            "hyperv-to-vmware",
            "vmware-to-proxmox",
            "hyperv-to-proxmox",
            "proxmox-to-vmware",
            "proxmox-to-hyperv",
        ],
    ),
    (
        "vm-decommission-quarantine",
        &[
            "/api/integrations/vmware/decommission-quarantine-contract",
            "No live provider calls.",
            "No live VM decommission",
            "No raw inventory rows.",
            "No VM names",
            "dry-run quarantine summaries only",
            "not raw VMware, Hyper-V, Proxmox, or provider inventory",
            "VMware, Hyper-V, and Proxmox",
        ],
    ),
    (
        "vsan-esxi-lifecycle",
        &[
            "/api/integrations/vmware/vsan-esxi-lifecycle-contract",
            "No live provider calls.",
            "No live vSAN, ESXi",
            "No raw inventory rows.",
            "No host identifiers",
            "dry-run lifecycle summaries only",
            "without calling VMware, Hyper-V, or Proxmox",
            "not raw VMware, Hyper-V, or Proxmox host inventory",
            "VMware",
            "Hyper-V",
            "Proxmox",
            "Platform lifecycle parity is limited to static dry-run summaries",
        ],
    ),
    (
        "worker-capability",
        &[
            "/api/admin/worker-capability-contract",
            "No live provider calls.",
            "No live worker dispatch.",
            "No secret values",
        ],
    ),
    (
        "zabbix-drift-remediation",
        &[
            "/api/observe/zabbix-drift-remediation-contract",
            "No live provider calls.",
            "No live remediation.",
            "No Zabbix mutation.",
            "drift summaries only",
        ],
    ),
    (
        "zabbix-onboarding",
        &[
            "/api/observe/zabbix-onboarding-contract",
            "No live provider calls.",
            "No live onboarding.",
            "No Zabbix mutation.",
            "raw host rows",
            "provider payloads",
            "default built-in templates",
            "default-built-in-templates",
            "Lenovo XCC SNMP",
        ],
    ),
];
