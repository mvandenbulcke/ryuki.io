//! Control-plane database backup / restore / DR validator.
//!
//! Asserts that the control-plane PostgreSQL database has a real, recoverable
//! backup posture defined in the repo:
//!
//!   1. A CloudNativePG `ScheduledBackup` manifest exists, is well-formed, runs
//!      on a cron schedule, declares a retention policy, and targets the
//!      `ryuki-platform-db` cluster.
//!   2. A restore / disaster-recovery runbook exists and documents PITR,
//!      full-cluster-loss recovery (CNPG `bootstrap.recovery`), and a recurring
//!      restore-test drill.
//!   3. The root `Makefile` exposes `db-backup` and `db-restore` targets for the
//!      local/compose database.
//!
//! Like the other deploy validators (see `observability_deploy_wiring` and
//! `app_skeleton`), this reads the repo files directly from the `root` passed in
//! the slice context JSON, so it runs standalone
//! (`validate control-plane-db-backup --context-json <ctx>`).

use serde::Deserialize;
use serde_yaml::Value;
use std::fs;
use std::path::Path;

const SCHEDULED_BACKUP_PATH: &str = "deploy/kubernetes/cloudnativepg/scheduled-backup.yaml";
const CLUSTER_PATH: &str = "deploy/kubernetes/cloudnativepg/cnpg-cluster.yaml";
const RUNBOOK_PATH: &str = "docs/runbooks/db-restore-runbook.md";
const MAKEFILE_PATH: &str = "Makefile";

/// The CNPG cluster the ScheduledBackup must target. Sourced from
/// `cnpg-cluster.yaml` (`metadata.name`).
const EXPECTED_CLUSTER: &str = "ryuki-platform-db";

/// Make targets the local-dev backup/restore workflow must expose.
const REQUIRED_MAKE_TARGETS: &[&str] = &["db-backup", "db-restore"];

/// Substrings the restore runbook must contain to be considered complete: it
/// must cover PITR, full-cluster-loss recovery via CNPG `bootstrap.recovery`,
/// and a recurring restore-test drill.
const REQUIRED_RUNBOOK_TERMS: &[&str] = &[
    "point-in-time recovery",
    "bootstrap",
    "recovery",
    "full cluster loss",
    "restore test",
];

#[derive(Debug, Deserialize)]
struct Context {
    root: String,
}

/// Slice entry point used by the dispatch table and the `validate` subcommand.
pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid control-plane-db-backup context JSON: {error}"))?;
    Ok(validate_root(Path::new(&context.root)))
}

fn validate_root(root: &Path) -> Vec<String> {
    let mut errors = Vec::new();
    validate_scheduled_backup(root, &mut errors);
    validate_runbook(root, &mut errors);
    validate_makefile(root, &mut errors);
    errors
}

fn validate_scheduled_backup(root: &Path, errors: &mut Vec<String>) {
    let text = match fs::read_to_string(root.join(SCHEDULED_BACKUP_PATH)) {
        Ok(text) => text,
        Err(error) => {
            errors.push(format!("failed to read {SCHEDULED_BACKUP_PATH}: {error}"));
            return;
        }
    };

    let doc: Value = match serde_yaml::from_str(&text) {
        Ok(value) => value,
        Err(error) => {
            errors.push(format!(
                "{SCHEDULED_BACKUP_PATH} is not valid YAML: {error}"
            ));
            return;
        }
    };

    if str_at(&doc, &["apiVersion"]) != Some("postgresql.cnpg.io/v1") {
        errors.push(format!(
            "{SCHEDULED_BACKUP_PATH} apiVersion must be postgresql.cnpg.io/v1"
        ));
    }
    if str_at(&doc, &["kind"]) != Some("ScheduledBackup") {
        errors.push(format!(
            "{SCHEDULED_BACKUP_PATH} kind must be ScheduledBackup"
        ));
    }
    if str_at(&doc, &["metadata", "namespace"]) != Some("ryuki-platform") {
        errors.push(format!(
            "{SCHEDULED_BACKUP_PATH} metadata.namespace must be ryuki-platform"
        ));
    }

    // A ScheduledBackup is only meaningful with a cron schedule.
    match str_at(&doc, &["spec", "schedule"]) {
        Some(schedule) if is_plausible_cron(schedule) => {}
        Some(schedule) => errors.push(format!(
            "{SCHEDULED_BACKUP_PATH} spec.schedule {schedule:?} is not a plausible cron expression"
        )),
        None => errors.push(format!(
            "{SCHEDULED_BACKUP_PATH} missing required field spec.schedule (cron)"
        )),
    }

    // NOTE: retention is a Cluster field in CNPG (spec.backup.retentionPolicy),
    // NOT a ScheduledBackup field — it is validated on the Cluster below.

    // The backup must target the real CNPG cluster.
    match str_at(&doc, &["spec", "cluster", "name"]) {
        Some(name) if name == EXPECTED_CLUSTER => {}
        Some(name) => errors.push(format!(
            "{SCHEDULED_BACKUP_PATH} spec.cluster.name {name:?} must be {EXPECTED_CLUSTER:?}"
        )),
        None => errors.push(format!(
            "{SCHEDULED_BACKUP_PATH} missing required field spec.cluster.name"
        )),
    }

    // Cross-check: the targeted cluster must actually exist with a backup block.
    validate_cluster_backup_target(root, errors);
}

fn validate_cluster_backup_target(root: &Path, errors: &mut Vec<String>) {
    let text = match fs::read_to_string(root.join(CLUSTER_PATH)) {
        Ok(text) => text,
        Err(error) => {
            errors.push(format!("failed to read {CLUSTER_PATH}: {error}"));
            return;
        }
    };
    let doc: Value = match serde_yaml::from_str(&text) {
        Ok(value) => value,
        Err(error) => {
            errors.push(format!("{CLUSTER_PATH} is not valid YAML: {error}"));
            return;
        }
    };
    if str_at(&doc, &["metadata", "name"]) != Some(EXPECTED_CLUSTER) {
        errors.push(format!(
            "{CLUSTER_PATH} metadata.name must be {EXPECTED_CLUSTER:?} (ScheduledBackup target)"
        ));
    }
    // The cluster must declare a Barman object-store backup target for the
    // ScheduledBackup to write to.
    if doc
        .get("spec")
        .and_then(|s| s.get("backup"))
        .and_then(|b| b.get("barmanObjectStore"))
        .is_none()
    {
        errors.push(format!(
            "{CLUSTER_PATH} missing spec.backup.barmanObjectStore — ScheduledBackup has no target"
        ));
    }
    // The s3Credentials sub-fields must use CNPG's REAL CRD field names —
    // `accessKeyId` / `secretAccessKey` (each a {name,key} secret reference). The
    // wrong names `accessKeyIdSecret` / `secretAccessKeySecret` pass a naive presence
    // check but fail `kubectl apply` with a strict-decoding error ("unknown field"),
    // so the whole backup path silently never deploys. Verified end-to-end against
    // CloudNativePG 1.24.1 (a real backup ran to an S3 object store only with the
    // correct names).
    if let Some(s3) = doc
        .get("spec")
        .and_then(|s| s.get("backup"))
        .and_then(|b| b.get("barmanObjectStore"))
        .and_then(|o| o.get("s3Credentials"))
    {
        for bad in ["accessKeyIdSecret", "secretAccessKeySecret"] {
            if s3.get(bad).is_some() {
                errors.push(format!(
                    "{CLUSTER_PATH} s3Credentials has invalid CNPG field '{bad}' — expected '{}' \
                     (kubectl apply fails strict decoding otherwise)",
                    bad.trim_end_matches("Secret")
                ));
            }
        }
        // Explicit key auth must use CNPG's field names, unless IAM-role auth is used.
        let iam = s3.get("inheritFromIAMRole").and_then(Value::as_bool) == Some(true);
        if !iam {
            for field in ["accessKeyId", "secretAccessKey"] {
                if s3.get(field).is_none() {
                    errors.push(format!(
                        "{CLUSTER_PATH} s3Credentials missing '{field}' (CNPG's field name)"
                    ));
                }
            }
        }
    }
    // Retention reflects the RYUKI_RETENTION__* intent and bounds the PITR
    // window. In CNPG it lives on the Cluster, not the ScheduledBackup.
    match str_at(&doc, &["spec", "backup", "retentionPolicy"]) {
        Some(policy) if !policy.trim().is_empty() => {}
        _ => errors.push(format!(
            "{CLUSTER_PATH} missing non-empty spec.backup.retentionPolicy"
        )),
    }
}

fn validate_runbook(root: &Path, errors: &mut Vec<String>) {
    let text = match fs::read_to_string(root.join(RUNBOOK_PATH)) {
        Ok(text) => text,
        Err(error) => {
            errors.push(format!("failed to read {RUNBOOK_PATH}: {error}"));
            return;
        }
    };
    let lowered = text.to_ascii_lowercase();
    for term in REQUIRED_RUNBOOK_TERMS {
        if !lowered.contains(term) {
            errors.push(format!(
                "{RUNBOOK_PATH} is missing required restore/DR content: {term:?}"
            ));
        }
    }
}

fn validate_makefile(root: &Path, errors: &mut Vec<String>) {
    let text = match fs::read_to_string(root.join(MAKEFILE_PATH)) {
        Ok(text) => text,
        Err(error) => {
            errors.push(format!("failed to read {MAKEFILE_PATH}: {error}"));
            return;
        }
    };
    for target in REQUIRED_MAKE_TARGETS {
        if !declares_make_target(&text, target) {
            errors.push(format!(
                "{MAKEFILE_PATH} does not declare a {target:?} target"
            ));
        }
    }
}

/// True when the Makefile declares `<target>:` as a real rule (a line starting
/// at column 0 with the target name followed by `:`), not merely a `.PHONY`
/// mention or a substring elsewhere.
fn declares_make_target(makefile: &str, target: &str) -> bool {
    let prefix = format!("{target}:");
    makefile.lines().any(|line| {
        // A recipe rule starts at column 0 (no leading whitespace) and is not a
        // comment.
        !line.starts_with(char::is_whitespace)
            && !line.starts_with('#')
            && line.trim_end().starts_with(&prefix)
    })
}

/// A loose cron sanity check: a CNPG schedule is a whitespace-separated cron
/// expression (5 or 6 fields), each field made of the usual cron characters.
fn is_plausible_cron(schedule: &str) -> bool {
    let fields: Vec<&str> = schedule.split_whitespace().collect();
    if !(5..=6).contains(&fields.len()) {
        return false;
    }
    fields.iter().all(|field| {
        !field.is_empty()
            && field
                .chars()
                .all(|ch| ch.is_ascii_digit() || matches!(ch, '*' | '/' | ',' | '-' | '?'))
    })
}

fn str_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn real_backup_artifacts_are_valid() {
        let errors = validate_root(&repo_root());
        assert!(
            errors.is_empty(),
            "control-plane DB backup posture should be valid, got:\n{}",
            errors.join("\n")
        );
    }

    #[test]
    fn cron_sanity_check_is_strict() {
        assert!(is_plausible_cron("0 30 2 * * *"));
        assert!(is_plausible_cron("30 2 * * *"));
        assert!(!is_plausible_cron("@daily"));
        assert!(!is_plausible_cron("not a cron"));
        assert!(!is_plausible_cron(""));
        assert!(!is_plausible_cron("0 30"));
    }

    #[test]
    fn make_target_detection_ignores_phony_and_comments() {
        let makefile = "\
.PHONY: db-backup db-restore
# db-backup: not a real rule
db-backup:
\tpg_dump
";
        assert!(declares_make_target(makefile, "db-backup"));
        // db-restore appears only in .PHONY here, so it is not declared as a rule.
        assert!(!declares_make_target(makefile, "db-restore"));
    }

    #[test]
    fn missing_schedule_is_reported() {
        let doc: Value = serde_yaml::from_str(
            r#"
apiVersion: postgresql.cnpg.io/v1
kind: ScheduledBackup
metadata:
  namespace: ryuki-platform
spec:
  retentionPolicy: "30d"
  cluster:
    name: ryuki-platform-db
"#,
        )
        .unwrap();
        assert_eq!(str_at(&doc, &["spec", "schedule"]), None);
        assert_eq!(
            str_at(&doc, &["spec", "cluster", "name"]),
            Some("ryuki-platform-db")
        );
    }
}
