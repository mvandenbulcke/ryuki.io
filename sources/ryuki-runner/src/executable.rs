//! Approved top-level infrastructure executable boundary.
//!
//! Terraform and Ansible commands may receive provider credentials or run
//! with mutation authority. Production callers therefore cannot select those
//! CLIs through `PATH`: they must configure an absolute canonical path and an
//! expected tool version. The path is admitted only after filesystem
//! provenance checks, a bounded identity/version probe, and (when configured)
//! a SHA-256 comparison. Only an [`ApprovedExecutable`] can cross into the
//! credential-attaching runner implementations.

use std::{
    env,
    fs::{self, File, Metadata},
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

use ryuki_engine::runners::RunnerError;
use sha2::{Digest, Sha256};

use super::exec::{run_executable_identity_probe, CommandCancellation};

const PROBE_ENV_ALLOWLIST: &[&str] = &["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"];
const MAX_EXPECTED_VERSION_LEN: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ApprovedTool {
    Terraform,
    AnsiblePlaybook,
}

impl ApprovedTool {
    fn label(self) -> &'static str {
        match self {
            Self::Terraform => "terraform",
            Self::AnsiblePlaybook => "ansible-playbook",
        }
    }

    fn path_env(self) -> &'static str {
        match self {
            Self::Terraform => "RYUKI_TERRAFORM_EXECUTABLE",
            Self::AnsiblePlaybook => "RYUKI_ANSIBLE_PLAYBOOK_EXECUTABLE",
        }
    }

    fn version_env(self) -> &'static str {
        match self {
            Self::Terraform => "RYUKI_TERRAFORM_EXPECTED_VERSION",
            Self::AnsiblePlaybook => "RYUKI_ANSIBLE_PLAYBOOK_EXPECTED_VERSION",
        }
    }

    fn digest_env(self) -> &'static str {
        match self {
            Self::Terraform => "RYUKI_TERRAFORM_EXECUTABLE_SHA256",
            Self::AnsiblePlaybook => "RYUKI_ANSIBLE_PLAYBOOK_EXECUTABLE_SHA256",
        }
    }

    fn version_args(self) -> &'static [&'static str] {
        match self {
            Self::Terraform => &["version"],
            Self::AnsiblePlaybook => &["--version"],
        }
    }

    fn expected_identity_line(self, version: &str) -> String {
        match self {
            Self::Terraform => format!("Terraform v{version}"),
            Self::AnsiblePlaybook => format!("ansible-playbook [core {version}]"),
        }
    }
}

/// Capability proving that one configured top-level CLI passed local
/// provenance and identity validation before any credential-bearing command
/// was constructed.
#[derive(Clone, Debug)]
pub(crate) struct ApprovedExecutable {
    canonical_path: PathBuf,
}

/// Non-secret identity of an executable admitted by the existing provenance,
/// filesystem, optional-content-pin, and bounded version-probe policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovedExecutableProvenance {
    pub canonical_path: String,
    pub expected_version: String,
    pub expected_sha256: Option<String>,
}

impl ApprovedExecutable {
    pub(crate) fn configured(
        tool: ApprovedTool,
        cancellation: Option<&CommandCancellation>,
    ) -> Result<Self, RunnerError> {
        Self::configured_with_provenance(tool, cancellation).map(|(approved, _)| approved)
    }

    fn configured_with_provenance(
        tool: ApprovedTool,
        cancellation: Option<&CommandCancellation>,
    ) -> Result<(Self, ApprovedExecutableProvenance), RunnerError> {
        let path = required_environment(tool.path_env())?;
        let expected_version = required_environment(tool.version_env())?;
        let expected_digest = optional_environment(tool.digest_env())?;
        let approved = Self::validate(
            tool,
            Path::new(&path),
            &expected_version,
            expected_digest.as_deref(),
            cancellation,
        )?;
        let canonical_path = approved
            .canonical_path
            .to_str()
            .ok_or_else(|| {
                approval_error("canonical executable path is not valid UTF-8".to_string())
            })?
            .to_string();
        Ok((
            approved,
            ApprovedExecutableProvenance {
                canonical_path,
                expected_version,
                expected_sha256: validate_expected_digest(expected_digest.as_deref())?,
            },
        ))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.canonical_path
    }

    fn validate(
        tool: ApprovedTool,
        configured_path: &Path,
        expected_version: &str,
        expected_digest: Option<&str>,
        cancellation: Option<&CommandCancellation>,
    ) -> Result<Self, RunnerError> {
        validate_expected_version(expected_version)?;
        let expected_digest = validate_expected_digest(expected_digest)?;
        let (canonical_path, before) = validate_filesystem_path(configured_path)?;

        if let Some(expected_digest) = expected_digest.as_deref() {
            let actual_digest = sha256_file(&canonical_path)?;
            if actual_digest != expected_digest {
                return Err(approval_error(format!(
                    "{} executable digest does not match {}",
                    tool.label(),
                    tool.digest_env()
                )));
            }
        }

        let mut command = Command::new(&canonical_path);
        apply_probe_environment(&mut command);
        command.args(tool.version_args());
        let output = run_executable_identity_probe(command, cancellation)?;
        if !output.status.success() {
            return Err(approval_error(format!(
                "{} executable identity probe exited non-zero",
                tool.label()
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let identity_line = stdout.lines().find(|line| !line.trim().is_empty());
        let expected_line = tool.expected_identity_line(expected_version);
        if identity_line != Some(expected_line.as_str()) {
            return Err(approval_error(format!(
                "configured executable did not identify as {} version {}",
                tool.label(),
                expected_version
            )));
        }

        // Detect ordinary replacement during digest/probe admission. The safe
        // parent-chain requirement limits replacement to the trusted owner,
        // but a stable before/after identity also prevents accidental upgrades
        // from being admitted halfway through validation.
        let (canonical_after, after) = validate_filesystem_path(configured_path)?;
        if canonical_after != canonical_path || after != before {
            return Err(approval_error(format!(
                "{} executable changed while its identity was being validated",
                tool.label()
            )));
        }

        Ok(Self { canonical_path })
    }

    /// Existing command-behavior tests use deterministic shims rather than an
    /// installed infrastructure tool. This constructor is absent from normal
    /// builds, so production credential paths cannot bypass admission.
    #[cfg(test)]
    pub(crate) fn for_test(binary: impl Into<PathBuf>) -> Self {
        Self {
            canonical_path: binary.into(),
        }
    }
}

/// Re-run the exact Terraform executable approval policy and return only its
/// non-secret identity for execution-trust binding. This performs no provider
/// or backend contact.
pub fn approved_terraform_executable_provenance(
) -> Result<ApprovedExecutableProvenance, RunnerError> {
    ApprovedExecutable::configured_with_provenance(ApprovedTool::Terraform, None)
        .map(|(_, provenance)| provenance)
}

fn required_environment(key: &'static str) -> Result<String, RunnerError> {
    match env::var(key) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        Ok(_) | Err(env::VarError::NotPresent) => Err(approval_error(format!(
            "required configuration {key} is missing or empty"
        ))),
        Err(env::VarError::NotUnicode(_)) => Err(approval_error(format!(
            "required configuration {key} is not valid UTF-8"
        ))),
    }
}

fn optional_environment(key: &'static str) -> Result<Option<String>, RunnerError> {
    match env::var(key) {
        Ok(value) if value.trim().is_empty() => Ok(None),
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(approval_error(format!(
            "optional configuration {key} is not valid UTF-8"
        ))),
    }
}

fn validate_expected_version(version: &str) -> Result<(), RunnerError> {
    if version.is_empty()
        || version.len() > MAX_EXPECTED_VERSION_LEN
        || version.trim() != version
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_'))
    {
        return Err(approval_error(
            "expected executable version must be a short, unadorned version token".to_string(),
        ));
    }
    Ok(())
}

fn validate_expected_digest(digest: Option<&str>) -> Result<Option<String>, RunnerError> {
    let Some(digest) = digest else {
        return Ok(None);
    };
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(approval_error(
            "configured executable SHA-256 must contain exactly 64 hexadecimal characters"
                .to_string(),
        ));
    }
    Ok(Some(digest.to_ascii_lowercase()))
}

fn validate_filesystem_path(
    configured_path: &Path,
) -> Result<(PathBuf, FileFingerprint), RunnerError> {
    if !configured_path.is_absolute() {
        return Err(approval_error(format!(
            "executable path must be absolute, not {:?}",
            configured_path
        )));
    }

    let link_metadata = fs::symlink_metadata(configured_path).map_err(|error| {
        approval_error(format!(
            "cannot inspect configured executable {:?}: {error}",
            configured_path
        ))
    })?;
    if link_metadata.file_type().is_symlink() {
        return Err(approval_error(format!(
            "configured executable {:?} must not be a symlink",
            configured_path
        )));
    }
    if !link_metadata.is_file() {
        return Err(approval_error(format!(
            "configured executable {:?} is not a regular file",
            configured_path
        )));
    }

    let canonical_path = fs::canonicalize(configured_path).map_err(|error| {
        approval_error(format!(
            "cannot canonicalize configured executable {:?}: {error}",
            configured_path
        ))
    })?;
    if canonical_path.as_path() != configured_path {
        return Err(approval_error(format!(
            "executable path must already be canonical (configured {:?}, canonical {:?})",
            configured_path, canonical_path
        )));
    }

    validate_unix_provenance(&canonical_path, &link_metadata)?;
    Ok((
        canonical_path,
        FileFingerprint::from_metadata(&link_metadata),
    ))
}

#[cfg(unix)]
fn validate_unix_provenance(path: &Path, metadata: &Metadata) -> Result<(), RunnerError> {
    use std::os::unix::fs::MetadataExt;

    // SAFETY: geteuid has no preconditions and does not dereference memory.
    let effective_uid = unsafe { libc::geteuid() };
    validate_unix_owner(path, metadata.uid(), effective_uid, "executable")?;

    let file_mode = metadata.mode() & 0o7777;
    if file_mode & 0o111 == 0 {
        return Err(approval_error(format!(
            "configured executable {:?} has no execute bit",
            path
        )));
    }
    if file_mode & 0o022 != 0 {
        return Err(approval_error(format!(
            "configured executable {:?} is writable by group or others",
            path
        )));
    }

    let mut parent = path.parent();
    while let Some(directory) = parent {
        let directory_metadata = fs::symlink_metadata(directory).map_err(|error| {
            approval_error(format!(
                "cannot inspect executable parent {:?}: {error}",
                directory
            ))
        })?;
        if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
            return Err(approval_error(format!(
                "executable parent {:?} must be a real directory",
                directory
            )));
        }
        validate_unix_owner(
            directory,
            directory_metadata.uid(),
            effective_uid,
            "parent directory",
        )?;

        let directory_mode = directory_metadata.mode() & 0o7777;
        let root_owned_sticky = directory_metadata.uid() == 0 && directory_mode & 0o1000 != 0;
        if directory_mode & 0o022 != 0 && !root_owned_sticky {
            return Err(approval_error(format!(
                "executable parent {:?} is writable by group or others",
                directory
            )));
        }
        parent = directory.parent();
    }
    Ok(())
}

#[cfg(unix)]
fn validate_unix_owner(
    path: &Path,
    owner_uid: u32,
    effective_uid: u32,
    kind: &str,
) -> Result<(), RunnerError> {
    if owner_uid != 0 && owner_uid != effective_uid {
        return Err(approval_error(format!(
            "{kind} {:?} is owned by untrusted uid {owner_uid}",
            path
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_unix_provenance(_path: &Path, _metadata: &Metadata) -> Result<(), RunnerError> {
    Ok(())
}

fn apply_probe_environment(command: &mut Command) {
    command.env_clear();
    for key in PROBE_ENV_ALLOWLIST {
        if let Ok(value) = env::var(key) {
            command.env(key, value);
        }
    }
}

fn sha256_file(path: &Path) -> Result<String, RunnerError> {
    use std::fmt::Write as _;

    let mut file = File::open(path).map_err(|error| {
        approval_error(format!(
            "cannot open executable {:?} for hashing: {error}",
            path
        ))
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            approval_error(format!("cannot hash executable {:?}: {error}", path))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(encoded)
}

#[derive(Debug, PartialEq, Eq)]
struct FileFingerprint {
    len: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    gid: u32,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(not(unix))]
    modified: Option<std::time::SystemTime>,
}

impl FileFingerprint {
    fn from_metadata(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self {
                len: metadata.len(),
                device: metadata.dev(),
                inode: metadata.ino(),
                mode: metadata.mode(),
                uid: metadata.uid(),
                gid: metadata.gid(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                len: metadata.len(),
                modified: metadata.modified().ok(),
            }
        }
    }
}

fn approval_error(detail: String) -> RunnerError {
    RunnerError::Spawn(format!("executable approval failed: {detail}"))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    const TERRAFORM_VERSION: &str = "1.9.8";

    fn write_tool(directory: &Path, name: &str, identity_line: &str) -> PathBuf {
        let path = directory.join(name);
        fs::write(
            &path,
            format!(
                "#!/bin/sh\ncase \"$1\" in version|--version) printf '%s\\n' '{}'; exit 0 ;; esac\nexit 0\n",
                identity_line
            ),
        )
        .expect("write executable fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .expect("chmod executable fixture");
        fs::canonicalize(path).expect("canonical fixture path")
    }

    #[test]
    fn approves_canonical_regular_owned_tool_with_expected_identity() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = write_tool(directory.path(), "terraform-approved", "Terraform v1.9.8");

        let approved = ApprovedExecutable::validate(
            ApprovedTool::Terraform,
            &path,
            TERRAFORM_VERSION,
            None,
            None,
        )
        .expect("valid executable must be approved");
        assert_eq!(approved.path(), path);
    }

    #[test]
    fn approves_ansible_core_identity_through_the_same_boundary() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = write_tool(
            directory.path(),
            "ansible-playbook-approved",
            "ansible-playbook [core 2.18.1]",
        );

        let approved = ApprovedExecutable::validate(
            ApprovedTool::AnsiblePlaybook,
            &path,
            "2.18.1",
            None,
            None,
        )
        .expect("valid Ansible executable must be approved");
        assert_eq!(approved.path(), path);
    }

    #[test]
    fn rejects_bare_and_relative_executable_paths() {
        for path in [Path::new("terraform"), Path::new("bin/terraform")] {
            let error = ApprovedExecutable::validate(
                ApprovedTool::Terraform,
                path,
                TERRAFORM_VERSION,
                None,
                None,
            )
            .expect_err("PATH-selected and relative tools must be rejected");
            assert!(error.to_string().contains("absolute"));
        }
    }

    #[test]
    fn rejects_symlinked_executable() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target = write_tool(directory.path(), "terraform-target", "Terraform v1.9.8");
        let link = target
            .parent()
            .expect("fixture parent")
            .join("terraform-link");
        symlink(&target, &link).expect("create symlink fixture");

        let error = ApprovedExecutable::validate(
            ApprovedTool::Terraform,
            &link,
            TERRAFORM_VERSION,
            None,
            None,
        )
        .expect_err("symlinked executable must be rejected");
        assert!(error.to_string().contains("symlink"));
    }

    #[test]
    fn rejects_symlinked_parent_component() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let real_parent = directory.path().join("real-parent");
        fs::create_dir(&real_parent).expect("create real parent");
        let target = write_tool(&real_parent, "terraform", "Terraform v1.9.8");
        let linked_parent = directory.path().join("linked-parent");
        symlink(&real_parent, &linked_parent).expect("create parent symlink fixture");
        let configured = linked_parent.join(target.file_name().expect("fixture filename"));

        let error = ApprovedExecutable::validate(
            ApprovedTool::Terraform,
            &configured,
            TERRAFORM_VERSION,
            None,
            None,
        )
        .expect_err("symlinked parent component must be rejected");
        assert!(error.to_string().contains("canonical"));
    }

    #[test]
    fn rejects_non_regular_executable_path() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let configured = fs::canonicalize(directory.path()).expect("canonical fixture path");

        let error = ApprovedExecutable::validate(
            ApprovedTool::Terraform,
            &configured,
            TERRAFORM_VERSION,
            None,
            None,
        )
        .expect_err("directory must not be admitted as an executable");
        assert!(error.to_string().contains("regular file"));
    }

    #[test]
    fn rejects_group_or_other_writable_executable() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = write_tool(directory.path(), "terraform-writable", "Terraform v1.9.8");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).expect("make fixture unsafe");

        let error = ApprovedExecutable::validate(
            ApprovedTool::Terraform,
            &path,
            TERRAFORM_VERSION,
            None,
            None,
        )
        .expect_err("writable executable must be rejected");
        assert!(error.to_string().contains("writable"));
    }

    #[test]
    fn rejects_writable_parent_chain() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let unsafe_parent = fs::canonicalize(directory.path())
            .expect("canonical tempdir")
            .join("unsafe-parent");
        fs::create_dir(&unsafe_parent).expect("create unsafe parent");
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777))
            .expect("make parent unsafe");
        let path = write_tool(&unsafe_parent, "terraform", "Terraform v1.9.8");

        let error = ApprovedExecutable::validate(
            ApprovedTool::Terraform,
            &path,
            TERRAFORM_VERSION,
            None,
            None,
        )
        .expect_err("writable parent must be rejected");
        assert!(error.to_string().contains("parent"));
        assert!(error.to_string().contains("writable"));
    }

    #[test]
    fn rejects_wrong_tool_identity_or_version() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = write_tool(
            directory.path(),
            "not-terraform",
            "ansible-playbook [core 1.9.8]",
        );

        let error = ApprovedExecutable::validate(
            ApprovedTool::Terraform,
            &path,
            TERRAFORM_VERSION,
            None,
            None,
        )
        .expect_err("wrong identity must be rejected");
        assert!(error.to_string().contains("did not identify as terraform"));
    }

    #[test]
    fn optional_digest_is_enforced_when_configured() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = write_tool(directory.path(), "terraform-digest", "Terraform v1.9.8");
        let digest = sha256_file(&path).expect("fixture digest");
        ApprovedExecutable::validate(
            ApprovedTool::Terraform,
            &path,
            TERRAFORM_VERSION,
            Some(&digest),
            None,
        )
        .expect("matching digest must be accepted");

        let error = ApprovedExecutable::validate(
            ApprovedTool::Terraform,
            &path,
            TERRAFORM_VERSION,
            Some(&"0".repeat(64)),
            None,
        )
        .expect_err("mismatched digest must be rejected");
        assert!(error.to_string().contains("digest"));
    }
}
