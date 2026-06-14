//! Per-run isolated workspace management (RAII).
//!
//! Each runner invocation gets its own `TempDir` (0700) that is automatically
//! removed on drop — including on panic. No secrets persist after the run.

use ryuki_engine::runners::RunnerError;
use std::path::{Path, PathBuf};

/// An isolated workspace for one runner invocation.
///
/// The inner `TempDir` is removed on drop. All files written here are scoped
/// to this workspace; no cross-run state is possible.
pub struct Workspace {
    dir: tempfile::TempDir,
}

impl Workspace {
    /// Create a new isolated workspace directory (mode 0700 on Unix).
    pub fn new() -> Result<Self, RunnerError> {
        let dir = tempfile::Builder::new()
            .prefix("ryuki-runner-")
            .tempdir()
            .map_err(|e| RunnerError::WorkspaceSetup(e.to_string()))?;

        // Restrict permissions to owner-only on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(dir.path(), perms)
                .map_err(|e| RunnerError::WorkspaceSetup(e.to_string()))?;
        }

        Ok(Self { dir })
    }

    /// Returns the path to the workspace directory.
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Write a file into the workspace with mode 0600 (owner read/write only).
    ///
    /// # Arguments
    /// * `name` — filename within the workspace (no path separators).
    /// * `content` — byte content to write.
    ///
    /// # Security
    /// 0600 permissions ensure that only the process owner can read the file.
    /// Secret files (vars, credential files) MUST use this method.
    pub fn write_file_0600(&self, name: &str, content: &[u8]) -> Result<PathBuf, RunnerError> {
        let path = self.dir.path().join(name);
        std::fs::write(&path, content)
            .map_err(|e| RunnerError::WorkspaceSetup(format!("write {name}: {e}")))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&path, perms)
                .map_err(|e| RunnerError::WorkspaceSetup(format!("chmod {name}: {e}")))?;
        }

        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_creates_temp_dir() {
        let ws = Workspace::new().expect("workspace creation must succeed");
        assert!(ws.path().exists(), "workspace directory must exist");
        assert!(ws.path().is_dir(), "workspace path must be a directory");
    }

    #[test]
    fn workspace_removed_on_drop() {
        let path = {
            let ws = Workspace::new().expect("workspace creation");
            ws.path().to_path_buf()
        };
        // After drop, the directory must not exist.
        assert!(
            !path.exists(),
            "workspace directory must be removed after drop"
        );
    }

    #[test]
    fn write_file_0600_creates_readable_file() {
        let ws = Workspace::new().expect("workspace creation");
        let content = b"vars = { region = \"eu-west\" }";
        let path = ws
            .write_file_0600("terraform.tfvars.json", content)
            .expect("write must succeed");

        assert!(path.exists(), "file must exist");
        let read_back = std::fs::read(&path).expect("must be readable");
        assert_eq!(read_back, content);
    }

    #[cfg(unix)]
    #[test]
    fn write_file_0600_has_correct_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let ws = Workspace::new().expect("workspace creation");
        ws.write_file_0600("secret.json", b"{}").expect("write");
        let path = ws.path().join("secret.json");
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        // Only owner read+write (0o600). Mask to lower 9 bits.
        assert_eq!(mode & 0o777, 0o600, "file permissions must be 0600");
    }
}
