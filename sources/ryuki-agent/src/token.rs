//! Agent bearer-token resolution and on-disk persistence (S5 self-registration).
//!
//! ## Token resolution precedence (fail-closed)
//!
//! 1. `RYUKI_AGENT_TOKEN` env var — always wins when set (pre-S5 behavior,
//!    byte-compatible: same `rya_` prefix validation in `config.rs`).
//! 2. Token file at `token_path` (`RYUKI_AGENT_TOKEN_PATH`, default
//!    `agent.token` next to the key file) — written once by first-boot
//!    self-registration, or placed there by an operator. On Unix every path
//!    component is opened without following links, and the final object must be
//!    a regular file owned by the effective service UID with no group/other
//!    permission bits.
//! 3. First-boot self-registration — only when neither source has a token AND
//!    `RYUKI_AGENT_SELF_REGISTER=true`. The caller performs the network call;
//!    this module only persists and validates.
//! 4. Otherwise: a fatal error naming all three options.
//!
//! A token file that EXISTS but is malformed is a hard error — resolution never
//! falls through to self-registration in that case, because re-registering
//! would consume a new `agent_id` slot (or 409-conflict on the existing one)
//! while a possibly-recoverable token sits on disk. The operator must fix or
//! deliberately remove the file.
//!
//! ## Persistence format
//!
//! The plaintext token (`rya_` + 64 hex chars) plus a single trailing newline,
//! mode **0600**, `create_new` — the exact discipline of `identity.rs`: the
//! file is created 0600 atomically in a single `open` (no permission window)
//! and an existing file is NEVER overwritten. The CP stores only the token's
//! hash and returns the plaintext exactly once, so silently clobbering this
//! file would permanently destroy the credential.

use std::fs::File;
use std::path::Path;

use thiserror::Error;

use crate::client::RegisterResponse;
use crate::config::AgentConfig;

/// Agent tokens issued by the CP carry this prefix (`ryuki-api/src/agents.rs`
/// `AGENT_TOKEN_PREFIX`). Both the env var and the token file are validated
/// against it so a misconfigured credential fails at startup, not as a 401 on
/// every request.
pub const TOKEN_PREFIX: &str = "rya_";

/// Bound an operator-supplied file before allocating. Issued agent tokens are
/// under 100 bytes; 4 KiB leaves ample compatibility room while preventing a
/// special or accidentally huge file from consuming unbounded memory.
const MAX_TOKEN_FILE_BYTES: usize = 4 * 1024;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("I/O error for token file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// `save_token_file` is create-only; an existing file is never clobbered.
    #[error(
        "token file {path} already exists — refusing to overwrite. \
         Remove it deliberately if this agent must re-enroll"
    )]
    AlreadyExists { path: String },
    /// The token (from file or registration response) has the wrong shape.
    /// The reason NEVER embeds the token value itself.
    #[error("invalid token in {origin}: {reason}")]
    Malformed { origin: String, reason: String },
    /// The file exists but does not meet the local credential boundary.
    /// Reasons describe metadata only and never include file contents.
    #[error("unsafe token file {path}: {reason}")]
    UnsafeFile { path: String, reason: &'static str },
    /// std does not expose enough opened-handle security information on this
    /// platform to make a safe claim about an existing plaintext bearer.
    #[error(
        "secure token-file {operation} for {path} is unsupported on this platform; use RYUKI_AGENT_TOKEN or install a platform-specific owner/DACL/reparse-point adapter"
    )]
    UnsupportedPlatform {
        path: String,
        operation: &'static str,
    },
    /// No token from any source and self-registration is disabled.
    #[error(
        "no agent token available: set RYUKI_AGENT_TOKEN, provide a token file at \
         {token_path}, or set RYUKI_AGENT_SELF_REGISTER=true for first-boot \
         self-registration"
    )]
    NoToken { token_path: String },
}

// ---------------------------------------------------------------------------
// Token shape validation (shared by file load + registration response)
// ---------------------------------------------------------------------------

/// Validate the shape of a plaintext agent token. Returns a reason string on
/// failure; the reason never contains the token value.
fn check_token_shape(token: &str) -> Result<(), String> {
    if token.is_empty() {
        return Err("token is empty".to_owned());
    }
    if !token.starts_with(TOKEN_PREFIX) {
        return Err(format!("token must start with '{TOKEN_PREFIX}'"));
    }
    // A truncated write, editor artifact, or concatenated file shows up as
    // embedded whitespace / control characters — reject rather than send a
    // garbled credential on every request.
    if token.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("token must be a single line with no embedded whitespace".to_owned());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Token file persistence
// ---------------------------------------------------------------------------

/// Persist the plaintext token to a NEW file at `path`, mode **0600**.
///
/// Create-only (`create_new`), mirroring [`crate::identity::AgentIdentity::save`]:
/// on Unix the parent ancestry is walked through pinned directory handles and
/// the file is created 0600 atomically with `openat`, so no path component can
/// redirect the write through a symlink and the credential is never
/// momentarily world-readable. An existing file is refused with
/// [`TokenError::AlreadyExists`] — the CP returns the plaintext token exactly
/// once, so an overwrite would irrecoverably destroy it.
///
/// A single trailing newline is appended for operator friendliness (`cat`);
/// [`load_token_file`] trims it back off.
pub fn save_token_file(path: &Path, token: &str) -> Result<(), TokenError> {
    #[cfg(unix)]
    let path_str = path.display().to_string();

    // Never persist a token we would refuse to load back.
    check_token_shape(token).map_err(|reason| TokenError::Malformed {
        origin: "registration response".to_owned(),
        reason,
    })?;
    if token.len().saturating_add(1) > MAX_TOKEN_FILE_BYTES {
        return Err(TokenError::Malformed {
            origin: "registration response".to_owned(),
            reason: format!("token exceeds the {MAX_TOKEN_FILE_BYTES}-byte file limit"),
        });
    }

    #[cfg(not(unix))]
    {
        return Err(TokenError::UnsupportedPlatform {
            path: path.display().to_string(),
            operation: "persistence",
        });
    }

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let mut file = create_new_token_file(path, &path_str)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|source| TokenError::Io {
                path: path_str.clone(),
                source,
            })?;
        // Validate the just-created descriptor before copying the one-time
        // bearer into it. This catches filesystems that do not honor the
        // requested owner/mode semantics.
        // SAFETY: geteuid takes no pointers and has no preconditions.
        let effective_uid = unsafe { libc::geteuid() };
        validate_open_token_file(&file, &path_str, effective_uid)?;
        file.write_all(format!("{token}\n").as_bytes())
            .map_err(|e| TokenError::Io {
                path: path_str,
                source: e,
            })?;

        Ok(())
    }
}

/// Load a previously-persisted token from `path`.
///
/// On Unix the path is resolved through pinned directory descriptors, rejecting
/// links and `..` at every component. The final object is opened once with
/// `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`, then metadata from that exact
/// descriptor must prove it is a regular file owned by the effective UID with
/// no group/other permission bits. The bounded UTF-8 read is performed from the
/// same descriptor, so a rename or path replacement after open cannot redirect
/// the credential read.
///
/// Trailing whitespace (the newline `save_token_file` appends, or one added by
/// an operator's `echo`) is trimmed; anything else malformed is a hard error —
/// a bad token file must stop startup, never degrade into per-request 401s.
pub fn load_token_file(path: &Path) -> Result<String, TokenError> {
    let path_str = path.display().to_string();
    let file = open_validated_token_file(path, &path_str)?;
    load_token_from_open_file(file, &path_str)
}

#[cfg(unix)]
fn open_validated_token_file(path: &Path, path_str: &str) -> Result<File, TokenError> {
    let (parent, final_name) = open_token_parent(path, path_str)?;
    let file = open_file_at(
        &parent,
        &final_name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        None,
    )
    .map_err(|source| {
        if source.raw_os_error() == Some(libc::ELOOP) {
            TokenError::UnsafeFile {
                path: path_str.to_owned(),
                reason: "symbolic links are not allowed",
            }
        } else {
            TokenError::Io {
                path: path_str.to_owned(),
                source,
            }
        }
    })?;

    // SAFETY: geteuid takes no pointers and has no preconditions.
    let effective_uid = unsafe { libc::geteuid() };
    validate_open_token_file(&file, path_str, effective_uid)?;

    Ok(file)
}

/// Resolve a token path beneath a pinned root/cwd handle. Every parent is
/// opened relative to the previous descriptor with `O_NOFOLLOW | O_DIRECTORY`,
/// so a linked or concurrently replaced ancestor cannot redirect the final
/// read/write. Relative `..` is rejected instead of escaping the cwd anchor.
#[cfg(unix)]
fn open_token_parent(path: &Path, path_str: &str) -> Result<(File, std::ffi::CString), TokenError> {
    use std::path::Component;

    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => names.push(name.to_owned()),
            Component::ParentDir => {
                return Err(TokenError::UnsafeFile {
                    path: path_str.to_owned(),
                    reason: "parent-directory ('..') components are not allowed",
                });
            }
            Component::Prefix(_) => {
                return Err(TokenError::UnsafeFile {
                    path: path_str.to_owned(),
                    reason: "unsupported token-file path prefix",
                });
            }
        }
    }

    let final_name = names.pop().ok_or_else(|| TokenError::UnsafeFile {
        path: path_str.to_owned(),
        reason: "path must name a token file",
    })?;
    let final_name = unix_component(&final_name, path_str)?;

    let anchor = if path.is_absolute() { "/" } else { "." };
    let mut parent = open_directory(anchor, path_str)?;
    for name in names {
        let name = unix_component(&name, path_str)?;
        parent = open_file_at(
            &parent,
            &name,
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC,
            None,
        )
        .map_err(|source| {
            if matches!(
                source.raw_os_error(),
                Some(libc::ELOOP) | Some(libc::ENOTDIR)
            ) {
                TokenError::UnsafeFile {
                    path: path_str.to_owned(),
                    reason: "parent path components must be real directories, not symbolic links",
                }
            } else {
                TokenError::Io {
                    path: path_str.to_owned(),
                    source,
                }
            }
        })?;
    }

    Ok((parent, final_name))
}

#[cfg(unix)]
fn create_new_token_file(path: &Path, path_str: &str) -> Result<File, TokenError> {
    let (parent, final_name) = open_token_parent(path, path_str)?;
    open_file_at(
        &parent,
        &final_name,
        libc::O_WRONLY
            | libc::O_CREAT
            | libc::O_EXCL
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | libc::O_CLOEXEC,
        Some(0o600),
    )
    .map_err(|source| {
        if source.kind() == std::io::ErrorKind::AlreadyExists {
            TokenError::AlreadyExists {
                path: path_str.to_owned(),
            }
        } else if source.raw_os_error() == Some(libc::ELOOP) {
            TokenError::UnsafeFile {
                path: path_str.to_owned(),
                reason: "symbolic links are not allowed",
            }
        } else {
            TokenError::Io {
                path: path_str.to_owned(),
                source,
            }
        }
    })
}

#[cfg(unix)]
fn open_directory(anchor: &str, path_str: &str) -> Result<File, TokenError> {
    let anchor = std::ffi::CString::new(anchor).expect("static anchor contains no NUL");
    // SAFETY: anchor is NUL-terminated, flags require no variadic mode, and a
    // successful descriptor is immediately owned by File.
    let descriptor = unsafe {
        libc::open(
            anchor.as_ptr(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC,
        )
    };
    file_from_descriptor(descriptor).map_err(|source| TokenError::Io {
        path: path_str.to_owned(),
        source,
    })
}

#[cfg(unix)]
fn open_file_at(
    parent: &File,
    name: &std::ffi::CStr,
    flags: libc::c_int,
    mode: Option<libc::mode_t>,
) -> std::io::Result<File> {
    use std::os::unix::io::AsRawFd;

    // SAFETY: name is NUL-terminated, parent remains open for the call, and a
    // mode is supplied exactly when O_CREAT is present.
    let descriptor = unsafe {
        match mode {
            Some(mode) => libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                flags,
                mode as libc::c_uint,
            ),
            None => libc::openat(parent.as_raw_fd(), name.as_ptr(), flags),
        }
    };
    file_from_descriptor(descriptor)
}

#[cfg(unix)]
fn file_from_descriptor(descriptor: libc::c_int) -> std::io::Result<File> {
    use std::os::unix::io::FromRawFd;

    if descriptor < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: open/openat returned a new owned descriptor on success.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

#[cfg(unix)]
fn unix_component(
    component: &std::ffi::OsStr,
    path_str: &str,
) -> Result<std::ffi::CString, TokenError> {
    use std::os::unix::ffi::OsStrExt;

    std::ffi::CString::new(component.as_bytes()).map_err(|_| TokenError::Io {
        path: path_str.to_owned(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "token-file path contains a NUL byte",
        ),
    })
}

#[cfg(unix)]
fn validate_open_token_file(
    file: &File,
    path_str: &str,
    effective_uid: u32,
) -> Result<(), TokenError> {
    use std::os::unix::fs::MetadataExt;

    // File::metadata is fstat on the already-open descriptor. Never replace
    // this with path metadata followed by a second open: that reintroduces the
    // link/swap race this boundary closes.
    let metadata = file.metadata().map_err(|source| TokenError::Io {
        path: path_str.to_owned(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(TokenError::UnsafeFile {
            path: path_str.to_owned(),
            reason: "must be a regular file",
        });
    }
    if metadata.uid() != effective_uid {
        return Err(TokenError::UnsafeFile {
            path: path_str.to_owned(),
            reason: "must be owned by the effective service user",
        });
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(TokenError::UnsafeFile {
            path: path_str.to_owned(),
            reason: "must not grant any permissions to group or other users",
        });
    }

    Ok(())
}

#[cfg(not(unix))]
fn open_validated_token_file(path: &Path, path_str: &str) -> Result<File, TokenError> {
    // Preserve NotFound as absence so first-boot selection remains possible,
    // but never read an existing plaintext credential without an equivalent
    // opened-handle owner/DACL/reparse-point implementation.
    match std::fs::symlink_metadata(path) {
        Err(source) => Err(TokenError::Io {
            path: path_str.to_owned(),
            source,
        }),
        Ok(_) => Err(TokenError::UnsupportedPlatform {
            path: path_str.to_owned(),
            operation: "loading",
        }),
    }
}

fn load_token_from_open_file(file: File, path_str: &str) -> Result<String, TokenError> {
    use std::io::Read;

    let mut raw = String::new();
    file.take((MAX_TOKEN_FILE_BYTES + 1) as u64)
        .read_to_string(&mut raw)
        .map_err(|source| TokenError::Io {
            path: path_str.to_owned(),
            source,
        })?;
    if raw.len() > MAX_TOKEN_FILE_BYTES {
        return Err(TokenError::Malformed {
            origin: format!("token file {path_str}"),
            reason: format!("file exceeds the {MAX_TOKEN_FILE_BYTES}-byte limit"),
        });
    }
    // Only the trailing newline (ours or an operator echo's CRLF) is
    // tolerated; any other whitespace means the file was mangled and startup
    // must stop rather than normalize it.
    let token = raw.strip_suffix('\n').unwrap_or(&raw);
    let token = token.strip_suffix('\r').unwrap_or(token);
    check_token_shape(token).map_err(|reason| TokenError::Malformed {
        origin: format!("token file {path_str}"),
        reason,
    })?;
    Ok(token.to_owned())
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// Outcome of token resolution — where the token came from, or that first-boot
/// self-registration should run.
#[derive(Debug)]
pub enum ResolvedToken {
    /// `RYUKI_AGENT_TOKEN` was set (highest precedence; pre-S5 path).
    FromEnv(String),
    /// Loaded from the token file at `AgentConfig::token_path`.
    FromFile(String),
    /// No token anywhere and `RYUKI_AGENT_SELF_REGISTER=true` — the caller
    /// should register with the CP and persist the returned token.
    SelfRegister,
}

/// Resolve the agent bearer token per the module-level precedence.
///
/// Fail-closed: a malformed token file is an error (never a silent fall-through
/// to re-registration), and with no token from any source and self-registration
/// disabled, the error names every remedy.
pub fn resolve_token(cfg: &AgentConfig) -> Result<ResolvedToken, TokenError> {
    // 1. Env var wins unconditionally — existing deployments keep their exact
    //    behavior even when a token file also exists.
    if let Some(token) = &cfg.token {
        return Ok(ResolvedToken::FromEnv(token.clone()));
    }

    // 2. Token file. Attempt the load and treat ONLY NotFound as absence:
    //    Path::exists() collapses permission and I/O errors to false, which
    //    would silently route an inaccessible token file into re-registration.
    match load_token_file(&cfg.token_path) {
        Ok(token) => return Ok(ResolvedToken::FromFile(token)),
        Err(TokenError::Io { ref source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
        }
        Err(other) => return Err(other),
    }

    // 3. First-boot self-registration, only when explicitly opted in.
    if cfg.self_register {
        #[cfg(unix)]
        {
            return Ok(ResolvedToken::SelfRegister);
        }
        #[cfg(not(unix))]
        {
            // Do not consume a one-time enrollment token when this platform
            // cannot persist it under a verified owner/DACL/reparse policy.
            return Err(TokenError::UnsupportedPlatform {
                path: cfg.token_path.display().to_string(),
                operation: "self-registration token persistence",
            });
        }
    }

    Err(TokenError::NoToken {
        token_path: cfg.token_path.display().to_string(),
    })
}

// ---------------------------------------------------------------------------
// Registration-response validation
// ---------------------------------------------------------------------------

/// Validate the CP's registration response before persisting anything.
///
/// Fail-closed: a response for a different `agent_id`, or a token that fails
/// the shape check, is fatal — persisting a garbled credential would only
/// surface later as 403s on every poll.
pub fn validate_register_response(
    resp: &RegisterResponse,
    expected_agent_id: &str,
) -> Result<(), TokenError> {
    if resp.agent_id != expected_agent_id {
        // Deliberately omit the RETURNED agent_id value: a buggy or hostile
        // response could carry the one-time token in that field, and this
        // error string ends up in operator logs.
        return Err(TokenError::Malformed {
            origin: "registration response".to_owned(),
            reason: format!(
                "control plane answered for a different agent_id than the \
                 registered '{expected_agent_id}'"
            ),
        });
    }
    check_token_shape(&resp.token).map_err(|reason| TokenError::Malformed {
        origin: "registration response".to_owned(),
        reason,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use tempfile::TempDir;

    const TOK: &str = "rya_0123456789abcdef";

    /// macOS exposes its temporary directory through the root-owned `/var`
    /// compatibility symlink. Canonicalise that trusted test harness prefix so
    /// tests exercise agent-controlled path components rather than a platform
    /// alias above the state directory.
    fn temp_path(dir: &TempDir) -> PathBuf {
        dir.path().canonicalize().expect("canonical tempdir")
    }

    // Injectable config source — same pattern as config.rs tests (no process
    // env mutation, parallel-safe).
    fn cfg_from(pairs: &[(&str, &str)]) -> AgentConfig {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        AgentConfig::from_source(|k| map.get(k).cloned()).expect("config must parse")
    }

    /// Base config (no env token) with the token file inside `dir`.
    fn cfg_with_token_path(dir: &TempDir, extra: &[(&str, &str)]) -> (AgentConfig, PathBuf) {
        let token_path = temp_path(dir).join("agent.token");
        let mut pairs = vec![
            ("RYUKI_AGENT_CP_URL", "https://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
            (
                "RYUKI_AGENT_ENROLLMENT_CHALLENGE_ID",
                "00000000-0000-0000-0000-000000000001",
            ),
            (
                "RYUKI_AGENT_ENROLLMENT_CHALLENGE",
                "ryc_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
        ];
        let tp = token_path.display().to_string();
        pairs.push(("RYUKI_AGENT_TOKEN_PATH", tp.as_str()));
        pairs.extend_from_slice(extra);
        (cfg_from(&pairs), token_path)
    }

    #[cfg(unix)]
    fn write_token_fixture(path: &Path, contents: &str, mode: u32) {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .expect("create token fixture");
        file.write_all(contents.as_bytes())
            .expect("write token fixture");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .expect("set token fixture mode");
    }

    // -----------------------------------------------------------------------
    // save / load round-trip + permissions + overwrite refusal
    // -----------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn save_load_roundtrip() {
        let dir = TempDir::new().expect("tempdir");
        let path = temp_path(&dir).join("agent.token");

        save_token_file(&path, TOK).expect("save must succeed");
        let loaded = load_token_file(&path).expect("load must succeed");
        assert_eq!(loaded, TOK, "loaded token must equal the saved one");
    }

    #[cfg(unix)]
    #[test]
    fn saved_token_file_has_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().expect("tempdir");
        let path = temp_path(&dir).join("agent.token");
        save_token_file(&path, TOK).expect("save");

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "token file must be mode 0600");
    }

    #[cfg(unix)]
    #[test]
    fn save_refuses_to_overwrite_existing_token_file() {
        let dir = TempDir::new().expect("tempdir");
        let path = temp_path(&dir).join("agent.token");

        save_token_file(&path, TOK).expect("first save");
        let second = save_token_file(&path, "rya_other");
        assert!(
            matches!(second, Err(TokenError::AlreadyExists { .. })),
            "second save must refuse to overwrite, got: {second:?}"
        );
        // The original credential must be intact.
        assert_eq!(load_token_file(&path).expect("load"), TOK);
    }

    #[test]
    fn save_rejects_malformed_token() {
        let dir = TempDir::new().expect("tempdir");
        let path = temp_path(&dir).join("agent.token");
        // Never persist a token that load would refuse.
        let result = save_token_file(&path, "not-an-agent-token");
        assert!(matches!(result, Err(TokenError::Malformed { .. })));
        assert!(!path.exists(), "no file must be created for a bad token");
    }

    #[cfg(unix)]
    #[test]
    fn load_trims_trailing_newline() {
        let dir = TempDir::new().expect("tempdir");
        let path = temp_path(&dir).join("agent.token");
        // Operator wrote the file with `echo` (trailing newline).
        write_token_fixture(&path, &format!("{TOK}\n"), 0o600);
        assert_eq!(load_token_file(&path).expect("load"), TOK);
    }

    #[test]
    fn load_missing_file_is_io_error() {
        let dir = TempDir::new().expect("tempdir");
        let result = load_token_file(&temp_path(&dir).join("nonexistent.token"));
        assert!(matches!(result, Err(TokenError::Io { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_malformed_contents() {
        let dir = TempDir::new().expect("tempdir");
        let cases: &[(&str, &str)] = &[
            ("empty", ""),
            ("whitespace-only", "  \n"),
            ("wrong-prefix", "abc123\n"),
            ("multi-line", "rya_abc\nrya_def\n"),
            ("embedded-space", "rya_ab cd\n"),
        ];
        for (name, contents) in cases {
            let path = temp_path(&dir).join(format!("{name}.token"));
            write_token_fixture(&path, contents, 0o600);
            let result = load_token_file(&path);
            assert!(
                matches!(result, Err(TokenError::Malformed { .. })),
                "{name}: must be Malformed, got: {result:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn malformed_error_never_leaks_token_value() {
        let dir = TempDir::new().expect("tempdir");
        let path = temp_path(&dir).join("agent.token");
        write_token_fixture(&path, "secret-but-wrong-prefix", 0o600);
        let err = load_token_file(&path).expect_err("must fail");
        assert!(
            !err.to_string().contains("secret-but-wrong-prefix"),
            "error message must not contain the file contents: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_accepts_owner_only_readable_file() {
        let dir = TempDir::new().expect("tempdir");
        let path = temp_path(&dir).join("agent.token");
        write_token_fixture(&path, TOK, 0o400);

        assert_eq!(load_token_file(&path).expect("0400 file must load"), TOK);
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_any_group_or_other_permission_bits() {
        for mode in [0o640, 0o644, 0o604, 0o711] {
            let dir = TempDir::new().expect("tempdir");
            let path = temp_path(&dir).join(format!("agent-{mode:o}.token"));
            write_token_fixture(&path, TOK, mode);

            let result = load_token_file(&path);
            assert!(
                matches!(result, Err(TokenError::UnsafeFile { .. })),
                "mode {mode:o} must be rejected, got {result:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_final_symlink_without_reading_target() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().expect("tempdir");
        let dir_path = temp_path(&dir);
        let target = dir_path.join("target.token");
        let link = dir_path.join("agent.token");
        write_token_fixture(&target, TOK, 0o600);
        symlink(&target, &link).expect("create symlink");

        assert!(
            matches!(load_token_file(&link), Err(TokenError::UnsafeFile { .. })),
            "final symlink must fail closed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_and_save_reject_linked_parent_components() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().expect("tempdir");
        let dir_path = temp_path(&dir);
        let real_parent = dir_path.join("real-state");
        let linked_parent = dir_path.join("linked-state");
        std::fs::create_dir(&real_parent).expect("create real state directory");
        symlink(&real_parent, &linked_parent).expect("create linked parent");

        let real_token = real_parent.join("agent.token");
        write_token_fixture(&real_token, TOK, 0o600);
        let linked_token = linked_parent.join("agent.token");
        assert!(
            matches!(
                load_token_file(&linked_token),
                Err(TokenError::UnsafeFile { .. })
            ),
            "loading must not escape through a linked parent component"
        );

        let linked_new_token = linked_parent.join("new.token");
        assert!(
            matches!(
                save_token_file(&linked_new_token, "rya_replacement"),
                Err(TokenError::UnsafeFile { .. })
            ),
            "persistence must not escape through a linked parent component"
        );
        assert!(
            !real_parent.join("new.token").exists(),
            "a rejected linked-parent write must create nothing at its target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn relative_parent_directory_escape_is_rejected() {
        let result = load_token_file(Path::new("../agent.token"));
        assert!(
            matches!(result, Err(TokenError::UnsafeFile { .. })),
            "relative '..' must not escape the pinned cwd anchor"
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_directory_fifo_socket_and_device_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::net::UnixListener;

        let dir = TempDir::new().expect("tempdir");
        assert!(
            matches!(
                load_token_file(&temp_path(&dir)),
                Err(TokenError::UnsafeFile { .. })
            ),
            "directory must be rejected as non-regular"
        );

        let fifo = temp_path(&dir).join("agent.token.fifo");
        let fifo_c = CString::new(fifo.as_os_str().as_bytes()).expect("path has no NUL");
        // SAFETY: fifo_c is a valid NUL-terminated path and mode has no invalid bits.
        let rc = unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo must succeed");
        assert!(
            matches!(load_token_file(&fifo), Err(TokenError::UnsafeFile { .. })),
            "FIFO must be opened nonblocking and rejected as non-regular"
        );

        let socket = temp_path(&dir).join("agent.token.socket");
        let _listener = UnixListener::bind(&socket).expect("bind Unix socket fixture");
        assert!(
            load_token_file(&socket).is_err(),
            "Unix socket must be rejected promptly without consuming contents"
        );

        let device = File::open("/dev/null").expect("open portable Unix device fixture");
        // SAFETY: geteuid takes no pointers and has no preconditions.
        let effective_uid = unsafe { libc::geteuid() };
        assert!(
            matches!(
                validate_open_token_file(&device, "/dev/null", effective_uid),
                Err(TokenError::UnsafeFile { .. })
            ),
            "device handles must be rejected as non-regular"
        );
    }

    #[cfg(unix)]
    #[test]
    fn opened_handle_owner_validation_rejects_foreign_uid() {
        use std::os::unix::fs::MetadataExt;

        let dir = TempDir::new().expect("tempdir");
        let path = temp_path(&dir).join("agent.token");
        write_token_fixture(&path, TOK, 0o600);
        let file = File::open(&path).expect("open fixture");
        let actual_uid = file.metadata().expect("metadata").uid();
        let foreign_uid = actual_uid.wrapping_add(1);

        assert!(
            matches!(
                validate_open_token_file(&file, "fixture", foreign_uid),
                Err(TokenError::UnsafeFile { .. })
            ),
            "opened handle must reject an owner other than the effective UID"
        );
    }

    #[cfg(unix)]
    #[test]
    fn read_stays_on_validated_handle_after_path_replacement() {
        let dir = TempDir::new().expect("tempdir");
        let dir_path = temp_path(&dir);
        let path = dir_path.join("agent.token");
        let original_path = dir_path.join("original.token");
        write_token_fixture(&path, TOK, 0o600);
        let file = open_validated_token_file(&path, "fixture").expect("validated open");

        std::fs::rename(&path, &original_path).expect("move original path");
        write_token_fixture(&path, "rya_replacement", 0o600);

        assert_eq!(
            load_token_from_open_file(file, "fixture").expect("read opened handle"),
            TOK,
            "path replacement after validation must not redirect the read"
        );
        assert_eq!(
            load_token_file(&path).expect("replacement is independently valid"),
            "rya_replacement"
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_oversized_file_after_bounded_read() {
        let dir = TempDir::new().expect("tempdir");
        let path = temp_path(&dir).join("agent.token");
        let oversized = format!("rya_{}", "a".repeat(MAX_TOKEN_FILE_BYTES));
        write_token_fixture(&path, &oversized, 0o600);

        assert!(
            matches!(load_token_file(&path), Err(TokenError::Malformed { .. })),
            "oversized token file must fail closed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn save_refuses_existing_symlink_and_preserves_target() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().expect("tempdir");
        let dir_path = temp_path(&dir);
        let target = dir_path.join("target.token");
        let link = dir_path.join("agent.token");
        write_token_fixture(&target, TOK, 0o600);
        symlink(&target, &link).expect("create symlink");

        assert!(
            matches!(
                save_token_file(&link, "rya_replacement"),
                Err(TokenError::AlreadyExists { .. })
            ),
            "create-only save must refuse a final symlink"
        );
        assert_eq!(load_token_file(&target).expect("target remains valid"), TOK);
    }

    #[cfg(not(unix))]
    #[test]
    fn existing_token_files_and_persistence_fail_closed_without_platform_adapter() {
        let dir = TempDir::new().expect("tempdir");
        let path = temp_path(&dir).join("agent.token");
        std::fs::write(&path, TOK).expect("write fixture");
        assert!(matches!(
            load_token_file(&path),
            Err(TokenError::UnsupportedPlatform { .. })
        ));

        let save_path = temp_path(&dir).join("new.token");
        assert!(matches!(
            save_token_file(&save_path, TOK),
            Err(TokenError::UnsupportedPlatform { .. })
        ));
        assert!(!save_path.exists());
    }

    // -----------------------------------------------------------------------
    // resolve_token precedence
    // -----------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn resolve_env_token_wins_over_existing_file() {
        let dir = TempDir::new().expect("tempdir");
        let (cfg, token_path) = cfg_with_token_path(&dir, &[("RYUKI_AGENT_TOKEN", "rya_from_env")]);
        // The dormant file is intentionally insecure: env precedence must
        // avoid touching it at all.
        write_token_fixture(&token_path, "rya_from_file", 0o644);

        let resolved = resolve_token(&cfg).expect("resolve");
        assert!(
            matches!(&resolved, ResolvedToken::FromEnv(t) if t == "rya_from_env"),
            "env token must win over the file, got: {resolved:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_falls_back_to_token_file_when_env_unset() {
        let dir = TempDir::new().expect("tempdir");
        let (cfg, token_path) = cfg_with_token_path(&dir, &[]);
        save_token_file(&token_path, "rya_from_file").expect("save");

        let resolved = resolve_token(&cfg).expect("resolve");
        assert!(
            matches!(&resolved, ResolvedToken::FromFile(t) if t == "rya_from_file"),
            "file token must be used when env is unset, got: {resolved:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_self_register_when_no_token_anywhere_and_opted_in() {
        let dir = TempDir::new().expect("tempdir");
        let (cfg, _) = cfg_with_token_path(&dir, &[("RYUKI_AGENT_SELF_REGISTER", "true")]);

        let resolved = resolve_token(&cfg).expect("resolve");
        assert!(matches!(resolved, ResolvedToken::SelfRegister));
    }

    #[cfg(not(unix))]
    #[test]
    fn self_registration_fails_before_network_when_secure_persistence_is_unsupported() {
        let dir = TempDir::new().expect("tempdir");
        let (cfg, _) = cfg_with_token_path(&dir, &[("RYUKI_AGENT_SELF_REGISTER", "true")]);

        assert!(matches!(
            resolve_token(&cfg),
            Err(TokenError::UnsupportedPlatform { .. })
        ));
    }

    #[test]
    fn resolve_errors_when_no_token_and_self_register_disabled() {
        let dir = TempDir::new().expect("tempdir");
        let (cfg, _) = cfg_with_token_path(&dir, &[]);

        let err = resolve_token(&cfg).expect_err("must fail with no token source");
        let msg = err.to_string();
        // The error must name every remedy.
        assert!(
            msg.contains("RYUKI_AGENT_TOKEN"),
            "must name the env var: {msg}"
        );
        assert!(
            msg.contains("RYUKI_AGENT_SELF_REGISTER"),
            "must name the self-register opt-in: {msg}"
        );
        assert!(
            msg.contains("agent.token"),
            "must name the file path: {msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_malformed_file_is_fatal_not_a_fallthrough_to_registration() {
        // A malformed EXISTING file must never silently re-register.
        let dir = TempDir::new().expect("tempdir");
        let (cfg, token_path) = cfg_with_token_path(&dir, &[("RYUKI_AGENT_SELF_REGISTER", "true")]);
        write_token_fixture(&token_path, "garbage", 0o600);

        let result = resolve_token(&cfg);
        assert!(
            matches!(result, Err(TokenError::Malformed { .. })),
            "malformed file must be fatal even with self_register on, got: {result:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_insecure_file_is_fatal_not_a_fallthrough_to_registration() {
        let dir = TempDir::new().expect("tempdir");
        let (cfg, token_path) = cfg_with_token_path(&dir, &[("RYUKI_AGENT_SELF_REGISTER", "true")]);
        write_token_fixture(&token_path, TOK, 0o644);

        let result = resolve_token(&cfg);
        assert!(
            matches!(result, Err(TokenError::UnsafeFile { .. })),
            "unsafe existing file must remain fatal even with self-registration enabled"
        );
    }

    // -----------------------------------------------------------------------
    // validate_register_response
    // -----------------------------------------------------------------------

    fn resp(agent_id: &str, token: &str) -> RegisterResponse {
        RegisterResponse {
            agent_id: agent_id.to_owned(),
            token: token.to_owned(),
        }
    }

    #[test]
    fn register_response_valid_passes() {
        validate_register_response(&resp("defra", TOK), "defra").expect("valid response must pass");
    }

    #[test]
    fn register_response_wrong_agent_id_is_rejected() {
        let result = validate_register_response(&resp("other-agent", TOK), "defra");
        assert!(
            matches!(result, Err(TokenError::Malformed { .. })),
            "an answer for a different agent_id must be rejected"
        );
    }

    #[test]
    fn register_response_bad_token_shape_is_rejected() {
        for bad in ["", "abc123", "rya_with space", "rya_line\nbreak"] {
            let result = validate_register_response(&resp("defra", bad), "defra");
            assert!(
                matches!(result, Err(TokenError::Malformed { .. })),
                "token {bad:?} must be rejected"
            );
        }
    }
}
