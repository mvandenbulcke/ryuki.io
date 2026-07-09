//! Agent bearer-token resolution and on-disk persistence (S5 self-registration).
//!
//! ## Token resolution precedence (fail-closed)
//!
//! 1. `RYUKI_AGENT_TOKEN` env var — always wins when set (pre-S5 behavior,
//!    byte-compatible: same `rya_` prefix validation in `config.rs`).
//! 2. Token file at `token_path` (`RYUKI_AGENT_TOKEN_PATH`, default
//!    `agent.token` next to the key file) — written once by first-boot
//!    self-registration, or placed there by an operator.
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

use std::path::Path;

use thiserror::Error;

use crate::client::RegisterResponse;
use crate::config::AgentConfig;

/// Agent tokens issued by the CP carry this prefix (`ryuki-api/src/agents.rs`
/// `AGENT_TOKEN_PREFIX`). Both the env var and the token file are validated
/// against it so a misconfigured credential fails at startup, not as a 401 on
/// every request.
pub const TOKEN_PREFIX: &str = "rya_";

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
/// on Unix the file is created 0600 atomically in a single `open`, so the
/// credential is never momentarily world-readable, and an existing file is
/// refused with [`TokenError::AlreadyExists`] — the CP returns the plaintext
/// token exactly once, so an overwrite would irrecoverably destroy it.
///
/// A single trailing newline is appended for operator friendliness (`cat`);
/// [`load_token_file`] trims it back off.
pub fn save_token_file(path: &Path, token: &str) -> Result<(), TokenError> {
    let path_str = path.display().to_string();

    // Never persist a token we would refuse to load back.
    check_token_shape(token).map_err(|reason| TokenError::Malformed {
        origin: "registration response".to_owned(),
        reason,
    })?;

    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            TokenError::AlreadyExists {
                path: path_str.clone(),
            }
        } else {
            TokenError::Io {
                path: path_str.clone(),
                source: e,
            }
        }
    })?;
    file.write_all(format!("{token}\n").as_bytes())
        .map_err(|e| TokenError::Io {
            path: path_str,
            source: e,
        })?;

    Ok(())
}

/// Load a previously-persisted token from `path`.
///
/// Trailing whitespace (the newline `save_token_file` appends, or one added by
/// an operator's `echo`) is trimmed; anything else malformed is a hard error —
/// a bad token file must stop startup, never degrade into per-request 401s.
pub fn load_token_file(path: &Path) -> Result<String, TokenError> {
    let path_str = path.display().to_string();
    let raw = std::fs::read_to_string(path).map_err(|e| TokenError::Io {
        path: path_str.clone(),
        source: e,
    })?;
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
        Err(TokenError::Io { ref source, .. })
            if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(other) => return Err(other),
    }

    // 3. First-boot self-registration, only when explicitly opted in.
    if cfg.self_register {
        return Ok(ResolvedToken::SelfRegister);
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
        let token_path = dir.path().join("agent.token");
        let mut pairs = vec![
            ("RYUKI_AGENT_CP_URL", "https://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
        ];
        let tp = token_path.display().to_string();
        pairs.push(("RYUKI_AGENT_TOKEN_PATH", tp.as_str()));
        pairs.extend_from_slice(extra);
        (cfg_from(&pairs), token_path)
    }

    // -----------------------------------------------------------------------
    // save / load round-trip + permissions + overwrite refusal
    // -----------------------------------------------------------------------

    #[test]
    fn save_load_roundtrip() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("agent.token");

        save_token_file(&path, TOK).expect("save must succeed");
        let loaded = load_token_file(&path).expect("load must succeed");
        assert_eq!(loaded, TOK, "loaded token must equal the saved one");
    }

    #[cfg(unix)]
    #[test]
    fn saved_token_file_has_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("agent.token");
        save_token_file(&path, TOK).expect("save");

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "token file must be mode 0600");
    }

    #[test]
    fn save_refuses_to_overwrite_existing_token_file() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("agent.token");

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
        let path = dir.path().join("agent.token");
        // Never persist a token that load would refuse.
        let result = save_token_file(&path, "not-an-agent-token");
        assert!(matches!(result, Err(TokenError::Malformed { .. })));
        assert!(!path.exists(), "no file must be created for a bad token");
    }

    #[test]
    fn load_trims_trailing_newline() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("agent.token");
        // Operator wrote the file with `echo` (trailing newline).
        std::fs::write(&path, format!("{TOK}\n")).expect("write");
        assert_eq!(load_token_file(&path).expect("load"), TOK);
    }

    #[test]
    fn load_missing_file_is_io_error() {
        let dir = TempDir::new().expect("tempdir");
        let result = load_token_file(&dir.path().join("nonexistent.token"));
        assert!(matches!(result, Err(TokenError::Io { .. })));
    }

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
            let path = dir.path().join(format!("{name}.token"));
            std::fs::write(&path, contents).expect("write");
            let result = load_token_file(&path);
            assert!(
                matches!(result, Err(TokenError::Malformed { .. })),
                "{name}: must be Malformed, got: {result:?}"
            );
        }
    }

    #[test]
    fn malformed_error_never_leaks_token_value() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("agent.token");
        std::fs::write(&path, "secret-but-wrong-prefix").expect("write");
        let err = load_token_file(&path).expect_err("must fail");
        assert!(
            !err.to_string().contains("secret-but-wrong-prefix"),
            "error message must not contain the file contents: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // resolve_token precedence
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_env_token_wins_over_existing_file() {
        let dir = TempDir::new().expect("tempdir");
        let (cfg, token_path) =
            cfg_with_token_path(&dir, &[("RYUKI_AGENT_TOKEN", "rya_from_env")]);
        save_token_file(&token_path, "rya_from_file").expect("save");

        let resolved = resolve_token(&cfg).expect("resolve");
        assert!(
            matches!(&resolved, ResolvedToken::FromEnv(t) if t == "rya_from_env"),
            "env token must win over the file, got: {resolved:?}"
        );
    }

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

    #[test]
    fn resolve_self_register_when_no_token_anywhere_and_opted_in() {
        let dir = TempDir::new().expect("tempdir");
        let (cfg, _) = cfg_with_token_path(&dir, &[("RYUKI_AGENT_SELF_REGISTER", "true")]);

        let resolved = resolve_token(&cfg).expect("resolve");
        assert!(matches!(resolved, ResolvedToken::SelfRegister));
    }

    #[test]
    fn resolve_errors_when_no_token_and_self_register_disabled() {
        let dir = TempDir::new().expect("tempdir");
        let (cfg, _) = cfg_with_token_path(&dir, &[]);

        let err = resolve_token(&cfg).expect_err("must fail with no token source");
        let msg = err.to_string();
        // The error must name every remedy.
        assert!(msg.contains("RYUKI_AGENT_TOKEN"), "must name the env var: {msg}");
        assert!(
            msg.contains("RYUKI_AGENT_SELF_REGISTER"),
            "must name the self-register opt-in: {msg}"
        );
        assert!(msg.contains("agent.token"), "must name the file path: {msg}");
    }

    #[test]
    fn resolve_malformed_file_is_fatal_not_a_fallthrough_to_registration() {
        // A malformed EXISTING file must never silently re-register.
        let dir = TempDir::new().expect("tempdir");
        let (cfg, token_path) =
            cfg_with_token_path(&dir, &[("RYUKI_AGENT_SELF_REGISTER", "true")]);
        std::fs::write(&token_path, "garbage").expect("write");

        let result = resolve_token(&cfg);
        assert!(
            matches!(result, Err(TokenError::Malformed { .. })),
            "malformed file must be fatal even with self_register on, got: {result:?}"
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
        validate_register_response(&resp("defra", TOK), "defra")
            .expect("valid response must pass");
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
