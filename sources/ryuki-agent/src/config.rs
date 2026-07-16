//! Agent configuration — loaded from environment variables.
//!
//! ## Required variables
//!
//! | Env var                         | Field           | Notes                          |
//! |---------------------------------|-----------------|--------------------------------|
//! | `RYUKI_AGENT_CP_URL`            | `cp_base_url`   | e.g. `https://ryuki.example/`  |
//! | `RYUKI_AGENT_PLATFORM`          | `platform`      | e.g. `defra`                   |
//!
//! ## Optional variables (defaults shown)
//!
//! | Env var                                | Field                      | Default |
//! |----------------------------------------|----------------------------|---------|
//! | `RYUKI_AGENT_TOKEN`                    | `token`                    | (unset) — see token precedence |
//! | `RYUKI_AGENT_TOKEN_PATH`               | `token_path`               | `agent.token` next to the key file |
//! | `RYUKI_AGENT_SELF_REGISTER`            | `self_register`            | `false` |
//! | `RYUKI_AGENT_ENROLLMENT_CHALLENGE_ID`  | `enrollment_challenge_id`  | (required with self-registration) |
//! | `RYUKI_AGENT_ENROLLMENT_CHALLENGE`     | `enrollment_challenge`     | (required with self-registration) |
//! | `RYUKI_AGENT_ALLOW_INSECURE_LOOPBACK`  | loopback HTTP development policy | `false` |
//! | `RYUKI_AGENT_KEY_PATH`                 | `key_path`                 | `agent.key` (cwd) |
//! | `RYUKI_AGENT_POLL_INTERVAL_SECS`       | `poll_interval_secs`       | 10      |
//! | `RYUKI_AGENT_LEASE_SECS`               | `lease_secs`               | 300     |
//! | `RYUKI_AGENT_ALLOW_LIVE`               | `allow_live`               | `false` |
//! | `RYUKI_AGENT_MAX_OUTBOX_ATTEMPTS`      | `max_outbox_attempts`      | 10      |
//! | `RYUKI_AGENT_OUTBOX_DRAIN_INTERVAL_SECS` | `outbox_drain_interval_secs` | 60  |
//!
//! ## Runner executable approval
//!
//! The runner crate reads `RYUKI_TERRAFORM_EXECUTABLE` plus
//! `RYUKI_TERRAFORM_EXPECTED_VERSION`, and
//! `RYUKI_ANSIBLE_PLAYBOOK_EXECUTABLE` plus
//! `RYUKI_ANSIBLE_PLAYBOOK_EXPECTED_VERSION`, only when the corresponding tool
//! is needed. Paths must be absolute and canonical. Optional
//! `RYUKI_TERRAFORM_EXECUTABLE_SHA256` and
//! `RYUKI_ANSIBLE_PLAYBOOK_EXECUTABLE_SHA256` values add content pins. These
//! values are intentionally not fields on `AgentConfig`: the executable is
//! admitted at the command boundary immediately before use, so credentials
//! cannot be attached to a merely startup-checked path.
//!
//! ### Token resolution precedence (S5 self-registration)
//!
//! The bearer token is resolved at startup in this order (`token::resolve_token`):
//!
//! 1. `RYUKI_AGENT_TOKEN` — always wins when set. Validation is byte-compatible
//!    with the pre-S5 behavior (non-empty, `rya_` prefix required).
//! 2. The token file at `RYUKI_AGENT_TOKEN_PATH` — written by first-boot
//!    self-registration (0600, create-only) or placed there by an operator.
//!    A file that exists but is malformed is FATAL, never a fall-through.
//! 3. First-boot self-registration, only when `RYUKI_AGENT_SELF_REGISTER` is
//!    `"true"` / `"1"` (same strict opt-in parse as `RYUKI_AGENT_ALLOW_LIVE`):
//!    trusted provisioning must also supply the paired challenge id and
//!    one-time challenge. The agent signs that exact claim with its existing
//!    Ed25519 key, registers with the CP, persists the returned token to the
//!    token file, and exits 0 pending admin approval.
//! 4. Otherwise startup fails with an error naming all three options.
//!
//! Existing token paths are resolved through pinned handles without following
//! symlinks in any component and validated from the final opened handle. On Unix
//! they must be regular, owned by the effective service UID, and grant no
//! permissions to group/other users. Platforms without an equivalent
//! owner/DACL/reparse-point adapter fail closed.
//!
//! ### `RYUKI_AGENT_ALLOW_INSECURE_LOOPBACK`
//!
//! Plain HTTP is denied by default for every execution mode and token source.
//! Local development/test harnesses may opt in with the exact value `true` or
//! `1`, but the parsed destination must still be `localhost` or a standard-
//! library-confirmed IPv4/IPv6 loopback literal. Redirects remain disabled and
//! ambient proxies are bypassed for this local-only exception.
//!
//! ### `RYUKI_AGENT_MAX_OUTBOX_ATTEMPTS`
//!
//! Maximum number of transient-failure delivery attempts before an outbox entry
//! is moved to the dead-letter directory (`<outbox_dir>/dead/`).  `OperatorAlert`
//! entries (401/403) do NOT count toward this limit.  Must be >= 1.
//!
//! ### `RYUKI_AGENT_OUTBOX_DRAIN_INTERVAL_SECS`
//!
//! How often the agent drains the outbox during the poll loop (in seconds).
//! Must be >= 1 (0 would drain on every poll tick, hammering the CP).
//! The outbox is always drained once at startup regardless of this setting.
//!
//! ### `RYUKI_AGENT_ALLOW_LIVE`
//!
//! Controls whether this agent may execute jobs that touch real infrastructure:
//!
//! - **Absent or any value other than `"true"` / `"1"` → `false`** (safe
//!   default).  The agent will still run `OfflineDryRun` jobs; it will refuse
//!   `LivePlan` and `LiveApply` jobs with `LiveRefused`.
//! - **`"true"` or `"1"` → `true`**: live execution is enabled.  The agent
//!   must also carry real platform credentials in its environment for live
//!   jobs to succeed.
//!
//! Live execution must be **explicitly opted into**; a missing variable is
//! always treated as `false`, never as an error.

use std::path::PathBuf;

use thiserror::Error;

use ryuki_protocol::{
    Capabilities, AGENT_ENROLLMENT_CHALLENGE_HEX_BYTES, AGENT_ENROLLMENT_CHALLENGE_PREFIX,
};
use uuid::Uuid;

use crate::client::ControlPlaneEndpoint;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("required environment variable {var} is not set")]
    MissingEnv { var: &'static str },
    #[error("environment variable {var} has invalid value {value:?}: {reason}")]
    InvalidEnv {
        var: &'static str,
        value: String,
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// AgentConfig
// ---------------------------------------------------------------------------

/// Runtime configuration for the ryuki-agent binary.
///
/// `Debug` is implemented manually to REDACT the bearer token — deriving it
/// would leak the token into any `tracing` call that formats the config.
#[derive(Clone)]
pub struct AgentConfig {
    /// Parsed, transport-validated URL of the Ryuki control plane.
    ///
    /// HTTPS is mandatory. Plain HTTP is admitted only for an exact loopback
    /// endpoint when `RYUKI_AGENT_ALLOW_INSECURE_LOOPBACK=true` (or `1`) is
    /// explicitly set for a local development/test harness.
    pub cp_base_url: ControlPlaneEndpoint,

    /// Whether the explicit loopback-only HTTP development policy was enabled.
    /// Remote HTTP remains invalid even when this is true.
    pub allow_insecure_loopback: bool,

    /// Platform / site identifier this agent serves (e.g. `defra`).
    pub platform: String,

    /// Bearer token supplied directly via `RYUKI_AGENT_TOKEN`.
    /// Must start with `rya_` when set (validation unchanged from pre-S5).
    ///
    /// `None` when the env var is absent — the token is then resolved at
    /// startup from the token file or via first-boot self-registration
    /// (`token::resolve_token`; see the module-level precedence doc). The
    /// fail-closed property is preserved: with no token from ANY source and
    /// self-registration disabled, startup fails.
    pub token: Option<String>,

    /// Path to the on-disk bearer-token file (plaintext `rya_…` + newline).
    /// Existing Unix files must be effective-UID-owned regular files with no
    /// group/other permission bits (0400 and 0600 are both accepted).
    ///
    /// Set via `RYUKI_AGENT_TOKEN_PATH`; defaults to `agent.token` in the SAME
    /// directory as `key_path` — token and key share one operational blast
    /// radius (same host, same backup story), mirroring the outbox placement.
    pub token_path: PathBuf,

    /// Whether first-boot self-registration is enabled.
    ///
    /// Set via `RYUKI_AGENT_SELF_REGISTER=true` (or `1`) — the same strict
    /// opt-in parse as `allow_live`: absence or any other value is `false`,
    /// never an error. Only consulted when neither `RYUKI_AGENT_TOKEN` nor the
    /// token file provides a token.
    pub self_register: bool,

    /// Trusted provisioning challenge identifier consumed on first-boot
    /// registration. It is not a durable identity credential.
    pub enrollment_challenge_id: Option<Uuid>,

    /// One-time challenge secret delivered through the deployment's existing
    /// provider-neutral secret/bootstrap channel. `Debug` always redacts it.
    pub enrollment_challenge: Option<String>,

    /// Path to the on-disk Ed25519 secret key file (binary, 32 bytes, 0600).
    pub key_path: PathBuf,

    /// How many seconds to wait between `GET /jobs` poll attempts when the
    /// previous poll returned 204 (no work).
    pub poll_interval_secs: u64,

    /// Lease TTL hint sent to the control plane (informational; the CP enforces
    /// its own TTL, this config value is used by the agent for backoff tuning).
    pub lease_secs: u64,

    /// Capabilities advertised to the CP at registration time.
    ///
    /// S4a: always `Capabilities::default()` (no terraform/ansible probed yet).
    /// S4b: detect installed tools and versions at startup.
    pub capabilities: Capabilities,

    /// Whether this agent is permitted to execute jobs that touch real
    /// infrastructure (`LivePlan` / `LiveApply`).
    ///
    /// Set via `RYUKI_AGENT_ALLOW_LIVE=true` (or `1`).  Defaults to `false`;
    /// absence of the variable is treated as `false` (not an error).  Any
    /// value other than `"true"` / `"1"` is also treated as `false`.
    ///
    /// See the module-level doc comment for the full opt-in semantics.
    pub allow_live: bool,

    /// Maximum number of transient-failure delivery attempts before an outbox
    /// entry is quarantined to `<outbox_dir>/dead/`.
    ///
    /// `OperatorAlert` entries (401/403) do NOT count toward this limit.
    /// Set via `RYUKI_AGENT_MAX_OUTBOX_ATTEMPTS` (default 10, must be >= 1).
    pub max_outbox_attempts: u32,

    /// How often (in seconds) the poll loop drains the outbox while idle.
    ///
    /// Set via `RYUKI_AGENT_OUTBOX_DRAIN_INTERVAL_SECS` (default 60).
    /// Must be >= 1; 0 is rejected (would drain on every tick).
    pub outbox_drain_interval_secs: u64,
}

impl std::fmt::Debug for AgentConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentConfig")
            .field("cp_base_url", &self.cp_base_url)
            .field("allow_insecure_loopback", &self.allow_insecure_loopback)
            .field("platform", &self.platform)
            // Presence only — Some("<redacted>") / None — never the value.
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("token_path", &self.token_path)
            .field("self_register", &self.self_register)
            .field("enrollment_challenge_id", &self.enrollment_challenge_id)
            .field(
                "enrollment_challenge",
                &self.enrollment_challenge.as_ref().map(|_| "<redacted>"),
            )
            .field("key_path", &self.key_path)
            .field("poll_interval_secs", &self.poll_interval_secs)
            .field("lease_secs", &self.lease_secs)
            .field("capabilities", &self.capabilities)
            .field("allow_live", &self.allow_live)
            .field("max_outbox_attempts", &self.max_outbox_attempts)
            .field(
                "outbox_drain_interval_secs",
                &self.outbox_drain_interval_secs,
            )
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

impl AgentConfig {
    /// Load configuration from the process environment.
    ///
    /// Thin wrapper over [`AgentConfig::from_source`]; the only place that reads
    /// the global environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_source(|var| std::env::var(var).ok())
    }

    /// Parse configuration from an arbitrary key→value source.
    ///
    /// `get` returns `Some(value)` if the key is present, `None` otherwise.
    /// [`from_env`](Self::from_env) supplies the process environment; tests
    /// inject a map so they never mutate global state and stay parallel-safe
    /// (mutating `std::env` from parallel tests is a data race — that is exactly
    /// what this indirection avoids).
    ///
    /// Returns `Err` if any *required* variable is absent or if an optional
    /// variable has an invalid value (e.g. non-numeric interval).
    pub fn from_source(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let raw_cp_base_url = require(&get, "RYUKI_AGENT_CP_URL")?;
        // Plain HTTP is never inferred from execution mode or hostname. It is
        // a separate, strict development/test opt-in, and the endpoint parser
        // still limits it to exact loopback destinations.
        let allow_insecure_loopback = matches!(
            get("RYUKI_AGENT_ALLOW_INSECURE_LOOPBACK").as_deref(),
            Some("true") | Some("1")
        );
        // This admission gate runs before platform/token/file parsing. A bad
        // transport therefore fails startup before any credential is resolved.
        let cp_base_url = ControlPlaneEndpoint::parse(&raw_cp_base_url, allow_insecure_loopback)
            .map_err(|e| ConfigError::InvalidEnv {
                var: "RYUKI_AGENT_CP_URL",
                // A rejected URL may contain userinfo; never copy it into logs.
                value: "<redacted>".to_owned(),
                reason: e.to_string(),
            })?;

        let platform = require(&get, "RYUKI_AGENT_PLATFORM")?;
        // platform is interpolated into URL path segments, so constrain it to a
        // safe slug (alphanumeric, '.', '-', '_') — no slashes, spaces, or other
        // characters that could alter the request path.
        if !is_slug(&platform) {
            return Err(ConfigError::InvalidEnv {
                var: "RYUKI_AGENT_PLATFORM",
                value: platform,
                reason: "must be a slug: ASCII alphanumeric, '.', '-' or '_' only".to_owned(),
            });
        }

        // RYUKI_AGENT_TOKEN is OPTIONAL since the S5 self-registration slice.
        // When SET, validation is byte-compatible with the pre-S5 behavior:
        // empty/whitespace counts as absent, and a present value must carry the
        // `rya_` prefix (fail early with a clear message instead of getting 401
        // on every request). When ABSENT, startup resolves the token from the
        // token file or first-boot self-registration — see `token::resolve_token`.
        let token = match get("RYUKI_AGENT_TOKEN").filter(|v| !v.trim().is_empty()) {
            Some(t) => {
                if !t.starts_with("rya_") {
                    return Err(ConfigError::InvalidEnv {
                        var: "RYUKI_AGENT_TOKEN",
                        value: "<redacted>".to_owned(),
                        reason: "agent token must start with 'rya_'".to_owned(),
                    });
                }
                Some(t)
            }
            None => None,
        };

        let key_path = get("RYUKI_AGENT_KEY_PATH").unwrap_or_else(|| "agent.key".to_owned());
        let key_path = PathBuf::from(key_path);

        // Token-file path: explicit env wins; the default is `agent.token` in
        // the key file's directory (for the default `agent.key` in cwd this is
        // `agent.token` in cwd). Same next-to-the-key placement as the outbox.
        let token_path = match get("RYUKI_AGENT_TOKEN_PATH").filter(|v| !v.trim().is_empty()) {
            Some(p) => PathBuf::from(p),
            None => key_path
                .parent()
                .map(|dir| dir.join("agent.token"))
                .unwrap_or_else(|| PathBuf::from("agent.token")),
        };

        // `RYUKI_AGENT_SELF_REGISTER` is an explicit opt-in with the exact
        // semantics of `RYUKI_AGENT_ALLOW_LIVE`: only "true"/"1" enable it;
        // absence or any other value is false (fail-safe), never an error.
        let self_register = matches!(
            get("RYUKI_AGENT_SELF_REGISTER").as_deref(),
            Some("true") | Some("1")
        );

        let enrollment_challenge_id =
            match get("RYUKI_AGENT_ENROLLMENT_CHALLENGE_ID")
                .filter(|value| !value.trim().is_empty())
            {
                Some(value) => Some(Uuid::parse_str(value.trim()).map_err(|error| {
                    ConfigError::InvalidEnv {
                        var: "RYUKI_AGENT_ENROLLMENT_CHALLENGE_ID",
                        value,
                        reason: error.to_string(),
                    }
                })?),
                None => None,
            };
        let enrollment_challenge =
            get("RYUKI_AGENT_ENROLLMENT_CHALLENGE").filter(|value| !value.trim().is_empty());
        if let Some(challenge) = enrollment_challenge.as_deref() {
            let expected_len =
                AGENT_ENROLLMENT_CHALLENGE_PREFIX.len() + AGENT_ENROLLMENT_CHALLENGE_HEX_BYTES;
            let valid = challenge.len() == expected_len
                && challenge.starts_with(AGENT_ENROLLMENT_CHALLENGE_PREFIX)
                && challenge[AGENT_ENROLLMENT_CHALLENGE_PREFIX.len()..]
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
            if !valid {
                return Err(ConfigError::InvalidEnv {
                    var: "RYUKI_AGENT_ENROLLMENT_CHALLENGE",
                    value: "<redacted>".to_owned(),
                    reason: format!(
                        "must be {AGENT_ENROLLMENT_CHALLENGE_PREFIX} followed by exactly {AGENT_ENROLLMENT_CHALLENGE_HEX_BYTES} lowercase hexadecimal characters"
                    ),
                });
            }
        }
        if enrollment_challenge_id.is_some() != enrollment_challenge.is_some() {
            return Err(ConfigError::InvalidEnv {
                var: "RYUKI_AGENT_ENROLLMENT_CHALLENGE_ID",
                value: "<redacted>".to_owned(),
                reason: "the challenge id and one-time challenge must be configured together"
                    .to_owned(),
            });
        }
        if self_register && enrollment_challenge_id.is_none() {
            return Err(ConfigError::MissingEnv {
                var: "RYUKI_AGENT_ENROLLMENT_CHALLENGE_ID",
            });
        }

        let poll_interval_secs = optional_u64(&get, "RYUKI_AGENT_POLL_INTERVAL_SECS", 10)?;
        // A zero poll interval would busy-loop the pull-loop (heartbeat + poll
        // with no sleep), hammering the control plane. Reject it explicitly.
        if poll_interval_secs == 0 {
            return Err(ConfigError::InvalidEnv {
                var: "RYUKI_AGENT_POLL_INTERVAL_SECS",
                value: "0".to_owned(),
                reason: "must be >= 1 second (0 would busy-loop the control plane)".to_owned(),
            });
        }
        let lease_secs = optional_u64(&get, "RYUKI_AGENT_LEASE_SECS", 300)?;

        // `RYUKI_AGENT_ALLOW_LIVE` is a safety gate: absence is always `false`.
        // Only the exact strings "true" and "1" enable live execution.
        // Any other value (including typos, empty string, etc.) silently maps
        // to `false` — the agent does NOT produce an error, so a misconfigured
        // value fails safe rather than preventing startup.
        let allow_live = matches!(
            get("RYUKI_AGENT_ALLOW_LIVE").as_deref(),
            Some("true") | Some("1")
        );

        let max_outbox_attempts = optional_u32(&get, "RYUKI_AGENT_MAX_OUTBOX_ATTEMPTS", 10)?;
        if max_outbox_attempts == 0 {
            return Err(ConfigError::InvalidEnv {
                var: "RYUKI_AGENT_MAX_OUTBOX_ATTEMPTS",
                value: "0".to_owned(),
                reason: "must be >= 1 (0 would never quarantine, retrying forever)".to_owned(),
            });
        }

        let outbox_drain_interval_secs =
            optional_u64(&get, "RYUKI_AGENT_OUTBOX_DRAIN_INTERVAL_SECS", 60)?;
        if outbox_drain_interval_secs == 0 {
            return Err(ConfigError::InvalidEnv {
                var: "RYUKI_AGENT_OUTBOX_DRAIN_INTERVAL_SECS",
                value: "0".to_owned(),
                reason: "must be >= 1 second (0 would drain on every poll tick)".to_owned(),
            });
        }

        Ok(Self {
            cp_base_url,
            allow_insecure_loopback,
            platform,
            token,
            token_path,
            self_register,
            enrollment_challenge_id,
            enrollment_challenge,
            key_path,
            poll_interval_secs,
            lease_secs,
            capabilities: Capabilities::default(),
            allow_live,
            max_outbox_attempts,
            outbox_drain_interval_secs,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require(
    get: &impl Fn(&str) -> Option<String>,
    var: &'static str,
) -> Result<String, ConfigError> {
    // An empty (or whitespace-only) value is treated as absent — an empty
    // CP URL / platform / token is never a valid configuration.
    get(var)
        .filter(|v| !v.trim().is_empty())
        .ok_or(ConfigError::MissingEnv { var })
}

/// True if `s` is a non-empty ASCII slug (alphanumeric, '.', '-' or '_').
fn is_slug(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

fn optional_u64(
    get: &impl Fn(&str) -> Option<String>,
    var: &'static str,
    default: u64,
) -> Result<u64, ConfigError> {
    match get(var) {
        None => Ok(default),
        Some(val) => val.parse::<u64>().map_err(|e| ConfigError::InvalidEnv {
            var,
            value: val,
            reason: e.to_string(),
        }),
    }
}

fn optional_u32(
    get: &impl Fn(&str) -> Option<String>,
    var: &'static str,
    default: u32,
) -> Result<u32, ConfigError> {
    match get(var) {
        None => Ok(default),
        Some(val) => val.parse::<u32>().map_err(|e| ConfigError::InvalidEnv {
            var,
            value: val,
            reason: e.to_string(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // Builds an injectable source from a slice of pairs. Tests pass this to
    // `from_source` so they never touch the process environment — no global
    // mutation, so every test is parallel-safe with no ordering dependency.
    fn src(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn parses_full_env() {
        let cfg = AgentConfig::from_source(src(&[
            ("RYUKI_AGENT_CP_URL", "https://cp.example.com/"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
            ("RYUKI_AGENT_TOKEN", "rya_abc123"),
            ("RYUKI_AGENT_KEY_PATH", "/etc/ryuki/agent.key"),
            ("RYUKI_AGENT_POLL_INTERVAL_SECS", "15"),
            ("RYUKI_AGENT_LEASE_SECS", "600"),
        ]))
        .expect("must parse");
        // Operator-facing form remains normalized without a trailing slash.
        assert_eq!(cfg.cp_base_url.to_string(), "https://cp.example.com");
        assert!(!cfg.allow_insecure_loopback);
        assert_eq!(cfg.platform, "defra");
        assert_eq!(cfg.token, Some("rya_abc123".to_owned()));
        assert_eq!(cfg.key_path, PathBuf::from("/etc/ryuki/agent.key"));
        // Default token path lands NEXT TO the key file.
        assert_eq!(cfg.token_path, PathBuf::from("/etc/ryuki/agent.token"));
        assert_eq!(cfg.poll_interval_secs, 15);
        assert_eq!(cfg.lease_secs, 600);
    }

    #[test]
    fn defaults_applied_for_optional_vars() {
        // Only the required vars present → optionals fall back to defaults.
        let cfg = AgentConfig::from_source(src(&[
            ("RYUKI_AGENT_CP_URL", "https://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "gblon"),
            ("RYUKI_AGENT_TOKEN", "rya_xyz"),
        ]))
        .expect("must parse with defaults");
        assert_eq!(cfg.key_path, PathBuf::from("agent.key"));
        // Default key is in cwd → default token file is `agent.token` in cwd.
        assert_eq!(cfg.token_path, PathBuf::from("agent.token"));
        assert!(!cfg.self_register, "self_register must default to false");
        assert!(
            !cfg.allow_insecure_loopback,
            "insecure loopback transport must default to false"
        );
        assert_eq!(cfg.poll_interval_secs, 10);
        assert_eq!(cfg.lease_secs, 300);
    }

    #[test]
    fn errors_on_missing_required_cp_url() {
        let result = AgentConfig::from_source(src(&[]));
        assert!(
            matches!(
                result,
                Err(ConfigError::MissingEnv {
                    var: "RYUKI_AGENT_CP_URL"
                })
            ),
            "missing CP_URL must be a MissingEnv error"
        );
    }

    #[test]
    fn errors_on_missing_required_platform() {
        let result =
            AgentConfig::from_source(src(&[("RYUKI_AGENT_CP_URL", "https://cp.example.com")]));
        assert!(
            matches!(
                result,
                Err(ConfigError::MissingEnv {
                    var: "RYUKI_AGENT_PLATFORM"
                })
            ),
            "missing PLATFORM must be a MissingEnv error"
        );
    }

    #[test]
    fn missing_token_env_is_none_not_an_error() {
        // S5: RYUKI_AGENT_TOKEN is no longer required at parse time — the
        // token may come from the token file or first-boot self-registration.
        // Fail-closed still holds: `token::resolve_token` errors at startup
        // when no source provides a token.
        let cfg = AgentConfig::from_source(src(&[
            ("RYUKI_AGENT_CP_URL", "https://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
        ]))
        .expect("config must parse without RYUKI_AGENT_TOKEN");
        assert_eq!(cfg.token, None, "absent env token must parse as None");
    }

    #[test]
    fn errors_on_invalid_poll_interval() {
        let result = AgentConfig::from_source(src(&[
            ("RYUKI_AGENT_CP_URL", "https://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
            ("RYUKI_AGENT_TOKEN", "rya_tok"),
            ("RYUKI_AGENT_POLL_INTERVAL_SECS", "not-a-number"),
        ]));
        assert!(
            matches!(
                result,
                Err(ConfigError::InvalidEnv {
                    var: "RYUKI_AGENT_POLL_INTERVAL_SECS",
                    ..
                })
            ),
            "non-numeric POLL_INTERVAL_SECS must be InvalidEnv"
        );
    }

    #[test]
    fn rejects_empty_required_value() {
        let result = AgentConfig::from_source(src(&[("RYUKI_AGENT_CP_URL", "   ")]));
        assert!(
            matches!(
                result,
                Err(ConfigError::MissingEnv {
                    var: "RYUKI_AGENT_CP_URL"
                })
            ),
            "whitespace-only required value must be treated as missing"
        );
    }

    #[test]
    fn rejects_non_http_scheme() {
        let result = AgentConfig::from_source(src(&[
            ("RYUKI_AGENT_CP_URL", "ftp://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
            ("RYUKI_AGENT_TOKEN", "rya_tok"),
        ]));
        assert!(
            matches!(
                result,
                Err(ConfigError::InvalidEnv {
                    var: "RYUKI_AGENT_CP_URL",
                    ..
                })
            ),
            "non-http(s) scheme must be rejected"
        );
    }

    #[test]
    fn rejects_bad_platform_slug() {
        let result = AgentConfig::from_source(src(&[
            ("RYUKI_AGENT_CP_URL", "https://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "bad/platform"),
            ("RYUKI_AGENT_TOKEN", "rya_tok"),
        ]));
        assert!(
            matches!(
                result,
                Err(ConfigError::InvalidEnv {
                    var: "RYUKI_AGENT_PLATFORM",
                    ..
                })
            ),
            "platform with a slash must be rejected"
        );
    }

    #[test]
    fn accepts_custom_site_platform_with_dot() {
        let cfg = AgentConfig::from_source(src(&[
            ("RYUKI_AGENT_CP_URL", "https://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "DC.EU-01"),
            ("RYUKI_AGENT_TOKEN", "rya_tok"),
        ]))
        .expect("custom site codes containing dots must be valid agent platforms");

        assert_eq!(cfg.platform, "DC.EU-01");
    }

    #[test]
    fn rejects_token_without_rya_prefix() {
        let result = AgentConfig::from_source(src(&[
            ("RYUKI_AGENT_CP_URL", "https://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
            ("RYUKI_AGENT_TOKEN", "abc123"),
        ]));
        assert!(
            matches!(
                result,
                Err(ConfigError::InvalidEnv {
                    var: "RYUKI_AGENT_TOKEN",
                    ..
                })
            ),
            "token without rya_ prefix must be rejected"
        );
    }

    #[test]
    fn explicit_token_path_env_wins_over_default() {
        let cfg = AgentConfig::from_source(src(&[
            ("RYUKI_AGENT_CP_URL", "https://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
            ("RYUKI_AGENT_KEY_PATH", "/etc/ryuki/agent.key"),
            ("RYUKI_AGENT_TOKEN_PATH", "/var/lib/ryuki/agent.token"),
        ]))
        .expect("must parse");
        assert_eq!(
            cfg.token_path,
            PathBuf::from("/var/lib/ryuki/agent.token"),
            "explicit RYUKI_AGENT_TOKEN_PATH must override the next-to-key default"
        );
    }

    #[test]
    fn empty_token_path_env_falls_back_to_default() {
        let cfg = AgentConfig::from_source(src(&[
            ("RYUKI_AGENT_CP_URL", "https://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
            ("RYUKI_AGENT_TOKEN_PATH", "   "),
        ]))
        .expect("must parse");
        assert_eq!(
            cfg.token_path,
            PathBuf::from("agent.token"),
            "whitespace-only RYUKI_AGENT_TOKEN_PATH must be treated as absent"
        );
    }

    #[test]
    fn self_register_parses_like_allow_live() {
        // Absent → false; only "true"/"1" enable; anything else is false.
        let base = [
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
        let with = |val: Option<&str>| {
            let mut pairs: Vec<(&str, &str)> = base.to_vec();
            if let Some(v) = val {
                pairs.push(("RYUKI_AGENT_SELF_REGISTER", v));
            }
            AgentConfig::from_source(src(&pairs)).expect("must parse")
        };
        assert!(!with(None).self_register, "absent must default to false");
        assert!(with(Some("true")).self_register);
        assert!(with(Some("1")).self_register);
        for garbage in ["yes", "TRUE", "on", "0", "false", ""] {
            assert!(
                !with(Some(garbage)).self_register,
                "RYUKI_AGENT_SELF_REGISTER={garbage:?} must be treated as false"
            );
        }
    }

    #[test]
    fn self_registration_requires_a_complete_canonical_challenge() {
        let missing = AgentConfig::from_source(src(&[
            ("RYUKI_AGENT_CP_URL", "https://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
            ("RYUKI_AGENT_SELF_REGISTER", "true"),
        ]));
        assert!(matches!(
            missing,
            Err(ConfigError::MissingEnv {
                var: "RYUKI_AGENT_ENROLLMENT_CHALLENGE_ID"
            })
        ));

        let malformed = AgentConfig::from_source(src(&[
            ("RYUKI_AGENT_CP_URL", "https://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
            ("RYUKI_AGENT_SELF_REGISTER", "true"),
            (
                "RYUKI_AGENT_ENROLLMENT_CHALLENGE_ID",
                "00000000-0000-0000-0000-000000000001",
            ),
            ("RYUKI_AGENT_ENROLLMENT_CHALLENGE", "ryc_NOT-SECRET"),
        ]));
        assert!(matches!(
            malformed,
            Err(ConfigError::InvalidEnv {
                var: "RYUKI_AGENT_ENROLLMENT_CHALLENGE",
                value,
                ..
            }) if value == "<redacted>"
        ));
    }

    #[test]
    fn rejects_zero_poll_interval() {
        let result = AgentConfig::from_source(src(&[
            ("RYUKI_AGENT_CP_URL", "https://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
            ("RYUKI_AGENT_TOKEN", "rya_tok"),
            ("RYUKI_AGENT_POLL_INTERVAL_SECS", "0"),
        ]));
        assert!(
            matches!(
                result,
                Err(ConfigError::InvalidEnv {
                    var: "RYUKI_AGENT_POLL_INTERVAL_SECS",
                    ..
                })
            ),
            "a zero poll interval must be rejected (would busy-loop)"
        );
    }

    #[test]
    fn remote_cleartext_is_rejected_for_every_execution_mode() {
        for allow_live in ["false", "true"] {
            let result = AgentConfig::from_source(src(&[
                ("RYUKI_AGENT_CP_URL", "http://cp.example.com"),
                ("RYUKI_AGENT_PLATFORM", "defra"),
                ("RYUKI_AGENT_TOKEN", "rya_tok"),
                ("RYUKI_AGENT_ALLOW_LIVE", allow_live),
            ]));
            assert!(
                matches!(
                    result,
                    Err(ConfigError::InvalidEnv {
                        var: "RYUKI_AGENT_CP_URL",
                        ..
                    })
                ),
                "remote HTTP must be rejected when allow_live={allow_live}"
            );
        }
    }

    #[test]
    fn explicit_switch_does_not_admit_remote_cleartext() {
        let result = AgentConfig::from_source(src(&[
            ("RYUKI_AGENT_CP_URL", "http://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
            ("RYUKI_AGENT_TOKEN", "rya_tok"),
            ("RYUKI_AGENT_ALLOW_INSECURE_LOOPBACK", "true"),
        ]));
        assert!(
            matches!(
                result,
                Err(ConfigError::InvalidEnv {
                    var: "RYUKI_AGENT_CP_URL",
                    ..
                })
            ),
            "the development switch must never admit a remote HTTP host"
        );
    }

    #[test]
    fn invalid_transport_fails_before_credential_configuration_is_read() {
        let result = AgentConfig::from_source(|var| {
            match var {
            "RYUKI_AGENT_CP_URL" => Some("http://cp.example.com".to_owned()),
            "RYUKI_AGENT_ALLOW_INSECURE_LOOPBACK" => None,
            other => panic!(
                "transport rejection must dominate platform/token/file/self-registration reads; accessed {other}"
            ),
        }
        });
        assert!(matches!(
            result,
            Err(ConfigError::InvalidEnv {
                var: "RYUKI_AGENT_CP_URL",
                ..
            })
        ));
    }

    #[test]
    fn allow_live_over_https_is_allowed() {
        let cfg = AgentConfig::from_source(src(&[
            ("RYUKI_AGENT_CP_URL", "https://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
            ("RYUKI_AGENT_TOKEN", "rya_tok"),
            ("RYUKI_AGENT_ALLOW_LIVE", "true"),
        ]))
        .expect("allow_live over https must be accepted");
        assert!(cfg.allow_live);
    }

    #[test]
    fn loopback_http_requires_explicit_switch() {
        let result = AgentConfig::from_source(src(&[
            ("RYUKI_AGENT_CP_URL", "http://127.0.0.1:8081"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
            ("RYUKI_AGENT_TOKEN", "rya_tok"),
        ]));
        assert!(
            matches!(
                result,
                Err(ConfigError::InvalidEnv {
                    var: "RYUKI_AGENT_CP_URL",
                    ..
                })
            ),
            "loopback HTTP must be rejected without the dedicated opt-in"
        );
    }

    #[test]
    fn explicit_switch_admits_only_loopback_http() {
        for url in [
            "http://127.0.0.1:8081",
            "http://127.42.7.9:8081",
            "http://localhost:8080",
            "http://[::1]:8081",
        ] {
            let cfg = AgentConfig::from_source(src(&[
                ("RYUKI_AGENT_CP_URL", url),
                ("RYUKI_AGENT_PLATFORM", "defra"),
                ("RYUKI_AGENT_TOKEN", "rya_tok"),
                ("RYUKI_AGENT_ALLOW_INSECURE_LOOPBACK", "true"),
                ("RYUKI_AGENT_ALLOW_LIVE", "true"),
            ]))
            .unwrap_or_else(|e| panic!("explicit loopback endpoint {url} must be accepted: {e}"));
            assert!(cfg.allow_live);
            assert!(cfg.allow_insecure_loopback);
            assert!(cfg.cp_base_url.is_insecure_loopback());
        }
    }

    #[test]
    fn insecure_loopback_switch_uses_strict_opt_in_values() {
        for enabled in ["true", "1"] {
            let cfg = AgentConfig::from_source(src(&[
                ("RYUKI_AGENT_CP_URL", "http://127.0.0.1:8081"),
                ("RYUKI_AGENT_PLATFORM", "defra"),
                ("RYUKI_AGENT_ALLOW_INSECURE_LOOPBACK", enabled),
            ]))
            .expect("true/1 must enable loopback HTTP");
            assert!(cfg.allow_insecure_loopback);
        }
        for disabled in ["yes", "TRUE", "on", "0", "false", ""] {
            let result = AgentConfig::from_source(src(&[
                ("RYUKI_AGENT_CP_URL", "http://127.0.0.1:8081"),
                ("RYUKI_AGENT_PLATFORM", "defra"),
                ("RYUKI_AGENT_ALLOW_INSECURE_LOOPBACK", disabled),
            ]));
            assert!(
                result.is_err(),
                "{disabled:?} must not enable the loopback HTTP exception"
            );
        }
    }

    #[test]
    fn malformed_or_unsafe_control_plane_urls_are_rejected_and_redacted() {
        for url in [
            "http://127.0.0.1.evil.com",
            "http://localhost.evil.example",
            "http://0.0.0.0:8081",
            "https://0.0.0.0:8443",
            "https://[::]:8443",
            "http://localhost:8081@evil.example",
            "http://@localhost:8081",
            "https://user@cp.example.com",
            "https://cp.example.com?next=http://evil.example",
            "https://cp.example.com#fragment",
            "https://",
        ] {
            let result = AgentConfig::from_source(src(&[
                ("RYUKI_AGENT_CP_URL", url),
                ("RYUKI_AGENT_PLATFORM", "defra"),
                ("RYUKI_AGENT_ALLOW_INSECURE_LOOPBACK", "true"),
            ]));
            match result {
                Err(ConfigError::InvalidEnv {
                    var,
                    value,
                    reason: _,
                }) => {
                    assert_eq!(var, "RYUKI_AGENT_CP_URL", "unexpected error for {url}");
                    assert_eq!(value, "<redacted>", "rejected URL must not enter logs");
                }
                other => panic!("unsafe URL {url:?} must be rejected, got {other:?}"),
            }
        }
    }

    #[test]
    fn debug_redacts_token() {
        let cfg = AgentConfig::from_source(src(&[
            ("RYUKI_AGENT_CP_URL", "https://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
            ("RYUKI_AGENT_TOKEN", "rya_supersecret"),
            (
                "RYUKI_AGENT_ENROLLMENT_CHALLENGE_ID",
                "00000000-0000-0000-0000-000000000001",
            ),
            (
                "RYUKI_AGENT_ENROLLMENT_CHALLENGE",
                "ryc_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
        ]))
        .expect("must parse");
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("rya_supersecret"),
            "Debug output must not contain the token"
        );
        assert!(dbg.contains("<redacted>"), "Debug must show <redacted>");
        assert!(
            !dbg.contains("0123456789abcdef0123456789abcdef"),
            "Debug output must not contain the one-time enrollment challenge"
        );
    }

    // -----------------------------------------------------------------------
    // allow_live parsing
    // -----------------------------------------------------------------------

    fn cfg_with_allow_live(val: Option<&str>) -> AgentConfig {
        let base = [
            ("RYUKI_AGENT_CP_URL", "https://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
            ("RYUKI_AGENT_TOKEN", "rya_tok"),
        ];
        let mut map: std::collections::HashMap<String, String> = base
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        if let Some(v) = val {
            map.insert("RYUKI_AGENT_ALLOW_LIVE".to_owned(), v.to_owned());
        }
        AgentConfig::from_source(|k| map.get(k).cloned()).expect("must parse")
    }

    #[test]
    fn allow_live_absent_is_false() {
        // Safe default: absence of the env var must produce false.
        let cfg = cfg_with_allow_live(None);
        assert!(
            !cfg.allow_live,
            "absent RYUKI_AGENT_ALLOW_LIVE must default to false"
        );
    }

    #[test]
    fn allow_live_true_string_enables() {
        let cfg = cfg_with_allow_live(Some("true"));
        assert!(
            cfg.allow_live,
            "RYUKI_AGENT_ALLOW_LIVE=true must enable allow_live"
        );
    }

    #[test]
    fn allow_live_one_string_enables() {
        let cfg = cfg_with_allow_live(Some("1"));
        assert!(
            cfg.allow_live,
            "RYUKI_AGENT_ALLOW_LIVE=1 must enable allow_live"
        );
    }

    #[test]
    fn allow_live_garbage_is_false() {
        // Typos and unrecognised values must silently fall back to false (fail-safe).
        for garbage in &["yes", "TRUE", "True", "on", "enabled", "0", "false", ""] {
            let cfg = cfg_with_allow_live(Some(garbage));
            assert!(
                !cfg.allow_live,
                "RYUKI_AGENT_ALLOW_LIVE={garbage:?} must be treated as false (fail-safe)"
            );
        }
    }

    // -----------------------------------------------------------------------
    // max_outbox_attempts + outbox_drain_interval_secs
    // -----------------------------------------------------------------------

    fn base_src() -> impl Fn(&str) -> Option<String> {
        src(&[
            ("RYUKI_AGENT_CP_URL", "https://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
            ("RYUKI_AGENT_TOKEN", "rya_tok"),
        ])
    }

    #[test]
    fn max_outbox_attempts_default_is_10() {
        let cfg = AgentConfig::from_source(base_src()).expect("must parse");
        assert_eq!(cfg.max_outbox_attempts, 10);
    }

    #[test]
    fn max_outbox_attempts_custom_parses() {
        let s = src(&[
            ("RYUKI_AGENT_CP_URL", "https://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
            ("RYUKI_AGENT_TOKEN", "rya_tok"),
            ("RYUKI_AGENT_MAX_OUTBOX_ATTEMPTS", "5"),
        ]);
        let cfg = AgentConfig::from_source(s).expect("must parse");
        assert_eq!(cfg.max_outbox_attempts, 5);
    }

    #[test]
    fn max_outbox_attempts_rejects_zero() {
        let s = src(&[
            ("RYUKI_AGENT_CP_URL", "https://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
            ("RYUKI_AGENT_TOKEN", "rya_tok"),
            ("RYUKI_AGENT_MAX_OUTBOX_ATTEMPTS", "0"),
        ]);
        let result = AgentConfig::from_source(s);
        assert!(
            matches!(
                result,
                Err(ConfigError::InvalidEnv {
                    var: "RYUKI_AGENT_MAX_OUTBOX_ATTEMPTS",
                    ..
                })
            ),
            "zero max_outbox_attempts must be rejected"
        );
    }

    #[test]
    fn outbox_drain_interval_default_is_60() {
        let cfg = AgentConfig::from_source(base_src()).expect("must parse");
        assert_eq!(cfg.outbox_drain_interval_secs, 60);
    }

    #[test]
    fn outbox_drain_interval_custom_parses() {
        let s = src(&[
            ("RYUKI_AGENT_CP_URL", "https://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
            ("RYUKI_AGENT_TOKEN", "rya_tok"),
            ("RYUKI_AGENT_OUTBOX_DRAIN_INTERVAL_SECS", "120"),
        ]);
        let cfg = AgentConfig::from_source(s).expect("must parse");
        assert_eq!(cfg.outbox_drain_interval_secs, 120);
    }

    #[test]
    fn outbox_drain_interval_rejects_zero() {
        let s = src(&[
            ("RYUKI_AGENT_CP_URL", "https://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
            ("RYUKI_AGENT_TOKEN", "rya_tok"),
            ("RYUKI_AGENT_OUTBOX_DRAIN_INTERVAL_SECS", "0"),
        ]);
        let result = AgentConfig::from_source(s);
        assert!(
            matches!(
                result,
                Err(ConfigError::InvalidEnv {
                    var: "RYUKI_AGENT_OUTBOX_DRAIN_INTERVAL_SECS",
                    ..
                })
            ),
            "zero drain interval must be rejected"
        );
    }
}
