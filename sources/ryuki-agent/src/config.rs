//! Agent configuration — loaded from environment variables.
//!
//! ## Required variables
//!
//! | Env var                         | Field           | Notes                          |
//! |---------------------------------|-----------------|--------------------------------|
//! | `RYUKI_AGENT_CP_URL`            | `cp_base_url`   | e.g. `https://ryuki.example/`  |
//! | `RYUKI_AGENT_PLATFORM`          | `platform`      | e.g. `defra`                   |
//! | `RYUKI_AGENT_TOKEN`             | `token`         | Bearer token (rya_ prefix)     |
//!
//! ## Optional variables (defaults shown)
//!
//! | Env var                         | Field               | Default |
//! |---------------------------------|---------------------|---------|
//! | `RYUKI_AGENT_KEY_PATH`          | `key_path`          | `agent.key` (cwd) |
//! | `RYUKI_AGENT_POLL_INTERVAL_SECS`| `poll_interval_secs`| 10      |
//! | `RYUKI_AGENT_LEASE_SECS`        | `lease_secs`        | 300     |
//! | `RYUKI_AGENT_ALLOW_LIVE`        | `allow_live`        | `false` |
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

use ryuki_protocol::Capabilities;

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
    /// Base URL of the Ryuki control plane (e.g. `https://ryuki.example.com`).
    /// Trailing slash is stripped on construction so callers can always append
    /// a path directly.
    pub cp_base_url: String,

    /// Platform / site identifier this agent serves (e.g. `defra`).
    pub platform: String,

    /// Bearer token issued by the CP on successful registration.
    /// Must start with `rya_`.  Used by S4b to construct `CpClient`.
    #[allow(dead_code)]
    pub token: String,

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
}

impl std::fmt::Debug for AgentConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentConfig")
            .field("cp_base_url", &self.cp_base_url)
            .field("platform", &self.platform)
            .field("token", &"<redacted>")
            .field("key_path", &self.key_path)
            .field("poll_interval_secs", &self.poll_interval_secs)
            .field("lease_secs", &self.lease_secs)
            .field("capabilities", &self.capabilities)
            .field("allow_live", &self.allow_live)
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
        let cp_base_url = require(&get, "RYUKI_AGENT_CP_URL")?;
        // Strip trailing slash for consistent path construction.
        let cp_base_url = cp_base_url.trim_end_matches('/').to_owned();
        // The bearer token is sent on every request, so the transport must be
        // a URL we recognise. (HTTPS is not hard-required because the e2e tests
        // and local runs use http://127.0.0.1; main.rs warns on cleartext.)
        if !(cp_base_url.starts_with("http://") || cp_base_url.starts_with("https://")) {
            return Err(ConfigError::InvalidEnv {
                var: "RYUKI_AGENT_CP_URL",
                value: cp_base_url,
                reason: "must start with http:// or https://".to_owned(),
            });
        }

        let platform = require(&get, "RYUKI_AGENT_PLATFORM")?;
        // platform is interpolated into URL path segments, so constrain it to a
        // safe slug (alphanumeric, '-', '_') — no slashes, spaces, or other
        // characters that could alter the request path.
        if !is_slug(&platform) {
            return Err(ConfigError::InvalidEnv {
                var: "RYUKI_AGENT_PLATFORM",
                value: platform,
                reason: "must be a slug: ASCII alphanumeric, '-' or '_' only".to_owned(),
            });
        }

        let token = require(&get, "RYUKI_AGENT_TOKEN")?;
        // The CP only accepts agent tokens with the `rya_` prefix; fail early
        // with a clear message instead of getting 401 on every request.
        if !token.starts_with("rya_") {
            return Err(ConfigError::InvalidEnv {
                var: "RYUKI_AGENT_TOKEN",
                value: "<redacted>".to_owned(),
                reason: "agent token must start with 'rya_'".to_owned(),
            });
        }

        let key_path = get("RYUKI_AGENT_KEY_PATH").unwrap_or_else(|| "agent.key".to_owned());
        let key_path = PathBuf::from(key_path);

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

        // SECURITY: a live-capable agent bootstraps trust by fetching the CP
        // public key over `cp_base_url` (then verifying every grant against it).
        // Over cleartext http:// a network MITM could substitute its own key and
        // forge approval grants — so live execution requires https://, except a
        // loopback URL (local dev / the e2e harness). Fail closed at startup.
        if allow_live && cp_base_url.starts_with("http://") && !is_loopback_url(&cp_base_url) {
            return Err(ConfigError::InvalidEnv {
                var: "RYUKI_AGENT_ALLOW_LIVE",
                value: "true".to_owned(),
                reason: format!(
                    "live execution requires an https:// control-plane URL (got cleartext \
                     {cp_base_url}); a MITM over http:// could substitute the CP signing key and \
                     forge grants. Use https://, or a loopback URL for local testing"
                ),
            });
        }

        Ok(Self {
            cp_base_url,
            platform,
            token,
            key_path,
            poll_interval_secs,
            lease_secs,
            capabilities: Capabilities::default(),
            allow_live,
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

/// True if `url` (http:// or https://) targets a loopback authority. Used to
/// allow cleartext only for local dev/test. The authority is matched exactly (or
/// with a `:port`) so a hostname like `127.0.0.1.evil.com` is NOT treated as
/// loopback.
fn is_loopback_url(url: &str) -> bool {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    // Authority is everything up to the first '/'.
    let authority = rest.split('/').next().unwrap_or(rest);
    const LOOPBACKS: &[&str] = &["localhost", "127.0.0.1", "[::1]", "0.0.0.0"];
    LOOPBACKS
        .iter()
        .any(|h| authority == *h || authority.starts_with(&format!("{h}:")))
}

/// True if `s` is a non-empty ASCII slug (alphanumeric, '-' or '_').
fn is_slug(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
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
        // Trailing slash must be stripped.
        assert_eq!(cfg.cp_base_url, "https://cp.example.com");
        assert_eq!(cfg.platform, "defra");
        assert_eq!(cfg.token, "rya_abc123");
        assert_eq!(cfg.key_path, PathBuf::from("/etc/ryuki/agent.key"));
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
    fn errors_on_missing_required_token() {
        let result = AgentConfig::from_source(src(&[
            ("RYUKI_AGENT_CP_URL", "https://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
        ]));
        assert!(
            matches!(
                result,
                Err(ConfigError::MissingEnv {
                    var: "RYUKI_AGENT_TOKEN"
                })
            ),
            "missing TOKEN must be a MissingEnv error"
        );
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
    fn allow_live_over_cleartext_remote_is_rejected() {
        let result = AgentConfig::from_source(src(&[
            ("RYUKI_AGENT_CP_URL", "http://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
            ("RYUKI_AGENT_TOKEN", "rya_tok"),
            ("RYUKI_AGENT_ALLOW_LIVE", "true"),
        ]));
        assert!(
            matches!(
                result,
                Err(ConfigError::InvalidEnv {
                    var: "RYUKI_AGENT_ALLOW_LIVE",
                    ..
                })
            ),
            "allow_live over cleartext http:// to a remote host must be rejected"
        );
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
    fn allow_live_over_loopback_http_is_allowed() {
        // Local dev / e2e harness uses http://127.0.0.1.
        for url in [
            "http://127.0.0.1:8081",
            "http://localhost:8080",
            "http://[::1]:8081",
        ] {
            let cfg = AgentConfig::from_source(src(&[
                ("RYUKI_AGENT_CP_URL", url),
                ("RYUKI_AGENT_PLATFORM", "defra"),
                ("RYUKI_AGENT_TOKEN", "rya_tok"),
                ("RYUKI_AGENT_ALLOW_LIVE", "true"),
            ]))
            .unwrap_or_else(|e| panic!("allow_live over loopback {url} must be accepted: {e}"));
            assert!(cfg.allow_live);
        }
    }

    #[test]
    fn cleartext_remote_allowed_when_live_disabled() {
        // Without allow_live the agent only does OfflineDryRun; cleartext is
        // permitted (a warning is logged) since no CP-key trust is bootstrapped.
        let cfg = AgentConfig::from_source(src(&[
            ("RYUKI_AGENT_CP_URL", "http://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
            ("RYUKI_AGENT_TOKEN", "rya_tok"),
        ]))
        .expect("cleartext is allowed when live is disabled");
        assert!(!cfg.allow_live);
    }

    #[test]
    fn loopback_lookalike_host_is_not_loopback() {
        // A hostname that merely STARTS WITH a loopback literal must not be
        // treated as loopback.
        let result = AgentConfig::from_source(src(&[
            ("RYUKI_AGENT_CP_URL", "http://127.0.0.1.evil.com"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
            ("RYUKI_AGENT_TOKEN", "rya_tok"),
            ("RYUKI_AGENT_ALLOW_LIVE", "true"),
        ]));
        assert!(
            result.is_err(),
            "a loopback-lookalike host must not bypass the https requirement"
        );
    }

    #[test]
    fn debug_redacts_token() {
        let cfg = AgentConfig::from_source(src(&[
            ("RYUKI_AGENT_CP_URL", "https://cp.example.com"),
            ("RYUKI_AGENT_PLATFORM", "defra"),
            ("RYUKI_AGENT_TOKEN", "rya_supersecret"),
        ]))
        .expect("must parse");
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("rya_supersecret"),
            "Debug output must not contain the token"
        );
        assert!(dbg.contains("<redacted>"), "Debug must show <redacted>");
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
}
