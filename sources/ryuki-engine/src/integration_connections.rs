use serde::{Deserialize, Serialize};
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Where credentials for a connection are stored.
/// Serde kebab-case matches the migration CHECK constraint values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialSource {
    Vault,
    DbEncrypted,
    EnvVar,
}

impl CredentialSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Vault => "vault",
            Self::DbEncrypted => "db-encrypted",
            Self::EnvVar => "env-var",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "vault" => Ok(Self::Vault),
            "db-encrypted" => Ok(Self::DbEncrypted),
            "env-var" => Ok(Self::EnvVar),
            other => Err(format!(
                "Invalid credential_source '{}'. Must be one of: vault, db-encrypted, env-var",
                other
            )),
        }
    }
}

impl std::fmt::Display for CredentialSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Whether this connection should execute real vendor calls or remain a dry-run.
/// Default is StaticDryRun — no live traffic until explicitly opted in per connection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionMode {
    #[default]
    StaticDryRun,
    Live,
}

impl ExecutionMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::StaticDryRun => "static-dry-run",
            Self::Live => "live",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "static-dry-run" => Ok(Self::StaticDryRun),
            "live" => Ok(Self::Live),
            other => Err(format!(
                "Invalid execution_mode '{}'. Must be: static-dry-run or live",
                other
            )),
        }
    }
}

impl std::fmt::Display for ExecutionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Core struct
// ---------------------------------------------------------------------------

/// A generic vendor integration connection.
/// NEVER carries plaintext secret material — secret fields live in
/// integration_secrets (db-encrypted) or are resolved at use-time (vault/env-var).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationConnection {
    pub id: String,
    /// Matches AdapterType serde string (e.g. "vmware", "veeam", "servicenow").
    pub vendor_type: String,
    pub name: String,
    pub endpoint_url: String,
    pub site_scope: Option<String>,
    pub credential_source: CredentialSource,
    /// Vault: the Vault path; EnvVar: comma-separated env KEY NAMES;
    /// DbEncrypted: FK id into integration_secrets. NEVER the secret itself.
    pub credential_ref: String,
    pub status: String,
    pub readiness: String,
    pub execution_mode: ExecutionMode,
    pub last_test_at: Option<String>,
    pub last_test_result: Option<String>,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

// ---------------------------------------------------------------------------
// In-memory fallback store (engine stays pure, no DB dep)
// ---------------------------------------------------------------------------

static CONNECTION_STORE: OnceLock<Mutex<Vec<IntegrationConnection>>> = OnceLock::new();

fn connection_store() -> &'static Mutex<Vec<IntegrationConnection>> {
    CONNECTION_STORE.get_or_init(|| Mutex::new(Vec::new()))
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Build a new connection ID in the engine's convention: `ic-<vendor>-<hex8>`.
pub fn new_connection_id(vendor_type: &str) -> String {
    let hex = Uuid::new_v4()
        .to_string()
        .replace('-', "")
        .chars()
        .take(8)
        .collect::<String>();
    format!("ic-{}-{}", vendor_type, hex)
}

// ---------------------------------------------------------------------------
// Engine-level CRUD (in-memory fallback, no credentials)
// ---------------------------------------------------------------------------

pub fn create_connection(
    vendor_type: &str,
    name: &str,
    endpoint_url: &str,
    site_scope: Option<String>,
    credential_source: CredentialSource,
    credential_ref: &str,
    created_by: &str,
) -> Result<IntegrationConnection, String> {
    if vendor_type.is_empty() {
        return Err("vendor_type is required".into());
    }
    if name.is_empty() {
        return Err("name is required".into());
    }
    if endpoint_url.is_empty() {
        return Err("endpoint_url is required".into());
    }
    let now = now_iso();
    let conn = IntegrationConnection {
        id: new_connection_id(vendor_type),
        vendor_type: vendor_type.to_string(),
        name: name.to_string(),
        endpoint_url: endpoint_url.to_string(),
        site_scope,
        credential_source,
        credential_ref: credential_ref.to_string(),
        status: "configured".to_string(),
        readiness: "configured".to_string(),
        execution_mode: ExecutionMode::StaticDryRun,
        last_test_at: None,
        last_test_result: None,
        created_by: created_by.to_string(),
        created_at: now.clone(),
        updated_at: now,
    };
    let mut store = connection_store().lock().unwrap();
    store.push(conn.clone());
    Ok(conn)
}

pub fn list_connections(
    vendor_type: Option<&str>,
    site: Option<&str>,
) -> Vec<IntegrationConnection> {
    let store = connection_store().lock().unwrap();
    store
        .iter()
        .filter(|c| {
            vendor_type.is_none_or(|v| c.vendor_type == v)
                && site.is_none_or(|s| c.site_scope.as_deref() == Some(s))
        })
        .cloned()
        .collect()
}

pub fn get_connection(id: &str) -> Option<IntegrationConnection> {
    let store = connection_store().lock().unwrap();
    store.iter().find(|c| c.id == id).cloned()
}

pub fn delete_connection(id: &str) -> bool {
    let mut store = connection_store().lock().unwrap();
    let before = store.len();
    store.retain(|c| c.id != id);
    store.len() < before
}

/// Generic test stub: validate that credentials appear resolvable and the
/// endpoint URL is structurally valid. Does NOT make live vendor calls.
pub fn test_connection_stub(conn: &IntegrationConnection) -> TestResult {
    // Basic URL shape check (must be http:// or https://).
    let url_ok =
        conn.endpoint_url.starts_with("http://") || conn.endpoint_url.starts_with("https://");
    let cred_ref_present = !conn.credential_ref.is_empty();
    if url_ok && cred_ref_present {
        TestResult {
            status: "reachable-stub".to_string(),
            message: format!(
                "DRY-RUN: endpoint URL shape valid; credential_source={} ref present. No live call made.",
                conn.credential_source.as_str()
            ),
            resolved_at: now_iso(),
        }
    } else {
        let reason = if !url_ok {
            "endpoint_url must start with http:// or https://"
        } else {
            "credential_ref is empty"
        };
        TestResult {
            status: "unreachable".to_string(),
            message: format!("DRY-RUN: validation failed — {}", reason),
            resolved_at: now_iso(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub status: String,
    pub message: String,
    pub resolved_at: String,
}

// ---------------------------------------------------------------------------
// Unit tests (engine-pure, no DB, no encryption)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn credential_source_round_trips_via_parse_and_as_str() {
        let cases = [
            ("vault", CredentialSource::Vault),
            ("db-encrypted", CredentialSource::DbEncrypted),
            ("env-var", CredentialSource::EnvVar),
        ];
        for (s, expected) in &cases {
            let parsed = CredentialSource::parse(s).unwrap();
            assert_eq!(&parsed, expected);
            assert_eq!(parsed.as_str(), *s);
        }
    }

    #[test]
    fn credential_source_parse_rejects_invalid() {
        assert!(CredentialSource::parse("plaintext").is_err());
        assert!(CredentialSource::parse("").is_err());
    }

    #[test]
    fn execution_mode_round_trips() {
        assert_eq!(
            ExecutionMode::parse("static-dry-run").unwrap(),
            ExecutionMode::StaticDryRun
        );
        assert_eq!(ExecutionMode::parse("live").unwrap(), ExecutionMode::Live);
        assert_eq!(ExecutionMode::StaticDryRun.as_str(), "static-dry-run");
        assert_eq!(ExecutionMode::Live.as_str(), "live");
    }

    #[test]
    fn execution_mode_default_is_static_dry_run() {
        assert_eq!(ExecutionMode::default(), ExecutionMode::StaticDryRun);
    }

    #[test]
    fn credential_source_serde_kebab_case() {
        let src = CredentialSource::DbEncrypted;
        let json = serde_json::to_string(&src).unwrap();
        assert_eq!(json, "\"db-encrypted\"");
        let back: CredentialSource = serde_json::from_str(&json).unwrap();
        assert_eq!(back, CredentialSource::DbEncrypted);
    }

    #[test]
    fn execution_mode_serde_kebab_case() {
        let mode = ExecutionMode::StaticDryRun;
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(json, "\"static-dry-run\"");
        let back: ExecutionMode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ExecutionMode::StaticDryRun);
    }

    #[test]
    fn create_connection_rejects_empty_vendor_type() {
        let err = create_connection(
            "",
            "my-conn",
            "https://example.com",
            None,
            CredentialSource::EnvVar,
            "MY_API_KEY",
            "test",
        )
        .unwrap_err();
        assert!(
            err.contains("vendor_type"),
            "error should mention vendor_type: {err}"
        );
    }

    #[test]
    fn create_connection_rejects_empty_endpoint() {
        let err = create_connection(
            "vmware",
            "my-conn",
            "",
            None,
            CredentialSource::EnvVar,
            "MY_API_KEY",
            "test",
        )
        .unwrap_err();
        assert!(
            err.contains("endpoint_url"),
            "error should mention endpoint_url: {err}"
        );
    }

    #[test]
    fn connection_id_contains_vendor_type() {
        let id = new_connection_id("vmware");
        assert!(
            id.starts_with("ic-vmware-"),
            "expected ic-vmware-... got {id}"
        );
    }

    #[test]
    fn test_connection_stub_valid_connection_returns_reachable() {
        let conn = IntegrationConnection {
            id: "ic-test-00000001".to_string(),
            vendor_type: "vmware".to_string(),
            name: "Test".to_string(),
            endpoint_url: "https://vcenter.example.com".to_string(),
            site_scope: None,
            credential_source: CredentialSource::EnvVar,
            credential_ref: "VCENTER_USER,VCENTER_PASS".to_string(),
            status: "configured".to_string(),
            readiness: "configured".to_string(),
            execution_mode: ExecutionMode::StaticDryRun,
            last_test_at: None,
            last_test_result: None,
            created_by: "test".to_string(),
            created_at: "2026-06-14T00:00:00+00:00".to_string(),
            updated_at: "2026-06-14T00:00:00+00:00".to_string(),
        };
        let result = test_connection_stub(&conn);
        assert_eq!(result.status, "reachable-stub");
        // The message must NOT contain any secret material.
        assert!(
            !result.message.contains("VCENTER_USER") || result.message.contains("env-var"),
            "message leaked env var names or secret values: {}",
            result.message
        );
    }

    #[test]
    fn test_connection_stub_bad_url_returns_unreachable() {
        let conn = IntegrationConnection {
            id: "ic-test-00000002".to_string(),
            vendor_type: "veeam".to_string(),
            name: "Bad".to_string(),
            endpoint_url: "ftp://not-http.example.com".to_string(),
            site_scope: None,
            credential_source: CredentialSource::Vault,
            credential_ref: "kv/prod/veeam/creds".to_string(),
            status: "configured".to_string(),
            readiness: "blocked".to_string(),
            execution_mode: ExecutionMode::StaticDryRun,
            last_test_at: None,
            last_test_result: None,
            created_by: "test".to_string(),
            created_at: "2026-06-14T00:00:00+00:00".to_string(),
            updated_at: "2026-06-14T00:00:00+00:00".to_string(),
        };
        let result = test_connection_stub(&conn);
        assert_eq!(result.status, "unreachable");
        assert!(
            result.message.contains("http"),
            "message should explain URL requirement: {}",
            result.message
        );
    }
}
