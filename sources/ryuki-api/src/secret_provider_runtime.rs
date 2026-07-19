//! Production Vault Kubernetes workload-authentication runtime.
//!
//! This module owns provider authentication, the client-token lease, and the
//! bounded KV-v2 read that consumes that lease without exporting its bearer.
//! Higher-level secret selection remains a separate typed capability. A caller
//! must retain this runtime and drive [`VaultKubernetesRuntime::maintenance_step`]
//! from an admitted lifecycle task before using it as a production resolver.

use base64::Engine as _;
use chrono::{DateTime, Utc};
use reqwest::header::HeaderValue;
use reqwest::{Certificate, Client, Response, Url};
use ryuki_core::conformance_trust::canonical_json_bytes;
use ryuki_engine::secret_material::{
    IssuedSecretLease, ResolvedSecret, SecretLeaseLifecycleInput, SecretLeaseMetadata,
    SecretLeaseRevocationOwner, SecretMaterial, SecretRef, SecretResolutionContext,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::future::Future;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

use crate::security_contracts::VerifiedSecretProviderRuntimeBinding;

pub const VAULT_PROJECTED_TOKEN_PATH: &str = "/var/run/secrets/ryuki/vault-auth/token";
pub const VAULT_CA_BUNDLE_PATH: &str = "/var/run/secrets/ryuki/vault-tls/ca.crt";
pub const SECRET_REFERENCE_FINGERPRINT_KEYRING_PATH: &str =
    "/var/run/secrets/ryuki/secret-reference-fingerprint/keyring";
pub const SECRET_REFERENCE_FINGERPRINT_KEYRING_PATH_ENV: &str =
    "RYUKI_SECRET_REFERENCE_FINGERPRINT_KEYRING_PATH";

const RUNTIME_ENV_PREFIX: &str = "RYUKI_SECRET_PROVIDER_RUNTIME__";
const RUNTIME_ENV_PROVIDER_ID: &str = "RYUKI_SECRET_PROVIDER_RUNTIME__PROVIDER_ID";
const RUNTIME_ENV_CONFIGURATION_VERSION: &str =
    "RYUKI_SECRET_PROVIDER_RUNTIME__CONFIGURATION_VERSION";
const RUNTIME_ENV_API_FLAVOR: &str = "RYUKI_SECRET_PROVIDER_RUNTIME__API_FLAVOR";
const RUNTIME_ENV_ENDPOINT: &str = "RYUKI_SECRET_PROVIDER_RUNTIME__ENDPOINT";
const RUNTIME_ENV_CA_BUNDLE_PATH: &str = "RYUKI_SECRET_PROVIDER_RUNTIME__CA_BUNDLE_PATH";
const RUNTIME_ENV_KUBERNETES_AUTH_MOUNT: &str =
    "RYUKI_SECRET_PROVIDER_RUNTIME__KUBERNETES_AUTH_MOUNT";
const RUNTIME_ENV_KUBERNETES_ROLE: &str = "RYUKI_SECRET_PROVIDER_RUNTIME__KUBERNETES_ROLE";
const RUNTIME_ENV_KUBERNETES_AUDIENCE: &str = "RYUKI_SECRET_PROVIDER_RUNTIME__KUBERNETES_AUDIENCE";
const RUNTIME_ENV_PROJECTED_TOKEN_PATH: &str =
    "RYUKI_SECRET_PROVIDER_RUNTIME__PROJECTED_TOKEN_PATH";
const RUNTIME_ENV_EXPECTED_SERVICE_ACCOUNT_NAMESPACE: &str =
    "RYUKI_SECRET_PROVIDER_RUNTIME__EXPECTED_SERVICE_ACCOUNT_NAMESPACE";
const RUNTIME_ENV_EXPECTED_SERVICE_ACCOUNT_NAME: &str =
    "RYUKI_SECRET_PROVIDER_RUNTIME__EXPECTED_SERVICE_ACCOUNT_NAME";
const RUNTIME_ENV_EXPECTED_TOKEN_POLICY: &str =
    "RYUKI_SECRET_PROVIDER_RUNTIME__EXPECTED_TOKEN_POLICY";
const RUNTIME_ENV_KEYS: [&str; 12] = [
    RUNTIME_ENV_PROVIDER_ID,
    RUNTIME_ENV_CONFIGURATION_VERSION,
    RUNTIME_ENV_API_FLAVOR,
    RUNTIME_ENV_ENDPOINT,
    RUNTIME_ENV_CA_BUNDLE_PATH,
    RUNTIME_ENV_KUBERNETES_AUTH_MOUNT,
    RUNTIME_ENV_KUBERNETES_ROLE,
    RUNTIME_ENV_KUBERNETES_AUDIENCE,
    RUNTIME_ENV_PROJECTED_TOKEN_PATH,
    RUNTIME_ENV_EXPECTED_SERVICE_ACCOUNT_NAMESPACE,
    RUNTIME_ENV_EXPECTED_SERVICE_ACCOUNT_NAME,
    RUNTIME_ENV_EXPECTED_TOKEN_POLICY,
];

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CA_BUNDLE_BYTES: usize = 256 * 1024;
const MAX_CA_CERTIFICATES: usize = 16;
const MAX_PROJECTED_JWT_BYTES: usize = 32 * 1024;
const MAX_PROJECTED_JWT_PAYLOAD_BYTES: usize = 16 * 1024;
const MAX_PROVIDER_RESPONSE_BYTES: usize = 1 << 20;
const MAX_SECRET_VALUE_BYTES: usize = 256 * 1024;
const MAX_VAULT_REQUEST_ID_BYTES: usize = 128;
const MAX_CLIENT_TOKEN_BYTES: usize = 8 * 1024;
const PROJECTED_JWT_CLOCK_SKEW_SECONDS: i64 = 30;
const MAX_PROJECTED_JWT_LIFETIME_SECONDS: i64 = 900;
const REQUESTED_TOKEN_TTL_SECONDS: u64 = 600;
const MAX_TOKEN_TTL_SECONDS: u64 = 900;
const MIN_USABLE_TOKEN_TTL_SECONDS: u64 = 30;
const MAX_SESSION_AGE_SECONDS: u64 = 900;
const READINESS_PROBE_INTERVAL: Duration = Duration::from_secs(30);
const READINESS_MAX_STALENESS: Duration = Duration::from_secs(60);
// A static KV-v2 read has no provider-side renewable secret lease. This
// code-owned interval bounds only how long callers may treat the returned
// material allocation as fresh before resolving again.
const STATIC_RESOLUTION_FRESHNESS_SECONDS: i64 = 10;

const HASHICORP_COMPATIBILITY_PROFILE_ID: &str = "backend-profile:hashicorp-vault-kv-v2-v1";
const HASHICORP_COMPATIBILITY_PROFILE_VERSION: u64 = 1;
const RETAINED_CONSUMER_ID: &str = "consumer:ryuki-api-integration-secret-resolver";
const ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROTOCOL_VERSION: &str = "1.0.0";
const KV2_RESOLVER_CAPABILITY_VERSION: &str = "1.0.0";
const BACKEND_COMPATIBILITY_PROFILE_DIGEST_CONTRACT: &str =
    "ryuki-secret-provider-backend-compatibility-profile-v1";
const ENDPOINT_BASE_URL_DIGEST_CONTRACT: &str =
    "ryuki-secret-provider-endpoint-base-url-binding-v1";
const CA_TRUST_DIGEST_CONTRACT: &str = "ryuki-secret-provider-ca-trust-binding-v1";
const WORKLOAD_IDENTITY_DIGEST_CONTRACT: &str =
    "ryuki-secret-provider-workload-identity-binding-v1";
const WORKLOAD_AUDIENCE_DIGEST_CONTRACT: &str =
    "ryuki-secret-provider-workload-audience-binding-v1";
const TOKEN_PATH_DIGEST_CONTRACT: &str = "ryuki-secret-provider-token-path-binding-v1";
const PROVIDER_AUTHENTICATION_DIGEST_CONTRACT: &str =
    "ryuki-secret-provider-authentication-binding-v1";
const IMPLEMENTED_CAPABILITIES: [(&str, &str); 2] =
    [("kv-v2-read", "1.0.0"), ("kv-v2-resolve", "1.0.0")];

type RuntimeFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum VaultApiFlavor {
    HashicorpVaultV1,
    OpenBaoV1,
}

impl VaultApiFlavor {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HashicorpVaultV1 => "hashicorp-vault-v1",
            Self::OpenBaoV1 => "openbao-v1",
        }
    }

    pub fn adapter_kind(self) -> &'static str {
        match self {
            Self::HashicorpVaultV1 => "secret.hashicorp-vault",
            Self::OpenBaoV1 => "secret.openbao",
        }
    }
}

/// Closed, non-secret configuration for one production Vault workload identity.
///
/// The process-wide static-token compatibility variables intentionally have no
/// representation here. [`VaultKubernetesRuntime::from_config`] also rejects
/// their ambient presence before reading the CA bundle or projected JWT.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VaultKubernetesRuntimeConfig {
    pub provider_id: String,
    pub configuration_version: u64,
    pub api_flavor: VaultApiFlavor,
    pub endpoint: String,
    pub ca_bundle_path: PathBuf,
    pub kubernetes_auth_mount: String,
    pub kubernetes_role: String,
    pub kubernetes_audience: String,
    pub projected_token_path: PathBuf,
    pub expected_service_account_namespace: String,
    pub expected_service_account_name: String,
    pub expected_token_policy: String,
}

impl std::fmt::Debug for VaultKubernetesRuntimeConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VaultKubernetesRuntimeConfig")
            .field("provider_id", &self.provider_id)
            .field("configuration_version", &self.configuration_version)
            .field("api_flavor", &self.api_flavor)
            .field("endpoint", &"[BOUND]")
            .field("ca_bundle_path", &"[BOUND]")
            .field("kubernetes_auth_mount", &"[BOUND]")
            .field("kubernetes_role", &"[BOUND]")
            .field("kubernetes_audience", &"[BOUND]")
            .field("projected_token_path", &"[BOUND]")
            .field("expected_service_account_namespace", &"[BOUND]")
            .field("expected_service_account_name", &"[BOUND]")
            .field("expected_token_policy", &"[BOUND]")
            .finish()
    }
}

impl VaultKubernetesRuntimeConfig {
    /// Capture the complete workload-auth configuration once at startup.
    ///
    /// The prefixed environment is a closed object: unknown fields, partial
    /// configuration, non-Unicode values, blanks, and non-canonical numeric or
    /// enum encodings all fail before any CA, JWT, or provider I/O occurs.
    pub(crate) fn from_environment(
        required: bool,
    ) -> Result<Option<Self>, VaultKubernetesRuntimeError> {
        Self::from_environment_snapshot(runtime_environment_snapshot()?, required)
    }

    fn from_environment_snapshot(
        snapshot: BTreeMap<String, OsString>,
        required: bool,
    ) -> Result<Option<Self>, VaultKubernetesRuntimeError> {
        if let Some(name) = snapshot
            .keys()
            .find(|name| !RUNTIME_ENV_KEYS.contains(&name.as_str()))
        {
            return Err(VaultKubernetesRuntimeError::RuntimeEnvironmentUnknown {
                name: name.clone(),
            });
        }
        if snapshot.is_empty() {
            return if required {
                Err(VaultKubernetesRuntimeError::RuntimeEnvironmentMissing)
            } else {
                Ok(None)
            };
        }
        if snapshot.len() != RUNTIME_ENV_KEYS.len()
            || RUNTIME_ENV_KEYS
                .iter()
                .any(|name| !snapshot.contains_key(*name))
        {
            return Err(VaultKubernetesRuntimeError::RuntimeEnvironmentIncomplete);
        }

        let configuration_version =
            required_runtime_environment_text(&snapshot, RUNTIME_ENV_CONFIGURATION_VERSION)?;
        let parsed_configuration_version = configuration_version.parse::<u64>().map_err(|_| {
            VaultKubernetesRuntimeError::RuntimeEnvironmentInvalid {
                name: RUNTIME_ENV_CONFIGURATION_VERSION,
            }
        })?;
        if parsed_configuration_version == 0
            || parsed_configuration_version.to_string() != configuration_version
        {
            return Err(VaultKubernetesRuntimeError::RuntimeEnvironmentInvalid {
                name: RUNTIME_ENV_CONFIGURATION_VERSION,
            });
        }
        let api_flavor =
            match required_runtime_environment_text(&snapshot, RUNTIME_ENV_API_FLAVOR)?.as_str() {
                "hashicorp-vault-v1" => VaultApiFlavor::HashicorpVaultV1,
                "openbao-v1" => VaultApiFlavor::OpenBaoV1,
                _ => {
                    return Err(VaultKubernetesRuntimeError::RuntimeEnvironmentInvalid {
                        name: RUNTIME_ENV_API_FLAVOR,
                    });
                }
            };

        Ok(Some(Self {
            provider_id: required_runtime_environment_text(&snapshot, RUNTIME_ENV_PROVIDER_ID)?,
            configuration_version: parsed_configuration_version,
            api_flavor,
            endpoint: required_runtime_environment_text(&snapshot, RUNTIME_ENV_ENDPOINT)?,
            ca_bundle_path: PathBuf::from(required_runtime_environment_text(
                &snapshot,
                RUNTIME_ENV_CA_BUNDLE_PATH,
            )?),
            kubernetes_auth_mount: required_runtime_environment_text(
                &snapshot,
                RUNTIME_ENV_KUBERNETES_AUTH_MOUNT,
            )?,
            kubernetes_role: required_runtime_environment_text(
                &snapshot,
                RUNTIME_ENV_KUBERNETES_ROLE,
            )?,
            kubernetes_audience: required_runtime_environment_text(
                &snapshot,
                RUNTIME_ENV_KUBERNETES_AUDIENCE,
            )?,
            projected_token_path: PathBuf::from(required_runtime_environment_text(
                &snapshot,
                RUNTIME_ENV_PROJECTED_TOKEN_PATH,
            )?),
            expected_service_account_namespace: required_runtime_environment_text(
                &snapshot,
                RUNTIME_ENV_EXPECTED_SERVICE_ACCOUNT_NAMESPACE,
            )?,
            expected_service_account_name: required_runtime_environment_text(
                &snapshot,
                RUNTIME_ENV_EXPECTED_SERVICE_ACCOUNT_NAME,
            )?,
            expected_token_policy: required_runtime_environment_text(
                &snapshot,
                RUNTIME_ENV_EXPECTED_TOKEN_POLICY,
            )?,
        }))
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VaultKubernetesRuntimeError {
    #[error("production secret-provider runtime environment is not configured")]
    RuntimeEnvironmentMissing,
    #[error("secret-provider runtime environment must configure every required field together")]
    RuntimeEnvironmentIncomplete,
    #[error("secret-provider runtime environment contains unsupported field '{name}'")]
    RuntimeEnvironmentUnknown { name: String },
    #[error("secret-provider runtime environment field '{name}' is invalid")]
    RuntimeEnvironmentInvalid { name: &'static str },
    #[error("the dedicated SecretRef fingerprint keyring path is not configured")]
    FingerprintKeyringPathMissing,
    #[error("the dedicated SecretRef fingerprint keyring path is invalid")]
    FingerprintKeyringPathInvalid,
    #[error("legacy or ambiguous Vault process configuration is present")]
    LegacyVaultConfigurationPresent,
    #[error("the selected secret-service API flavor is not independently supported")]
    UnsupportedApiFlavor,
    #[error("secret-provider runtime configuration field '{field}' is invalid ({reason})")]
    InvalidConfiguration {
        field: &'static str,
        reason: &'static str,
    },
    #[error("the configured Vault CA bundle is unavailable or not a regular bounded file")]
    CaBundleUnavailable,
    #[error("the configured Vault CA bundle is invalid")]
    CaBundleInvalid,
    #[error("Vault HTTP client initialization failed")]
    ClientInitializationFailed,
    #[error("the projected Kubernetes service-account token is unavailable")]
    ProjectedTokenUnavailable,
    #[error("the projected Kubernetes service-account token is invalid")]
    ProjectedTokenInvalid,
    #[error("Vault {operation} transport failed")]
    ProviderTransport { operation: &'static str },
    #[error("Vault {operation} returned HTTP {status}")]
    ProviderHttpStatus {
        operation: &'static str,
        status: u16,
    },
    #[error("Vault {operation} returned an invalid bounded response")]
    ProviderResponse { operation: &'static str },
    #[error("Vault authenticated a different Kubernetes workload identity")]
    WorkloadIdentityMismatch,
    #[error("Vault issued a token outside the admitted lease or policy contract")]
    TokenLeaseRejected,
    #[error("Vault workload authentication has not established a usable lease")]
    NotAuthenticated,
    #[error("Vault workload-auth retry is deferred for {retry_after_seconds} seconds")]
    RetryDeferred { retry_after_seconds: u64 },
    #[error("Vault workload-auth lease generation changed during verification")]
    GenerationChanged,
    #[error("Vault workload-auth runtime state is unavailable")]
    RuntimeStateUnavailable,
    #[error("Vault workload-auth runtime has stopped")]
    RuntimeStopped,
    #[error("the Vault KV-v2 secret reference does not match this provider runtime")]
    SecretReferenceMismatch,
    #[error("the Vault KV-v2 secret reference is outside the admitted resolution context")]
    SecretResolutionContextMismatch,
    #[error("the Vault KV-v2 secret reference is invalid")]
    SecretReferenceInvalid,
    #[error("secret-provider runtime observation leaf could not be canonicalized")]
    BindingCanonicalizationFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultReadinessState {
    Ready,
    Unauthenticated,
    LeaseExpired,
    LeaseNearExpiry,
    ConfirmationStale,
    ReloginRequired,
    Stopped,
}

fn runtime_environment_snapshot() -> Result<BTreeMap<String, OsString>, VaultKubernetesRuntimeError>
{
    let mut snapshot = BTreeMap::new();
    for (raw_name, value) in std::env::vars_os() {
        let displayed_name = raw_name.to_string_lossy();
        if !displayed_name.starts_with(RUNTIME_ENV_PREFIX) {
            continue;
        }
        let name = raw_name.into_string().map_err(|_| {
            VaultKubernetesRuntimeError::RuntimeEnvironmentUnknown {
                name: format!("{RUNTIME_ENV_PREFIX}[NON-UNICODE]"),
            }
        })?;
        snapshot.insert(name, value);
    }
    Ok(snapshot)
}

fn required_runtime_environment_text(
    snapshot: &BTreeMap<String, OsString>,
    name: &'static str,
) -> Result<String, VaultKubernetesRuntimeError> {
    let value = snapshot
        .get(name)
        .ok_or(VaultKubernetesRuntimeError::RuntimeEnvironmentIncomplete)?
        .to_str()
        .ok_or(VaultKubernetesRuntimeError::RuntimeEnvironmentInvalid { name })?;
    if value.is_empty() || value.trim() != value {
        return Err(VaultKubernetesRuntimeError::RuntimeEnvironmentInvalid { name });
    }
    Ok(value.to_string())
}

/// Read the dedicated SecretRef fingerprint keyring projection path.
///
/// Production requires the exact mounted path. Non-production may omit the
/// projection, but cannot redirect it to ambient or mutable storage when the
/// selector is present.
pub(crate) fn fingerprint_keyring_path_from_environment(
    required: bool,
) -> Result<Option<PathBuf>, VaultKubernetesRuntimeError> {
    let Some(raw) = std::env::var_os(SECRET_REFERENCE_FINGERPRINT_KEYRING_PATH_ENV) else {
        return if required {
            Err(VaultKubernetesRuntimeError::FingerprintKeyringPathMissing)
        } else {
            Ok(None)
        };
    };
    let path = raw
        .to_str()
        .filter(|value| *value == SECRET_REFERENCE_FINGERPRINT_KEYRING_PATH)
        .map(PathBuf::from)
        .ok_or(VaultKubernetesRuntimeError::FingerprintKeyringPathInvalid)?;
    Ok(Some(path))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultReadinessSnapshot {
    pub state: VaultReadinessState,
    pub generation: u64,
    pub remaining_ttl_seconds: u64,
    pub last_confirmation_age_seconds: u64,
    pub workload_identity_binding_digest: Option<String>,
}

impl VaultReadinessSnapshot {
    pub fn is_ready(&self) -> bool {
        self.state == VaultReadinessState::Ready
    }
}

/// Independently measured operational leaves for the retained Vault runtime.
///
/// This is deliberately not the `ryuki-secret-provider-runtime-binding-v1`
/// digest and must never be substituted for it. The live guard compares these
/// leaves with the separately authenticated binding document, then composes the
/// higher-level D -> P -> R -> I receipt chain itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VaultRuntimeOperationalObservation {
    pub(crate) provider_id: String,
    pub(crate) provider_configuration_version: u64,
    pub(crate) adapter_kind: String,
    pub(crate) adapter_version: String,
    pub(crate) protocol_version: String,
    pub(crate) backend_compatibility_profile: VaultBackendCompatibilityObservation,
    pub(crate) transport: VaultTransportObservation,
    pub(crate) credential_source: VaultCredentialSourceObservation,
    pub(crate) capability_bindings: Vec<VaultCapabilityObservation>,
    pub(crate) retained_consumer_ids: Vec<String>,
    pub(crate) ownership: VaultRuntimeOwnershipObservation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VaultBackendCompatibilityObservation {
    pub(crate) profile_id: String,
    pub(crate) profile_version: u64,
    pub(crate) digest_contract: String,
    pub(crate) binding_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VaultTransportObservation {
    pub(crate) endpoint_base_url_binding_digest: String,
    pub(crate) ca_trust_binding_digest: String,
    pub(crate) https_required: bool,
    pub(crate) redirects_allowed: bool,
    pub(crate) ambient_proxy_allowed: bool,
    pub(crate) built_in_roots_allowed: bool,
    pub(crate) connect_timeout_millis: u64,
    pub(crate) request_timeout_millis: u64,
    pub(crate) response_body_max_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VaultCredentialSourceObservation {
    pub(crate) kind: String,
    pub(crate) identity_binding_digest: String,
    pub(crate) audience_binding_digest: String,
    pub(crate) token_path_binding_digest: String,
    pub(crate) provider_authentication_digest_contract: String,
    pub(crate) provider_authentication_binding_digest: String,
    pub(crate) static_bearer_allowed: bool,
    pub(crate) exported_bearer_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VaultCapabilityObservation {
    pub(crate) capability_id: String,
    pub(crate) semantic_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VaultRuntimeOwnershipObservation {
    pub(crate) single_runtime_owner: bool,
    pub(crate) ambient_reconfiguration_allowed: bool,
}

#[derive(Clone, Copy, Default)]
struct LegacyVaultEnvironment {
    present: bool,
}

impl LegacyVaultEnvironment {
    fn capture() -> Self {
        const KEYS: [&str; 8] = [
            "VAULT_ADDR",
            "VAULT_TOKEN",
            "VAULT_TOKEN_FILE",
            "VAULT_CACERT",
            "VAULT_NAMESPACE",
            "VAULT_SKIP_VERIFY",
            "VAULT_CLIENT_CERT",
            "VAULT_CLIENT_KEY",
        ];
        let present = KEYS.iter().any(|name| std::env::var_os(name).is_some())
            || std::env::var_os("RYUKI_VAULT_ALLOW_INSECURE_LOOPBACK").is_some();
        Self { present }
    }

    fn reject(self) -> Result<(), VaultKubernetesRuntimeError> {
        if self.present {
            Err(VaultKubernetesRuntimeError::LegacyVaultConfigurationPresent)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone)]
struct ValidatedRuntimeConfig {
    original: VaultKubernetesRuntimeConfig,
    endpoint: Url,
}

#[derive(Serialize)]
struct CompatibilityProfileProjection<'a> {
    digest_contract: &'static str,
    profile_id: &'a str,
    profile_version: u64,
    api_flavor: &'a str,
    protocol_version: &'static str,
    login_api: &'a str,
    lookup_self_api: &'a str,
    renew_self_api: &'a str,
    token_header: &'a str,
    capability_bindings: [CapabilitySemanticProjection<'static>; 2],
    limitations: [&'static str; 5],
}

#[derive(Clone, Copy, Serialize)]
struct CapabilitySemanticProjection<'a> {
    capability_id: &'a str,
    semantic_version: &'a str,
}

#[derive(Serialize)]
struct EndpointBaseUrlProjection<'a> {
    digest_contract: &'static str,
    scheme: &'static str,
    host: &'a str,
    effective_port: u16,
    path_prefix: &'a str,
}

#[derive(Serialize)]
struct CaTrustProjection<'a> {
    digest_contract: &'static str,
    ca_bundle_base64: &'a str,
}

#[derive(Serialize)]
struct WorkloadIdentityProjection<'a> {
    digest_contract: &'static str,
    namespace: &'a str,
    service_account_name: &'a str,
}

#[derive(Serialize)]
struct WorkloadAudienceProjection<'a> {
    digest_contract: &'static str,
    audiences: [&'a str; 1],
}

#[derive(Serialize)]
struct TokenPathProjection<'a> {
    digest_contract: &'static str,
    normalized_absolute_path: &'a str,
}

#[derive(Clone, Copy, Serialize)]
struct TtlLimitProjection {
    limit_id: &'static str,
    seconds: u64,
}

#[derive(Serialize)]
struct ProviderAuthenticationProjection<'a> {
    digest_contract: &'static str,
    authentication_kind: &'static str,
    api_flavor: &'a str,
    vault_namespace: Option<&'a str>,
    normalized_auth_mount: &'a str,
    role: &'a str,
    expected_token_policy: &'a str,
    expected_token_type: &'static str,
    token_renewable_required: bool,
    ttl_limits: [TtlLimitProjection; 5],
}

impl ValidatedRuntimeConfig {
    fn new(
        original: VaultKubernetesRuntimeConfig,
        legacy_environment: LegacyVaultEnvironment,
    ) -> Result<Self, VaultKubernetesRuntimeError> {
        legacy_environment.reject()?;
        if original.api_flavor != VaultApiFlavor::HashicorpVaultV1 {
            return Err(VaultKubernetesRuntimeError::UnsupportedApiFlavor);
        }
        validate_provider_id(&original.provider_id)?;
        if original.configuration_version == 0 {
            return Err(invalid("configuration_version", "must be positive"));
        }
        if original.ca_bundle_path != Path::new(VAULT_CA_BUNDLE_PATH) {
            return Err(invalid(
                "ca_bundle_path",
                "must use the fixed projection path",
            ));
        }
        if original.projected_token_path != Path::new(VAULT_PROJECTED_TOKEN_PATH) {
            return Err(invalid(
                "projected_token_path",
                "must use the fixed projection path",
            ));
        }
        validate_absolute_normal_path(&original.ca_bundle_path, "ca_bundle_path")?;
        validate_absolute_normal_path(&original.projected_token_path, "projected_token_path")?;
        if original.kubernetes_auth_mount != "kubernetes" {
            return Err(invalid(
                "kubernetes_auth_mount",
                "v1 admits only the exact kubernetes mount",
            ));
        }
        validate_vault_name(&original.kubernetes_role, "kubernetes_role")?;
        if original.kubernetes_audience != "vault" {
            return Err(invalid(
                "kubernetes_audience",
                "v1 requires the exact singleton audience 'vault'",
            ));
        }
        validate_dns_label(
            &original.expected_service_account_namespace,
            "expected_service_account_namespace",
        )?;
        validate_dns_label(
            &original.expected_service_account_name,
            "expected_service_account_name",
        )?;
        validate_vault_name(&original.expected_token_policy, "expected_token_policy")?;
        if matches!(original.expected_token_policy.as_str(), "default" | "root") {
            return Err(invalid(
                "expected_token_policy",
                "must not admit Vault's default or root policy",
            ));
        }

        if original.endpoint.is_empty() || original.endpoint.trim() != original.endpoint {
            return Err(invalid(
                "endpoint",
                "must be nonempty without surrounding whitespace",
            ));
        }
        let mut endpoint = Url::parse(&original.endpoint)
            .map_err(|_| invalid("endpoint", "must be an absolute URL"))?;
        if endpoint.scheme() != "https" {
            return Err(invalid("endpoint", "must use HTTPS"));
        }
        if endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || original.endpoint.contains('\\')
        {
            return Err(invalid(
                "endpoint",
                "must have a host and no userinfo, query, or fragment",
            ));
        }
        if !endpoint.path().ends_with('/') {
            let normalized = format!("{}/", endpoint.path());
            endpoint.set_path(&normalized);
        }
        let path = endpoint.path();
        if path.contains('%')
            || (path != "/" && path.contains("//"))
            || path
                .trim_matches('/')
                .split('/')
                .any(|segment| matches!(segment, "." | ".."))
        {
            return Err(invalid(
                "endpoint",
                "must use a normalized unescaped reverse-proxy path prefix",
            ));
        }

        Ok(Self { original, endpoint })
    }

    fn api_url(&self, segments: &[&str]) -> Result<Url, VaultKubernetesRuntimeError> {
        let mut url = self.endpoint.clone();
        let mut path = url
            .path_segments_mut()
            .map_err(|_| invalid("endpoint", "must be hierarchical"))?;
        path.pop_if_empty();
        path.push("v1");
        for segment in segments {
            path.push(segment);
        }
        drop(path);
        Ok(url)
    }
}

impl VaultRuntimeOperationalObservation {
    fn measure(
        config: &ValidatedRuntimeConfig,
        ca_trust_binding_digest: String,
    ) -> Result<Self, VaultKubernetesRuntimeError> {
        let capability_bindings = IMPLEMENTED_CAPABILITIES
            .iter()
            .map(
                |(capability_id, semantic_version)| VaultCapabilityObservation {
                    capability_id: (*capability_id).to_string(),
                    semantic_version: (*semantic_version).to_string(),
                },
            )
            .collect();
        Ok(Self {
            provider_id: config.original.provider_id.clone(),
            provider_configuration_version: config.original.configuration_version,
            adapter_kind: config.original.api_flavor.adapter_kind().to_string(),
            adapter_version: ADAPTER_VERSION.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            backend_compatibility_profile: VaultBackendCompatibilityObservation {
                profile_id: HASHICORP_COMPATIBILITY_PROFILE_ID.to_string(),
                profile_version: HASHICORP_COMPATIBILITY_PROFILE_VERSION,
                digest_contract: BACKEND_COMPATIBILITY_PROFILE_DIGEST_CONTRACT.to_string(),
                binding_digest: compatibility_profile_digest(config.original.api_flavor)?,
            },
            transport: VaultTransportObservation {
                endpoint_base_url_binding_digest: endpoint_base_url_digest(&config.endpoint)?,
                ca_trust_binding_digest,
                https_required: true,
                redirects_allowed: false,
                ambient_proxy_allowed: false,
                built_in_roots_allowed: false,
                connect_timeout_millis: CONNECT_TIMEOUT.as_millis() as u64,
                request_timeout_millis: REQUEST_TIMEOUT.as_millis() as u64,
                response_body_max_bytes: MAX_PROVIDER_RESPONSE_BYTES as u64,
            },
            credential_source: VaultCredentialSourceObservation {
                kind: "kubernetes-service-account-jwt".to_string(),
                identity_binding_digest: workload_identity_digest(config)?,
                audience_binding_digest: workload_audience_digest(config)?,
                token_path_binding_digest: token_path_digest(config)?,
                provider_authentication_digest_contract: PROVIDER_AUTHENTICATION_DIGEST_CONTRACT
                    .to_string(),
                provider_authentication_binding_digest: provider_authentication_digest(config)?,
                static_bearer_allowed: false,
                exported_bearer_allowed: false,
            },
            capability_bindings,
            retained_consumer_ids: vec![RETAINED_CONSUMER_ID.to_string()],
            ownership: VaultRuntimeOwnershipObservation {
                single_runtime_owner: true,
                ambient_reconfiguration_allowed: false,
            },
        })
    }
}

fn invalid(field: &'static str, reason: &'static str) -> VaultKubernetesRuntimeError {
    VaultKubernetesRuntimeError::InvalidConfiguration { field, reason }
}

fn validate_provider_id(value: &str) -> Result<(), VaultKubernetesRuntimeError> {
    let Some(suffix) = value.strip_prefix("provider:") else {
        return Err(invalid("provider_id", "must use the provider: namespace"));
    };
    if suffix.len() < 3
        || suffix.len() > 127
        || !suffix
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !suffix.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(invalid("provider_id", "has an invalid identifier shape"));
    }
    Ok(())
}

fn validate_vault_name(
    value: &str,
    field: &'static str,
) -> Result<(), VaultKubernetesRuntimeError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(invalid(field, "must be a bounded single Vault name"));
    }
    Ok(())
}

fn validate_dns_label(value: &str, field: &'static str) -> Result<(), VaultKubernetesRuntimeError> {
    if value.is_empty()
        || value.len() > 63
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(invalid(field, "must be a DNS label"));
    }
    Ok(())
}

fn validate_absolute_normal_path(
    path: &Path,
    field: &'static str,
) -> Result<(), VaultKubernetesRuntimeError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid(field, "must be an absolute normalized path"));
    }
    Ok(())
}

fn digest_canonical(value: &impl Serialize) -> Result<String, VaultKubernetesRuntimeError> {
    let value = serde_json::to_value(value)
        .map_err(|_| VaultKubernetesRuntimeError::BindingCanonicalizationFailed)?;
    let canonical = canonical_json_bytes(&value)
        .map_err(|_| VaultKubernetesRuntimeError::BindingCanonicalizationFailed)?;
    Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
}

fn compatibility_profile_digest(
    flavor: VaultApiFlavor,
) -> Result<String, VaultKubernetesRuntimeError> {
    if flavor != VaultApiFlavor::HashicorpVaultV1 {
        return Err(VaultKubernetesRuntimeError::UnsupportedApiFlavor);
    }
    digest_canonical(&CompatibilityProfileProjection {
        digest_contract: BACKEND_COMPATIBILITY_PROFILE_DIGEST_CONTRACT,
        profile_id: HASHICORP_COMPATIBILITY_PROFILE_ID,
        profile_version: HASHICORP_COMPATIBILITY_PROFILE_VERSION,
        api_flavor: flavor.as_str(),
        protocol_version: PROTOCOL_VERSION,
        login_api: "POST /v1/auth/{mount}/login",
        lookup_self_api: "GET /v1/auth/token/lookup-self",
        renew_self_api: "POST /v1/auth/token/renew-self",
        token_header: "X-Vault-Token",
        capability_bindings: [
            CapabilitySemanticProjection {
                capability_id: IMPLEMENTED_CAPABILITIES[0].0,
                semantic_version: IMPLEMENTED_CAPABILITIES[0].1,
            },
            CapabilitySemanticProjection {
                capability_id: IMPLEMENTED_CAPABILITIES[1].0,
                semantic_version: IMPLEMENTED_CAPABILITIES[1].1,
            },
        ],
        limitations: [
            "no-ambient-proxy",
            "no-built-in-roots",
            "no-redirects",
            "no-static-bearer",
            "openbao-unsupported",
        ],
    })
}

fn endpoint_base_url_digest(endpoint: &Url) -> Result<String, VaultKubernetesRuntimeError> {
    let host = endpoint
        .host_str()
        .ok_or_else(|| invalid("endpoint", "must have a host"))?;
    let effective_port = endpoint
        .port_or_known_default()
        .ok_or_else(|| invalid("endpoint", "must have a known effective port"))?;
    digest_canonical(&EndpointBaseUrlProjection {
        digest_contract: ENDPOINT_BASE_URL_DIGEST_CONTRACT,
        scheme: "https",
        host,
        effective_port,
        path_prefix: endpoint.path(),
    })
}

fn ca_trust_digest(bytes: &[u8]) -> Result<String, VaultKubernetesRuntimeError> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    digest_canonical(&CaTrustProjection {
        digest_contract: CA_TRUST_DIGEST_CONTRACT,
        ca_bundle_base64: &encoded,
    })
}

fn workload_identity_digest(
    config: &ValidatedRuntimeConfig,
) -> Result<String, VaultKubernetesRuntimeError> {
    digest_canonical(&WorkloadIdentityProjection {
        digest_contract: WORKLOAD_IDENTITY_DIGEST_CONTRACT,
        namespace: &config.original.expected_service_account_namespace,
        service_account_name: &config.original.expected_service_account_name,
    })
}

fn workload_audience_digest(
    config: &ValidatedRuntimeConfig,
) -> Result<String, VaultKubernetesRuntimeError> {
    digest_canonical(&WorkloadAudienceProjection {
        digest_contract: WORKLOAD_AUDIENCE_DIGEST_CONTRACT,
        audiences: [&config.original.kubernetes_audience],
    })
}

fn token_path_digest(
    config: &ValidatedRuntimeConfig,
) -> Result<String, VaultKubernetesRuntimeError> {
    let path = config
        .original
        .projected_token_path
        .to_str()
        .ok_or_else(|| invalid("projected_token_path", "must contain Unicode text"))?;
    digest_canonical(&TokenPathProjection {
        digest_contract: TOKEN_PATH_DIGEST_CONTRACT,
        normalized_absolute_path: path,
    })
}

fn provider_authentication_digest(
    config: &ValidatedRuntimeConfig,
) -> Result<String, VaultKubernetesRuntimeError> {
    digest_canonical(&ProviderAuthenticationProjection {
        digest_contract: PROVIDER_AUTHENTICATION_DIGEST_CONTRACT,
        authentication_kind: "kubernetes-service-account-jwt",
        api_flavor: config.original.api_flavor.as_str(),
        vault_namespace: None,
        normalized_auth_mount: &config.original.kubernetes_auth_mount,
        role: &config.original.kubernetes_role,
        expected_token_policy: &config.original.expected_token_policy,
        expected_token_type: "service",
        token_renewable_required: true,
        ttl_limits: [
            TtlLimitProjection {
                limit_id: "limit:vault-client-token.maximum-session-age",
                seconds: MAX_SESSION_AGE_SECONDS,
            },
            TtlLimitProjection {
                limit_id: "limit:vault-client-token.maximum-ttl",
                seconds: MAX_TOKEN_TTL_SECONDS,
            },
            TtlLimitProjection {
                limit_id: "limit:vault-client-token.minimum-usable-ttl",
                seconds: MIN_USABLE_TOKEN_TTL_SECONDS,
            },
            TtlLimitProjection {
                limit_id: "limit:vault-client-token.requested-ttl",
                seconds: REQUESTED_TOKEN_TTL_SECONDS,
            },
            TtlLimitProjection {
                limit_id: "limit:vault-workload-jwt.maximum-lifetime",
                seconds: MAX_PROJECTED_JWT_LIFETIME_SECONDS as u64,
            },
        ],
    })
}

fn load_ca_bundle(path: &Path) -> Result<(Vec<Certificate>, String), VaultKubernetesRuntimeError> {
    let metadata =
        std::fs::metadata(path).map_err(|_| VaultKubernetesRuntimeError::CaBundleUnavailable)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_CA_BUNDLE_BYTES as u64 {
        return Err(VaultKubernetesRuntimeError::CaBundleUnavailable);
    }
    let file =
        std::fs::File::open(path).map_err(|_| VaultKubernetesRuntimeError::CaBundleUnavailable)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((MAX_CA_BUNDLE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| VaultKubernetesRuntimeError::CaBundleUnavailable)?;
    if bytes.is_empty() || bytes.len() > MAX_CA_BUNDLE_BYTES {
        return Err(VaultKubernetesRuntimeError::CaBundleUnavailable);
    }
    let certificates = Certificate::from_pem_bundle(&bytes)
        .map_err(|_| VaultKubernetesRuntimeError::CaBundleInvalid)?;
    if certificates.is_empty() || certificates.len() > MAX_CA_CERTIFICATES {
        return Err(VaultKubernetesRuntimeError::CaBundleInvalid);
    }
    let digest = ca_trust_digest(&bytes)?;
    Ok((certificates, digest))
}

fn build_http_client(
    certificates: Vec<Certificate>,
) -> Result<Client, VaultKubernetesRuntimeError> {
    let mut builder = Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .https_only(true)
        .tls_built_in_root_certs(false);
    for certificate in certificates {
        builder = builder.add_root_certificate(certificate);
    }
    builder
        .build()
        .map_err(|_| VaultKubernetesRuntimeError::ClientInitializationFailed)
}

trait RuntimeClock: Send + Sync {
    fn monotonic_now(&self) -> Instant;
    fn unix_now_seconds(&self) -> i64;
}

struct SystemRuntimeClock;

impl RuntimeClock for SystemRuntimeClock {
    fn monotonic_now(&self) -> Instant {
        Instant::now()
    }

    fn unix_now_seconds(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
            .unwrap_or(0)
    }
}

trait ProjectedJwtSource: Send + Sync {
    fn read<'a>(
        &'a self,
    ) -> RuntimeFuture<'a, Result<Zeroizing<String>, VaultKubernetesRuntimeError>>;
}

struct FileProjectedJwtSource {
    path: PathBuf,
}

impl ProjectedJwtSource for FileProjectedJwtSource {
    fn read<'a>(
        &'a self,
    ) -> RuntimeFuture<'a, Result<Zeroizing<String>, VaultKubernetesRuntimeError>> {
        Box::pin(async move { read_projected_jwt_file(&self.path).await })
    }
}

async fn read_projected_jwt_file(
    path: &Path,
) -> Result<Zeroizing<String>, VaultKubernetesRuntimeError> {
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| VaultKubernetesRuntimeError::ProjectedTokenUnavailable)?;
    let metadata = file
        .metadata()
        .await
        .map_err(|_| VaultKubernetesRuntimeError::ProjectedTokenUnavailable)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_PROJECTED_JWT_BYTES as u64
    {
        return Err(VaultKubernetesRuntimeError::ProjectedTokenUnavailable);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take((MAX_PROJECTED_JWT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| VaultKubernetesRuntimeError::ProjectedTokenUnavailable)?;
    if bytes.is_empty() || bytes.len() > MAX_PROJECTED_JWT_BYTES {
        return Err(VaultKubernetesRuntimeError::ProjectedTokenUnavailable);
    }
    let token = std::str::from_utf8(&bytes)
        .map_err(|_| VaultKubernetesRuntimeError::ProjectedTokenInvalid)?;
    if token.trim() != token || token.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(VaultKubernetesRuntimeError::ProjectedTokenInvalid);
    }
    Ok(Zeroizing::new(token.to_owned()))
}

struct ProjectedJwtIdentity {
    service_account_uid: Zeroizing<String>,
}

struct ValidatedVaultKv2SecretReference {
    mount: String,
    path_segments: Vec<String>,
    field: String,
    pinned_version: Option<u64>,
}

fn validate_projected_jwt(
    token: &str,
    config: &ValidatedRuntimeConfig,
    unix_now: i64,
) -> Result<ProjectedJwtIdentity, VaultKubernetesRuntimeError> {
    let mut segments = token.split('.');
    let header = segments.next();
    let payload = segments.next();
    let signature = segments.next();
    if header.is_none_or(str::is_empty)
        || payload.is_none_or(str::is_empty)
        || signature.is_none_or(str::is_empty)
        || segments.next().is_some()
    {
        return Err(VaultKubernetesRuntimeError::ProjectedTokenInvalid);
    }
    let mut decoded = Zeroizing::new(Vec::new());
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode_vec(payload.expect("payload checked above"), &mut decoded)
        .map_err(|_| VaultKubernetesRuntimeError::ProjectedTokenInvalid)?;
    if decoded.is_empty() || decoded.len() > MAX_PROJECTED_JWT_PAYLOAD_BYTES {
        return Err(VaultKubernetesRuntimeError::ProjectedTokenInvalid);
    }
    let claims = ZeroizingProviderJson(
        serde_json::from_slice(decoded.as_slice())
            .map_err(|_| VaultKubernetesRuntimeError::ProjectedTokenInvalid)?,
    );
    let claims = claims
        .0
        .as_object()
        .ok_or(VaultKubernetesRuntimeError::ProjectedTokenInvalid)?;

    let audience_matches = match claims.get("aud") {
        Some(Value::String(audience)) => audience == &config.original.kubernetes_audience,
        Some(Value::Array(audiences)) => {
            audiences.len() == 1
                && audiences[0].as_str() == Some(config.original.kubernetes_audience.as_str())
        }
        _ => false,
    };
    let expected_subject = format!(
        "system:serviceaccount:{}:{}",
        config.original.expected_service_account_namespace,
        config.original.expected_service_account_name
    );
    if !audience_matches
        || claims.get("sub").and_then(Value::as_str) != Some(expected_subject.as_str())
    {
        return Err(VaultKubernetesRuntimeError::ProjectedTokenInvalid);
    }

    let exp = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(VaultKubernetesRuntimeError::ProjectedTokenInvalid)?;
    let iat = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or(VaultKubernetesRuntimeError::ProjectedTokenInvalid)?;
    let nbf = claims
        .get("nbf")
        .and_then(Value::as_i64)
        .ok_or(VaultKubernetesRuntimeError::ProjectedTokenInvalid)?;
    let lifetime = exp
        .checked_sub(iat)
        .ok_or(VaultKubernetesRuntimeError::ProjectedTokenInvalid)?;
    let latest_admitted_time = unix_now.saturating_add(PROJECTED_JWT_CLOCK_SKEW_SECONDS);
    if exp <= unix_now.saturating_add(MIN_USABLE_TOKEN_TTL_SECONDS as i64)
        || iat > latest_admitted_time
        || nbf > latest_admitted_time
        || nbf < iat.saturating_sub(PROJECTED_JWT_CLOCK_SKEW_SECONDS)
        || nbf >= exp
        || exp <= iat
        || lifetime > MAX_PROJECTED_JWT_LIFETIME_SECONDS
    {
        return Err(VaultKubernetesRuntimeError::ProjectedTokenInvalid);
    }

    let kubernetes = claims
        .get("kubernetes.io")
        .and_then(Value::as_object)
        .ok_or(VaultKubernetesRuntimeError::ProjectedTokenInvalid)?;
    let service_account = kubernetes
        .get("serviceaccount")
        .and_then(Value::as_object)
        .ok_or(VaultKubernetesRuntimeError::ProjectedTokenInvalid)?;
    let pod = kubernetes
        .get("pod")
        .and_then(Value::as_object)
        .ok_or(VaultKubernetesRuntimeError::ProjectedTokenInvalid)?;
    let namespace = kubernetes
        .get("namespace")
        .and_then(Value::as_str)
        .ok_or(VaultKubernetesRuntimeError::ProjectedTokenInvalid)?;
    let service_account_name = service_account
        .get("name")
        .and_then(Value::as_str)
        .ok_or(VaultKubernetesRuntimeError::ProjectedTokenInvalid)?;
    let service_account_uid = service_account
        .get("uid")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or(VaultKubernetesRuntimeError::ProjectedTokenInvalid)?;
    let _pod_uid = pod
        .get("uid")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or(VaultKubernetesRuntimeError::ProjectedTokenInvalid)?;
    if namespace != config.original.expected_service_account_namespace
        || service_account_name != config.original.expected_service_account_name
    {
        return Err(VaultKubernetesRuntimeError::ProjectedTokenInvalid);
    }

    Ok(ProjectedJwtIdentity {
        service_account_uid: Zeroizing::new(service_account_uid.to_owned()),
    })
}

fn validate_kv2_secret_reference(
    reference: &SecretRef,
    observation: &VaultRuntimeOperationalObservation,
) -> Result<ValidatedVaultKv2SecretReference, VaultKubernetesRuntimeError> {
    reference
        .validate()
        .map_err(|_| VaultKubernetesRuntimeError::SecretReferenceInvalid)?;
    if reference.provider_id() != observation.provider_id
        || reference.provider_config_version() != observation.provider_configuration_version
    {
        return Err(VaultKubernetesRuntimeError::SecretReferenceMismatch);
    }
    let valid_component = |value: &str, maximum: usize| {
        !value.is_empty()
            && value.len() <= maximum
            && !matches!(value, "." | "..")
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'~')
            })
    };
    let locator = reference.opaque_locator();
    if locator.is_empty()
        || locator.len() > 1_024
        || locator.starts_with('/')
        || locator.ends_with('/')
        || locator.contains('#')
    {
        return Err(VaultKubernetesRuntimeError::SecretReferenceInvalid);
    }
    let mut locator_segments = locator.split('/');
    let mount = locator_segments
        .next()
        .filter(|mount| valid_component(mount, 64))
        .ok_or(VaultKubernetesRuntimeError::SecretReferenceInvalid)?;
    let path_segments = locator_segments.map(str::to_string).collect::<Vec<_>>();
    if path_segments.is_empty()
        || path_segments.len() > 32
        || path_segments
            .iter()
            .any(|segment| !valid_component(segment, 128))
    {
        return Err(VaultKubernetesRuntimeError::SecretReferenceInvalid);
    }
    let field = reference
        .field_selector()
        .filter(|field| {
            !field.is_empty()
                && field.len() <= 256
                && field.trim() == *field
                && !field.chars().any(char::is_control)
        })
        .ok_or(VaultKubernetesRuntimeError::SecretReferenceInvalid)?;
    let pinned_version = reference
        .version_selector()
        .pinned_version()
        .map(|raw| {
            raw.parse::<u64>()
                .ok()
                .filter(|version| *version > 0 && version.to_string() == raw)
                .ok_or(VaultKubernetesRuntimeError::SecretReferenceInvalid)
        })
        .transpose()?;
    Ok(ValidatedVaultKv2SecretReference {
        mount: mount.to_string(),
        path_segments,
        field: field.to_string(),
        pinned_version,
    })
}

struct ProviderAuthLease {
    token: Zeroizing<String>,
    ttl_seconds: u64,
    renewable: bool,
    token_type: Option<String>,
    token_policies: Vec<String>,
    metadata: BTreeMap<String, String>,
}

struct ProviderLookupLease {
    ttl_seconds: u64,
    renewable: bool,
    token_policies: Vec<String>,
    metadata: BTreeMap<String, String>,
}

struct ProviderKv2Read {
    request_id: String,
    version: u64,
    material: Zeroizing<Vec<u8>>,
}

struct ZeroizingJsonString(Zeroizing<String>);

impl ZeroizingJsonString {
    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Default for ZeroizingJsonString {
    fn default() -> Self {
        Self(Zeroizing::new(String::new()))
    }
}

impl<'de> Deserialize<'de> for ZeroizingJsonString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}

impl PartialEq for ZeroizingJsonString {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for ZeroizingJsonString {}

impl PartialOrd for ZeroizingJsonString {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ZeroizingJsonString {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl std::borrow::Borrow<str> for ZeroizingJsonString {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

#[derive(Deserialize)]
struct Kv2ReadEnvelope {
    request_id: ZeroizingJsonString,
    data: Kv2ReadData,
}

#[derive(Deserialize)]
struct Kv2ReadData {
    data: BTreeMap<ZeroizingJsonString, ZeroizingJsonString>,
    metadata: Kv2ReadMetadata,
}

#[derive(Deserialize)]
struct Kv2ReadMetadata {
    version: u64,
    #[serde(default)]
    destroyed: bool,
    #[serde(default)]
    deletion_time: ZeroizingJsonString,
}

trait VaultKubernetesProtocol: Send + Sync {
    fn login<'a>(
        &'a self,
        mount: &'a str,
        role: &'a str,
        jwt: &'a str,
    ) -> RuntimeFuture<'a, Result<ProviderAuthLease, VaultKubernetesRuntimeError>>;

    fn lookup_self<'a>(
        &'a self,
        token: &'a str,
    ) -> RuntimeFuture<'a, Result<ProviderLookupLease, VaultKubernetesRuntimeError>>;

    fn renew_self<'a>(
        &'a self,
        token: &'a str,
    ) -> RuntimeFuture<'a, Result<ProviderAuthLease, VaultKubernetesRuntimeError>>;

    fn read_kv2<'a>(
        &'a self,
        token: &'a str,
        reference: &'a ValidatedVaultKv2SecretReference,
    ) -> RuntimeFuture<'a, Result<ProviderKv2Read, VaultKubernetesRuntimeError>>;
}

struct HttpVaultKubernetesProtocol {
    client: Client,
    config: Arc<ValidatedRuntimeConfig>,
}

#[derive(Serialize)]
struct LoginRequest<'a> {
    role: &'a str,
    jwt: &'a str,
}

#[derive(Serialize)]
struct RenewRequest<'a> {
    increment: &'a str,
}

#[derive(Deserialize)]
struct AuthEnvelope {
    auth: Option<AuthPayload>,
}

#[derive(Deserialize)]
struct AuthPayload {
    client_token: String,
    lease_duration: u64,
    renewable: bool,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    token_policies: Vec<String>,
    #[serde(default)]
    policies: Vec<String>,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct LookupEnvelope {
    data: Option<LookupPayload>,
}

#[derive(Deserialize)]
struct LookupPayload {
    ttl: u64,
    renewable: bool,
    #[serde(default, alias = "token_policies")]
    policies: Vec<String>,
    #[serde(default)]
    meta: BTreeMap<String, String>,
}

fn kv2_read_url(
    config: &ValidatedRuntimeConfig,
    reference: &ValidatedVaultKv2SecretReference,
) -> Result<Url, VaultKubernetesRuntimeError> {
    let mut segments = Vec::with_capacity(reference.path_segments.len() + 2);
    segments.push(reference.mount.as_str());
    segments.push("data");
    segments.extend(reference.path_segments.iter().map(String::as_str));
    let mut url = config.api_url(&segments)?;
    if let Some(version) = reference.pinned_version {
        url.query_pairs_mut()
            .append_pair("version", &version.to_string());
    }
    Ok(url)
}

fn sensitive_vault_token_header(token: &str) -> Result<HeaderValue, VaultKubernetesRuntimeError> {
    let mut value = HeaderValue::from_str(token)
        .map_err(|_| VaultKubernetesRuntimeError::TokenLeaseRejected)?;
    value.set_sensitive(true);
    Ok(value)
}

impl VaultKubernetesProtocol for HttpVaultKubernetesProtocol {
    fn login<'a>(
        &'a self,
        mount: &'a str,
        role: &'a str,
        jwt: &'a str,
    ) -> RuntimeFuture<'a, Result<ProviderAuthLease, VaultKubernetesRuntimeError>> {
        Box::pin(async move {
            let url = self.config.api_url(&["auth", mount, "login"])?;
            let response = self
                .client
                .post(url)
                .json(&LoginRequest { role, jwt })
                .send()
                .await
                .map_err(|_| VaultKubernetesRuntimeError::ProviderTransport {
                    operation: "login",
                })?;
            auth_lease_from_response(response, "login").await
        })
    }

    fn lookup_self<'a>(
        &'a self,
        token: &'a str,
    ) -> RuntimeFuture<'a, Result<ProviderLookupLease, VaultKubernetesRuntimeError>> {
        Box::pin(async move {
            let url = self.config.api_url(&["auth", "token", "lookup-self"])?;
            let response = self
                .client
                .get(url)
                .header("X-Vault-Token", sensitive_vault_token_header(token)?)
                .send()
                .await
                .map_err(|_| VaultKubernetesRuntimeError::ProviderTransport {
                    operation: "lookup-self",
                })?;
            let envelope: LookupEnvelope = bounded_json(response, "lookup-self").await?;
            let data = envelope
                .data
                .ok_or(VaultKubernetesRuntimeError::ProviderResponse {
                    operation: "lookup-self",
                })?;
            Ok(ProviderLookupLease {
                ttl_seconds: data.ttl,
                renewable: data.renewable,
                token_policies: data.policies,
                metadata: data.meta,
            })
        })
    }

    fn renew_self<'a>(
        &'a self,
        token: &'a str,
    ) -> RuntimeFuture<'a, Result<ProviderAuthLease, VaultKubernetesRuntimeError>> {
        Box::pin(async move {
            let url = self.config.api_url(&["auth", "token", "renew-self"])?;
            let response = self
                .client
                .post(url)
                .header("X-Vault-Token", sensitive_vault_token_header(token)?)
                .json(&RenewRequest { increment: "600s" })
                .send()
                .await
                .map_err(|_| VaultKubernetesRuntimeError::ProviderTransport {
                    operation: "renew-self",
                })?;
            auth_lease_from_response(response, "renew-self").await
        })
    }

    fn read_kv2<'a>(
        &'a self,
        token: &'a str,
        reference: &'a ValidatedVaultKv2SecretReference,
    ) -> RuntimeFuture<'a, Result<ProviderKv2Read, VaultKubernetesRuntimeError>> {
        Box::pin(async move {
            let response = self
                .client
                .get(kv2_read_url(&self.config, reference)?)
                .header("X-Vault-Token", sensitive_vault_token_header(token)?)
                .send()
                .await
                .map_err(|_| VaultKubernetesRuntimeError::ProviderTransport {
                    operation: "kv-v2-read",
                })?;
            kv2_read_from_response(response, reference).await
        })
    }
}

async fn auth_lease_from_response(
    response: Response,
    operation: &'static str,
) -> Result<ProviderAuthLease, VaultKubernetesRuntimeError> {
    let envelope: AuthEnvelope = bounded_json(response, operation).await?;
    let payload = envelope
        .auth
        .ok_or(VaultKubernetesRuntimeError::ProviderResponse { operation })?;
    let token = Zeroizing::new(payload.client_token);
    if token.is_empty()
        || token.len() > MAX_CLIENT_TOKEN_BYTES
        || !token.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(VaultKubernetesRuntimeError::TokenLeaseRejected);
    }
    let token_policies = match (payload.token_policies, payload.policies) {
        (token_policies, policies) if token_policies.is_empty() => policies,
        (token_policies, policies) if policies.is_empty() || policies == token_policies => {
            token_policies
        }
        _ => return Err(VaultKubernetesRuntimeError::TokenLeaseRejected),
    };
    Ok(ProviderAuthLease {
        token,
        ttl_seconds: payload.lease_duration,
        renewable: payload.renewable,
        token_type: payload.token_type,
        token_policies,
        metadata: payload.metadata,
    })
}

async fn bounded_json<T: DeserializeOwned>(
    response: Response,
    operation: &'static str,
) -> Result<T, VaultKubernetesRuntimeError> {
    let bytes = bounded_response_body(response, operation).await?;
    serde_json::from_slice(bytes.as_slice())
        .map_err(|_| VaultKubernetesRuntimeError::ProviderResponse { operation })
}

async fn bounded_response_body(
    response: Response,
    operation: &'static str,
) -> Result<Zeroizing<Vec<u8>>, VaultKubernetesRuntimeError> {
    let status = response.status();
    if status.as_u16() != 200 {
        return Err(VaultKubernetesRuntimeError::ProviderHttpStatus {
            operation,
            status: status.as_u16(),
        });
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_PROVIDER_RESPONSE_BYTES as u64)
    {
        return Err(VaultKubernetesRuntimeError::ProviderResponse { operation });
    }
    let mut response = response;
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| VaultKubernetesRuntimeError::ProviderTransport { operation })?
    {
        let next_length = bytes
            .len()
            .checked_add(chunk.len())
            .ok_or(VaultKubernetesRuntimeError::ProviderResponse { operation })?;
        if next_length > MAX_PROVIDER_RESPONSE_BYTES {
            return Err(VaultKubernetesRuntimeError::ProviderResponse { operation });
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

struct ZeroizingProviderJson(Value);

impl Drop for ZeroizingProviderJson {
    fn drop(&mut self) {
        zeroize_json_value(&mut self.0);
    }
}

fn zeroize_json_value(value: &mut Value) {
    match value {
        Value::String(string) => string.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(zeroize_json_value),
        Value::Object(object) => {
            for (mut key, mut nested) in std::mem::take(object) {
                key.zeroize();
                zeroize_json_value(&mut nested);
            }
        }
        Value::Bool(boolean) => *boolean = false,
        Value::Number(number) => *number = 0_u64.into(),
        Value::Null => {}
    }
}

fn valid_vault_request_id(request_id: &str) -> bool {
    !request_id.is_empty()
        && request_id.len() <= MAX_VAULT_REQUEST_ID_BYTES
        && request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn validate_provider_kv2_read(
    read: &ProviderKv2Read,
    reference: &ValidatedVaultKv2SecretReference,
) -> Result<(), VaultKubernetesRuntimeError> {
    if !valid_vault_request_id(&read.request_id)
        || read.version == 0
        || reference
            .pinned_version
            .is_some_and(|expected| expected != read.version)
        || read.material.is_empty()
        || read.material.len() > MAX_SECRET_VALUE_BYTES
    {
        return Err(VaultKubernetesRuntimeError::ProviderResponse {
            operation: "kv-v2-read",
        });
    }
    Ok(())
}

async fn kv2_read_from_response(
    response: Response,
    reference: &ValidatedVaultKv2SecretReference,
) -> Result<ProviderKv2Read, VaultKubernetesRuntimeError> {
    const OPERATION: &str = "kv-v2-read";
    let bytes = bounded_response_body(response, OPERATION).await?;
    parse_kv2_response_body(bytes.as_slice(), reference)
}

fn parse_kv2_response_body(
    bytes: &[u8],
    reference: &ValidatedVaultKv2SecretReference,
) -> Result<ProviderKv2Read, VaultKubernetesRuntimeError> {
    const OPERATION: &str = "kv-v2-read";
    // Decode the secret map directly as strings. This avoids retaining any
    // unselected numeric/boolean secret scalar in a generic JSON tree; every
    // owned key and value is explicitly zeroized by the envelope guard.
    let body: Kv2ReadEnvelope = serde_json::from_slice(bytes).map_err(|_| {
        VaultKubernetesRuntimeError::ProviderResponse {
            operation: OPERATION,
        }
    })?;
    if !valid_vault_request_id(body.request_id.as_str()) {
        return Err(VaultKubernetesRuntimeError::ProviderResponse {
            operation: OPERATION,
        });
    }
    let request_id = body.request_id.as_str().to_string();
    let version = body.data.metadata.version;
    if version == 0 {
        return Err(VaultKubernetesRuntimeError::ProviderResponse {
            operation: OPERATION,
        });
    }
    if reference
        .pinned_version
        .is_some_and(|expected| expected != version)
    {
        return Err(VaultKubernetesRuntimeError::ProviderResponse {
            operation: OPERATION,
        });
    }
    if body.data.metadata.destroyed || !body.data.metadata.deletion_time.as_str().is_empty() {
        return Err(VaultKubernetesRuntimeError::ProviderResponse {
            operation: OPERATION,
        });
    }
    let material = body
        .data
        .data
        .get(reference.field.as_str())
        .map(ZeroizingJsonString::as_str)
        .filter(|material| !material.is_empty() && material.len() <= MAX_SECRET_VALUE_BYTES)
        .ok_or(VaultKubernetesRuntimeError::ProviderResponse {
            operation: OPERATION,
        })?;
    let read = ProviderKv2Read {
        request_id,
        version,
        material: Zeroizing::new(material.as_bytes().to_vec()),
    };
    validate_provider_kv2_read(&read, reference)?;
    Ok(read)
}

struct SecretToken(Zeroizing<String>);

impl std::fmt::Debug for SecretToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretToken([REDACTED])")
    }
}

/// Opaque immutable proof of one currently confirmed provider-token lease.
///
/// The bearer is intentionally private and has no getter. Consumers must use a
/// provider operation implemented by this module rather than exporting it.
pub(crate) struct VaultAuthenticatedLease {
    token: Arc<SecretToken>,
    generation: u64,
    expires_at: Instant,
    renew_at: Instant,
    hard_relogin_at: Instant,
    last_confirmed_at: Instant,
    workload_identity_binding_digest: String,
}

impl VaultAuthenticatedLease {
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
}

impl std::fmt::Debug for VaultAuthenticatedLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VaultAuthenticatedLease")
            .field("generation", &self.generation)
            .field(
                "workload_identity_binding_digest",
                &self.workload_identity_binding_digest,
            )
            .field("token", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

enum RuntimeSessionState {
    Empty { generation: u64 },
    Established(Arc<VaultAuthenticatedLease>),
}

impl RuntimeSessionState {
    fn generation(&self) -> u64 {
        match self {
            Self::Empty { generation } => *generation,
            Self::Established(lease) => lease.generation,
        }
    }

    fn lease(&self) -> Option<&Arc<VaultAuthenticatedLease>> {
        match self {
            Self::Empty { .. } => None,
            Self::Established(lease) => Some(lease),
        }
    }
}

#[derive(Default)]
struct RetryState {
    consecutive_failures: u32,
    not_before: Option<Instant>,
}

enum RuntimeBindingAuthority {
    Verified(Arc<VerifiedSecretProviderRuntimeBinding>),
    #[cfg(test)]
    Test,
}

const RUNTIME_LIFECYCLE_RUNNING: u8 = 0;
const RUNTIME_LIFECYCLE_SHUTTING_DOWN: u8 = 1;
const RUNTIME_LIFECYCLE_STOPPED: u8 = 2;

/// Process-lifetime owner of the exact Vault client, credential source, token
/// lease, and verified binding identity used by the retained resolver.
pub(crate) struct VaultKubernetesRuntime {
    config: Arc<ValidatedRuntimeConfig>,
    observation: Arc<VaultRuntimeOperationalObservation>,
    binding_authority: RuntimeBindingAuthority,
    protocol: Arc<dyn VaultKubernetesProtocol>,
    jwt_source: Arc<dyn ProjectedJwtSource>,
    clock: Arc<dyn RuntimeClock>,
    state: RwLock<RuntimeSessionState>,
    retry: RwLock<RetryState>,
    refresh_gate: Mutex<()>,
    lifecycle: AtomicU8,
}

impl std::fmt::Debug for VaultKubernetesRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let readiness = self.readiness_snapshot();
        formatter
            .debug_struct("VaultKubernetesRuntime")
            .field("provider_id", &self.observation.provider_id)
            .field(
                "provider_configuration_version",
                &self.observation.provider_configuration_version,
            )
            .field("adapter_kind", &self.observation.adapter_kind)
            .field("readiness", &readiness)
            .field("credential", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl VaultKubernetesRuntimeError {
    fn definitively_invalidates_session(&self) -> bool {
        matches!(
            self,
            Self::ProviderHttpStatus {
                operation: "lookup-self" | "renew-self",
                status: 400 | 403,
            } | Self::TokenLeaseRejected
                | Self::WorkloadIdentityMismatch
        )
    }
}

impl VaultKubernetesRuntime {
    /// Construct the production runtime from closed operational configuration
    /// and the exact already-verified binding object retained by startup.
    pub(crate) fn from_config(
        config: VaultKubernetesRuntimeConfig,
        verified_binding: Arc<VerifiedSecretProviderRuntimeBinding>,
    ) -> Result<Arc<Self>, VaultKubernetesRuntimeError> {
        let config = Arc::new(ValidatedRuntimeConfig::new(
            config,
            LegacyVaultEnvironment::capture(),
        )?);
        let (certificates, ca_trust_binding_digest) =
            load_ca_bundle(&config.original.ca_bundle_path)?;
        let client = build_http_client(certificates)?;
        let observation = Arc::new(VaultRuntimeOperationalObservation::measure(
            &config,
            ca_trust_binding_digest,
        )?);
        let protocol = Arc::new(HttpVaultKubernetesProtocol {
            client,
            config: config.clone(),
        });
        let jwt_source = Arc::new(FileProjectedJwtSource {
            path: config.original.projected_token_path.clone(),
        });
        Ok(Arc::new(Self::new_inner(
            config,
            observation,
            RuntimeBindingAuthority::Verified(verified_binding),
            protocol,
            jwt_source,
            Arc::new(SystemRuntimeClock),
        )))
    }

    #[cfg(test)]
    fn new_for_test(
        config: VaultKubernetesRuntimeConfig,
        protocol: Arc<dyn VaultKubernetesProtocol>,
        jwt_source: Arc<dyn ProjectedJwtSource>,
        clock: Arc<dyn RuntimeClock>,
    ) -> Result<Arc<Self>, VaultKubernetesRuntimeError> {
        let config = Arc::new(ValidatedRuntimeConfig::new(
            config,
            LegacyVaultEnvironment::default(),
        )?);
        let observation = Arc::new(VaultRuntimeOperationalObservation::measure(
            &config,
            ca_trust_digest(b"deterministic-test-ca")?,
        )?);
        Ok(Arc::new(Self::new_inner(
            config,
            observation,
            RuntimeBindingAuthority::Test,
            protocol,
            jwt_source,
            clock,
        )))
    }

    fn new_inner(
        config: Arc<ValidatedRuntimeConfig>,
        observation: Arc<VaultRuntimeOperationalObservation>,
        binding_authority: RuntimeBindingAuthority,
        protocol: Arc<dyn VaultKubernetesProtocol>,
        jwt_source: Arc<dyn ProjectedJwtSource>,
        clock: Arc<dyn RuntimeClock>,
    ) -> Self {
        Self {
            config,
            observation,
            binding_authority,
            protocol,
            jwt_source,
            clock,
            state: RwLock::new(RuntimeSessionState::Empty { generation: 0 }),
            retry: RwLock::new(RetryState::default()),
            refresh_gate: Mutex::new(()),
            lifecycle: AtomicU8::new(RUNTIME_LIFECYCLE_RUNNING),
        }
    }

    fn ensure_running(&self) -> Result<(), VaultKubernetesRuntimeError> {
        if self.lifecycle.load(Ordering::Acquire) == RUNTIME_LIFECYCLE_RUNNING {
            Ok(())
        } else {
            Err(VaultKubernetesRuntimeError::RuntimeStopped)
        }
    }

    /// Exact measured operational leaves. No aggregate runtime-binding digest
    /// is exposed or self-asserted here.
    pub(crate) fn operational_observation(&self) -> &Arc<VaultRuntimeOperationalObservation> {
        &self.observation
    }

    /// Preserve pointer identity with the authenticated binding consumed at
    /// construction. The live guard uses this for identity, then compares each
    /// independently measured leaf itself.
    pub(crate) fn verified_binding(&self) -> Option<&Arc<VerifiedSecretProviderRuntimeBinding>> {
        match &self.binding_authority {
            RuntimeBindingAuthority::Verified(binding) => Some(binding),
            #[cfg(test)]
            RuntimeBindingAuthority::Test => None,
        }
    }

    pub(crate) fn is_bound_to(&self, binding: &Arc<VerifiedSecretProviderRuntimeBinding>) -> bool {
        self.verified_binding()
            .is_some_and(|retained| Arc::ptr_eq(retained, binding))
    }

    /// Establish the first lease, or return the exact current lease if it is
    /// already fresh. Calls are serialized without holding the state lock over
    /// provider I/O.
    pub(crate) async fn authenticate(
        &self,
    ) -> Result<Arc<VaultAuthenticatedLease>, VaultKubernetesRuntimeError> {
        self.ensure_running()?;
        let _refresh = self.refresh_gate.lock().await;
        self.ensure_running()?;
        if let Some(delay) = self.retry_delay()? {
            return Err(VaultKubernetesRuntimeError::RetryDeferred {
                retry_after_seconds: delay.as_secs().max(1),
            });
        }
        if let Some(current) = self.current_lease()? {
            if self.snapshot_for(Some(&current)).is_ready() {
                return Ok(current);
            }
            let generation = self.invalidate_current(current.generation)?;
            return self.login_with_retry_locked(generation).await;
        }
        let expected_generation = self.current_generation()?;
        self.login_with_retry_locked(expected_generation).await
    }

    /// Return a currently confirmed exact lease, performing one due
    /// maintenance action first. This never returns a bearer value.
    pub(crate) async fn ensure_fresh(
        &self,
    ) -> Result<Arc<VaultAuthenticatedLease>, VaultKubernetesRuntimeError> {
        self.ensure_running()?;
        if self.next_maintenance_delay().is_zero() || !self.readiness_snapshot().is_ready() {
            self.maintenance_step().await?;
        }
        let lease = self
            .current_lease()?
            .ok_or(VaultKubernetesRuntimeError::NotAuthenticated)?;
        if !self.snapshot_for(Some(&lease)).is_ready() {
            return Err(VaultKubernetesRuntimeError::NotAuthenticated);
        }
        Ok(lease)
    }

    /// Resolve one typed KV-v2 reference without exporting the Vault bearer.
    ///
    /// The returned metadata expiry is a short, code-owned resolver freshness
    /// lease for the in-memory material. It is not a Vault dynamic-secret
    /// lease and grants no provider-token renewal or revocation authority.
    pub(crate) async fn resolve_kv2(
        &self,
        secret_ref: &SecretRef,
        context: &SecretResolutionContext,
    ) -> Result<ResolvedSecret, VaultKubernetesRuntimeError> {
        self.ensure_running()?;
        secret_ref
            .validate()
            .map_err(|_| VaultKubernetesRuntimeError::SecretReferenceInvalid)?;
        if secret_ref.provider_id() != self.observation.provider_id
            || secret_ref.provider_config_version()
                != self.observation.provider_configuration_version
        {
            return Err(VaultKubernetesRuntimeError::SecretReferenceMismatch);
        }
        context
            .admits(secret_ref)
            .map_err(|_| VaultKubernetesRuntimeError::SecretResolutionContextMismatch)?;
        let reference = validate_kv2_secret_reference(secret_ref, &self.observation)?;

        // Admission above is intentionally complete before ensure_fresh can
        // read a projected JWT or perform provider I/O.
        let lease = self.ensure_fresh().await?;
        if !self.lease_is_current(&lease) || !self.snapshot_for(Some(&lease)).is_ready() {
            return Err(VaultKubernetesRuntimeError::GenerationChanged);
        }
        let read = self
            .protocol
            .read_kv2(lease.token.0.as_str(), &reference)
            .await?;
        self.ensure_running()?;
        if !self.lease_is_current(&lease) || !self.snapshot_for(Some(&lease)).is_ready() {
            return Err(VaultKubernetesRuntimeError::GenerationChanged);
        }
        validate_provider_kv2_read(&read, &reference)?;

        let issued_at = DateTime::<Utc>::from_timestamp(self.clock.unix_now_seconds(), 0)
            .ok_or(VaultKubernetesRuntimeError::RuntimeStateUnavailable)?;
        let expires_at = issued_at
            .checked_add_signed(chrono::Duration::seconds(
                STATIC_RESOLUTION_FRESHNESS_SECONDS,
            ))
            .ok_or(VaultKubernetesRuntimeError::RuntimeStateUnavailable)?;
        let issued = IssuedSecretLease::try_new(
            format!("lease:vault-kv-v2-freshness:{}", read.request_id),
            read.version.to_string(),
            issued_at,
            expires_at,
        )
        .map_err(|_| VaultKubernetesRuntimeError::ProviderResponse {
            operation: "kv-v2-read",
        })?;
        let metadata = SecretLeaseMetadata::try_new(
            secret_ref,
            context,
            KV2_RESOLVER_CAPABILITY_VERSION,
            SecretLeaseRevocationOwner::WorkloadRuntime,
            SecretLeaseLifecycleInput::Active(issued),
        )
        .map_err(|_| VaultKubernetesRuntimeError::SecretReferenceInvalid)?;
        let material = SecretMaterial::new(read.material.as_slice().to_vec()).map_err(|_| {
            VaultKubernetesRuntimeError::ProviderResponse {
                operation: "kv-v2-read",
            }
        })?;
        if !self.lease_is_current(&lease) || !self.snapshot_for(Some(&lease)).is_ready() {
            return Err(VaultKubernetesRuntimeError::GenerationChanged);
        }
        Ok(ResolvedSecret { material, metadata })
    }

    /// Run at most one scheduled confirmation/renewal transition. Explicit
    /// invalid-token responses receive one fresh-JWT relogin; transport,
    /// throttling, and server failures preserve the prior lease without a
    /// second credential-bearing request.
    pub(crate) async fn maintenance_step(
        &self,
    ) -> Result<VaultReadinessSnapshot, VaultKubernetesRuntimeError> {
        self.ensure_running()?;
        let _refresh = self.refresh_gate.lock().await;
        self.ensure_running()?;
        if self.retry_delay()?.is_some() {
            return Ok(self.readiness_snapshot());
        }
        let Some(current) = self.current_lease()? else {
            let generation = self.current_generation()?;
            let established = self.login_with_retry_locked(generation).await?;
            return Ok(self.snapshot_for(Some(&established)));
        };
        let now = self.clock.monotonic_now();
        if now >= current.hard_relogin_at
            || now >= current.expires_at
            || current.expires_at.saturating_duration_since(now)
                <= Duration::from_secs(MIN_USABLE_TOKEN_TTL_SECONDS)
        {
            let generation = self.invalidate_current(current.generation)?;
            let established = self.login_with_retry_locked(generation).await?;
            return Ok(self.snapshot_for(Some(&established)));
        }

        let result = if now >= current.renew_at {
            self.renew_once_locked(&current).await
        } else if now.saturating_duration_since(current.last_confirmed_at)
            >= READINESS_PROBE_INTERVAL
        {
            self.confirm_once_locked(&current).await
        } else {
            return Ok(self.snapshot_for(Some(&current)));
        };

        match result {
            Ok(established) => Ok(self.snapshot_for(Some(&established))),
            Err(error) if error.definitively_invalidates_session() => {
                let generation = self.invalidate_current(current.generation)?;
                let established = self.login_with_retry_locked(generation).await?;
                Ok(self.snapshot_for(Some(&established)))
            }
            Err(error) => {
                self.record_retry()?;
                Err(error)
            }
        }
    }

    pub(crate) fn readiness_snapshot(&self) -> VaultReadinessSnapshot {
        if self.lifecycle.load(Ordering::Acquire) != RUNTIME_LIFECYCLE_RUNNING {
            return stopped_snapshot();
        }
        match self.state.read() {
            Ok(state) => match &*state {
                RuntimeSessionState::Empty { generation } => unauthenticated_snapshot(*generation),
                RuntimeSessionState::Established(lease) => self.snapshot_for(Some(lease)),
            },
            Err(_) => unauthenticated_snapshot(0),
        }
    }

    pub(crate) fn next_maintenance_delay(&self) -> Duration {
        if self.lifecycle.load(Ordering::Acquire) != RUNTIME_LIFECYCLE_RUNNING {
            return READINESS_PROBE_INTERVAL;
        }
        let now = self.clock.monotonic_now();
        let Ok(state) = self.state.read() else {
            return Duration::ZERO;
        };
        let base_delay = match state.lease() {
            None => Duration::ZERO,
            Some(lease) => {
                let expiry_floor = lease
                    .expires_at
                    .checked_sub(Duration::from_secs(MIN_USABLE_TOKEN_TTL_SECONDS))
                    .unwrap_or(lease.expires_at);
                [
                    lease.renew_at,
                    lease.hard_relogin_at,
                    lease.last_confirmed_at + READINESS_PROBE_INTERVAL,
                    expiry_floor,
                ]
                .into_iter()
                .min()
                .unwrap_or(now)
                .saturating_duration_since(now)
            }
        };
        drop(state);
        match self.retry_delay() {
            Ok(Some(retry_delay)) => base_delay.max(retry_delay),
            Ok(None) => base_delay,
            Err(_) => Duration::ZERO,
        }
    }

    /// Confirm that a consumer still retains the exact current session Arc,
    /// not merely a matching generation copied from an earlier lease.
    pub(crate) fn lease_is_current(&self, lease: &Arc<VaultAuthenticatedLease>) -> bool {
        if self.lifecycle.load(Ordering::Acquire) != RUNTIME_LIFECYCLE_RUNNING {
            return false;
        }
        self.state
            .read()
            .ok()
            .and_then(|state| state.lease().cloned())
            .is_some_and(|current| Arc::ptr_eq(&current, lease))
    }

    /// Return the remaining interval for which the exact current lease can
    /// support a production guard witness. This never exposes the bearer and
    /// is bounded by both provider expiry and the confirmation-staleness cap.
    pub(crate) fn witness_valid_for(
        &self,
        lease: &Arc<VaultAuthenticatedLease>,
    ) -> Result<Duration, VaultKubernetesRuntimeError> {
        self.ensure_running()?;
        if !self.lease_is_current(lease) || !self.snapshot_for(Some(lease)).is_ready() {
            return Err(VaultKubernetesRuntimeError::NotAuthenticated);
        }
        let now = self.clock.monotonic_now();
        let confirmation_deadline = lease
            .last_confirmed_at
            .checked_add(READINESS_MAX_STALENESS)
            .ok_or(VaultKubernetesRuntimeError::RuntimeStateUnavailable)?;
        let usable_expiry_deadline = lease
            .expires_at
            .checked_sub(Duration::from_secs(MIN_USABLE_TOKEN_TTL_SECONDS))
            .unwrap_or(lease.expires_at);
        Ok(usable_expiry_deadline
            .min(confirmation_deadline)
            .saturating_duration_since(now))
    }

    /// Permanently stop this runtime and discard its current session before
    /// the process owner releases the maintenance task. Future authentication,
    /// maintenance, and resolution attempts fail closed rather than relogin.
    pub(crate) async fn shutdown(&self) -> Result<(), VaultKubernetesRuntimeError> {
        match self.lifecycle.compare_exchange(
            RUNTIME_LIFECYCLE_RUNNING,
            RUNTIME_LIFECYCLE_SHUTTING_DOWN,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(RUNTIME_LIFECYCLE_STOPPED) => return Ok(()),
            Err(_) => return Err(VaultKubernetesRuntimeError::RuntimeStopped),
        }
        // Fence and drop the retained bearer before the first suspension
        // point. A caller may bound or cancel shutdown while maintenance is
        // blocked in provider I/O; cancellation must never leave the old
        // session current or the runtime callable.
        let result = (|| {
            let mut state = self
                .state
                .write()
                .map_err(|_| VaultKubernetesRuntimeError::RuntimeStateUnavailable)?;
            let generation = state
                .generation()
                .checked_add(1)
                .ok_or(VaultKubernetesRuntimeError::GenerationChanged)?;
            *state = RuntimeSessionState::Empty { generation };
            let mut retry = self
                .retry
                .write()
                .map_err(|_| VaultKubernetesRuntimeError::RuntimeStateUnavailable)?;
            *retry = RetryState::default();
            Ok(())
        })();
        self.lifecycle
            .store(RUNTIME_LIFECYCLE_STOPPED, Ordering::Release);
        result
    }

    async fn login_locked(
        &self,
        expected_generation: u64,
    ) -> Result<Arc<VaultAuthenticatedLease>, VaultKubernetesRuntimeError> {
        let jwt = self.jwt_source.read().await?;
        let identity =
            validate_projected_jwt(jwt.as_str(), &self.config, self.clock.unix_now_seconds())?;
        let auth = self
            .protocol
            .login(
                &self.config.original.kubernetes_auth_mount,
                &self.config.original.kubernetes_role,
                jwt.as_str(),
            )
            .await?;
        validate_auth_lease(
            &auth,
            &self.config,
            Some(identity.service_account_uid.as_str()),
            true,
        )?;
        let lookup = self.protocol.lookup_self(auth.token.as_str()).await?;
        validate_lookup_lease(
            &lookup,
            &self.config,
            Some(identity.service_account_uid.as_str()),
        )?;
        let ttl_seconds = auth.ttl_seconds.min(lookup.ttl_seconds);
        self.install_session(
            expected_generation,
            Arc::new(SecretToken(auth.token)),
            ttl_seconds,
            None,
            None,
        )
    }

    async fn login_with_retry_locked(
        &self,
        expected_generation: u64,
    ) -> Result<Arc<VaultAuthenticatedLease>, VaultKubernetesRuntimeError> {
        match self.login_locked(expected_generation).await {
            Ok(lease) => Ok(lease),
            Err(error) => {
                self.record_retry()?;
                Err(error)
            }
        }
    }

    async fn renew_once_locked(
        &self,
        current: &Arc<VaultAuthenticatedLease>,
    ) -> Result<Arc<VaultAuthenticatedLease>, VaultKubernetesRuntimeError> {
        let identity = self.read_current_projected_identity().await?;
        // Confirm identity continuity before extending the old token. This
        // avoids retaining a Kubernetes UID while still preventing renewal of
        // a token issued to a deleted/recreated ServiceAccount identity.
        let before_renew = self.protocol.lookup_self(current.token.0.as_str()).await?;
        validate_lookup_lease(
            &before_renew,
            &self.config,
            Some(identity.service_account_uid.as_str()),
        )?;
        let auth = self.protocol.renew_self(current.token.0.as_str()).await?;
        validate_auth_lease(
            &auth,
            &self.config,
            Some(identity.service_account_uid.as_str()),
            false,
        )?;
        if auth.token.as_bytes() != current.token.0.as_bytes() {
            return Err(VaultKubernetesRuntimeError::TokenLeaseRejected);
        }
        let lookup = self.protocol.lookup_self(current.token.0.as_str()).await?;
        validate_lookup_lease(
            &lookup,
            &self.config,
            Some(identity.service_account_uid.as_str()),
        )?;
        let ttl_seconds = auth.ttl_seconds.min(lookup.ttl_seconds);
        self.install_session(
            current.generation,
            current.token.clone(),
            ttl_seconds,
            Some(current.hard_relogin_at),
            None,
        )
    }

    async fn confirm_once_locked(
        &self,
        current: &Arc<VaultAuthenticatedLease>,
    ) -> Result<Arc<VaultAuthenticatedLease>, VaultKubernetesRuntimeError> {
        let identity = self.read_current_projected_identity().await?;
        let lookup = self.protocol.lookup_self(current.token.0.as_str()).await?;
        validate_lookup_lease(
            &lookup,
            &self.config,
            Some(identity.service_account_uid.as_str()),
        )?;
        self.install_session(
            current.generation,
            current.token.clone(),
            lookup.ttl_seconds,
            Some(current.hard_relogin_at),
            Some(current.renew_at),
        )
    }

    async fn read_current_projected_identity(
        &self,
    ) -> Result<ProjectedJwtIdentity, VaultKubernetesRuntimeError> {
        let jwt = self.jwt_source.read().await?;
        validate_projected_jwt(jwt.as_str(), &self.config, self.clock.unix_now_seconds())
    }

    fn install_session(
        &self,
        expected_generation: u64,
        token: Arc<SecretToken>,
        ttl_seconds: u64,
        hard_relogin_at: Option<Instant>,
        preserved_renew_at: Option<Instant>,
    ) -> Result<Arc<VaultAuthenticatedLease>, VaultKubernetesRuntimeError> {
        validate_lease_ttl(ttl_seconds)?;
        let now = self.clock.monotonic_now();
        let generation = expected_generation
            .checked_add(1)
            .ok_or(VaultKubernetesRuntimeError::GenerationChanged)?;
        let expires_at = now
            .checked_add(Duration::from_secs(ttl_seconds))
            .ok_or(VaultKubernetesRuntimeError::TokenLeaseRejected)?;
        let renew_at = match preserved_renew_at {
            Some(deadline) if deadline > now => deadline,
            Some(_) => return Err(VaultKubernetesRuntimeError::TokenLeaseRejected),
            None => now
                .checked_add(Duration::from_secs((ttl_seconds * 2) / 3))
                .ok_or(VaultKubernetesRuntimeError::TokenLeaseRejected)?,
        };
        let hard_relogin_at = match hard_relogin_at {
            Some(deadline) if deadline > now => deadline,
            Some(_) => return Err(VaultKubernetesRuntimeError::TokenLeaseRejected),
            None => now
                .checked_add(Duration::from_secs(MAX_SESSION_AGE_SECONDS))
                .ok_or(VaultKubernetesRuntimeError::TokenLeaseRejected)?,
        };
        let established = Arc::new(VaultAuthenticatedLease {
            token,
            generation,
            expires_at,
            renew_at,
            hard_relogin_at,
            last_confirmed_at: now,
            workload_identity_binding_digest: self
                .observation
                .credential_source
                .identity_binding_digest
                .clone(),
        });
        let mut state = self
            .state
            .write()
            .map_err(|_| VaultKubernetesRuntimeError::RuntimeStateUnavailable)?;
        if state.generation() != expected_generation {
            return Err(VaultKubernetesRuntimeError::GenerationChanged);
        }
        *state = RuntimeSessionState::Established(established.clone());
        drop(state);
        self.clear_retry();
        Ok(established)
    }

    fn invalidate_current(
        &self,
        expected_generation: u64,
    ) -> Result<u64, VaultKubernetesRuntimeError> {
        let generation = expected_generation
            .checked_add(1)
            .ok_or(VaultKubernetesRuntimeError::GenerationChanged)?;
        let mut state = self
            .state
            .write()
            .map_err(|_| VaultKubernetesRuntimeError::RuntimeStateUnavailable)?;
        if state.generation() != expected_generation {
            return Err(VaultKubernetesRuntimeError::GenerationChanged);
        }
        *state = RuntimeSessionState::Empty { generation };
        Ok(generation)
    }

    fn retry_delay(&self) -> Result<Option<Duration>, VaultKubernetesRuntimeError> {
        let retry = self
            .retry
            .read()
            .map_err(|_| VaultKubernetesRuntimeError::RuntimeStateUnavailable)?;
        Ok(retry.not_before.and_then(|deadline| {
            let delay = deadline.saturating_duration_since(self.clock.monotonic_now());
            (!delay.is_zero()).then_some(delay)
        }))
    }

    fn record_retry(&self) -> Result<(), VaultKubernetesRuntimeError> {
        let mut retry = self
            .retry
            .write()
            .map_err(|_| VaultKubernetesRuntimeError::RuntimeStateUnavailable)?;
        let exponent = retry.consecutive_failures.min(5);
        let seconds = (1_u64 << exponent).min(30);
        retry.consecutive_failures = retry.consecutive_failures.saturating_add(1);
        retry.not_before = self
            .clock
            .monotonic_now()
            .checked_add(Duration::from_secs(seconds));
        Ok(())
    }

    fn clear_retry(&self) {
        if let Ok(mut retry) = self.retry.write() {
            *retry = RetryState::default();
        }
    }

    fn current_generation(&self) -> Result<u64, VaultKubernetesRuntimeError> {
        self.state
            .read()
            .map(|state| state.generation())
            .map_err(|_| VaultKubernetesRuntimeError::RuntimeStateUnavailable)
    }

    fn current_lease(
        &self,
    ) -> Result<Option<Arc<VaultAuthenticatedLease>>, VaultKubernetesRuntimeError> {
        self.state
            .read()
            .map(|state| state.lease().cloned())
            .map_err(|_| VaultKubernetesRuntimeError::RuntimeStateUnavailable)
    }

    fn snapshot_for(&self, lease: Option<&Arc<VaultAuthenticatedLease>>) -> VaultReadinessSnapshot {
        let Some(lease) = lease else {
            return unauthenticated_snapshot(0);
        };
        let now = self.clock.monotonic_now();
        let remaining = lease.expires_at.saturating_duration_since(now);
        let confirmation_age = now.saturating_duration_since(lease.last_confirmed_at);
        let state = if now >= lease.expires_at {
            VaultReadinessState::LeaseExpired
        } else if now >= lease.hard_relogin_at {
            VaultReadinessState::ReloginRequired
        } else if remaining <= Duration::from_secs(MIN_USABLE_TOKEN_TTL_SECONDS) {
            VaultReadinessState::LeaseNearExpiry
        } else if confirmation_age > READINESS_MAX_STALENESS {
            VaultReadinessState::ConfirmationStale
        } else {
            VaultReadinessState::Ready
        };
        VaultReadinessSnapshot {
            state,
            generation: lease.generation,
            remaining_ttl_seconds: remaining.as_secs(),
            last_confirmation_age_seconds: confirmation_age.as_secs(),
            workload_identity_binding_digest: Some(lease.workload_identity_binding_digest.clone()),
        }
    }
}

fn unauthenticated_snapshot(generation: u64) -> VaultReadinessSnapshot {
    VaultReadinessSnapshot {
        state: VaultReadinessState::Unauthenticated,
        generation,
        remaining_ttl_seconds: 0,
        last_confirmation_age_seconds: u64::MAX,
        workload_identity_binding_digest: None,
    }
}

fn stopped_snapshot() -> VaultReadinessSnapshot {
    VaultReadinessSnapshot {
        state: VaultReadinessState::Stopped,
        generation: 0,
        remaining_ttl_seconds: 0,
        last_confirmation_age_seconds: u64::MAX,
        workload_identity_binding_digest: None,
    }
}

fn validate_lease_ttl(ttl_seconds: u64) -> Result<(), VaultKubernetesRuntimeError> {
    if !(MIN_USABLE_TOKEN_TTL_SECONDS + 1..=REQUESTED_TOKEN_TTL_SECONDS).contains(&ttl_seconds) {
        return Err(VaultKubernetesRuntimeError::TokenLeaseRejected);
    }
    Ok(())
}

fn validate_token_policies(
    policies: &[String],
    expected_policy: &str,
) -> Result<(), VaultKubernetesRuntimeError> {
    if policies.len() != 1 || policies[0] != expected_policy {
        return Err(VaultKubernetesRuntimeError::TokenLeaseRejected);
    }
    Ok(())
}

fn validate_auth_lease(
    lease: &ProviderAuthLease,
    config: &ValidatedRuntimeConfig,
    expected_service_account_uid: Option<&str>,
    require_token_type: bool,
) -> Result<(), VaultKubernetesRuntimeError> {
    validate_lease_ttl(lease.ttl_seconds)?;
    if !lease.renewable
        || (require_token_type && lease.token_type.as_deref() != Some("service"))
        || lease
            .token_type
            .as_deref()
            .is_some_and(|token_type| token_type != "service")
    {
        return Err(VaultKubernetesRuntimeError::TokenLeaseRejected);
    }
    validate_token_policies(
        &lease.token_policies,
        &config.original.expected_token_policy,
    )?;
    validate_provider_metadata(&lease.metadata, config, expected_service_account_uid)
}

fn validate_lookup_lease(
    lease: &ProviderLookupLease,
    config: &ValidatedRuntimeConfig,
    expected_service_account_uid: Option<&str>,
) -> Result<(), VaultKubernetesRuntimeError> {
    validate_lease_ttl(lease.ttl_seconds)?;
    if !lease.renewable {
        return Err(VaultKubernetesRuntimeError::TokenLeaseRejected);
    }
    validate_token_policies(
        &lease.token_policies,
        &config.original.expected_token_policy,
    )?;
    validate_provider_metadata(&lease.metadata, config, expected_service_account_uid)
}

fn validate_provider_metadata(
    metadata: &BTreeMap<String, String>,
    config: &ValidatedRuntimeConfig,
    expected_service_account_uid: Option<&str>,
) -> Result<(), VaultKubernetesRuntimeError> {
    let uid = metadata
        .get("service_account_uid")
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or(VaultKubernetesRuntimeError::WorkloadIdentityMismatch)?;
    if metadata.get("role") != Some(&config.original.kubernetes_role)
        || metadata.get("service_account_namespace")
            != Some(&config.original.expected_service_account_namespace)
        || metadata.get("service_account_name")
            != Some(&config.original.expected_service_account_name)
        || expected_service_account_uid.is_some_and(|expected| uid != expected)
    {
        return Err(VaultKubernetesRuntimeError::WorkloadIdentityMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ryuki_engine::secret_material::{SecretLeaseLifecycleState, SecretVersionSelector};
    use serde_json::json;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Mutex as StdMutex;
    use tokio::sync::Notify;

    const BASE_UNIX: i64 = 1_800_000_000;
    const SERVICE_ACCOUNT_UID: &str = "service-account-uid-fixture";

    struct FakeClock {
        monotonic_base: Instant,
        unix_base: i64,
        offset_seconds: AtomicU64,
    }

    impl FakeClock {
        fn new(unix_base: i64) -> Arc<Self> {
            Arc::new(Self {
                monotonic_base: Instant::now(),
                unix_base,
                offset_seconds: AtomicU64::new(0),
            })
        }

        fn advance(&self, seconds: u64) {
            self.offset_seconds.fetch_add(seconds, Ordering::SeqCst);
        }
    }

    impl RuntimeClock for FakeClock {
        fn monotonic_now(&self) -> Instant {
            self.monotonic_base + Duration::from_secs(self.offset_seconds.load(Ordering::SeqCst))
        }

        fn unix_now_seconds(&self) -> i64 {
            self.unix_base + self.offset_seconds.load(Ordering::SeqCst) as i64
        }
    }

    struct FakeJwtSource {
        token: StdMutex<String>,
        reads: AtomicU64,
    }

    impl FakeJwtSource {
        fn new(token: String) -> Arc<Self> {
            Arc::new(Self {
                token: StdMutex::new(token),
                reads: AtomicU64::new(0),
            })
        }

        fn set_current(&self, token: String) {
            *self.token.lock().expect("fake JWT lock") = token;
        }

        fn reads(&self) -> u64 {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl ProjectedJwtSource for FakeJwtSource {
        fn read<'a>(
            &'a self,
        ) -> RuntimeFuture<'a, Result<Zeroizing<String>, VaultKubernetesRuntimeError>> {
            Box::pin(async move {
                self.reads.fetch_add(1, Ordering::SeqCst);
                let token = self
                    .token
                    .lock()
                    .map_err(|_| VaultKubernetesRuntimeError::RuntimeStateUnavailable)?
                    .clone();
                Ok(Zeroizing::new(token))
            })
        }
    }

    struct FakeProtocol {
        login_calls: AtomicU64,
        lookup_calls: AtomicU64,
        renew_calls: AtomicU64,
        read_calls: AtomicU64,
        login_error: StdMutex<Option<VaultKubernetesRuntimeError>>,
        renew_error: StdMutex<Option<VaultKubernetesRuntimeError>>,
        lookup_error: StdMutex<Option<VaultKubernetesRuntimeError>>,
        read_error: StdMutex<Option<VaultKubernetesRuntimeError>>,
        read_version: AtomicU64,
        last_read: StdMutex<Option<FakeKv2Observation>>,
        block_read: AtomicBool,
        read_entered: Notify,
        read_release: Notify,
        expected_policy: String,
        ttl_seconds: u64,
    }

    #[derive(Clone, PartialEq, Eq)]
    struct FakeKv2Observation {
        mount: String,
        path_segments: Vec<String>,
        field: String,
        pinned_version: Option<u64>,
    }

    impl FakeProtocol {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                login_calls: AtomicU64::new(0),
                lookup_calls: AtomicU64::new(0),
                renew_calls: AtomicU64::new(0),
                read_calls: AtomicU64::new(0),
                login_error: StdMutex::new(None),
                renew_error: StdMutex::new(None),
                lookup_error: StdMutex::new(None),
                read_error: StdMutex::new(None),
                read_version: AtomicU64::new(7),
                last_read: StdMutex::new(None),
                block_read: AtomicBool::new(false),
                read_entered: Notify::new(),
                read_release: Notify::new(),
                expected_policy: "ryuki-platform-api-runtime".to_string(),
                ttl_seconds: REQUESTED_TOKEN_TTL_SECONDS,
            })
        }

        fn metadata() -> BTreeMap<String, String> {
            BTreeMap::from([
                ("role".to_string(), "ryuki-platform-api".to_string()),
                (
                    "service_account_namespace".to_string(),
                    "ryuki-platform".to_string(),
                ),
                (
                    "service_account_name".to_string(),
                    "platform-api".to_string(),
                ),
                (
                    "service_account_uid".to_string(),
                    SERVICE_ACCOUNT_UID.to_string(),
                ),
            ])
        }

        fn set_renew_error(&self, error: VaultKubernetesRuntimeError) {
            *self.renew_error.lock().expect("fake renew lock") = Some(error);
        }

        fn set_login_error(&self, error: VaultKubernetesRuntimeError) {
            *self.login_error.lock().expect("fake login lock") = Some(error);
        }

        fn set_read_version(&self, version: u64) {
            self.read_version.store(version, Ordering::SeqCst);
        }

        fn read_calls(&self) -> u64 {
            self.read_calls.load(Ordering::SeqCst)
        }

        fn last_read(&self) -> Option<FakeKv2Observation> {
            self.last_read.lock().expect("fake read lock").clone()
        }

        fn block_next_read(&self) {
            self.block_read.store(true, Ordering::SeqCst);
        }

        async fn wait_until_read_enters(&self) {
            self.read_entered.notified().await;
        }

        fn release_read(&self) {
            self.read_release.notify_one();
        }

        fn counts(&self) -> (u64, u64, u64) {
            (
                self.login_calls.load(Ordering::SeqCst),
                self.lookup_calls.load(Ordering::SeqCst),
                self.renew_calls.load(Ordering::SeqCst),
            )
        }
    }

    impl VaultKubernetesProtocol for FakeProtocol {
        fn login<'a>(
            &'a self,
            _mount: &'a str,
            _role: &'a str,
            _jwt: &'a str,
        ) -> RuntimeFuture<'a, Result<ProviderAuthLease, VaultKubernetesRuntimeError>> {
            Box::pin(async move {
                let call = self.login_calls.fetch_add(1, Ordering::SeqCst) + 1;
                if let Some(error) = self
                    .login_error
                    .lock()
                    .map_err(|_| VaultKubernetesRuntimeError::RuntimeStateUnavailable)?
                    .take()
                {
                    return Err(error);
                }
                Ok(ProviderAuthLease {
                    token: Zeroizing::new(format!("vault-token-{call}")),
                    ttl_seconds: self.ttl_seconds,
                    renewable: true,
                    token_type: Some("service".to_string()),
                    token_policies: vec![self.expected_policy.clone()],
                    metadata: Self::metadata(),
                })
            })
        }

        fn lookup_self<'a>(
            &'a self,
            _token: &'a str,
        ) -> RuntimeFuture<'a, Result<ProviderLookupLease, VaultKubernetesRuntimeError>> {
            Box::pin(async move {
                self.lookup_calls.fetch_add(1, Ordering::SeqCst);
                if let Some(error) = self
                    .lookup_error
                    .lock()
                    .map_err(|_| VaultKubernetesRuntimeError::RuntimeStateUnavailable)?
                    .take()
                {
                    return Err(error);
                }
                Ok(ProviderLookupLease {
                    ttl_seconds: self.ttl_seconds,
                    renewable: true,
                    token_policies: vec![self.expected_policy.clone()],
                    metadata: Self::metadata(),
                })
            })
        }

        fn renew_self<'a>(
            &'a self,
            token: &'a str,
        ) -> RuntimeFuture<'a, Result<ProviderAuthLease, VaultKubernetesRuntimeError>> {
            Box::pin(async move {
                self.renew_calls.fetch_add(1, Ordering::SeqCst);
                if let Some(error) = self
                    .renew_error
                    .lock()
                    .map_err(|_| VaultKubernetesRuntimeError::RuntimeStateUnavailable)?
                    .take()
                {
                    return Err(error);
                }
                Ok(ProviderAuthLease {
                    token: Zeroizing::new(token.to_string()),
                    ttl_seconds: self.ttl_seconds,
                    renewable: true,
                    token_type: None,
                    token_policies: vec![self.expected_policy.clone()],
                    metadata: Self::metadata(),
                })
            })
        }

        fn read_kv2<'a>(
            &'a self,
            _token: &'a str,
            reference: &'a ValidatedVaultKv2SecretReference,
        ) -> RuntimeFuture<'a, Result<ProviderKv2Read, VaultKubernetesRuntimeError>> {
            Box::pin(async move {
                self.read_calls.fetch_add(1, Ordering::SeqCst);
                if self.block_read.swap(false, Ordering::SeqCst) {
                    self.read_entered.notify_one();
                    self.read_release.notified().await;
                }
                if let Some(error) = self
                    .read_error
                    .lock()
                    .map_err(|_| VaultKubernetesRuntimeError::RuntimeStateUnavailable)?
                    .take()
                {
                    return Err(error);
                }
                *self
                    .last_read
                    .lock()
                    .map_err(|_| VaultKubernetesRuntimeError::RuntimeStateUnavailable)? =
                    Some(FakeKv2Observation {
                        mount: reference.mount.clone(),
                        path_segments: reference.path_segments.clone(),
                        field: reference.field.clone(),
                        pinned_version: reference.pinned_version,
                    });
                Ok(ProviderKv2Read {
                    request_id: "vault-request-fixture-1".to_string(),
                    version: self.read_version.load(Ordering::SeqCst),
                    material: Zeroizing::new(b"fixture-secret-material".to_vec()),
                })
            })
        }
    }

    fn valid_config() -> VaultKubernetesRuntimeConfig {
        VaultKubernetesRuntimeConfig {
            provider_id: "provider:hashicorp-vault-primary".to_string(),
            configuration_version: 1,
            api_flavor: VaultApiFlavor::HashicorpVaultV1,
            endpoint: "https://vault.vault.svc:8200".to_string(),
            ca_bundle_path: PathBuf::from(VAULT_CA_BUNDLE_PATH),
            kubernetes_auth_mount: "kubernetes".to_string(),
            kubernetes_role: "ryuki-platform-api".to_string(),
            kubernetes_audience: "vault".to_string(),
            projected_token_path: PathBuf::from(VAULT_PROJECTED_TOKEN_PATH),
            expected_service_account_namespace: "ryuki-platform".to_string(),
            expected_service_account_name: "platform-api".to_string(),
            expected_token_policy: "ryuki-platform-api-runtime".to_string(),
        }
    }

    fn valid_environment_snapshot() -> BTreeMap<String, OsString> {
        BTreeMap::from([
            (
                RUNTIME_ENV_PROVIDER_ID.into(),
                "provider:hashicorp-vault-primary".into(),
            ),
            (RUNTIME_ENV_CONFIGURATION_VERSION.into(), "1".into()),
            (RUNTIME_ENV_API_FLAVOR.into(), "hashicorp-vault-v1".into()),
            (
                RUNTIME_ENV_ENDPOINT.into(),
                "https://vault.vault.svc:8200".into(),
            ),
            (
                RUNTIME_ENV_CA_BUNDLE_PATH.into(),
                VAULT_CA_BUNDLE_PATH.into(),
            ),
            (
                RUNTIME_ENV_KUBERNETES_AUTH_MOUNT.into(),
                "kubernetes".into(),
            ),
            (
                RUNTIME_ENV_KUBERNETES_ROLE.into(),
                "ryuki-platform-api".into(),
            ),
            (RUNTIME_ENV_KUBERNETES_AUDIENCE.into(), "vault".into()),
            (
                RUNTIME_ENV_PROJECTED_TOKEN_PATH.into(),
                VAULT_PROJECTED_TOKEN_PATH.into(),
            ),
            (
                RUNTIME_ENV_EXPECTED_SERVICE_ACCOUNT_NAMESPACE.into(),
                "ryuki-platform".into(),
            ),
            (
                RUNTIME_ENV_EXPECTED_SERVICE_ACCOUNT_NAME.into(),
                "platform-api".into(),
            ),
            (
                RUNTIME_ENV_EXPECTED_TOKEN_POLICY.into(),
                "ryuki-platform-api-runtime".into(),
            ),
        ])
    }

    #[test]
    fn runtime_environment_is_closed_complete_and_canonical() {
        let parsed = VaultKubernetesRuntimeConfig::from_environment_snapshot(
            valid_environment_snapshot(),
            true,
        )
        .expect("complete environment")
        .expect("runtime is configured");
        assert_eq!(parsed, valid_config());

        let mut partial = valid_environment_snapshot();
        partial.remove(RUNTIME_ENV_KUBERNETES_ROLE);
        assert_eq!(
            VaultKubernetesRuntimeConfig::from_environment_snapshot(partial, true),
            Err(VaultKubernetesRuntimeError::RuntimeEnvironmentIncomplete)
        );

        let mut unknown = valid_environment_snapshot();
        unknown.insert(
            "RYUKI_SECRET_PROVIDER_RUNTIME__UNREVIEWED_ESCAPE_HATCH".into(),
            "true".into(),
        );
        assert_eq!(
            VaultKubernetesRuntimeConfig::from_environment_snapshot(unknown, true),
            Err(VaultKubernetesRuntimeError::RuntimeEnvironmentUnknown {
                name: "RYUKI_SECRET_PROVIDER_RUNTIME__UNREVIEWED_ESCAPE_HATCH".into(),
            })
        );

        let mut noncanonical_version = valid_environment_snapshot();
        noncanonical_version.insert(RUNTIME_ENV_CONFIGURATION_VERSION.into(), "01".into());
        assert_eq!(
            VaultKubernetesRuntimeConfig::from_environment_snapshot(noncanonical_version, true),
            Err(VaultKubernetesRuntimeError::RuntimeEnvironmentInvalid {
                name: RUNTIME_ENV_CONFIGURATION_VERSION,
            })
        );
    }

    #[test]
    fn optional_runtime_environment_may_only_be_entirely_absent() {
        assert_eq!(
            VaultKubernetesRuntimeConfig::from_environment_snapshot(BTreeMap::new(), false),
            Ok(None)
        );
        assert_eq!(
            VaultKubernetesRuntimeConfig::from_environment_snapshot(BTreeMap::new(), true),
            Err(VaultKubernetesRuntimeError::RuntimeEnvironmentMissing)
        );
    }

    fn validated_config() -> Arc<ValidatedRuntimeConfig> {
        Arc::new(
            ValidatedRuntimeConfig::new(valid_config(), LegacyVaultEnvironment::default())
                .expect("valid runtime config"),
        )
    }

    fn typed_secret_ref(
        provider_id: &str,
        provider_configuration_version: u64,
        locator: &str,
        field: Option<&str>,
        version_selector: SecretVersionSelector,
    ) -> SecretRef {
        SecretRef::try_new(
            provider_id,
            provider_configuration_version,
            "deployment:prod-eu",
            "trust-domain:prod-eu",
            Some("tenant:one".to_string()),
            format!("hmac-sha256:{}", "a".repeat(64)),
            "key:secret-ref-fingerprint-v2",
            locator,
            field.map(str::to_string),
            "purpose:integration-authentication",
            version_selector,
        )
        .expect("valid typed secret reference fixture")
    }

    fn resolution_context(tenant_id: &str) -> SecretResolutionContext {
        SecretResolutionContext::try_new(
            "deployment:prod-eu",
            "trust-domain:prod-eu",
            Some(tenant_id.to_string()),
            "purpose:integration-authentication",
            "workload:platform-api",
            Some("request:typed-resolution-fixture".to_string()),
            None,
            9,
            11,
        )
        .expect("valid resolution context fixture")
    }

    fn projected_jwt(unix_now: i64, audience: Value, subject: &str, marker: &str) -> String {
        projected_jwt_with_times(
            audience,
            subject,
            marker,
            unix_now,
            unix_now,
            unix_now + 600,
        )
    }

    fn projected_jwt_with_times(
        audience: Value,
        subject: &str,
        marker: &str,
        iat: i64,
        nbf: i64,
        exp: i64,
    ) -> String {
        let header = json!({"alg": "RS256", "typ": "JWT"});
        let payload = json!({
            "aud": audience,
            "sub": subject,
            "iat": iat,
            "nbf": nbf,
            "exp": exp,
            "jti": marker,
            "kubernetes.io": {
                "namespace": "ryuki-platform",
                "serviceaccount": {
                    "name": "platform-api",
                    "uid": SERVICE_ACCOUNT_UID
                },
                "pod": {
                    "name": "platform-api-fixture",
                    "uid": format!("pod-{marker}")
                }
            }
        });
        let encode = |value: &Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(value).expect("serialize JWT fixture"))
        };
        format!(
            "{}.{}.{}",
            encode(&header),
            encode(&payload),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"fixture-signature")
        )
    }

    fn runtime_fixture(
        jwt_token: String,
    ) -> (
        Arc<VaultKubernetesRuntime>,
        Arc<FakeClock>,
        Arc<FakeJwtSource>,
        Arc<FakeProtocol>,
    ) {
        let clock = FakeClock::new(BASE_UNIX);
        let source = FakeJwtSource::new(jwt_token);
        let protocol = FakeProtocol::new();
        let runtime = VaultKubernetesRuntime::new_for_test(
            valid_config(),
            protocol.clone(),
            source.clone(),
            clock.clone(),
        )
        .expect("construct test runtime");
        (runtime, clock, source, protocol)
    }

    #[test]
    fn closed_config_rejects_legacy_http_openbao_and_unknown_fields() {
        let config = valid_config();
        let debug = format!("{config:?}");
        assert!(!debug.contains("vault.vault.svc"));
        assert!(!debug.contains(VAULT_PROJECTED_TOKEN_PATH));
        assert!(!debug.contains("ryuki-platform-api-runtime"));

        let mut value = serde_json::to_value(&config).expect("serialize config");
        value
            .as_object_mut()
            .expect("config object")
            .insert("vault_token".to_string(), json!("forbidden-static-token"));
        assert!(serde_json::from_value::<VaultKubernetesRuntimeConfig>(value).is_err());

        let mut openbao = config.clone();
        openbao.api_flavor = VaultApiFlavor::OpenBaoV1;
        let openbao_error =
            match ValidatedRuntimeConfig::new(openbao, LegacyVaultEnvironment::default()) {
                Ok(_) => panic!("OpenBao must remain a distinct unsupported flavor"),
                Err(error) => error,
            };
        assert_eq!(
            openbao_error,
            VaultKubernetesRuntimeError::UnsupportedApiFlavor
        );

        let mut http = config.clone();
        http.endpoint = "http://127.0.0.1:8200".to_string();
        assert!(matches!(
            ValidatedRuntimeConfig::new(http, LegacyVaultEnvironment::default()),
            Err(VaultKubernetesRuntimeError::InvalidConfiguration {
                field: "endpoint",
                ..
            })
        ));
        let mut ambiguous_prefix = config.clone();
        ambiguous_prefix.endpoint = "https://vault.vault.svc:8200/a//".to_string();
        assert!(matches!(
            ValidatedRuntimeConfig::new(ambiguous_prefix, LegacyVaultEnvironment::default()),
            Err(VaultKubernetesRuntimeError::InvalidConfiguration {
                field: "endpoint",
                ..
            })
        ));
        let mut root_policy = config.clone();
        root_policy.expected_token_policy = "root".to_string();
        assert!(matches!(
            ValidatedRuntimeConfig::new(root_policy, LegacyVaultEnvironment::default()),
            Err(VaultKubernetesRuntimeError::InvalidConfiguration {
                field: "expected_token_policy",
                ..
            })
        ));
        let legacy_error =
            match ValidatedRuntimeConfig::new(config, LegacyVaultEnvironment { present: true }) {
                Ok(_) => panic!("legacy Vault configuration must be rejected"),
                Err(error) => error,
            };
        assert_eq!(
            legacy_error,
            VaultKubernetesRuntimeError::LegacyVaultConfigurationPresent
        );
    }

    #[test]
    fn operational_observation_uses_named_independent_leaf_digests() {
        let config = validated_config();
        let first_ca = ca_trust_digest(b"first-ca").expect("CA digest");
        let observation = VaultRuntimeOperationalObservation::measure(&config, first_ca.clone())
            .expect("measure observation");
        assert_eq!(
            observation.backend_compatibility_profile.digest_contract,
            BACKEND_COMPATIBILITY_PROFILE_DIGEST_CONTRACT
        );
        assert_eq!(
            observation
                .credential_source
                .provider_authentication_digest_contract,
            PROVIDER_AUTHENTICATION_DIGEST_CONTRACT
        );
        assert_eq!(observation.transport.ca_trust_binding_digest, first_ca);
        assert_ne!(
            observation.transport.ca_trust_binding_digest,
            format!("sha256:{:x}", Sha256::digest(b"first-ca"))
        );
        assert!(observation
            .capability_bindings
            .windows(2)
            .all(|pair| pair[0].capability_id < pair[1].capability_id));

        let second = VaultRuntimeOperationalObservation::measure(
            &config,
            ca_trust_digest(b"second-ca").expect("second CA digest"),
        )
        .expect("second observation");
        assert_ne!(
            observation.transport.ca_trust_binding_digest,
            second.transport.ca_trust_binding_digest
        );

        let mut different_role = valid_config();
        different_role.kubernetes_role = "ryuki-platform-api-next".to_string();
        let different_role =
            ValidatedRuntimeConfig::new(different_role, LegacyVaultEnvironment::default())
                .expect("alternate role config");
        let different = VaultRuntimeOperationalObservation::measure(
            &different_role,
            observation.transport.ca_trust_binding_digest.clone(),
        )
        .expect("alternate observation");
        assert_ne!(
            observation
                .credential_source
                .provider_authentication_binding_digest,
            different
                .credential_source
                .provider_authentication_binding_digest
        );
        assert_eq!(
            observation.credential_source.identity_binding_digest,
            different.credential_source.identity_binding_digest
        );
    }

    #[test]
    fn projected_jwt_requires_exact_singleton_audience_and_subject() {
        let config = validated_config();
        let expected_subject = "system:serviceaccount:ryuki-platform:platform-api";
        let valid = projected_jwt(
            BASE_UNIX,
            json!(["vault"]),
            expected_subject,
            "valid-marker",
        );
        let identity = validate_projected_jwt(&valid, &config, BASE_UNIX)
            .expect("valid projected JWT identity");
        assert_eq!(identity.service_account_uid.as_str(), SERVICE_ACCOUNT_UID);

        for invalid in [
            projected_jwt(
                BASE_UNIX,
                json!(["vault", "another-audience"]),
                expected_subject,
                "multi-audience-secret-marker",
            ),
            projected_jwt(
                BASE_UNIX,
                json!(["vault"]),
                "system:serviceaccount:ryuki-platform:other",
                "wrong-subject-secret-marker",
            ),
        ] {
            let error = match validate_projected_jwt(&invalid, &config, BASE_UNIX) {
                Ok(_) => panic!("invalid projected JWT must be rejected"),
                Err(error) => error,
            };
            let rendered = format!("{error:?} {error}");
            assert_eq!(error, VaultKubernetesRuntimeError::ProjectedTokenInvalid);
            assert!(!rendered.contains("secret-marker"));
            assert!(!rendered.contains(&invalid));
        }

        let extreme_times = projected_jwt_with_times(
            json!(["vault"]),
            expected_subject,
            "extreme-time-marker",
            i64::MIN,
            i64::MIN,
            i64::MAX,
        );
        assert!(matches!(
            validate_projected_jwt(&extreme_times, &config, BASE_UNIX),
            Err(VaultKubernetesRuntimeError::ProjectedTokenInvalid)
        ));
    }

    #[test]
    fn kv2_url_uses_exact_pinned_query_and_omits_query_for_latest() {
        let config = validated_config();
        let mut reference = ValidatedVaultKv2SecretReference {
            mount: "secret".to_string(),
            path_segments: vec!["ryuki".to_string(), "vendor".to_string()],
            field: "password".to_string(),
            pinned_version: Some(7),
        };
        assert_eq!(
            kv2_read_url(&config, &reference)
                .expect("pinned URL")
                .as_str(),
            "https://vault.vault.svc:8200/v1/secret/data/ryuki/vendor?version=7"
        );
        reference.pinned_version = None;
        let latest = kv2_read_url(&config, &reference).expect("latest URL");
        assert_eq!(
            latest.as_str(),
            "https://vault.vault.svc:8200/v1/secret/data/ryuki/vendor"
        );
        assert!(latest.query().is_none());
    }

    #[test]
    fn vault_bearer_header_is_always_marked_sensitive() {
        let header = sensitive_vault_token_header("vault-token-sensitive-fixture")
            .expect("valid Vault token header");
        assert!(header.is_sensitive());
        assert!(!format!("{header:?}").contains("vault-token-sensitive-fixture"));
    }

    #[test]
    fn kv2_response_requires_exact_version_request_id_and_selected_string_field() {
        let reference = ValidatedVaultKv2SecretReference {
            mount: "secret".to_string(),
            path_segments: vec!["ryuki".to_string(), "vendor".to_string()],
            field: "sensitive-field".to_string(),
            pinned_version: Some(7),
        };
        let valid = serde_json::to_vec(&json!({
            "request_id": "vault-request-fixture-2",
            "data": {
                "data": {"sensitive-field": "fixture-material"},
                "metadata": {
                    "version": 7,
                    "destroyed": false,
                    "deletion_time": ""
                }
            }
        }))
        .expect("serialize response fixture");
        let read = parse_kv2_response_body(&valid, &reference).expect("valid KV-v2 body");
        assert_eq!(read.version, 7);
        assert_eq!(read.request_id, "vault-request-fixture-2");
        assert_eq!(read.material.as_slice(), b"fixture-material");

        for invalid in [
            json!({
                "request_id": "vault-request-fixture-2",
                "version": 7,
                "data": {
                    "data": {"sensitive-field": "fixture-material"},
                    "metadata": {}
                }
            }),
            json!({
                "request_id": "vault-request-fixture-2",
                "data": {
                    "data": {"sensitive-field": "fixture-material"},
                    "metadata": {"version": 8}
                }
            }),
            json!({
                "request_id": "invalid/request/id",
                "data": {
                    "data": {"sensitive-field": "fixture-material"},
                    "metadata": {"version": 7}
                }
            }),
            json!({
                "request_id": "vault-request-fixture-2",
                "data": {
                    "data": {"sensitive-field": {"not": "a string"}},
                    "metadata": {"version": 7}
                }
            }),
        ] {
            let bytes = serde_json::to_vec(&invalid).expect("serialize invalid fixture");
            let error = match parse_kv2_response_body(&bytes, &reference) {
                Ok(_) => panic!("invalid KV-v2 body must fail closed"),
                Err(error) => error,
            };
            let rendered = format!("{error:?} {error}");
            assert!(matches!(
                error,
                VaultKubernetesRuntimeError::ProviderResponse {
                    operation: "kv-v2-read"
                }
            ));
            assert!(!rendered.contains("sensitive-field"));
            assert!(!rendered.contains("fixture-material"));
        }
    }

    #[tokio::test]
    async fn typed_kv2_admission_rejects_mismatch_and_locator_before_any_io() {
        let jwt = projected_jwt(
            BASE_UNIX,
            json!(["vault"]),
            "system:serviceaccount:ryuki-platform:platform-api",
            "no-io-marker",
        );
        let (runtime, _clock, source, protocol) = runtime_fixture(jwt);
        let context = resolution_context("tenant:one");
        let wrong_provider = typed_secret_ref(
            "provider:other",
            1,
            "secret/ryuki/vendor",
            Some("password"),
            SecretVersionSelector::pinned("7").expect("pinned version"),
        );
        assert!(matches!(
            runtime.resolve_kv2(&wrong_provider, &context).await,
            Err(VaultKubernetesRuntimeError::SecretReferenceMismatch)
        ));

        let valid = typed_secret_ref(
            "provider:hashicorp-vault-primary",
            1,
            "secret/ryuki/vendor",
            Some("password"),
            SecretVersionSelector::pinned("7").expect("pinned version"),
        );
        assert!(matches!(
            runtime
                .resolve_kv2(&valid, &resolution_context("tenant:two"))
                .await,
            Err(VaultKubernetesRuntimeError::SecretResolutionContextMismatch)
        ));

        let invalid_locator = typed_secret_ref(
            "provider:hashicorp-vault-primary",
            1,
            "secret//sensitive-locator",
            Some("sensitive-field"),
            SecretVersionSelector::latest_at_resolve(),
        );
        let error = match runtime.resolve_kv2(&invalid_locator, &context).await {
            Ok(_) => panic!("non-normal locator must be rejected"),
            Err(error) => error,
        };
        let rendered = format!("{error:?} {error}");
        assert_eq!(error, VaultKubernetesRuntimeError::SecretReferenceInvalid);
        assert!(!rendered.contains("sensitive-locator"));
        assert!(!rendered.contains("sensitive-field"));
        assert_eq!(source.reads(), 0);
        assert_eq!(protocol.counts(), (0, 0, 0));
        assert_eq!(protocol.read_calls(), 0);
    }

    #[tokio::test]
    async fn typed_kv2_resolve_returns_value_free_bounded_freshness_metadata() {
        let jwt = projected_jwt(
            BASE_UNIX,
            json!(["vault"]),
            "system:serviceaccount:ryuki-platform:platform-api",
            "kv2-success-marker",
        );
        let (runtime, _clock, source, protocol) = runtime_fixture(jwt);
        let reference = typed_secret_ref(
            "provider:hashicorp-vault-primary",
            1,
            "secret/ryuki/vendor",
            Some("password"),
            SecretVersionSelector::pinned("7").expect("pinned version"),
        );
        let resolved = runtime
            .resolve_kv2(&reference, &resolution_context("tenant:one"))
            .await
            .expect("typed KV-v2 resolve");
        assert_eq!(
            resolved.material.with_bytes(|bytes| bytes.to_vec()),
            b"fixture-secret-material"
        );
        assert_eq!(
            resolved.metadata.lifecycle_state(),
            SecretLeaseLifecycleState::Active
        );
        assert_eq!(resolved.metadata.resolved_version(), Some("7"));
        assert_eq!(
            resolved.metadata.expires_at(),
            DateTime::<Utc>::from_timestamp(BASE_UNIX + STATIC_RESOLUTION_FRESHNESS_SECONDS, 0)
        );
        let metadata = serde_json::to_value(&resolved.metadata).expect("serialize metadata");
        assert_eq!(
            metadata.get("leaseId").and_then(Value::as_str),
            Some("lease:vault-kv-v2-freshness:vault-request-fixture-1")
        );
        assert_eq!(
            metadata.get("resolutionMode").and_then(Value::as_str),
            Some("pinned")
        );
        assert_eq!(
            metadata.get("requestedVersion").and_then(Value::as_str),
            Some("7")
        );
        assert_eq!(
            metadata.get("revocationOwner").and_then(Value::as_str),
            Some("workload-runtime")
        );
        assert!(!metadata.to_string().contains("fixture-secret-material"));
        let observed = protocol.last_read().expect("recorded read");
        assert_eq!(observed.mount, "secret");
        assert_eq!(
            observed.path_segments,
            vec!["ryuki".to_string(), "vendor".to_string()]
        );
        assert_eq!(observed.field, "password");
        assert_eq!(observed.pinned_version, Some(7));
        assert_eq!(source.reads(), 1);
        assert_eq!(protocol.counts(), (1, 1, 0));
        assert_eq!(protocol.read_calls(), 1);
    }

    #[tokio::test]
    async fn typed_kv2_version_selection_is_exact_for_pinned_and_latest_reads() {
        let subject = "system:serviceaccount:ryuki-platform:platform-api";
        let pinned_jwt = projected_jwt(BASE_UNIX, json!(["vault"]), subject, "pinned-mismatch");
        let (pinned_runtime, _clock, _source, pinned_protocol) = runtime_fixture(pinned_jwt);
        pinned_protocol.set_read_version(8);
        let pinned = typed_secret_ref(
            "provider:hashicorp-vault-primary",
            1,
            "secret/ryuki/vendor",
            Some("password"),
            SecretVersionSelector::pinned("7").expect("pinned version"),
        );
        assert!(matches!(
            pinned_runtime
                .resolve_kv2(&pinned, &resolution_context("tenant:one"))
                .await,
            Err(VaultKubernetesRuntimeError::ProviderResponse {
                operation: "kv-v2-read"
            })
        ));

        let latest_jwt = projected_jwt(BASE_UNIX, json!(["vault"]), subject, "latest-read");
        let (latest_runtime, _clock, _source, latest_protocol) = runtime_fixture(latest_jwt);
        latest_protocol.set_read_version(9);
        let latest = typed_secret_ref(
            "provider:hashicorp-vault-primary",
            1,
            "secret/ryuki/vendor",
            Some("password"),
            SecretVersionSelector::latest_at_resolve(),
        );
        let resolved = latest_runtime
            .resolve_kv2(&latest, &resolution_context("tenant:one"))
            .await
            .expect("latest resolve");
        assert_eq!(resolved.metadata.resolved_version(), Some("9"));
        let latest_metadata =
            serde_json::to_value(&resolved.metadata).expect("serialize latest metadata");
        assert_eq!(
            latest_metadata
                .get("resolutionMode")
                .and_then(Value::as_str),
            Some("latest-at-resolve")
        );
        assert!(latest_metadata.get("requestedVersion").is_none());
        assert_eq!(
            latest_protocol
                .last_read()
                .expect("latest read observation")
                .pinned_version,
            None
        );
    }

    #[tokio::test]
    async fn typed_kv2_read_is_generation_fenced_after_provider_io() {
        let jwt = projected_jwt(
            BASE_UNIX,
            json!(["vault"]),
            "system:serviceaccount:ryuki-platform:platform-api",
            "generation-fence",
        );
        let (runtime, clock, _source, protocol) = runtime_fixture(jwt);
        runtime
            .authenticate()
            .await
            .expect("initial authentication");
        protocol.block_next_read();
        let task_runtime = runtime.clone();
        let task = tokio::spawn(async move {
            let reference = typed_secret_ref(
                "provider:hashicorp-vault-primary",
                1,
                "secret/ryuki/vendor",
                Some("password"),
                SecretVersionSelector::pinned("7").expect("pinned version"),
            );
            task_runtime
                .resolve_kv2(&reference, &resolution_context("tenant:one"))
                .await
        });
        protocol.wait_until_read_enters().await;
        clock.advance(31);
        let refreshed = runtime
            .maintenance_step()
            .await
            .expect("replace session generation");
        assert_eq!(refreshed.generation, 2);
        protocol.release_read();
        let error = match task.await.expect("resolve task") {
            Ok(_) => panic!("read under a replaced generation must be discarded"),
            Err(error) => error,
        };
        assert_eq!(error, VaultKubernetesRuntimeError::GenerationChanged);
        assert_eq!(protocol.read_calls(), 1);
    }

    #[tokio::test]
    async fn authenticate_confirms_lookup_and_never_exports_or_formats_tokens() {
        let jwt = projected_jwt(
            BASE_UNIX,
            json!(["vault"]),
            "system:serviceaccount:ryuki-platform:platform-api",
            "auth-secret-marker",
        );
        let (runtime, _clock, source, protocol) = runtime_fixture(jwt.clone());
        let lease = runtime.authenticate().await.expect("authenticate");
        assert_eq!(lease.generation(), 1);
        assert!(runtime.lease_is_current(&lease));
        assert!(runtime.readiness_snapshot().is_ready());
        assert_eq!(runtime.next_maintenance_delay(), Duration::from_secs(30));
        assert_eq!(source.reads(), 1);
        assert_eq!(protocol.counts(), (1, 1, 0));

        let same = runtime.ensure_fresh().await.expect("fresh lease");
        assert!(Arc::ptr_eq(&lease, &same));
        assert_eq!(protocol.counts(), (1, 1, 0));

        let debug = format!("{runtime:?} {lease:?}");
        assert!(!debug.contains("vault-token-1"));
        assert!(!debug.contains(SERVICE_ACCOUNT_UID));
        assert!(!debug.contains(&jwt));
        assert!(runtime.verified_binding().is_none());
    }

    #[tokio::test]
    async fn confirmation_and_renewal_replace_exact_session_arc_with_generation_fencing() {
        let jwt = projected_jwt(
            BASE_UNIX,
            json!("vault"),
            "system:serviceaccount:ryuki-platform:platform-api",
            "renew-marker",
        );
        let (runtime, clock, _source, protocol) = runtime_fixture(jwt);
        let first = runtime.authenticate().await.expect("authenticate");
        let hard_relogin_at = first.hard_relogin_at;
        let token = first.token.clone();

        clock.advance(31);
        let confirmation = runtime
            .maintenance_step()
            .await
            .expect("lookup confirmation");
        assert_eq!(confirmation.generation, 2);
        let second = runtime.ensure_fresh().await.expect("confirmed lease");
        assert!(!Arc::ptr_eq(&first, &second));
        assert!(Arc::ptr_eq(&token, &second.token));
        assert_eq!(second.hard_relogin_at, hard_relogin_at);
        assert_eq!(protocol.counts(), (1, 2, 0));

        clock.advance(370);
        let renewed = runtime.maintenance_step().await.expect("renew lease");
        assert_eq!(renewed.generation, 3);
        let third = runtime.ensure_fresh().await.expect("renewed lease");
        assert!(Arc::ptr_eq(&token, &third.token));
        assert_eq!(third.hard_relogin_at, hard_relogin_at);
        assert!(renewed.is_ready());
        assert_eq!(protocol.counts(), (1, 4, 1));

        let fenced = runtime.install_session(
            1,
            third.token.clone(),
            REQUESTED_TOKEN_TTL_SECONDS,
            Some(third.hard_relogin_at),
            None,
        );
        assert!(matches!(
            fenced,
            Err(VaultKubernetesRuntimeError::GenerationChanged)
        ));
        assert!(runtime.lease_is_current(&third));
    }

    #[tokio::test]
    async fn explicit_invalid_renewal_relogs_in_once_with_a_fresh_projected_jwt() {
        let subject = "system:serviceaccount:ryuki-platform:platform-api";
        let first_jwt = projected_jwt(BASE_UNIX, json!(["vault"]), subject, "first-login");
        let second_jwt = projected_jwt(BASE_UNIX + 401, json!(["vault"]), subject, "second-login");
        let (runtime, clock, source, protocol) = runtime_fixture(first_jwt);
        let first = runtime.authenticate().await.expect("initial login");
        source.set_current(second_jwt);
        protocol.set_renew_error(VaultKubernetesRuntimeError::ProviderHttpStatus {
            operation: "renew-self",
            status: 403,
        });
        clock.advance(401);
        let snapshot = runtime.maintenance_step().await.expect("single relogin");
        let second = runtime.ensure_fresh().await.expect("replacement lease");
        assert!(snapshot.is_ready());
        assert_eq!(snapshot.generation, 3);
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(source.reads(), 3);
        assert_eq!(protocol.counts(), (2, 3, 1));
    }

    #[tokio::test]
    async fn definitive_invalidity_fences_old_lease_when_relogin_fails() {
        let jwt = projected_jwt(
            BASE_UNIX,
            json!(["vault"]),
            "system:serviceaccount:ryuki-platform:platform-api",
            "failed-relogin",
        );
        let (runtime, clock, _source, protocol) = runtime_fixture(jwt);
        let old = runtime.authenticate().await.expect("initial login");
        protocol.set_renew_error(VaultKubernetesRuntimeError::ProviderHttpStatus {
            operation: "renew-self",
            status: 403,
        });
        protocol
            .set_login_error(VaultKubernetesRuntimeError::ProviderTransport { operation: "login" });
        clock.advance(401);
        assert!(matches!(
            runtime.maintenance_step().await,
            Err(VaultKubernetesRuntimeError::ProviderTransport { operation: "login" })
        ));
        assert!(!runtime.lease_is_current(&old));
        let readiness = runtime.readiness_snapshot();
        assert_eq!(readiness.state, VaultReadinessState::Unauthenticated);
        assert_eq!(readiness.generation, 2);
        assert_eq!(runtime.next_maintenance_delay(), Duration::from_secs(1));
        assert_eq!(protocol.counts(), (2, 2, 1));
    }

    #[tokio::test]
    async fn uncertain_renewal_failure_preserves_the_existing_lease_without_relogin() {
        let jwt = projected_jwt(
            BASE_UNIX,
            json!(["vault"]),
            "system:serviceaccount:ryuki-platform:platform-api",
            "transport-failure",
        );
        let (runtime, clock, source, protocol) = runtime_fixture(jwt);
        let first = runtime.authenticate().await.expect("initial login");
        protocol.set_renew_error(VaultKubernetesRuntimeError::ProviderTransport {
            operation: "renew-self",
        });
        clock.advance(401);
        assert!(matches!(
            runtime.maintenance_step().await,
            Err(VaultKubernetesRuntimeError::ProviderTransport {
                operation: "renew-self"
            })
        ));
        assert!(runtime.lease_is_current(&first));
        assert_eq!(runtime.readiness_snapshot().generation, 1);
        assert_eq!(source.reads(), 2);
        assert_eq!(protocol.counts(), (1, 2, 1));
        assert_eq!(runtime.next_maintenance_delay(), Duration::from_secs(1));

        let deferred = runtime
            .maintenance_step()
            .await
            .expect("retry window returns cached readiness");
        assert!(!deferred.is_ready());
        assert_eq!(protocol.counts(), (1, 2, 1));

        clock.advance(1);
        let recovered = runtime
            .maintenance_step()
            .await
            .expect("retry after bounded backoff");
        assert!(recovered.is_ready());
        assert_eq!(recovered.generation, 2);
        assert_eq!(protocol.counts(), (1, 4, 2));
    }

    #[tokio::test]
    async fn shutdown_permanently_fences_authentication_and_maintenance() {
        let jwt = projected_jwt(
            BASE_UNIX,
            json!(["vault"]),
            "system:serviceaccount:ryuki-platform:platform-api",
            "shutdown",
        );
        let (runtime, _clock, _source, protocol) = runtime_fixture(jwt);
        let lease = runtime.authenticate().await.expect("initial login");
        assert!(runtime.witness_valid_for(&lease).expect("fresh witness") > Duration::ZERO);

        runtime.shutdown().await.expect("first shutdown");
        runtime.shutdown().await.expect("idempotent shutdown");
        assert_eq!(
            runtime.readiness_snapshot().state,
            VaultReadinessState::Stopped
        );
        assert!(!runtime.lease_is_current(&lease));
        assert!(matches!(
            runtime.authenticate().await,
            Err(VaultKubernetesRuntimeError::RuntimeStopped)
        ));
        assert!(matches!(
            runtime.maintenance_step().await,
            Err(VaultKubernetesRuntimeError::RuntimeStopped)
        ));
        assert_eq!(protocol.counts(), (1, 1, 0));
    }

    #[tokio::test]
    async fn shutdown_invalidates_the_lease_before_waiting_for_refresh_ownership() {
        let jwt = projected_jwt(
            BASE_UNIX,
            json!(["vault"]),
            "system:serviceaccount:ryuki-platform:platform-api",
            "shutdown-refresh-race",
        );
        let (runtime, _clock, _source, _protocol) = runtime_fixture(jwt);
        let lease = runtime.authenticate().await.expect("initial login");
        let refresh_owner = runtime.refresh_gate.lock().await;

        tokio::time::timeout(Duration::from_millis(10), runtime.shutdown())
            .await
            .expect("shutdown must not wait for refresh ownership")
            .expect("shutdown succeeds");
        assert!(!runtime.lease_is_current(&lease));
        assert_eq!(
            runtime.readiness_snapshot().state,
            VaultReadinessState::Stopped
        );
        drop(refresh_owner);
    }
}
