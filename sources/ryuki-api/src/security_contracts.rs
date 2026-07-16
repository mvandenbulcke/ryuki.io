//! Content-addressed deployment security admission.
//!
//! This module deliberately performs only local, bounded reads. Schemas are
//! embedded in the binary and external `$ref` retrieval is denied. Production
//! remains unavailable until trusted closure receipts and live runtime facts
//! can be verified; structural JSON can never promote itself to authority.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};

use chrono::{DateTime, Utc};
use jsonschema::{Retrieve, Uri};
use ryuki_core::config::{AuthMode, RyukiConfig};
use ryuki_core::security_profile::{
    DeploymentSecurityProfile, MigrationAuthoritySource, SecurityProfile, StartupAdmissionContext,
};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

pub(crate) const SECURITY_CONTRACT_ROOT_ENV: &str = "RYUKI_SECURITY_CONTRACT_ROOT";
pub(crate) const SECURITY_PROFILE_PATH_ENV: &str = "RYUKI_DEPLOYMENT_SECURITY_PROFILE_PATH";
pub(crate) const SECURITY_PROFILE_DIGEST_ENV: &str = "RYUKI_DEPLOYMENT_SECURITY_PROFILE_DIGEST";
pub(crate) const EXPECTED_DEPLOYMENT_ID_ENV: &str = "RYUKI_EXPECTED_DEPLOYMENT_ID";
pub(crate) const SECURITY_PROFILE_ENV: &str = "RYUKI_SECURITY_PROFILE";

const MAX_PROFILE_BYTES: u64 = 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DOCUMENTS: usize = 256;
const MAX_REFERENCE_DEPTH: usize = 16;
const MAX_REFERENCE_BINDINGS: usize = 256;
const MAX_JSON_DEPTH: usize = 64;
const MAX_JSON_NODES: usize = 100_000;
const MAX_JSON_ARRAY_ITEMS: usize = 4_096;
const MAX_JSON_OBJECT_MEMBERS: usize = 4_096;

const PROFILE_SCHEMA: &str =
    include_str!("../../../catalog/security-contracts/v1/deployment-security-profile.schema.json");
const PROVIDER_SCHEMA: &str =
    include_str!("../../../catalog/security-contracts/v1/provider-registry.schema.json");
const ACTION_SCHEMA: &str =
    include_str!("../../../catalog/security-contracts/v1/action-resource-registry.schema.json");
const LIMIT_SCHEMA: &str =
    include_str!("../../../catalog/security-contracts/v1/security-limit-profile.schema.json");
const PACKAGE_EXIT_RECEIPT_SCHEMA: &str =
    include_str!("../../../catalog/security-contracts/v1/package-exit-receipt.schema.json");

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StartupSecurityPins {
    pub(crate) contract_root: PathBuf,
    pub(crate) profile_path: PathBuf,
    pub(crate) profile_digest: String,
    pub(crate) deployment_id: String,
    pub(crate) security_profile: SecurityProfile,
}

impl StartupSecurityPins {
    pub(crate) fn from_environment() -> Result<Self, String> {
        Self::from_source(|name| std::env::var_os(name))
    }

    pub(crate) fn from_source(
        mut get: impl FnMut(&str) -> Option<OsString>,
    ) -> Result<Self, String> {
        let root = required_unicode(&mut get, SECURITY_CONTRACT_ROOT_ENV)?;
        let contract_root = PathBuf::from(&root);
        if !contract_root.is_absolute() {
            return Err(format!(
                "{SECURITY_CONTRACT_ROOT_ENV} must be an absolute path"
            ));
        }

        let profile_path_raw = required_unicode(&mut get, SECURITY_PROFILE_PATH_ENV)?;
        let profile_path = PathBuf::from(&profile_path_raw);
        validate_relative_path(SECURITY_PROFILE_PATH_ENV, &profile_path)?;

        let profile_digest = required_unicode(&mut get, SECURITY_PROFILE_DIGEST_ENV)?;
        validate_digest_pin(SECURITY_PROFILE_DIGEST_ENV, &profile_digest)?;

        let deployment_id = required_unicode(&mut get, EXPECTED_DEPLOYMENT_ID_ENV)?;
        validate_namespaced_id(EXPECTED_DEPLOYMENT_ID_ENV, &deployment_id, "deployment:")?;

        let profile_raw = required_unicode(&mut get, SECURITY_PROFILE_ENV)?;
        let security_profile = match profile_raw.as_str() {
            "development" => SecurityProfile::Development,
            "test" => SecurityProfile::Test,
            "production" => SecurityProfile::Production,
            _ => {
                return Err(format!(
                    "{SECURITY_PROFILE_ENV} must select exactly one of development, test, or production"
                ));
            }
        };

        Ok(Self {
            contract_root,
            profile_path,
            profile_digest,
            deployment_id,
            security_profile,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentReferenceBinding {
    document_id: String,
    document_version: u64,
    content_digest: String,
    artifact_locator: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialReferenceBinding {
    reference_id: String,
    reference_version: u64,
    reference_digest: String,
    artifact_locator: String,
    purpose: String,
    value_free: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DevelopmentFixtureKindConfig {
    configuration_kind: String,
    fixture_type: String,
    loopback_only: bool,
    isolated_network_required: bool,
    live_execution_allowed: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct OidcKindConfig {
    configuration_kind: String,
    issuer_ref: ContentReferenceBinding,
    endpoint_policy_ref: ContentReferenceBinding,
    validation_mode: String,
    client_id_ref: ContentReferenceBinding,
    client_authentication_method: String,
    accepted_audiences_ref: ContentReferenceBinding,
    accepted_algorithms: Vec<String>,
    redirect_policy_ref: ContentReferenceBinding,
    claim_mapping_ref: ContentReferenceBinding,
    assurance_mapping_ref: ContentReferenceBinding,
    logout_mode: String,
    lifecycle_mode: String,
    revocation_mode: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalWebauthnKindConfig {
    configuration_kind: String,
    relying_party_id_ref: ContentReferenceBinding,
    allowed_origins_policy_ref: ContentReferenceBinding,
    authenticator_policy_ref: ContentReferenceBinding,
    purpose: String,
    recovery_ceremony_ref: ContentReferenceBinding,
    session_limit_ids: Vec<String>,
    step_up_limit_ids: Vec<String>,
}

#[derive(Debug, Clone)]
enum ActiveProviderKindConfig {
    DevelopmentFixture(Box<DevelopmentFixtureKindConfig>),
    Oidc(Box<OidcKindConfig>),
    LocalWebauthn(Box<LocalWebauthnKindConfig>),
    NonAuthenticator {
        configuration_kind: String,
        content_addressed: Value,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct ActiveProviderConfiguration {
    provider_id: String,
    config_version: u64,
    payload_digest: String,
    kind: String,
    credential_refs: Vec<CredentialReferenceBinding>,
    kind_config: ActiveProviderKindConfig,
}

#[derive(Debug, Clone)]
pub(crate) struct SecurityContractContext {
    pub(crate) profile: DeploymentSecurityProfile,
    pub(crate) profile_digest: String,
    pub(crate) contract_root: PathBuf,
    pub(crate) profile_path: PathBuf,
    /// Active provider id -> immutable, content-addressed configuration.
    pub(crate) active_providers: BTreeMap<String, ActiveProviderConfiguration>,
}

impl SecurityContractContext {
    pub(crate) fn validate_runtime_bindings(
        &self,
        config: &RyukiConfig,
        legacy_auth_selector_present: bool,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        if self.profile.security_profile.is_production() {
            return Err(
                "production startup is blocked until trusted conformance receipts and runtime facts are verified"
                    .into(),
            );
        }

        if self.profile.migration_overlay.is_some()
            && matches!(config.auth_mode, AuthMode::EntraId | AuthMode::Local)
        {
            return Err(
                "migration_overlay cannot admit live local or entra-id authority; only mock/static dry-run is permitted"
                    .into(),
            );
        }
        let selected = self.select_authentication_provider(&config.auth_mode)?;

        match &self.profile.migration_overlay {
            Some(overlay) => {
                if !legacy_auth_selector_present {
                    return Err(
                        "migration_overlay requires the actual legacy RYUKI_AUTH_MODE selector"
                            .into(),
                    );
                }
                if overlay.authority_source != MigrationAuthoritySource::LegacyAuthMode {
                    return Err(
                        "the current legacy runtime requires migration_overlay.authority_source=legacy_auth_mode"
                            .into(),
                    );
                }
                if self.profile.security_profile.is_production() {
                    return Err("migration_overlay is unavailable in production".into());
                }
                let deadline = DateTime::parse_from_rfc3339(&overlay.retirement_deadline)
                    .map_err(|_| "migration_overlay retirement_deadline is invalid".to_string())?
                    .with_timezone(&Utc);
                if deadline <= now {
                    return Err("migration_overlay retirement_deadline has expired".into());
                }
            }
            None if legacy_auth_selector_present => {
                return Err(
                    "RYUKI_AUTH_MODE and the provider registry cannot both select authority without migration_overlay"
                        .into(),
                );
            }
            None => {}
        }

        self.validate_selected_provider(selected, config)?;

        if config.auth_mode.is_credential_free() {
            if !self.profile.security_profile.admits_development_fixture() {
                return Err(
                    "credential-free authentication requires an explicit development or test profile"
                        .into(),
                );
            }
            let listener = config
                .server
                .bind_address
                .parse::<SocketAddr>()
                .map_err(|_| {
                    "credential-free authentication requires a literal socket address".to_string()
                })?;
            if !listener.ip().is_loopback() || !public_url_is_loopback(&config.platform_url) {
                return Err(
                    "credential-free authentication requires loopback listener and public URL"
                        .into(),
                );
            }
        }
        Ok(())
    }

    fn select_authentication_provider(
        &self,
        auth_mode: &AuthMode,
    ) -> Result<&ActiveProviderConfiguration, String> {
        let candidates = self
            .active_providers
            .values()
            .filter(|provider| provider.matches_auth_mode(auth_mode))
            .collect::<Vec<_>>();
        match candidates.as_slice() {
            [selected] => Ok(*selected),
            [] => Err(format!(
                "no active provider configuration matches auth mode {}",
                auth_mode.as_str()
            )),
            _ => Err(format!(
                "auth mode {} is ambiguous across {} active provider configurations",
                auth_mode.as_str(),
                candidates.len()
            )),
        }
    }

    fn validate_selected_provider(
        &self,
        provider: &ActiveProviderConfiguration,
        config: &RyukiConfig,
    ) -> Result<(), String> {
        if provider.config_version == 0 {
            return Err(format!(
                "selected provider {} has an invalid config version",
                provider.provider_id
            ));
        }
        validate_digest_pin("selected provider payload_digest", &provider.payload_digest)?;

        match (&config.auth_mode, &provider.kind_config) {
            (AuthMode::StaticDryRun, ActiveProviderKindConfig::DevelopmentFixture(fixture))
                if fixture.fixture_type == "static-human" =>
            {
                validate_development_runtime(provider, fixture, config)
            }
            (AuthMode::MockDryRun, ActiveProviderKindConfig::DevelopmentFixture(fixture))
                if matches!(
                    fixture.fixture_type.as_str(),
                    "in-memory-secret-provider" | "test-workload"
                ) =>
            {
                validate_development_runtime(provider, fixture, config)
            }
            (
                AuthMode::MockDryRun | AuthMode::StaticDryRun,
                ActiveProviderKindConfig::DevelopmentFixture(_),
            ) => Err(format!(
                "active provider {} fixture type does not exactly match auth mode {}",
                provider.provider_id,
                config.auth_mode.as_str()
            )),
            (AuthMode::EntraId, ActiveProviderKindConfig::Oidc(oidc)) => {
                // The v1 provider schema intentionally stores content references, not
                // the resolved Entra tenant/client/endpoint values in `RyukiConfig`.
                // Accepting on provider kind alone would leave two authorities. Until
                // a typed runtime-value projection exists, live Entra is fail closed.
                let _ = oidc.security_binding_summary()?;
                Err(format!(
                    "selected provider {} cannot be bound to all live entra-id runtime values; typed runtime-value projections are required",
                    provider.provider_id
                ))
            }
            (AuthMode::Local, ActiveProviderKindConfig::LocalWebauthn(local)) => {
                // Local username/password material cannot be compared with the
                // WebAuthn reference-only contract without revealing or inventing a
                // second credential authority. Keep the mode unavailable.
                let _ = local.security_binding_summary()?;
                Err(format!(
                    "selected provider {} cannot be bound to local runtime credentials; typed credential projections are required",
                    provider.provider_id
                ))
            }
            _ => Err(format!(
                "active provider {} kind {} does not exactly match auth mode {}",
                provider.provider_id,
                provider.kind,
                config.auth_mode.as_str()
            )),
        }
    }
}

impl ActiveProviderConfiguration {
    fn matches_auth_mode(&self, auth_mode: &AuthMode) -> bool {
        matches!(
            (auth_mode, &self.kind_config),
            (
                AuthMode::MockDryRun | AuthMode::StaticDryRun,
                ActiveProviderKindConfig::DevelopmentFixture(_)
            ) | (AuthMode::EntraId, ActiveProviderKindConfig::Oidc(_))
                | (AuthMode::Local, ActiveProviderKindConfig::LocalWebauthn(_))
        )
    }
}

fn validate_development_runtime(
    provider: &ActiveProviderConfiguration,
    fixture: &DevelopmentFixtureKindConfig,
    config: &RyukiConfig,
) -> Result<(), String> {
    if fixture.configuration_kind != "development-fixture"
        || !fixture.loopback_only
        || !fixture.isolated_network_required
        || fixture.live_execution_allowed
    {
        return Err(format!(
            "active provider {} is not a closed dry-run fixture",
            provider.provider_id
        ));
    }
    if !provider.credential_refs.is_empty()
        || !config.local_auth.users.is_empty()
        || config.oidc.enabled
        || !config.oidc.client_secret.is_empty()
        || !config.entra_tenant_id.is_empty()
        || !config.entra_client_id.is_empty()
        || !config.entra_redirect_uri.is_empty()
    {
        return Err(format!(
            "active provider {} is credential-free but runtime credential authority is configured",
            provider.provider_id
        ));
    }
    Ok(())
}

pub(crate) fn load_startup_security_contract(
    pins: &StartupSecurityPins,
    now: DateTime<Utc>,
) -> Result<SecurityContractContext, String> {
    let mut store = ArtifactStore::open(&pins.contract_root)?;
    let profile_bytes = store.read(&pins.profile_path, MAX_PROFILE_BYTES)?;
    let actual_profile_digest = raw_digest(&profile_bytes);
    if actual_profile_digest != pins.profile_digest {
        return Err(format!(
            "deployment security profile digest mismatch: expected {}, got {actual_profile_digest}",
            pins.profile_digest
        ));
    }

    let profile_value = parse_json_strict(&profile_bytes)
        .map_err(|error| format!("deployment security profile JSON is invalid: {error}"))?;
    validate_against_schema(
        "deployment security profile",
        PROFILE_SCHEMA,
        &profile_value,
    )?;
    let profile: DeploymentSecurityProfile = serde_json::from_value(profile_value.clone())
        .map_err(|error| format!("deployment security profile is not losslessly typed: {error}"))?;
    let expected = StartupAdmissionContext {
        deployment_id: pins.deployment_id.clone(),
        security_profile: pins.security_profile,
        profile_digest: pins.profile_digest.clone(),
    };
    let errors = profile.validate_for_startup(&expected, &actual_profile_digest, now);
    if !errors.is_empty() {
        return Err(format!(
            "deployment security profile failed startup admission: {}",
            errors.join("; ")
        ));
    }

    let allow_repository_fixture_evidence = profile.security_profile.admits_development_fixture()
        && profile
            .enabled_features
            .iter()
            .any(|feature| feature == "repository-conformance")
        && profile
            .enabled_features
            .iter()
            .any(|feature| feature == "static-dry-run");
    let mut verifier = ReferenceVerifier::new(&mut store, allow_repository_fixture_evidence);
    verifier.verify_value(&profile_value, 0)?;

    let provider_locator = &profile.provider_registry_ref.artifact_locator;
    let provider_registry = verifier
        .documents
        .get(provider_locator)
        .ok_or_else(|| "provider registry reference did not resolve to JSON".to_string())?;
    let active_providers =
        validate_provider_registry(provider_registry, &profile, now, &verifier.documents)?;

    for (label, reference, expected_schema) in [
        (
            "provider registry",
            &profile.provider_registry_ref,
            PROVIDER_SCHEMA,
        ),
        (
            "action/resource registry",
            &profile.action_resource_registry_ref,
            ACTION_SCHEMA,
        ),
        (
            "security limit profile",
            &profile.security_limit_profile_ref,
            LIMIT_SCHEMA,
        ),
    ] {
        let document = verifier
            .documents
            .get(&reference.artifact_locator)
            .ok_or_else(|| format!("{label} reference did not resolve to JSON"))?;
        validate_against_schema(label, expected_schema, document)?;
        validate_active_deployment_document(label, document, &profile, now)?;
    }

    Ok(SecurityContractContext {
        profile,
        profile_digest: actual_profile_digest,
        contract_root: store.root,
        profile_path: pins.profile_path.clone(),
        active_providers,
    })
}

fn required_unicode(
    get: &mut impl FnMut(&str) -> Option<OsString>,
    name: &str,
) -> Result<String, String> {
    let value = get(name).ok_or_else(|| format!("{name} is required"))?;
    let value = value
        .into_string()
        .map_err(|_| format!("{name} must contain valid UTF-8"))?;
    if value.is_empty() || value.trim() != value {
        return Err(format!(
            "{name} must be non-empty and contain no surrounding whitespace"
        ));
    }
    Ok(value)
}

fn validate_namespaced_id(name: &str, value: &str, prefix: &str) -> Result<(), String> {
    let suffix = value
        .strip_prefix(prefix)
        .ok_or_else(|| format!("{name} must use the {prefix} namespace"))?;
    let bytes = suffix.as_bytes();
    if !(3..=127).contains(&bytes.len())
        || !bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(format!("{name} is not a canonical lowercase identifier"));
    }
    Ok(())
}

fn validate_digest_pin(name: &str, value: &str) -> Result<(), String> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(format!("{name} must use sha256:<64 lowercase hex>"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || hex.bytes().all(|byte| byte == b'0')
    {
        return Err(format!(
            "{name} must use a nonzero sha256:<64 lowercase hex> digest"
        ));
    }
    Ok(())
}

fn validate_relative_path(name: &str, path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("{name} must be a normalized relative path"));
    }
    Ok(())
}

fn public_url_is_loopback(raw: &str) -> bool {
    let Ok(url) = url::Url::parse(raw) else {
        return false;
    };
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return false;
    }
    match url.host_str() {
        Some(host) if host.eq_ignore_ascii_case("localhost") => true,
        Some(host) => host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback()),
        None => false,
    }
}

fn raw_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[derive(Debug)]
struct OfflineRetriever;

impl Retrieve for OfflineRetriever {
    fn retrieve(&self, uri: &Uri<String>) -> Result<Value, Box<dyn Error + Send + Sync>> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("offline schema retrieval denied for {uri}"),
        )
        .into())
    }
}

fn validate_against_schema(label: &str, raw_schema: &str, instance: &Value) -> Result<(), String> {
    let schema = parse_json_strict(raw_schema.as_bytes())
        .map_err(|error| format!("embedded {label} schema is invalid: {error}"))?;
    let validator = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .with_retriever(OfflineRetriever)
        .build(&schema)
        .map_err(|error| format!("embedded {label} schema failed to compile: {error}"))?;
    let errors = validator
        .iter_errors(instance)
        .map(|error| {
            format!(
                "{} at {}",
                error.masked(),
                if error.instance_path().as_str().is_empty() {
                    "/"
                } else {
                    error.instance_path().as_str()
                }
            )
        })
        .collect::<Vec<_>>();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{label} schema rejected the document: {}",
            errors.join("; ")
        ))
    }
}

struct ArtifactStore {
    root: PathBuf,
    cache: BTreeMap<PathBuf, Vec<u8>>,
    total_bytes: u64,
}

impl ArtifactStore {
    fn open(root: &Path) -> Result<Self, String> {
        let metadata = fs::symlink_metadata(root)
            .map_err(|error| format!("security contract root is unavailable: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("security contract root must be a regular directory, not a symlink".into());
        }
        let root = fs::canonicalize(root)
            .map_err(|error| format!("security contract root cannot be canonicalized: {error}"))?;
        Ok(Self {
            root,
            cache: BTreeMap::new(),
            total_bytes: 0,
        })
    }

    fn read(&mut self, locator: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
        validate_relative_path("artifact locator", locator)?;
        if let Some(bytes) = self.cache.get(locator) {
            return Ok(bytes.clone());
        }
        if self.cache.len() >= MAX_DOCUMENTS {
            return Err(format!(
                "security contract exceeds {MAX_DOCUMENTS} referenced documents"
            ));
        }

        let components = locator.components().collect::<Vec<_>>();
        let mut current = self.root.clone();
        for (index, component) in components.iter().enumerate() {
            let Component::Normal(segment) = component else {
                return Err("artifact locator is not normalized".into());
            };
            current.push(segment);
            let metadata = fs::symlink_metadata(&current).map_err(|error| {
                format!("artifact {} is unavailable: {error}", locator.display())
            })?;
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "artifact locator contains a symlink: {}",
                    locator.display()
                ));
            }
            let final_component = index + 1 == components.len();
            if (final_component && !metadata.is_file()) || (!final_component && !metadata.is_dir())
            {
                return Err(format!(
                    "artifact locator is not a regular file path: {}",
                    locator.display()
                ));
            }
        }
        let canonical = fs::canonicalize(&current).map_err(|error| {
            format!(
                "artifact {} cannot be canonicalized: {error}",
                locator.display()
            )
        })?;
        if !canonical.starts_with(&self.root) {
            return Err(format!(
                "artifact escapes the security contract root: {}",
                locator.display()
            ));
        }
        let metadata = fs::metadata(&canonical)
            .map_err(|error| format!("artifact {} metadata failed: {error}", locator.display()))?;
        if metadata.len() > max_bytes || metadata.len() > MAX_ARTIFACT_BYTES {
            return Err(format!(
                "artifact exceeds its byte limit: {}",
                locator.display()
            ));
        }
        let next_total = self
            .total_bytes
            .checked_add(metadata.len())
            .ok_or_else(|| "security contract byte accounting overflow".to_string())?;
        if next_total > MAX_TOTAL_BYTES {
            return Err(format!(
                "security contract exceeds {MAX_TOTAL_BYTES} total bytes"
            ));
        }
        let bytes = fs::read(&canonical)
            .map_err(|error| format!("artifact {} read failed: {error}", locator.display()))?;
        if bytes.len() as u64 != metadata.len() {
            return Err(format!(
                "artifact changed while being read: {}",
                locator.display()
            ));
        }
        self.total_bytes = next_total;
        self.cache.insert(locator.to_path_buf(), bytes.clone());
        Ok(bytes)
    }
}

#[derive(Debug, Clone)]
struct ReferenceBinding {
    locator: String,
    digest: String,
    artifact_kind: Option<String>,
    document_id: Option<String>,
    document_version: Option<u64>,
}

struct ReferenceVerifier<'a> {
    store: &'a mut ArtifactStore,
    visited: BTreeMap<String, String>,
    stack: Vec<String>,
    documents: BTreeMap<String, Value>,
    reference_bindings: usize,
    allow_repository_fixture_evidence: bool,
}

impl<'a> ReferenceVerifier<'a> {
    fn new(store: &'a mut ArtifactStore, allow_repository_fixture_evidence: bool) -> Self {
        Self {
            store,
            visited: BTreeMap::new(),
            stack: Vec::new(),
            documents: BTreeMap::new(),
            reference_bindings: 0,
            allow_repository_fixture_evidence,
        }
    }

    fn verify_value(&mut self, value: &Value, depth: usize) -> Result<(), String> {
        if depth > MAX_REFERENCE_DEPTH {
            return Err(format!(
                "security contract reference depth exceeds {MAX_REFERENCE_DEPTH}"
            ));
        }
        match value {
            Value::Object(object) => {
                if let Some(reference) = reference_binding_from_object(object) {
                    self.reference_bindings =
                        self.reference_bindings.checked_add(1).ok_or_else(|| {
                            "security contract reference accounting overflow".to_string()
                        })?;
                    if self.reference_bindings > MAX_REFERENCE_BINDINGS {
                        return Err(format!(
                            "security contract exceeds {MAX_REFERENCE_BINDINGS} total reference bindings"
                        ));
                    }
                    self.verify_reference(&reference, depth)?;
                }
                for child in object.values() {
                    self.verify_value(child, depth)?;
                }
            }
            Value::Array(values) => {
                for child in values {
                    self.verify_value(child, depth)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn verify_reference(
        &mut self,
        reference: &ReferenceBinding,
        depth: usize,
    ) -> Result<(), String> {
        if reference.locator.starts_with("json-pointer:") {
            return Err(
                "json-pointer references are unsupported for runtime artifact bytes".into(),
            );
        }
        let locator = PathBuf::from(&reference.locator);
        validate_relative_path("artifact locator", &locator)?;
        if self.stack.contains(&reference.locator) {
            return Err(format!(
                "security contract reference cycle reaches {}",
                reference.locator
            ));
        }
        if let Some(previous) = self.visited.get(&reference.locator) {
            if previous != &reference.digest {
                return Err(format!(
                    "artifact {} is referenced with conflicting digests",
                    reference.locator
                ));
            }
            if let Some(document) = self.documents.get(&reference.locator) {
                validate_reference_identity(reference, document)?;
                validate_typed_reference_document(reference, document)?;
            } else {
                self.validate_repository_fixture_evidence(reference)?;
            }
            return Ok(());
        }

        let bytes = self.store.read(&locator, MAX_ARTIFACT_BYTES)?;
        let actual = raw_digest(&bytes);
        if actual != reference.digest {
            return Err(format!(
                "artifact {} digest mismatch: expected {}, got {actual}",
                reference.locator, reference.digest
            ));
        }
        self.visited
            .insert(reference.locator.clone(), reference.digest.clone());

        if locator.extension().and_then(|value| value.to_str()) != Some("json") {
            return self.validate_repository_fixture_evidence(reference);
        }
        let document = parse_json_strict(&bytes)
            .map_err(|error| format!("artifact {} has invalid JSON: {error}", reference.locator))?;
        validate_reference_identity(reference, &document)?;
        validate_typed_reference_document(reference, &document)?;

        self.documents
            .insert(reference.locator.clone(), document.clone());
        self.stack.push(reference.locator.clone());
        let result = self.verify_value(&document, depth + 1);
        self.stack.pop();
        result
    }

    fn validate_repository_fixture_evidence(
        &self,
        reference: &ReferenceBinding,
    ) -> Result<(), String> {
        if !self.allow_repository_fixture_evidence {
            return Err(format!(
                "artifact {} is not typed JSON and cannot be used as runtime authority",
                reference.locator
            ));
        }

        // The checked-in repository-conformance fixture predates typed semantic
        // evidence for these source/spec projections. Permit only its exact,
        // content-addressed test/development references. The resulting context
        // still cannot be used unless runtime binding proves a static dry-run on
        // literal loopback, and production admission remains blocked earlier.
        let identity = reference.document_id.as_deref().unwrap_or_default();
        let exact_fixture_reference = matches!(
            (identity, reference.locator.as_str()),
            (
                "baseline:repository-development-fixture-v1",
                "docs/architecture/platform-security-boundary.md"
            ) | (
                "security-boundary:platform-production-v1",
                "docs/architecture/platform-security-boundary.md"
            ) | (
                "boundary-fixture-catalog:security-limit-repository-v1",
                "docs/architecture/platform-security-boundary.md"
            ) | (
                "control-plane-topology:repository-specification-v1",
                "docs/architecture/platform-security-boundary.md"
            ) | (
                "egress-policy:repository-specification-v1",
                "docs/architecture/platform-security-boundary.md"
            ) | (
                "retention-policy:repository-specification-v1",
                "docs/architecture/platform-security-boundary.md"
            ) | ("source:ryuki-api-main", "sources/ryuki-api/src/main.rs")
                | (
                    "source:ryuki-api-contracts",
                    "sources/ryuki-api/src/contracts.rs"
                )
                | (
                    "source:ryuki-api-scheduler",
                    "sources/ryuki-api/src/scheduler.rs"
                )
                | ("source:ryuki-api-agents", "sources/ryuki-api/src/agents.rs")
        );
        if !exact_fixture_reference || reference.document_version != Some(1) {
            return Err(format!(
                "artifact {} is untyped and is not an exact repository-conformance fixture reference",
                reference.locator
            ));
        }
        Ok(())
    }
}

fn reference_binding_from_object(object: &Map<String, Value>) -> Option<ReferenceBinding> {
    let locator = object.get("artifact_locator")?.as_str()?;
    let digest = object
        .get("content_digest")
        .or_else(|| object.get("reference_digest"))?
        .as_str()?;
    Some(ReferenceBinding {
        locator: locator.to_string(),
        digest: digest.to_string(),
        artifact_kind: object
            .get("artifact_kind")
            .and_then(Value::as_str)
            .map(str::to_string),
        document_id: object
            .get("document_id")
            .or_else(|| object.get("reference_id"))
            .and_then(Value::as_str)
            .map(str::to_string),
        document_version: object
            .get("document_version")
            .or_else(|| object.get("reference_version"))
            .and_then(Value::as_u64),
    })
}

fn validate_reference_identity(
    reference: &ReferenceBinding,
    document: &Value,
) -> Result<(), String> {
    if let Some(expected) = &reference.document_id {
        let actual = document
            .get("document_id")
            .or_else(|| document.get("receipt_id"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!(
                    "artifact {} omits referenced document identity",
                    reference.locator
                )
            })?;
        if actual != expected {
            return Err(format!(
                "artifact {} document identity mismatch",
                reference.locator
            ));
        }
    }
    if let Some(expected) = reference.document_version {
        let actual = document
            .get("document_version")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                format!(
                    "artifact {} omits referenced document version",
                    reference.locator
                )
            })?;
        if actual != expected {
            return Err(format!(
                "artifact {} document version mismatch",
                reference.locator
            ));
        }
    }
    Ok(())
}

fn validate_typed_reference_document(
    reference: &ReferenceBinding,
    document: &Value,
) -> Result<(), String> {
    let schema_uri = document.get("$schema").and_then(Value::as_str);
    match reference.artifact_kind.as_deref() {
        Some("provider-registry") => require_contract_document(
            reference,
            document,
            schema_uri,
            "provider-registry",
            "https://ryuki.io/schemas/security-contracts/v1/provider-registry.schema.json",
            PROVIDER_SCHEMA,
        ),
        Some("action-resource-registry") => require_contract_document(
            reference,
            document,
            schema_uri,
            "action-resource-registry",
            "https://ryuki.io/schemas/security-contracts/v1/action-resource-registry.schema.json",
            ACTION_SCHEMA,
        ),
        Some("security-limit-profile") => require_contract_document(
            reference,
            document,
            schema_uri,
            "security-limit-profile",
            "https://ryuki.io/schemas/security-contracts/v1/security-limit-profile.schema.json",
            LIMIT_SCHEMA,
        ),
        Some("deployment-security-profile") => require_contract_document(
            reference,
            document,
            schema_uri,
            "deployment-security-profile",
            "https://ryuki.io/schemas/security-contracts/v1/deployment-security-profile.schema.json",
            PROFILE_SCHEMA,
        ),
        Some("package-exit-receipt") => validate_against_schema(
            "package exit receipt",
            PACKAGE_EXIT_RECEIPT_SCHEMA,
            document,
        ),
        Some(
            "control-plane-topology" | "egress-policy" | "retention-policy" | "federation-policy",
        ) => Err(format!(
            "artifact {} uses a semantic kind without an embedded trusted schema",
            reference.locator
        )),
        Some(kind) => Err(format!(
            "artifact {} selects unsupported artifact kind {kind}",
            reference.locator
        )),
        None => match schema_uri {
            Some(
                "https://ryuki.io/schemas/security-contracts/v1/provider-registry.schema.json",
            ) => validate_against_schema("provider registry", PROVIDER_SCHEMA, document),
            Some(
                "https://ryuki.io/schemas/security-contracts/v1/action-resource-registry.schema.json",
            ) => validate_against_schema("action/resource registry", ACTION_SCHEMA, document),
            Some(
                "https://ryuki.io/schemas/security-contracts/v1/security-limit-profile.schema.json",
            ) => validate_against_schema("security limit profile", LIMIT_SCHEMA, document),
            Some(
                "https://ryuki.io/schemas/security-contracts/v1/deployment-security-profile.schema.json",
            ) => validate_against_schema("deployment security profile", PROFILE_SCHEMA, document),
            Some(unknown) => Err(format!(
                "artifact {} selects unsupported schema {unknown}",
                reference.locator
            )),
            None if reference
                .document_id
                .as_deref()
                .is_some_and(|identity| identity.starts_with("transition-receipt:")) =>
            {
                validate_transition_receipt_shape(reference, document)
            }
            None => Err(format!(
                "artifact {} is untyped JSON and cannot be used as semantic authority",
                reference.locator
            )),
        },
    }
}

fn require_contract_document(
    reference: &ReferenceBinding,
    document: &Value,
    actual_schema_uri: Option<&str>,
    expected_contract_kind: &str,
    expected_schema_uri: &str,
    schema: &str,
) -> Result<(), String> {
    if actual_schema_uri != Some(expected_schema_uri)
        || document.get("contract_kind").and_then(Value::as_str) != Some(expected_contract_kind)
    {
        return Err(format!(
            "artifact {} does not match declared artifact kind {expected_contract_kind}",
            reference.locator
        ));
    }
    validate_against_schema(expected_contract_kind, schema, document)
}

fn validate_transition_receipt_shape(
    reference: &ReferenceBinding,
    document: &Value,
) -> Result<(), String> {
    let object = document
        .as_object()
        .ok_or_else(|| format!("transition receipt {} must be an object", reference.locator))?;
    let expected_keys = BTreeSet::from([
        "document_id",
        "document_version",
        "provider_id",
        "config_version",
        "from_lifecycle_record_version",
        "to_lifecycle_record_version",
        "from_state",
        "to_state",
        "result",
    ]);
    let actual_keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual_keys != expected_keys {
        return Err(format!(
            "transition receipt {} is not the closed typed receipt shape",
            reference.locator
        ));
    }
    let provider_id = required_str(document, "provider_id", "transition receipt")?;
    validate_namespaced_id("transition receipt provider_id", provider_id, "provider:")?;
    required_u64(document, "config_version", "transition receipt")?;
    required_u64(
        document,
        "from_lifecycle_record_version",
        "transition receipt",
    )?;
    required_u64(
        document,
        "to_lifecycle_record_version",
        "transition receipt",
    )?;
    for field in ["from_state", "to_state"] {
        let state = required_str(document, field, "transition receipt")?;
        if !matches!(
            state,
            "configured" | "validated" | "active" | "draining" | "quarantined" | "removed"
        ) {
            return Err(format!("transition receipt has unsupported {field}"));
        }
    }
    if required_str(document, "result", "transition receipt")? != "pass" {
        return Err("transition receipt result must be pass".into());
    }
    Ok(())
}

fn validate_active_deployment_document(
    label: &str,
    document: &Value,
    profile: &DeploymentSecurityProfile,
    now: DateTime<Utc>,
) -> Result<(), String> {
    let lifecycle = document
        .get("lifecycle")
        .ok_or_else(|| format!("{label} omits lifecycle"))?;
    if lifecycle.get("state").and_then(Value::as_str) != Some("active") {
        return Err(format!("{label} must have active lifecycle"));
    }
    let effective_at = lifecycle
        .get("effective_at")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{label} omits lifecycle.effective_at"))?;
    let effective_at = DateTime::parse_from_rfc3339(effective_at)
        .map_err(|_| format!("{label} lifecycle.effective_at is invalid"))?
        .with_timezone(&Utc);
    if effective_at > now {
        return Err(format!("{label} active lifecycle is future-dated"));
    }
    let applicability = document
        .get("applicability")
        .ok_or_else(|| format!("{label} omits applicability"))?;
    if applicability
        .get("evaluation_scope")
        .and_then(Value::as_str)
        != Some("deployment")
    {
        return Err(format!("{label} must use deployment applicability"));
    }
    let profiles = string_set(applicability.get("security_profiles"));
    if !profiles.contains(profile.security_profile.as_str()) {
        return Err(format!(
            "{label} is not applicable to the selected security profile"
        ));
    }
    if let Some(deployments) = applicability.get("deployment_ids") {
        let deployments = string_set(Some(deployments));
        if deployments.len() != 1 || !deployments.contains(profile.deployment_id.as_str()) {
            return Err(format!(
                "{label} deployment applicability does not match the root"
            ));
        }
    }
    let root_features = profile
        .enabled_features
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for feature in string_set(applicability.get("enabled_feature_ids")) {
        if !root_features.contains(feature) {
            return Err(format!("{label} requires unselected feature {feature}"));
        }
    }
    Ok(())
}

fn validate_provider_registry(
    registry: &Value,
    profile: &DeploymentSecurityProfile,
    now: DateTime<Utc>,
    documents: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, ActiveProviderConfiguration>, String> {
    let configurations = registry
        .get("configurations")
        .and_then(Value::as_array)
        .ok_or_else(|| "provider registry configurations are missing".to_string())?;
    let tombstones = registry
        .get("provider_id_tombstones")
        .and_then(Value::as_array)
        .ok_or_else(|| "provider registry tombstones are missing".to_string())?;
    let tombstoned = tombstones
        .iter()
        .filter_map(|value| value.get("provider_id").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    if tombstoned.len() != tombstones.len() {
        return Err("provider registry contains duplicate or invalid tombstones".into());
    }

    let mut configs = BTreeMap::<(String, u64), &Value>::new();
    let mut typed_configs = BTreeMap::<(String, u64), ActiveProviderConfiguration>::new();
    let mut provider_kinds = BTreeMap::<String, String>::new();
    for configuration in configurations {
        let provider_id = required_str(configuration, "provider_id", "provider configuration")?;
        let version = required_u64(configuration, "config_version", "provider configuration")?;
        if configs
            .insert((provider_id.into(), version), configuration)
            .is_some()
        {
            return Err(format!(
                "duplicate provider configuration {provider_id}@{version}"
            ));
        }
        let kind = required_str(configuration, "kind", "provider configuration")?;
        if let Some(previous) = provider_kinds.insert(provider_id.into(), kind.into()) {
            if previous != kind {
                return Err(format!("provider {provider_id} changes immutable kind"));
            }
        }
        if tombstoned.contains(provider_id) {
            return Err(format!("tombstoned provider id {provider_id} is reused"));
        }
        validate_provider_payload(configuration)?;
        typed_configs.insert(
            (provider_id.into(), version),
            parse_active_provider_configuration(configuration)?,
        );
        let trust_domain =
            required_str(configuration, "trust_domain_id", "provider configuration")?;
        if !profile
            .trust_topology
            .trust_domain_ids
            .iter()
            .any(|candidate| candidate == trust_domain)
        {
            return Err(format!(
                "provider {provider_id} uses an unbound trust domain"
            ));
        }
        if !string_set(configuration.get("allowed_security_profiles"))
            .contains(profile.security_profile.as_str())
        {
            return Err(format!(
                "provider {provider_id} is not allowed in the selected profile"
            ));
        }
        if kind == "development-fixture" && profile.security_profile.is_production() {
            return Err("development provider is never applicable to production".into());
        }
    }

    let records = registry
        .get("provider_lifecycle")
        .and_then(Value::as_array)
        .ok_or_else(|| "provider lifecycle records are missing".to_string())?;
    let mut lifecycle = BTreeMap::<(String, u64, u64), &Value>::new();
    for record in records {
        let provider_id = required_str(record, "provider_id", "provider lifecycle")?;
        let config_version = required_u64(record, "config_version", "provider lifecycle")?;
        let record_version =
            required_u64(record, "lifecycle_record_version", "provider lifecycle")?;
        if !configs.contains_key(&(provider_id.into(), config_version)) {
            return Err(format!(
                "provider lifecycle references unknown {provider_id}@{config_version}"
            ));
        }
        if lifecycle
            .insert((provider_id.into(), config_version, record_version), record)
            .is_some()
        {
            return Err(format!(
                "duplicate provider lifecycle record {provider_id}@{config_version}#{record_version}"
            ));
        }
        let effective = required_str(record, "effective_at", "provider lifecycle")?;
        let effective = DateTime::parse_from_rfc3339(effective)
            .map_err(|_| "provider lifecycle effective_at is invalid".to_string())?
            .with_timezone(&Utc);
        if effective > now {
            return Err(format!(
                "provider lifecycle {provider_id}#{record_version} is future-dated"
            ));
        }
    }

    let mut grouped = BTreeMap::<(String, u64), Vec<(u64, &Value)>>::new();
    for ((provider_id, config_version, record_version), record) in &lifecycle {
        grouped
            .entry((provider_id.clone(), *config_version))
            .or_default()
            .push((*record_version, *record));
    }
    for provider_key in configs.keys() {
        if !grouped.contains_key(provider_key) {
            return Err(format!(
                "provider configuration {}@{} has no lifecycle history",
                provider_key.0, provider_key.1
            ));
        }
    }
    let mut active = BTreeMap::<String, ActiveProviderConfiguration>::new();
    let mut active_configurations = BTreeSet::<(String, u64)>::new();
    for ((provider_id, config_version), mut history) in grouped {
        history.sort_by_key(|(version, _)| *version);
        for (index, (version, record)) in history.iter().enumerate() {
            if index == 0 {
                if *version != 1 || record.get("supersedes_lifecycle_record_version").is_some() {
                    return Err(format!(
                        "provider lifecycle {provider_id}@{config_version} must start at version 1"
                    ));
                }
                if required_str(record, "state", "provider lifecycle")? != "configured" {
                    return Err(format!(
                        "provider lifecycle {provider_id}@{config_version} must begin configured"
                    ));
                }
            } else {
                let (previous_version, previous) = history[index - 1];
                if *version != previous_version + 1
                    || record
                        .get("supersedes_lifecycle_record_version")
                        .and_then(Value::as_u64)
                        != Some(previous_version)
                {
                    return Err(format!(
                        "provider lifecycle {provider_id}@{config_version} has a broken supersession chain"
                    ));
                }
                validate_lifecycle_transition(
                    required_str(previous, "state", "provider lifecycle")?,
                    required_str(record, "state", "provider lifecycle")?,
                )?;
                validate_lifecycle_transition_receipt(
                    &provider_id,
                    config_version,
                    previous_version,
                    previous,
                    *version,
                    record,
                    documents,
                )?;
            }
        }
        let (_, latest) = history.last().expect("non-empty lifecycle history");
        if required_str(latest, "state", "provider lifecycle")? == "active" {
            let configuration = typed_configs
                .get(&(provider_id.clone(), config_version))
                .expect("lifecycle configuration checked above");
            if active
                .insert(provider_id.clone(), configuration.clone())
                .is_some()
            {
                return Err(format!(
                    "provider {provider_id} has multiple active configuration versions"
                ));
            }
            active_configurations.insert((provider_id.clone(), config_version));
        }
    }
    if active.is_empty() {
        return Err("provider registry has no active provider authority".into());
    }
    for ((provider_id, config_version), configuration) in &configs {
        if string_set(configuration.get("required_for_profiles"))
            .contains(profile.security_profile.as_str())
            && !active_configurations.contains(&(provider_id.clone(), *config_version))
        {
            return Err(format!(
                "required provider {provider_id}@{config_version} is not active"
            ));
        }
    }
    Ok(active)
}

fn parse_active_provider_configuration(
    configuration: &Value,
) -> Result<ActiveProviderConfiguration, String> {
    let provider_id = required_str(configuration, "provider_id", "provider configuration")?;
    let config_version = required_u64(configuration, "config_version", "provider configuration")?;
    let payload_digest = required_str(configuration, "payload_digest", "provider configuration")?;
    let kind = required_str(configuration, "kind", "provider configuration")?;
    let credential_refs = serde_json::from_value::<Vec<CredentialReferenceBinding>>(
        configuration
            .get("credential_refs")
            .cloned()
            .ok_or_else(|| "provider configuration omits credential_refs".to_string())?,
    )
    .map_err(|error| format!("provider credential references are not typed: {error}"))?;
    for reference in &credential_refs {
        reference.validate()?;
    }

    let raw_kind_config = configuration
        .get("kind_config")
        .cloned()
        .ok_or_else(|| "provider configuration omits kind_config".to_string())?;
    let kind_config = match kind {
        "development-fixture" => ActiveProviderKindConfig::DevelopmentFixture(Box::new(
            serde_json::from_value(raw_kind_config).map_err(|error| {
                format!("development fixture kind_config is not typed: {error}")
            })?,
        )),
        "oidc" | "oidc-broker" => ActiveProviderKindConfig::Oidc(Box::new(
            serde_json::from_value(raw_kind_config)
                .map_err(|error| format!("OIDC kind_config is not typed: {error}"))?,
        )),
        "local-webauthn" => ActiveProviderKindConfig::LocalWebauthn(Box::new(
            serde_json::from_value(raw_kind_config)
                .map_err(|error| format!("local WebAuthn kind_config is not typed: {error}"))?,
        )),
        _ => ActiveProviderKindConfig::NonAuthenticator {
            configuration_kind: raw_kind_config
                .get("configuration_kind")
                .and_then(Value::as_str)
                .ok_or_else(|| "provider kind_config omits configuration_kind".to_string())?
                .into(),
            content_addressed: raw_kind_config,
        },
    };
    kind_config.validate_type(kind)?;

    Ok(ActiveProviderConfiguration {
        provider_id: provider_id.into(),
        config_version,
        payload_digest: payload_digest.into(),
        kind: kind.into(),
        credential_refs,
        kind_config,
    })
}

impl ContentReferenceBinding {
    fn validate(&self) -> Result<(), String> {
        if self.document_version == 0 || self.document_id.is_empty() {
            return Err("typed content reference omits identity/version".into());
        }
        validate_digest_pin("typed content reference digest", &self.content_digest)?;
        validate_relative_path(
            "typed content reference locator",
            Path::new(&self.artifact_locator),
        )
    }
}

impl CredentialReferenceBinding {
    fn validate(&self) -> Result<(), String> {
        if self.reference_version == 0 || self.reference_id.is_empty() || self.purpose.is_empty() {
            return Err("typed credential reference omits identity/version/purpose".into());
        }
        if !self.value_free {
            return Err("typed credential reference must remain value-free".into());
        }
        validate_digest_pin("typed credential reference digest", &self.reference_digest)?;
        validate_relative_path(
            "typed credential reference locator",
            Path::new(&self.artifact_locator),
        )
    }
}

impl ActiveProviderKindConfig {
    fn validate_type(&self, provider_kind: &str) -> Result<(), String> {
        match self {
            Self::DevelopmentFixture(fixture)
                if provider_kind == "development-fixture"
                    && fixture.configuration_kind == "development-fixture" =>
            {
                Ok(())
            }
            Self::Oidc(oidc)
                if matches!(provider_kind, "oidc" | "oidc-broker")
                    && oidc.configuration_kind == provider_kind =>
            {
                oidc.security_binding_summary().map(|_| ())
            }
            Self::LocalWebauthn(local)
                if provider_kind == "local-webauthn"
                    && local.configuration_kind == "local-webauthn" =>
            {
                local.security_binding_summary().map(|_| ())
            }
            Self::NonAuthenticator {
                configuration_kind,
                content_addressed,
            } if configuration_kind == provider_kind && content_addressed.is_object() => Ok(()),
            _ => Err(format!(
                "provider kind {provider_kind} does not match its typed kind_config"
            )),
        }
    }
}

impl OidcKindConfig {
    fn security_binding_summary(&self) -> Result<usize, String> {
        for reference in [
            &self.issuer_ref,
            &self.endpoint_policy_ref,
            &self.client_id_ref,
            &self.accepted_audiences_ref,
            &self.redirect_policy_ref,
            &self.claim_mapping_ref,
            &self.assurance_mapping_ref,
        ] {
            reference.validate()?;
        }
        if self.validation_mode.is_empty()
            || self.client_authentication_method.is_empty()
            || self.accepted_algorithms.is_empty()
            || self.logout_mode.is_empty()
            || self.lifecycle_mode.is_empty()
            || self.revocation_mode.is_empty()
        {
            return Err("OIDC kind_config omits security binding semantics".into());
        }
        Ok(self.accepted_algorithms.len())
    }
}

impl LocalWebauthnKindConfig {
    fn security_binding_summary(&self) -> Result<usize, String> {
        for reference in [
            &self.relying_party_id_ref,
            &self.allowed_origins_policy_ref,
            &self.authenticator_policy_ref,
            &self.recovery_ceremony_ref,
        ] {
            reference.validate()?;
        }
        if self.purpose.is_empty()
            || self.session_limit_ids.is_empty()
            || self.step_up_limit_ids.is_empty()
        {
            return Err("local WebAuthn kind_config omits security binding semantics".into());
        }
        Ok(self.session_limit_ids.len() + self.step_up_limit_ids.len())
    }
}

fn validate_lifecycle_transition_receipt(
    provider_id: &str,
    config_version: u64,
    previous_record_version: u64,
    previous: &Value,
    next_record_version: u64,
    next: &Value,
    documents: &BTreeMap<String, Value>,
) -> Result<(), String> {
    let reference = next
        .get("transition_receipt_ref")
        .ok_or_else(|| "provider lifecycle transition omits transition_receipt_ref".to_string())?;
    let locator = required_str(
        reference,
        "artifact_locator",
        "provider lifecycle transition receipt reference",
    )?;
    let receipt = documents.get(locator).ok_or_else(|| {
        format!("provider lifecycle transition receipt {locator} did not resolve to typed JSON")
    })?;
    let expected = [
        ("provider_id", Value::String(provider_id.into())),
        ("config_version", Value::Number(config_version.into())),
        (
            "from_lifecycle_record_version",
            Value::Number(previous_record_version.into()),
        ),
        (
            "to_lifecycle_record_version",
            Value::Number(next_record_version.into()),
        ),
        (
            "from_state",
            Value::String(required_str(previous, "state", "provider lifecycle")?.into()),
        ),
        (
            "to_state",
            Value::String(required_str(next, "state", "provider lifecycle")?.into()),
        ),
        ("result", Value::String("pass".into())),
    ];
    for (field, expected_value) in expected {
        if receipt.get(field) != Some(&expected_value) {
            return Err(format!(
                "provider lifecycle transition receipt {locator} does not bind {field}"
            ));
        }
    }
    Ok(())
}

fn validate_provider_payload(configuration: &Value) -> Result<(), String> {
    let contract = configuration
        .get("payload_digest_contract")
        .ok_or_else(|| "provider payload digest contract is missing".to_string())?;
    if contract.get("algorithm").and_then(Value::as_str) != Some("sha-256")
        || contract.get("canonicalization").and_then(Value::as_str)
            != Some("ryuki-canonical-json-v1")
        || contract.get("digest_encoding").and_then(Value::as_str)
            != Some("sha256-prefix-lowercase-hex")
        || contract
            .get("excluded_json_pointers")
            .and_then(Value::as_array)
            != Some(&vec![Value::String("/payload_digest".into())])
    {
        return Err("provider payload digest contract is not ryuki-canonical-json-v1".into());
    }
    let mut payload = configuration.clone();
    payload
        .as_object_mut()
        .ok_or_else(|| "provider configuration is not an object".to_string())?
        .remove("payload_digest");
    let expected = raw_digest(canonical_json(&payload).as_bytes());
    if configuration.get("payload_digest").and_then(Value::as_str) != Some(expected.as_str()) {
        return Err("provider payload digest does not match immutable configuration".into());
    }
    Ok(())
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => serde_json::to_string(value).expect("string serialization"),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(values) => {
            let ordered = values.iter().collect::<BTreeMap<_, _>>();
            let members = ordered
                .into_iter()
                .map(|(key, value)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("key serialization"),
                        canonical_json(value)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{members}}}")
        }
    }
}

fn validate_lifecycle_transition(previous: &str, next: &str) -> Result<(), String> {
    let allowed = matches!(
        (previous, next),
        ("configured", "validated")
            | ("configured", "quarantined")
            | ("validated", "active")
            | ("validated", "quarantined")
            | ("active", "draining")
            | ("active", "quarantined")
            | ("draining", "removed")
            | ("draining", "quarantined")
            | ("quarantined", "removed")
    );
    if allowed {
        Ok(())
    } else {
        Err(format!(
            "invalid provider lifecycle transition {previous}->{next}"
        ))
    }
}

fn required_str<'a>(value: &'a Value, field: &str, label: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{label} omits {field}"))
}

fn required_u64(value: &Value, field: &str, label: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .filter(|version| *version > 0)
        .ok_or_else(|| format!("{label} omits positive {field}"))
}

fn string_set(value: Option<&Value>) -> BTreeSet<&str> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

struct DuplicateCheckedValue(Value);

impl<'de> Deserialize<'de> for DuplicateCheckedValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateCheckedValueVisitor)
    }
}

struct DuplicateCheckedValueVisitor;

impl<'de> Visitor<'de> for DuplicateCheckedValueVisitor {
    type Value = DuplicateCheckedValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue(Value::Bool(value)))
    }
    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue(Value::Number(Number::from(value))))
    }
    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue(Value::Number(Number::from(value))))
    }
    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(DuplicateCheckedValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }
    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue(Value::String(value.into())))
    }
    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue(Value::String(value)))
    }
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue(Value::Null))
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue(Value::Null))
    }
    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        DuplicateCheckedValue::deserialize(deserializer)
    }
    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<DuplicateCheckedValue>()? {
            values.push(value.0);
        }
        Ok(DuplicateCheckedValue(Value::Array(values)))
    }
    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!(
                    "duplicate JSON object key {key:?}"
                )));
            }
            let value = object.next_value::<DuplicateCheckedValue>()?;
            values.insert(key, value.0);
        }
        Ok(DuplicateCheckedValue(Value::Object(values)))
    }
}

fn parse_json_strict(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = DuplicateCheckedValue::deserialize(&mut deserializer)?.0;
    deserializer.end()?;
    let mut nodes = 0usize;
    validate_json_shape(&value, 0, &mut nodes).map_err(<serde_json::Error as de::Error>::custom)?;
    Ok(value)
}

fn validate_json_shape(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), String> {
    if depth > MAX_JSON_DEPTH {
        return Err(format!("JSON depth exceeds {MAX_JSON_DEPTH}"));
    }
    *nodes = nodes
        .checked_add(1)
        .ok_or_else(|| "JSON node accounting overflow".to_string())?;
    if *nodes > MAX_JSON_NODES {
        return Err(format!("JSON node count exceeds {MAX_JSON_NODES}"));
    }
    match value {
        Value::Array(values) => {
            if values.len() > MAX_JSON_ARRAY_ITEMS {
                return Err(format!("JSON array length exceeds {MAX_JSON_ARRAY_ITEMS}"));
            }
            for child in values {
                validate_json_shape(child, depth + 1, nodes)?;
            }
        }
        Value::Object(object) => {
            if object.len() > MAX_JSON_OBJECT_MEMBERS {
                return Err(format!(
                    "JSON object member count exceeds {MAX_JSON_OBJECT_MEMBERS}"
                ));
            }
            for child in object.values() {
                validate_json_shape(child, depth + 1, nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::io::Write;

    use chrono::TimeZone;
    use ryuki_core::security_profile::{ArtifactKind, MigrationOverlay, VersionedContentReference};
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;

    const DEPLOYMENT_ID: &str = "deployment:runtime-loader-test";
    const PROFILE_PATH: &str = "profiles/runtime-test.json";

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 16, 12, 0, 0).unwrap()
    }

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repository root")
    }

    struct ActiveFixture {
        _temp: TempDir,
        root: PathBuf,
        pins: StartupSecurityPins,
    }

    impl ActiveFixture {
        fn build() -> Self {
            let temp = TempDir::new().expect("temporary contract root");
            let root = temp.path().to_path_buf();
            let repository = repository_root();

            for relative in [
                "docs/architecture/platform-security-boundary.md",
                "sources/ryuki-api/src/main.rs",
                "sources/ryuki-api/src/contracts.rs",
                "sources/ryuki-api/src/scheduler.rs",
                "sources/ryuki-api/src/agents.rs",
            ] {
                copy_relative(&repository, &root, relative);
            }

            let transition_validated = write_json(
                &root,
                "evidence/provider-validated.json",
                &json!({
                    "document_id": "transition-receipt:provider-validated",
                    "document_version": 1,
                    "provider_id": "provider:repository-static-dry-run",
                    "config_version": 1,
                    "from_lifecycle_record_version": 1,
                    "to_lifecycle_record_version": 2,
                    "from_state": "configured",
                    "to_state": "validated",
                    "result": "pass"
                }),
            );
            let transition_active = write_json(
                &root,
                "evidence/provider-active.json",
                &json!({
                    "document_id": "transition-receipt:provider-active",
                    "document_version": 1,
                    "provider_id": "provider:repository-static-dry-run",
                    "config_version": 1,
                    "from_lifecycle_record_version": 2,
                    "to_lifecycle_record_version": 3,
                    "from_state": "validated",
                    "to_state": "active",
                    "result": "pass"
                }),
            );

            let mut provider: Value =
                serde_json::from_slice(
                    &fs::read(repository.join(
                        "catalog/security-contracts/v1/provider-registry.implementation.json",
                    ))
                    .unwrap(),
                )
                .unwrap();
            provider["lifecycle"]["state"] = json!("active");
            provider["applicability"]["evaluation_scope"] = json!("deployment");
            provider["applicability"]["security_profiles"] = json!(["test"]);
            let configured = provider["provider_lifecycle"][0].clone();
            let mut validated = configured.clone();
            validated["lifecycle_record_version"] = json!(2);
            validated["state"] = json!("validated");
            validated["supersedes_lifecycle_record_version"] = json!(1);
            validated["transition_receipt_ref"] = json!({
                "document_id": "transition-receipt:provider-validated",
                "document_version": 1,
                "content_digest": transition_validated,
                "artifact_locator": "evidence/provider-validated.json"
            });
            let mut active = validated.clone();
            active["lifecycle_record_version"] = json!(3);
            active["state"] = json!("active");
            active["supersedes_lifecycle_record_version"] = json!(2);
            active["transition_receipt_ref"] = json!({
                "document_id": "transition-receipt:provider-active",
                "document_version": 1,
                "content_digest": transition_active,
                "artifact_locator": "evidence/provider-active.json"
            });
            provider["provider_lifecycle"] = json!([configured, validated, active]);
            refresh_reference_digests(&mut provider, &root);
            refresh_provider_payload_digests(&mut provider);
            let provider_digest = write_json(
                &root,
                "catalog/security-contracts/v1/provider-registry.runtime-test.json",
                &provider,
            );

            let mut action: Value = serde_json::from_slice(
                &fs::read(repository.join(
                    "catalog/security-contracts/v1/action-resource-registry.implementation.json",
                ))
                .unwrap(),
            )
            .unwrap();
            action["lifecycle"]["state"] = json!("active");
            action["applicability"]["evaluation_scope"] = json!("deployment");
            action["applicability"]["security_profiles"] = json!(["test"]);
            refresh_reference_digests(&mut action, &root);
            let action_digest = write_json(
                &root,
                "catalog/security-contracts/v1/action-resource-registry.runtime-test.json",
                &action,
            );

            let mut limits: Value = serde_json::from_slice(
                &fs::read(repository.join(
                    "catalog/security-contracts/v1/security-limit-profile.implementation.json",
                ))
                .unwrap(),
            )
            .unwrap();
            limits["lifecycle"]["state"] = json!("active");
            limits["applicability"]["evaluation_scope"] = json!("deployment");
            limits["applicability"]["security_profiles"] = json!(["test"]);
            limits["applicability"]["deployment_ids"] = json!([DEPLOYMENT_ID]);
            refresh_reference_digests(&mut limits, &root);
            let limit_digest = write_json(
                &root,
                "catalog/security-contracts/v1/security-limit-profile.runtime-test.json",
                &limits,
            );

            let specification_digest = raw_digest(
                &fs::read(root.join("docs/architecture/platform-security-boundary.md")).unwrap(),
            );
            let mut profile: Value = serde_json::from_slice(
                &fs::read(repository.join(
                    "catalog/security-contracts/v1/deployment-security-profile.implementation.json",
                ))
                .unwrap(),
            )
            .unwrap();
            profile["document_id"] = json!("deployment-security-profile:runtime-loader-test");
            profile["lifecycle"]["state"] = json!("active");
            profile["deployment_id"] = json!(DEPLOYMENT_ID);
            profile["applicability"]["deployment_ids"] = json!([DEPLOYMENT_ID]);
            profile["enabled_features"] = json!([
                "repository-conformance",
                "static-dry-run",
                "session-lookup-admission"
            ]);
            profile["applicability"]["enabled_feature_ids"] = profile["enabled_features"].clone();
            set_root_reference(
                &mut profile,
                "provider_registry_ref",
                "catalog/security-contracts/v1/provider-registry.runtime-test.json",
                &provider_digest,
            );
            set_root_reference(
                &mut profile,
                "provider_lifecycle_snapshot_ref",
                "catalog/security-contracts/v1/provider-registry.runtime-test.json",
                &provider_digest,
            );
            set_root_reference(
                &mut profile,
                "action_resource_registry_ref",
                "catalog/security-contracts/v1/action-resource-registry.runtime-test.json",
                &action_digest,
            );
            set_root_reference(
                &mut profile,
                "security_limit_profile_ref",
                "catalog/security-contracts/v1/security-limit-profile.runtime-test.json",
                &limit_digest,
            );
            for field in [
                "control_plane_topology_ref",
                "egress_policy_ref",
                "retention_policy_ref",
            ] {
                profile[field]["content_digest"] = json!(specification_digest);
            }
            let profile_digest = write_json(&root, PROFILE_PATH, &profile);
            let pins = StartupSecurityPins {
                contract_root: root.clone(),
                profile_path: PathBuf::from(PROFILE_PATH),
                profile_digest,
                deployment_id: DEPLOYMENT_ID.into(),
                security_profile: SecurityProfile::Test,
            };
            Self {
                _temp: temp,
                root,
                pins,
            }
        }

        fn load(&self) -> Result<SecurityContractContext, String> {
            load_startup_security_contract(&self.pins, fixed_now())
        }

        fn rewrite_profile(&mut self, mutate: impl FnOnce(&mut Value)) {
            let path = self.root.join(PROFILE_PATH);
            let mut profile: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            mutate(&mut profile);
            self.pins.profile_digest = write_json(&self.root, PROFILE_PATH, &profile);
        }

        fn rewrite_provider(&mut self, mutate: impl FnOnce(&mut Value)) {
            let provider_path = "catalog/security-contracts/v1/provider-registry.runtime-test.json";
            let mut provider: Value =
                serde_json::from_slice(&fs::read(self.root.join(provider_path)).unwrap()).unwrap();
            mutate(&mut provider);
            let digest = write_json(&self.root, provider_path, &provider);
            self.rewrite_profile(|profile| {
                profile["provider_registry_ref"]["content_digest"] = json!(digest);
                profile["provider_lifecycle_snapshot_ref"]["content_digest"] = json!(digest);
            });
        }
    }

    fn copy_relative(source_root: &Path, destination_root: &Path, relative: &str) {
        let destination = destination_root.join(relative);
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::copy(source_root.join(relative), destination).unwrap();
    }

    fn write_json(root: &Path, relative: &str, value: &Value) -> String {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let bytes = serde_json::to_vec_pretty(value).unwrap();
        fs::write(path, &bytes).unwrap();
        raw_digest(&bytes)
    }

    fn refresh_reference_digests(value: &mut Value, root: &Path) {
        match value {
            Value::Object(object) => {
                let locator = object
                    .get("artifact_locator")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                if let Some(locator) = locator {
                    let bytes = fs::read(root.join(&locator)).unwrap_or_else(|error| {
                        panic!("test reference {locator} must exist: {error}")
                    });
                    let digest = raw_digest(&bytes);
                    if object.contains_key("content_digest") {
                        object.insert("content_digest".into(), json!(digest));
                    } else if object.contains_key("reference_digest") {
                        object.insert("reference_digest".into(), json!(digest));
                    }
                }
                for child in object.values_mut() {
                    refresh_reference_digests(child, root);
                }
            }
            Value::Array(values) => {
                for child in values {
                    refresh_reference_digests(child, root);
                }
            }
            _ => {}
        }
    }

    fn refresh_provider_payload_digests(provider: &mut Value) {
        for configuration in provider["configurations"].as_array_mut().unwrap() {
            let mut payload = configuration.clone();
            payload.as_object_mut().unwrap().remove("payload_digest");
            configuration["payload_digest"] =
                json!(raw_digest(canonical_json(&payload).as_bytes()));
        }
    }

    fn set_root_reference(profile: &mut Value, field: &str, locator: &str, digest: &str) {
        profile[field]["artifact_locator"] = json!(locator);
        profile[field]["content_digest"] = json!(digest);
    }

    #[test]
    fn pins_are_explicit_closed_and_independently_bound() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let values = BTreeMap::<String, OsString>::from([
            (
                SECURITY_CONTRACT_ROOT_ENV.into(),
                OsString::from("/contracts"),
            ),
            (
                SECURITY_PROFILE_PATH_ENV.into(),
                OsString::from("profiles/test.json"),
            ),
            (SECURITY_PROFILE_DIGEST_ENV.into(), OsString::from(&digest)),
            (
                EXPECTED_DEPLOYMENT_ID_ENV.into(),
                OsString::from(DEPLOYMENT_ID),
            ),
            (SECURITY_PROFILE_ENV.into(), OsString::from("test")),
        ]);
        let pins = StartupSecurityPins::from_source(|name| values.get(name).cloned()).unwrap();
        assert_eq!(pins.security_profile, SecurityProfile::Test);

        for missing in [
            SECURITY_CONTRACT_ROOT_ENV,
            SECURITY_PROFILE_PATH_ENV,
            SECURITY_PROFILE_DIGEST_ENV,
            EXPECTED_DEPLOYMENT_ID_ENV,
            SECURITY_PROFILE_ENV,
        ] {
            let error = StartupSecurityPins::from_source(|name| {
                (name != missing)
                    .then(|| values.get(name).cloned())
                    .flatten()
            })
            .unwrap_err();
            assert!(error.contains(missing));
        }
        let mut downgraded = values.clone();
        downgraded.insert(
            SECURITY_PROFILE_ENV.into(),
            OsString::from("test,production"),
        );
        assert!(StartupSecurityPins::from_source(|name| downgraded.get(name).cloned()).is_err());
        let mut traversal = values;
        traversal.insert(
            SECURITY_PROFILE_PATH_ENV.into(),
            OsString::from("../profile.json"),
        );
        assert!(StartupSecurityPins::from_source(|name| traversal.get(name).cloned()).is_err());
    }

    #[test]
    fn active_test_contract_loads_and_binds_credential_free_loopback() {
        let fixture = ActiveFixture::build();
        let context = fixture.load().expect("active test contract must load");
        assert_eq!(context.active_providers.len(), 1);
        let mut config = RyukiConfig {
            auth_mode: AuthMode::StaticDryRun,
            ..RyukiConfig::default()
        };
        assert!(context
            .validate_runtime_bindings(&config, false, fixed_now())
            .is_ok());

        config.auth_mode = AuthMode::MockDryRun;
        assert!(context
            .validate_runtime_bindings(&config, false, fixed_now())
            .unwrap_err()
            .contains("does not exactly match"));
    }

    #[test]
    fn exact_profile_and_reference_bytes_are_content_addressed() {
        let mut fixture = ActiveFixture::build();
        fs::OpenOptions::new()
            .append(true)
            .open(fixture.root.join(PROFILE_PATH))
            .unwrap()
            .write_all(b"\n")
            .unwrap();
        assert!(fixture
            .load()
            .unwrap_err()
            .contains("profile digest mismatch"));

        fixture = ActiveFixture::build();
        fs::OpenOptions::new()
            .append(true)
            .open(
                fixture
                    .root
                    .join("catalog/security-contracts/v1/provider-registry.runtime-test.json"),
            )
            .unwrap()
            .write_all(b"\n")
            .unwrap();
        let error = fixture.load().unwrap_err();
        assert!(error.contains("artifact") && error.contains("digest mismatch"));
    }

    #[test]
    fn strict_root_json_rejects_nested_duplicate_keys() {
        let mut fixture = ActiveFixture::build();
        let path = fixture.root.join(PROFILE_PATH);
        let raw = fs::read_to_string(&path).unwrap();
        let duplicated = raw.replacen(
            "\"lifecycle\": {",
            "\"lifecycle\": {\n    \"state\": \"active\",",
            1,
        );
        fs::write(&path, duplicated.as_bytes()).unwrap();
        fixture.pins.profile_digest = raw_digest(duplicated.as_bytes());
        assert!(fixture
            .load()
            .unwrap_err()
            .contains("duplicate JSON object key"));
    }

    #[test]
    fn inactive_future_and_production_roots_remain_blocked() {
        let mut inactive = ActiveFixture::build();
        inactive.rewrite_profile(|profile| profile["lifecycle"]["state"] = json!("candidate"));
        assert!(inactive
            .load()
            .unwrap_err()
            .contains("active deployment profile"));

        let mut future = ActiveFixture::build();
        future.rewrite_profile(|profile| {
            profile["lifecycle"]["effective_at"] = json!("2026-07-17T00:00:00Z")
        });
        assert!(future.load().unwrap_err().contains("future-dated"));

        let mut production = ActiveFixture::build();
        production.rewrite_profile(|profile| {
            profile["security_profile"] = json!("production");
            profile["applicability"]["security_profiles"] = json!(["production"]);
        });
        let error = production.load().unwrap_err();
        assert!(error.contains("production") || error.contains("receipt_bound"));
    }

    #[test]
    fn provider_authority_requires_valid_active_immutable_lifecycle() {
        let mut inactive = ActiveFixture::build();
        let transition_path = "evidence/provider-active.json";
        let mut transition: Value =
            serde_json::from_slice(&fs::read(inactive.root.join(transition_path)).unwrap())
                .unwrap();
        transition["to_state"] = json!("quarantined");
        let transition_digest = write_json(&inactive.root, transition_path, &transition);
        inactive.rewrite_provider(|provider| {
            provider["provider_lifecycle"][2]["state"] = json!("quarantined");
            provider["provider_lifecycle"][2]["transition_receipt_ref"]["content_digest"] =
                json!(transition_digest);
        });
        assert!(inactive.load().unwrap_err().contains("no active provider"));

        let mut tampered = ActiveFixture::build();
        tampered.rewrite_provider(|provider| {
            provider["configurations"][0]["capability_descriptor"]["advertised_capabilities"] =
                json!(["dry-run-only", "static-human-fixture", "unbound-change"])
        });
        assert!(tampered
            .load()
            .unwrap_err()
            .contains("provider payload digest"));

        let mut tombstoned = ActiveFixture::build();
        tombstoned.rewrite_provider(|provider| {
            provider["provider_id_tombstones"] = json!([{
                "provider_id": "provider:repository-static-dry-run",
                "last_config_version": 1,
                "removed_lifecycle_record_version": 4,
                "non_reusable": true
            }])
        });
        assert!(tombstoned
            .load()
            .unwrap_err()
            .contains("tombstoned provider"));
    }

    #[cfg(unix)]
    #[test]
    fn profile_symlink_is_rejected_before_reading() {
        use std::os::unix::fs::symlink;

        let mut fixture = ActiveFixture::build();
        let link = fixture.root.join("profiles/symlink.json");
        symlink(fixture.root.join(PROFILE_PATH), &link).unwrap();
        fixture.pins.profile_path = PathBuf::from("profiles/symlink.json");
        assert!(fixture.load().unwrap_err().contains("symlink"));
    }

    #[test]
    fn runtime_binding_rejects_legacy_conflict_and_nonloopback_fixture() {
        let fixture = ActiveFixture::build();
        let context = fixture.load().unwrap();
        let mut config = RyukiConfig {
            auth_mode: AuthMode::StaticDryRun,
            ..RyukiConfig::default()
        };
        assert!(context
            .validate_runtime_bindings(&config, true, fixed_now())
            .unwrap_err()
            .contains("migration_overlay"));

        config.server.bind_address = "0.0.0.0:8080".into();
        assert!(context
            .validate_runtime_bindings(&config, false, fixed_now())
            .unwrap_err()
            .contains("loopback"));
    }

    #[test]
    fn runtime_binding_rejects_ambiguous_provider_and_credential_mismatch() {
        let fixture = ActiveFixture::build();
        let mut context = fixture.load().unwrap();
        let mut duplicate = context.active_providers.values().next().unwrap().clone();
        duplicate.provider_id = "provider:second-static-dry-run".into();
        context
            .active_providers
            .insert(duplicate.provider_id.clone(), duplicate);
        let config = RyukiConfig {
            auth_mode: AuthMode::StaticDryRun,
            ..RyukiConfig::default()
        };
        assert!(context
            .validate_runtime_bindings(&config, false, fixed_now())
            .unwrap_err()
            .contains("ambiguous"));

        context
            .active_providers
            .remove("provider:second-static-dry-run");
        let mut credential_mismatch = config;
        credential_mismatch.oidc.client_secret = "test-only-placeholder".into(); // secret-scan-allow: non-secret test sentinel
        assert!(context
            .validate_runtime_bindings(&credential_mismatch, false, fixed_now())
            .unwrap_err()
            .contains("runtime credential authority"));
    }

    #[test]
    fn migration_overlay_rejects_local_and_entra_authority() {
        let fixture = ActiveFixture::build();
        let mut context = fixture.load().unwrap();
        context.profile.migration_overlay = Some(MigrationOverlay {
            overlay_id: "migration-overlay:runtime-test".into(),
            overlay_version: 1,
            security_profile: SecurityProfile::Test,
            authority_source: MigrationAuthoritySource::LegacyAuthMode,
            legacy_selector_present: true,
            provider_registry_present: true,
            retirement_deadline: "2026-07-17T00:00:00Z".into(),
            conflict_telemetry_name: "security.migration.conflict".into(),
            grants_authority: false,
            live_execution_allowed: false,
            zero_consumer_receipt_ref: VersionedContentReference {
                artifact_kind: ArtifactKind::PackageExitReceipt,
                document_id: "package-exit-receipt:runtime-test".into(),
                document_version: 1,
                content_digest: format!("sha256:{}", "a".repeat(64)),
                artifact_locator: "receipts/runtime-test.json".into(),
            },
        });
        for auth_mode in [AuthMode::Local, AuthMode::EntraId] {
            let config = RyukiConfig {
                auth_mode,
                ..RyukiConfig::default()
            };
            assert!(context
                .validate_runtime_bindings(&config, true, fixed_now())
                .unwrap_err()
                .contains("cannot admit live local or entra-id"));
        }
    }

    #[test]
    fn lifecycle_receipt_must_be_closed_and_bind_the_exact_transition() {
        let reference = ReferenceBinding {
            locator: "evidence/transition.json".into(),
            digest: format!("sha256:{}", "a".repeat(64)),
            artifact_kind: None,
            document_id: Some("transition-receipt:exact-transition".into()),
            document_version: Some(1),
        };
        let mut receipt = json!({
            "document_id": "transition-receipt:exact-transition",
            "document_version": 1,
            "provider_id": "provider:repository-static-dry-run",
            "config_version": 1,
            "from_lifecycle_record_version": 1,
            "to_lifecycle_record_version": 2,
            "from_state": "configured",
            "to_state": "validated",
            "result": "pass"
        });
        assert!(validate_typed_reference_document(&reference, &receipt).is_ok());
        receipt["untyped_extra"] = json!(true);
        assert!(validate_typed_reference_document(&reference, &receipt)
            .unwrap_err()
            .contains("closed typed receipt"));
        receipt.as_object_mut().unwrap().remove("untyped_extra");
        receipt["to_state"] = json!("active");
        let documents = BTreeMap::from([("evidence/transition.json".into(), receipt)]);
        let previous = json!({"state": "configured"});
        let next = json!({
            "state": "validated",
            "transition_receipt_ref": {
                "artifact_locator": "evidence/transition.json"
            }
        });
        assert!(validate_lifecycle_transition_receipt(
            "provider:repository-static-dry-run",
            1,
            1,
            &previous,
            2,
            &next,
            &documents,
        )
        .unwrap_err()
        .contains("does not bind to_state"));
    }

    #[test]
    fn repeated_reference_bindings_are_globally_bounded() {
        let temp = TempDir::new().unwrap();
        let receipt = json!({
            "document_id": "transition-receipt:repeated-binding",
            "document_version": 1,
            "provider_id": "provider:repository-static-dry-run",
            "config_version": 1,
            "from_lifecycle_record_version": 1,
            "to_lifecycle_record_version": 2,
            "from_state": "configured",
            "to_state": "validated",
            "result": "pass"
        });
        let digest = write_json(temp.path(), "evidence/repeated.json", &receipt);
        let binding = json!({
            "document_id": "transition-receipt:repeated-binding",
            "document_version": 1,
            "content_digest": digest,
            "artifact_locator": "evidence/repeated.json"
        });
        let value = Value::Array(vec![binding; MAX_REFERENCE_BINDINGS + 1]);
        let mut store = ArtifactStore::open(temp.path()).unwrap();
        let mut verifier = ReferenceVerifier::new(&mut store, false);
        assert!(verifier
            .verify_value(&value, 0)
            .unwrap_err()
            .contains("total reference bindings"));
    }

    #[test]
    fn repeated_locator_cannot_bypass_a_stronger_artifact_kind() {
        let temp = TempDir::new().unwrap();
        let receipt = json!({
            "document_id": "transition-receipt:type-confusion",
            "document_version": 1,
            "provider_id": "provider:repository-static-dry-run",
            "config_version": 1,
            "from_lifecycle_record_version": 1,
            "to_lifecycle_record_version": 2,
            "from_state": "configured",
            "to_state": "validated",
            "result": "pass"
        });
        let digest = write_json(temp.path(), "evidence/shared.json", &receipt);
        let generic = json!({
            "document_id": "transition-receipt:type-confusion",
            "document_version": 1,
            "content_digest": digest,
            "artifact_locator": "evidence/shared.json"
        });
        let stronger = json!({
            "artifact_kind": "provider-registry",
            "document_id": "transition-receipt:type-confusion",
            "document_version": 1,
            "content_digest": digest,
            "artifact_locator": "evidence/shared.json"
        });
        let mut store = ArtifactStore::open(temp.path()).unwrap();
        let mut verifier = ReferenceVerifier::new(&mut store, false);
        assert!(verifier
            .verify_value(&json!([generic, stronger]), 0)
            .unwrap_err()
            .contains("declared artifact kind"));
    }

    #[test]
    fn wide_reference_bindings_are_globally_bounded() {
        let temp = TempDir::new().unwrap();
        let mut bindings = Vec::new();
        for index in 0..=MAX_REFERENCE_BINDINGS {
            let identity = format!("transition-receipt:wide-{index}");
            let locator = format!("evidence/wide-{index}.json");
            let receipt = json!({
                "document_id": identity,
                "document_version": 1,
                "provider_id": "provider:repository-static-dry-run",
                "config_version": 1,
                "from_lifecycle_record_version": 1,
                "to_lifecycle_record_version": 2,
                "from_state": "configured",
                "to_state": "validated",
                "result": "pass"
            });
            let digest = write_json(temp.path(), &locator, &receipt);
            bindings.push(json!({
                "document_id": format!("transition-receipt:wide-{index}"),
                "document_version": 1,
                "content_digest": digest,
                "artifact_locator": locator
            }));
        }
        let mut store = ArtifactStore::open(temp.path()).unwrap();
        let mut verifier = ReferenceVerifier::new(&mut store, false);
        assert!(verifier
            .verify_value(&Value::Array(bindings), 0)
            .unwrap_err()
            .contains("total reference bindings"));
    }

    #[test]
    fn json_shape_limits_apply_before_schema_validation() {
        let oversized = Value::Array(vec![Value::Null; MAX_JSON_ARRAY_ITEMS + 1]);
        let bytes = serde_json::to_vec(&oversized).unwrap();
        assert!(parse_json_strict(&bytes)
            .unwrap_err()
            .to_string()
            .contains("JSON array length"));
    }
}
