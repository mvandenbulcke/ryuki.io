use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Component, Path};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::conformance_closure::{
    RUNTIME_GUARD_REQUIREMENT_BINDING_DIGEST_CONTRACT,
    RUNTIME_GUARD_SEMANTIC_CHALLENGE_BINDING_DIGEST_CONTRACT,
};
use crate::conformance_trust::{canonical_json_bytes, parse_json_strict};

pub const DEPLOYMENT_SECURITY_PROFILE_SCHEMA_URI: &str =
    "https://ryuki.io/schemas/security-contracts/v1/deployment-security-profile.schema.json";
pub const DEPLOYMENT_SECURITY_PROFILE_SCHEMA_VERSION: &str = "1.0.0";
pub const DEPLOYMENT_SECURITY_PROFILE_CONTRACT_KIND: &str = "deployment-security-profile";
pub const SECRET_PROVIDER_INVENTORY_DIGEST_CONTRACT: &str = "ryuki-secret-provider-inventory-v1";
pub const SECRET_PROVIDER_RUNTIME_BINDING_DIGEST_CONTRACT: &str =
    "ryuki-secret-provider-runtime-binding-v1";
pub const AUTHENTICATOR_INVENTORY_DIGEST_CONTRACT: &str = "ryuki-authenticator-inventory-v1";
pub const AUTHENTICATOR_RUNTIME_BINDING_DIGEST_CONTRACT: &str =
    "ryuki-authenticator-runtime-binding-v2";
pub const AUTHENTICATOR_PROVIDER_POLICY_BINDING_DIGEST_CONTRACT: &str =
    "ryuki-authenticator-provider-policy-binding-v1";
pub const AUTHENTICATOR_ORIGIN_BINDING_DIGEST_CONTRACT: &str =
    "ryuki-authenticator-origin-binding-v1";
pub const AUTHENTICATOR_CACHE_PARTITION_BINDING_DIGEST_CONTRACT: &str =
    "ryuki-authenticator-cache-partition-v1";
pub const AUTHENTICATOR_PROTOCOL_BINDING_DIGEST_CONTRACT: &str =
    "ryuki-authenticator-protocol-binding-v1";
pub const AUTHENTICATOR_BROWSER_STATE_AUTHORITY_BINDING_DIGEST_CONTRACT: &str =
    "ryuki-authenticator-browser-state-authority-binding-v1";
pub const AUTHENTICATOR_BROWSER_STATE_RELATION_V3: &str = "oidc_login_states_v3";
pub const AUTHENTICATOR_BROWSER_STATE_CONTRACT_SETTING: &str = "ryuki.oidc_login_state_contract";
pub const AUTHENTICATOR_BROWSER_STATE_CONTRACT_VERSION: u64 = 3;
pub const AUTHENTICATOR_BROWSER_STATE_CONSUME_OPERATION: &str = "delete-returning";
pub const AUTHENTICATOR_BROWSER_STATE_LIFETIME_LIMIT_ID: &str =
    "limit:authenticator.browser-state-lifetime";
pub const AUTHENTICATOR_BROWSER_STATE_MAXIMUM_TTL_SECONDS: u64 = 600;
pub const AUTHENTICATOR_BROWSER_PKCE_METHOD_S256: &str = "s256";
pub const AUTHENTICATOR_DERIVED_SESSION_RELATION: &str = "sessions";
pub const AUTHENTICATOR_DERIVED_SESSION_CREDENTIAL_FORMAT: &str = "opaque-random-256-bit";
pub const AUTHENTICATOR_DERIVED_SESSION_VERIFIER_ALGORITHM: &str = "hmac-sha256";
pub const AUTHENTICATOR_DERIVED_SESSION_VERIFIER_COLUMN_V3: &str = "session_bearer_verifier_v3";
pub const AUTHENTICATOR_BROWSER_SESSION_MAXIMUM_AGE_LIMIT_ID: &str =
    "limit:authenticator.browser-session-maximum-age";
pub const AUTHENTICATOR_FEDERATED_AUTHORITY_STALENESS_LIMIT_ID: &str =
    "limit:authenticator.federated-authority-staleness";
pub const POSTGRESQL_DATABASE_IDENTITY_DIGEST_CONTRACT: &str =
    "ryuki-postgresql-database-identity-v1";
pub const POSTGRESQL_PROVIDER_ROUTE_BINDING_DIGEST_CONTRACT: &str =
    "ryuki-postgresql-provider-route-binding-v1";
pub const POSTGRESQL_PROVIDER_ROUTE_MODE_DIRECT_SESSION_V1: &str = "direct-session-v1";
pub const POSTGRESQL_STORAGE_BINDING_DIGEST_CONTRACT: &str = "ryuki-postgresql-storage-binding-v1";
pub const POSTGRESQL_MIGRATION_INVENTORY_DIGEST_CONTRACT: &str =
    "ryuki-postgresql-migration-inventory-v1";
pub const EXTERNAL_SIGNING_KEY_IDENTITY_DIGEST_CONTRACT: &str =
    "ryuki-external-signing-key-identity-v1";
pub const EXTERNAL_SIGNING_INVENTORY_DIGEST_CONTRACT: &str = "ryuki-external-signing-inventory-v1";
pub const PRODUCTION_DEPENDENCY_COMPONENT_BINDING_DIGEST_CONTRACT: &str =
    "ryuki-production-dependency-component-binding-v1";
pub const PRODUCTION_DEPENDENCY_INVENTORY_DIGEST_CONTRACT: &str =
    "ryuki-production-dependency-inventory-v1";
pub const FIRST_OWNER_AUTHORITY_NAMESPACE_DIGEST_CONTRACT: &str =
    "ryuki-first-owner-authority-namespace-v1";
pub const FIRST_OWNER_CLOSURE_RECORD_DIGEST_CONTRACT: &str = "ryuki-first-owner-closure-record-v1";
pub const FIRST_OWNER_CLOSURE_CERTIFICATE_SCHEMA_URI: &str =
    "https://ryuki.io/schemas/security-contracts/v1/first-owner-closure-certificate.schema.json";
pub const FIRST_OWNER_CLOSURE_CERTIFICATE_SCHEMA_VERSION: &str = "1.0.0";
pub const FIRST_OWNER_CLOSURE_CERTIFICATE_CONTRACT_KIND: &str = "first-owner-closure-certificate";
pub const FIRST_OWNER_CLOSURE_CERTIFICATE_CANONICALIZATION: &str = "ryuki-canonical-json-v1";
pub const FIRST_OWNER_CLOSURE_CERTIFICATE_SIGNATURE_ALGORITHM: &str = "ed25519";
pub const FIRST_OWNER_CLOSURE_CERTIFICATE_SIGNATURE_DOMAIN: &str =
    "ryuki-v1/first-owner-closure-certificate";
pub const FIRST_OWNER_CLOSURE_CERTIFICATE_MAX_BYTES: usize = 256 * 1024;
pub const FIRST_OWNER_MAX_EXACT_JSON_INTEGER: u64 = 9_007_199_254_740_991;
pub const FIRST_OWNER_STATE_CONTRACT_VERSION: u64 = 1;
pub const FIRST_OWNER_PRIVILEGED_DOMAINS: [&str; 5] = [
    "audit-administration",
    "identity-administration",
    "live-execution-administration",
    "policy-administration",
    "secret-key-custody",
];

const REQUIRED_PRODUCTION_GUARDS: [GuardId; 8] = [
    GuardId::DurablePostgresql,
    GuardId::ApprovedSecretProvider,
    GuardId::HttpsPublicUrls,
    GuardId::SecureCookies,
    GuardId::NonDevelopmentAuthenticator,
    GuardId::ExternalSigningKeyMaterial,
    GuardId::MockDependenciesDisabled,
    GuardId::FirstOwnerPathClosed,
];

/// The one executable root for a serving process.
///
/// This type intentionally mirrors the published JSON Schema field-for-field.
/// JSON Schema validation runs before deserialization at the API boundary;
/// these semantic checks enforce cross-field rules that JSON Schema cannot.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeploymentSecurityProfile {
    #[serde(rename = "$schema")]
    pub schema_uri: String,
    pub schema_version: String,
    pub contract_kind: String,
    pub document_id: String,
    pub document_version: u64,
    pub lifecycle: DocumentLifecycle,
    pub applicability: DeploymentApplicability,
    pub deployment_profile_version: u64,
    pub deployment_id: String,
    pub security_profile: SecurityProfile,
    pub platform_configuration_version: u64,
    pub policy_version: u64,
    pub tenancy_mode: TenancyMode,
    pub trust_topology: TrustTopology,
    pub conformance_trust_root_registry_ref: VersionedContentReference,
    pub control_trace_ref: VersionedContentReference,
    pub provider_registry_ref: VersionedContentReference,
    pub provider_lifecycle_snapshot_ref: ProviderLifecycleReference,
    pub action_resource_registry_ref: VersionedContentReference,
    pub security_limit_profile_ref: VersionedContentReference,
    pub control_plane_topology_ref: VersionedContentReference,
    pub egress_policy_ref: VersionedContentReference,
    pub retention_policy_ref: VersionedContentReference,
    pub production_acceptance_receipt_ref: Option<VersionedContentReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_overlay: Option<MigrationOverlay>,
    pub enabled_features: Vec<String>,
    pub runtime_guard_evidence: RuntimeGuardEvidence,
}

/// Independently pinned process expectations used when a profile is selected
/// for startup. These values must come from deployment configuration, not from
/// the profile document being evaluated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupAdmissionContext {
    pub deployment_id: String,
    pub security_profile: SecurityProfile,
    pub profile_digest: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DocumentLifecycle {
    pub state: DocumentLifecycleState,
    pub effective_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<VersionedContentReference>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DocumentLifecycleState {
    ImplementationOnly,
    Candidate,
    Active,
    Deprecated,
    Retired,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeploymentApplicability {
    pub evaluation_scope: EvaluationScope,
    pub security_profiles: Vec<SecurityProfile>,
    pub deployment_ids: Vec<String>,
    pub enabled_feature_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationScope {
    Deployment,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SecurityProfile {
    Development,
    Test,
    Production,
}

impl SecurityProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Test => "test",
            Self::Production => "production",
        }
    }

    pub const fn is_production(self) -> bool {
        matches!(self, Self::Production)
    }

    pub const fn admits_development_fixture(self) -> bool {
        matches!(self, Self::Development | Self::Test)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TenancyMode {
    SingleTenant,
    MultiTenant,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustTopology {
    pub topology_kind: TrustTopologyKind,
    pub trust_domain_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_policy_ref: Option<VersionedContentReference>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustTopologyKind {
    SingleTrustDomain,
    FederatedTrustDomains,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VersionedContentReference {
    pub artifact_kind: ArtifactKind,
    pub document_id: String,
    pub document_version: u64,
    pub content_digest: String,
    pub artifact_locator: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    DeploymentSecurityProfile,
    ConformanceTrustRootRegistry,
    ControlTrace,
    ConformanceBundle,
    ProviderRegistry,
    ActionResourceRegistry,
    SecurityLimitProfile,
    ControlPlaneTopology,
    EgressPolicy,
    RetentionPolicy,
    FederationPolicy,
    PackageExitReceipt,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderLifecycleReference {
    pub artifact_kind: ProviderLifecycleArtifactKind,
    pub document_id: String,
    pub document_version: u64,
    pub content_digest: String,
    pub artifact_locator: String,
    pub projection: ProviderLifecycleProjection,
    pub required_states: Vec<ProviderLifecycleState>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderLifecycleArtifactKind {
    ProviderRegistry,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderLifecycleProjection {
    ProviderLifecycle,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProviderLifecycleState {
    Validated,
    Active,
    Draining,
    Quarantined,
    Removed,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationOverlay {
    pub overlay_id: String,
    pub overlay_version: u64,
    pub security_profile: SecurityProfile,
    pub authority_source: MigrationAuthoritySource,
    pub legacy_selector_present: bool,
    pub provider_registry_present: bool,
    pub retirement_deadline: String,
    pub conflict_telemetry_name: String,
    pub grants_authority: bool,
    pub live_execution_allowed: bool,
    pub zero_consumer_receipt_ref: VersionedContentReference,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MigrationAuthoritySource {
    ProviderRegistry,
    LegacyAuthMode,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeGuardEvidence {
    pub mode: RuntimeGuardMode,
    pub guards: Vec<GuardEvidence>,
    pub runtime_cross_check_required: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeGuardMode {
    NotApplicable,
    ReceiptBound,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuardEvidence {
    pub guard_id: GuardId,
    pub control_ids: Vec<String>,
    pub receipt_ref: VersionedContentReference,
    pub expected_value: RuntimeGuardExpectedValue,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum GuardId {
    DurablePostgresql,
    ApprovedSecretProvider,
    HttpsPublicUrls,
    SecureCookies,
    NonDevelopmentAuthenticator,
    ExternalSigningKeyMaterial,
    MockDependenciesDisabled,
    FirstOwnerPathClosed,
}

/// Closed receipt-bound value that one live runtime measurement must equal.
///
/// Digests name non-secret canonical projections. They never stand in for a
/// live measurement: the API must construct a typed witness from the actual
/// retained runtime handle and compare that witness with this exact value.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RuntimeGuardExpectedValue {
    DurablePostgresql {
        database_provider: ProductionDatabaseProvider,
        server_major_version: u16,
        attestation_profile_id: String,
        attestation_profile_version: u64,
        attestation_profile_digest: String,
        provider_route_binding_digest: String,
        database_identity_digest: String,
        storage_binding_digest: String,
        migration_inventory_digest: String,
        application_role: String,
        migration_role: String,
    },
    ApprovedSecretProvider {
        provider_inventory_digest: String,
        providers: Vec<ExpectedSecretProviderBinding>,
        required_capability_ids: Vec<String>,
    },
    HttpsPublicUrls {
        public_origin_set_digest: String,
        ingress_binding_digest: String,
        attestation_profile_id: String,
        attestation_profile_version: u64,
        attestation_profile_digest: String,
    },
    SecureCookies {
        policies: Vec<ExpectedCookiePolicy>,
        policy_inventory_digest: String,
    },
    NonDevelopmentAuthenticator {
        authenticator_inventory_digest: String,
        authenticators: Vec<ExpectedAuthenticatorBinding>,
    },
    ExternalSigningKeyMaterial {
        signing_inventory_digest: String,
        purposes: Vec<ExpectedSigningPurpose>,
    },
    MockDependenciesDisabled {
        dependency_inventory_digest: String,
        required_component_ids: Vec<String>,
    },
    FirstOwnerPathClosed {
        deployment_id: String,
        state_contract_version: u64,
        authority_namespace_digest: String,
        closure_record_digest: String,
    },
}

/// Canonical namespace shared by the deployment profile and the independently
/// verified public-ingress attestation protocol.
pub const INGRESS_ATTESTATION_PROFILE_ID_PREFIX: &str = "ingress-attestation-profile:";

/// Canonical namespace shared by the deployment profile and the independently
/// verified PostgreSQL infrastructure attestation protocol.
pub const POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_ID_PREFIX: &str =
    "postgresql-infrastructure-attestation-profile:";

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CookieSameSitePolicy {
    Strict,
    Lax,
    None,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProductionAuthenticatorKind {
    Oidc,
    OidcBroker,
    Passkey,
    OauthService,
    ApiToken,
    Workload,
    /// Retained in the typed parser for deterministic diagnostics in migration
    /// tooling; the current JSON Schema does not admit this legacy mechanism.
    MutualTls,
    /// Retained in the typed parser for deterministic diagnostics in migration
    /// tooling; the current JSON Schema does not admit this legacy mechanism.
    Composite,
}

impl ProductionAuthenticatorKind {
    pub const fn is_human(self) -> bool {
        matches!(self, Self::Oidc | Self::OidcBroker | Self::Passkey)
    }

    pub const fn is_legacy_mechanism(self) -> bool {
        matches!(self, Self::MutualTls | Self::Composite)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExpectedProviderBinding {
    pub provider_id: String,
    pub configuration_version: u64,
    pub configuration_payload_digest: String,
    pub lifecycle_record_version: u64,
    pub lifecycle_state: ProviderLifecycleState,
    pub capability_descriptor_id: String,
    pub capability_descriptor_version: u64,
    pub adapter_kind: String,
    pub adapter_version: String,
}

/// Exact non-secret identity measured from the retained PostgreSQL connection.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PostgresqlDatabaseIdentity {
    pub deployment_id: String,
    pub trust_domain_id: String,
    pub database_provider: ProductionDatabaseProvider,
    pub database_name: String,
    pub database_oid: u32,
    /// Decimal output of PostgreSQL's cluster system-identifier observation.
    pub cluster_system_identifier: String,
    pub server_address: String,
    pub server_port: u16,
    pub tls_enabled: bool,
    pub tls_protocol: String,
    pub tls_cipher_suite: String,
    pub tls_cipher_bits: u16,
    pub server_major_version: u16,
    pub primary: bool,
    pub writable: bool,
}

/// Stable, receipt-bound route used to establish one direct PostgreSQL TLS
/// session. The exact leaf certificate is pinned so a second endpoint with a
/// different certificate under the same CA cannot receive authentication
/// material before the independent session attestation runs. Socket addresses
/// and exporter values remain per-connection measurements.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PostgresqlProviderRouteBinding {
    pub route_mode: String,
    pub database_provider: ProductionDatabaseProvider,
    pub endpoint_dns_name: String,
    pub endpoint_port: u16,
    pub trust_anchor_bundle_digest: String,
    pub peer_leaf_certificate_digest: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum PostgresqlStoragePurpose {
    Data,
    Wal,
}

/// One durable provider-volume binding. Provider object identifiers are
/// represented only by one-way digests; raw cluster, PVC, PV, and volume
/// handles are deliberately excluded from the deployment profile.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PostgresqlStorageBinding {
    pub purpose: PostgresqlStoragePurpose,
    pub provider_cluster_uid_digest: String,
    pub persistent_volume_claim_uid_digest: String,
    pub persistent_volume_uid_digest: String,
    pub csi_driver: String,
    pub volume_handle_digest: String,
    pub storage_class: String,
}

/// One exact applied SQLx migration, sorted by monotonically increasing
/// migration version. The checksum digest hashes the checksum bytes read from
/// the live migration ledger; it is not supplied by a deployment operator.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PostgresqlMigrationInventoryRow {
    pub version: u64,
    pub checksum_digest: String,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeGuardDigestError {
    #[error("runtime-guard digest projection is not canonical: {0}")]
    InvalidProjection(&'static str),
    #[error("runtime-guard digest projection could not be encoded as canonical JSON")]
    Projection,
}

#[derive(Serialize)]
struct PostgresqlDatabaseIdentityProjection<'a> {
    digest_contract: &'static str,
    database_identity: &'a PostgresqlDatabaseIdentity,
}

#[derive(Serialize)]
struct PostgresqlProviderRouteBindingProjection<'a> {
    digest_contract: &'static str,
    provider_route_binding: &'a PostgresqlProviderRouteBinding,
}

#[derive(Serialize)]
struct PostgresqlStorageBindingProjection<'a> {
    digest_contract: &'static str,
    storage_bindings: &'a [PostgresqlStorageBinding],
}

#[derive(Serialize)]
struct PostgresqlMigrationInventoryProjection<'a> {
    digest_contract: &'static str,
    migrations: &'a [PostgresqlMigrationInventoryRow],
}

pub fn postgresql_database_identity_canonical_bytes(
    identity: &PostgresqlDatabaseIdentity,
) -> Result<Vec<u8>, RuntimeGuardDigestError> {
    validate_postgresql_database_identity_projection(identity)?;
    canonical_projection_bytes(PostgresqlDatabaseIdentityProjection {
        digest_contract: POSTGRESQL_DATABASE_IDENTITY_DIGEST_CONTRACT,
        database_identity: identity,
    })
}

pub fn postgresql_database_identity_digest(
    identity: &PostgresqlDatabaseIdentity,
) -> Result<String, RuntimeGuardDigestError> {
    digest_canonical_bytes(postgresql_database_identity_canonical_bytes(identity)?)
}

pub fn postgresql_provider_route_binding_canonical_bytes(
    binding: &PostgresqlProviderRouteBinding,
) -> Result<Vec<u8>, RuntimeGuardDigestError> {
    validate_postgresql_provider_route_binding_projection(binding)?;
    canonical_projection_bytes(PostgresqlProviderRouteBindingProjection {
        digest_contract: POSTGRESQL_PROVIDER_ROUTE_BINDING_DIGEST_CONTRACT,
        provider_route_binding: binding,
    })
}

pub fn postgresql_provider_route_binding_digest(
    binding: &PostgresqlProviderRouteBinding,
) -> Result<String, RuntimeGuardDigestError> {
    digest_canonical_bytes(postgresql_provider_route_binding_canonical_bytes(binding)?)
}

pub fn postgresql_storage_binding_canonical_bytes(
    bindings: &[PostgresqlStorageBinding],
) -> Result<Vec<u8>, RuntimeGuardDigestError> {
    validate_postgresql_storage_binding_projection(bindings)?;
    canonical_projection_bytes(PostgresqlStorageBindingProjection {
        digest_contract: POSTGRESQL_STORAGE_BINDING_DIGEST_CONTRACT,
        storage_bindings: bindings,
    })
}

pub fn postgresql_storage_binding_digest(
    bindings: &[PostgresqlStorageBinding],
) -> Result<String, RuntimeGuardDigestError> {
    digest_canonical_bytes(postgresql_storage_binding_canonical_bytes(bindings)?)
}

pub fn postgresql_migration_inventory_canonical_bytes(
    migrations: &[PostgresqlMigrationInventoryRow],
) -> Result<Vec<u8>, RuntimeGuardDigestError> {
    validate_postgresql_migration_inventory_projection(migrations)?;
    canonical_projection_bytes(PostgresqlMigrationInventoryProjection {
        digest_contract: POSTGRESQL_MIGRATION_INVENTORY_DIGEST_CONTRACT,
        migrations,
    })
}

pub fn postgresql_migration_inventory_digest(
    migrations: &[PostgresqlMigrationInventoryRow],
) -> Result<String, RuntimeGuardDigestError> {
    digest_canonical_bytes(postgresql_migration_inventory_canonical_bytes(migrations)?)
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExpectedSecretProviderBinding {
    pub provider: ExpectedProviderBinding,
    /// Digest of the exact non-secret initialized provider, authenticated
    /// transport, credential source, and retained-consumer projection.
    pub runtime_binding_digest: String,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SecretProviderInventoryDigestError {
    #[error("secret-provider inventory could not be projected as canonical JSON")]
    Projection,
}

#[derive(Serialize)]
struct SecretProviderInventoryProjection<'a> {
    digest_contract: &'static str,
    providers: &'a [ExpectedSecretProviderBinding],
    required_capability_ids: &'a [String],
}

/// Independently encode the exact sorted non-secret secret-provider bindings
/// and required capability inventory using `ryuki-canonical-json-v1`.
pub fn secret_provider_inventory_canonical_bytes(
    providers: &[ExpectedSecretProviderBinding],
    required_capability_ids: &[String],
) -> Result<Vec<u8>, SecretProviderInventoryDigestError> {
    let projection = SecretProviderInventoryProjection {
        digest_contract: SECRET_PROVIDER_INVENTORY_DIGEST_CONTRACT,
        providers,
        required_capability_ids,
    };
    let value: Value = serde_json::to_value(projection)
        .map_err(|_| SecretProviderInventoryDigestError::Projection)?;
    canonical_json_bytes(&value).map_err(|_| SecretProviderInventoryDigestError::Projection)
}

/// Independently recompute the receipt/runtime digest for the exact sorted
/// non-secret secret-provider and required-capability inventory.
pub fn secret_provider_inventory_digest(
    providers: &[ExpectedSecretProviderBinding],
    required_capability_ids: &[String],
) -> Result<String, SecretProviderInventoryDigestError> {
    let canonical = secret_provider_inventory_canonical_bytes(providers, required_capability_ids)?;
    Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExpectedAuthenticatorBinding {
    pub provider: ExpectedProviderBinding,
    pub authenticator_kind: ProductionAuthenticatorKind,
    /// Digest of the exact non-secret initialized verifier, credential-profile,
    /// and retained-consumer projection used for this provider.
    pub runtime_binding_digest: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatorKeySourceKind {
    JwtJwks,
    AuthenticatedIntrospection,
    Passkey,
    KeyedDigest,
    WorkloadTrustBundle,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatorCredentialCarrier {
    AuthorizationBearer,
    HostCookie,
    OauthCallback,
    PasskeyAssertion,
    ApiToken,
    MutualTls,
    WorkloadAssertion,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatorProofBinding {
    Bearer,
    Dpop,
    MutualTls,
    PkceS256,
    Passkey,
    KeyedToken,
    WorkloadAssertion,
}

/// Whether the input credential itself may be presented more than once.
///
/// This is deliberately separate from presentation replay defence. OAuth
/// access tokens and opaque sessions are reusable credentials even when each
/// presentation is sender-constrained by a fresh proof.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatorCredentialReuse {
    SingleUse,
    ReusableUntilExpiry,
}

/// Cryptographic binding between the credential and its presenter.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatorSenderConstraint {
    None,
    Dpop,
    MutualTls,
    Passkey,
    WorkloadAssertion,
}

/// Replay control applied to one presentation or browser ceremony.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatorPresentationReplayDefense {
    None,
    SingleUseState,
    DurableJti,
}

/// Closed nonce purpose. OIDC login nonces and DPoP nonces are not
/// interchangeable replay controls.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatorNonceBinding {
    None,
    OidcLogin,
    Dpop,
}

fn deserialize_explicit_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatorReplayRuntimeProjection {
    pub credential_reuse: AuthenticatorCredentialReuse,
    /// Registered security-limit identity governing the measured maximum
    /// credential lifetime. Single-use browser ceremonies bind their separate
    /// state lifetime through the protocol projection and use `None` here.
    #[serde(deserialize_with = "deserialize_explicit_option")]
    pub credential_lifetime_limit_id: Option<String>,
    /// Exact maximum validity interval enforced for reusable credentials.
    /// Single-use ceremonies carry their expiry in the protocol binding and
    /// therefore use `None` here.
    #[serde(deserialize_with = "deserialize_explicit_option")]
    pub maximum_credential_lifetime_seconds: Option<u64>,
    pub sender_constraint: AuthenticatorSenderConstraint,
    pub presentation_replay_defense: AuthenticatorPresentationReplayDefense,
    pub nonce_binding: AuthenticatorNonceBinding,
    /// Exact non-secret identity of the retained state/JTI authority. It is
    /// absent only when no presentation replay store exists.
    #[serde(deserialize_with = "deserialize_explicit_option")]
    pub replay_store_binding_digest: Option<String>,
}

/// Immutable verifier leaves measured from the exact initialized verifier.
/// Key bytes and remote tokens are excluded; the key-source digest covers only
/// the canonical non-secret public-key, trust-bundle, or opaque-key metadata.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatorVerifierRuntimeProjection {
    pub verifier_id: String,
    pub verifier_version: u64,
    /// Value-free digest of the exact canonical issuer identifier.
    pub issuer_binding_digest: String,
    /// Value-free digest of the exact canonical, sorted audience set.
    pub audience_set_binding_digest: String,
    pub accepted_algorithm_ids: Vec<String>,
    pub required_claim_ids: Vec<String>,
    /// Exact signed claim selected as the provider-qualified principal subject.
    /// The claim must also be present in `required_claim_ids`.
    pub provider_subject_claim_id: String,
    pub key_source_kind: AuthenticatorKeySourceKind,
    pub key_source_binding_digest: String,
    pub expiration_required: bool,
    pub not_before_required: bool,
    pub issued_at_required: bool,
    pub nonce_required: bool,
    pub clock_skew_limit_id: String,
    pub maximum_clock_skew_seconds: u32,
    pub redirects_allowed: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatorCredentialProfileRuntimeProjection {
    pub profile_id: String,
    pub profile_version: u64,
    pub token_profile: String,
    pub carrier: AuthenticatorCredentialCarrier,
    pub proof_binding: AuthenticatorProofBinding,
    pub replay: AuthenticatorReplayRuntimeProjection,
}

/// One complete, retained credential-admission path. Browser flow semantics
/// (authorization endpoint, token endpoint, redirect, PKCE, state, browser
/// binding and issued-session linkage) are represented by the value-free
/// protocol digest rather than being flattened into verifier-only claims.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatorRuntimePathProjection {
    pub path_id: String,
    pub path_version: u64,
    pub verifier: AuthenticatorVerifierRuntimeProjection,
    pub credential_profile: AuthenticatorCredentialProfileRuntimeProjection,
    /// Value-free digest of the retained cache-allocation inventory, whose
    /// preimage binds provider identity/configuration version, independent
    /// provider-policy Q, issuer, token profile, verifier, and every
    /// discovery/JWKS/introspection/nonce/replay/key cache owned by this path.
    /// P stays at R's top level to avoid a D/P fixed-point cycle. Each path must
    /// have a distinct partition.
    pub cache_partition_binding_digest: String,
    pub protocol_binding_digest: String,
    pub retained_consumer_ids: Vec<String>,
}

/// Closed semantic role of one retained OIDC credential path.
///
/// The role is repeated in the cache and protocol preimages so a coordinated
/// bearer/browser relabel cannot preserve either digest.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatorRuntimePathRole {
    DirectBearer,
    BrowserDerivedSession,
}

/// Identity leaves shared by the cache-partition and carrier-protocol
/// preimages. Values are non-secret and bind one exact provider-policy Q,
/// configuration version, verifier allocation, and credential path. P is not
/// repeated here because P includes D's content reference while D embeds these
/// cache/protocol digests; feeding P back into either preimage would create a
/// D/P fixed-point cycle. R binds P and Q independently at the top level.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatorRuntimePathIdentityProjection {
    pub provider_id: String,
    pub provider_configuration_version: u64,
    /// Q: provider policy after excluding only its top-level D reference.
    pub provider_policy_binding_digest: String,
    pub path_role: AuthenticatorRuntimePathRole,
    pub path_id: String,
    pub path_version: u64,
    pub verifier_id: String,
    pub verifier_version: u64,
    pub token_profile: String,
    pub issuer_binding_digest: String,
    pub audience_set_binding_digest: String,
    pub key_source_kind: AuthenticatorKeySourceKind,
    pub key_source_binding_digest: String,
}

/// Closed kinds of retained cache allocations that an OIDC path may own.
/// Variant order deliberately matches canonical serialized-name order.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatorCacheKind {
    BrowserLoginState,
    DerivedSessionCredential,
    JwksKeySet,
    NonceReplay,
    OidcDiscoveryDocument,
    TokenIntrospection,
}

/// Exact retained cache allocation inventory for one authenticator path.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatorCachePartitionProjection {
    pub path_identity: AuthenticatorRuntimePathIdentityProjection,
    pub cache_owner_id: String,
    pub cache_partition_id: String,
    pub cache_kinds: Vec<AuthenticatorCacheKind>,
    pub retained_consumer_ids: Vec<String>,
}

/// Typed, one-use OIDC browser-state authority. These constants describe the
/// post-cutover v3 relation and prevent an old writer/consumer from being
/// represented as equivalent live state custody.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatorBrowserStateAuthorityProjection {
    pub state_authority_id: String,
    pub state_authority_version: u64,
    pub relation_name: String,
    pub writer_contract_setting: String,
    pub writer_contract_version: u64,
    pub consume_operation: String,
    pub state_lifetime_limit_id: String,
    pub maximum_state_lifetime_seconds: u64,
    pub pkce_method: String,
    pub nonce_required: bool,
    pub browser_binding_required: bool,
    pub exact_origin_match_required: bool,
}

/// Closed token-endpoint client authentication modes admitted by the browser
/// exchange authority. Secret values are never projected.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatorBrowserClientAuthentication {
    None,
    ClientSecretPost,
}

/// Typed browser authorization-code exchange and provider-token custody.
/// Endpoint, redirect, client, and scope values remain value-free, separately
/// domain-bound SHA-256 digests.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatorBrowserExchangeAuthorityProjection {
    pub exchange_authority_id: String,
    pub exchange_authority_version: u64,
    pub authorization_endpoint_binding_digest: String,
    pub token_endpoint_binding_digest: String,
    pub redirect_uri_binding_digest: String,
    pub client_id_binding_digest: String,
    pub scopes_binding_digest: String,
    pub client_authentication: AuthenticatorBrowserClientAuthentication,
    pub client_credential_present: bool,
    pub connect_timeout_milliseconds: u64,
    pub request_timeout_milliseconds: u64,
    pub response_maximum_bytes: u64,
    pub https_required: bool,
    pub redirects_allowed: bool,
    pub ambient_proxy_allowed: bool,
    pub pkce_verifier_sent: bool,
    pub id_token_required: bool,
    pub provider_tokens_persisted: bool,
    pub provider_tokens_exposed: bool,
}

/// Typed server-side credential authority for a browser-derived session.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatorDerivedSessionAuthorityProjection {
    pub session_authority_id: String,
    pub session_authority_version: u64,
    pub relation_name: String,
    pub credential_format: String,
    pub credential_verifier_algorithm: String,
    pub credential_key_identity_digest: String,
    pub verifier_column_name: String,
    pub session_maximum_age_limit_id: String,
    pub maximum_session_age_seconds: u64,
    pub federated_authority_staleness_limit_id: String,
    pub maximum_federated_authority_staleness_seconds: u64,
    pub exact_origin_copy_required: bool,
    pub cookie_policy_binding_digest: String,
}

/// Exact retained carrier/replay protocol for one authenticator path.
/// Browser-only authorities must be explicit `null` for direct bearer paths
/// and present together for browser-derived-session paths.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatorProtocolBindingProjection {
    pub path_identity: AuthenticatorRuntimePathIdentityProjection,
    pub carrier: AuthenticatorCredentialCarrier,
    pub proof_binding: AuthenticatorProofBinding,
    pub replay: AuthenticatorReplayRuntimeProjection,
    #[serde(deserialize_with = "deserialize_explicit_option")]
    pub browser_exchange_authority: Option<AuthenticatorBrowserExchangeAuthorityProjection>,
    #[serde(deserialize_with = "deserialize_explicit_option")]
    pub browser_state_authority: Option<AuthenticatorBrowserStateAuthorityProjection>,
    #[serde(deserialize_with = "deserialize_explicit_option")]
    pub derived_session_authority: Option<AuthenticatorDerivedSessionAuthorityProjection>,
}

#[derive(Serialize)]
struct AuthenticatorCachePartitionBindingDigestProjection<'a> {
    digest_contract: &'static str,
    cache_partition: &'a AuthenticatorCachePartitionProjection,
}

#[derive(Serialize)]
struct AuthenticatorBrowserStateAuthorityBindingDigestProjection<'a> {
    digest_contract: &'static str,
    browser_state_authority: &'a AuthenticatorBrowserStateAuthorityProjection,
}

#[derive(Serialize)]
struct AuthenticatorProtocolBindingDigestProjection<'a> {
    digest_contract: &'static str,
    protocol_binding: &'a AuthenticatorProtocolBindingProjection,
}

/// Encode one validated cache allocation using `ryuki-canonical-json-v1`.
pub fn authenticator_cache_partition_binding_canonical_bytes(
    cache_partition: &AuthenticatorCachePartitionProjection,
) -> Result<Vec<u8>, RuntimeGuardDigestError> {
    validate_authenticator_cache_partition_projection(cache_partition)?;
    canonical_projection_bytes(AuthenticatorCachePartitionBindingDigestProjection {
        digest_contract: AUTHENTICATOR_CACHE_PARTITION_BINDING_DIGEST_CONTRACT,
        cache_partition,
    })
}

/// Digest the exact retained cache allocation. The digest is independently
/// separated from the provider and verifier authority digests in its preimage.
pub fn authenticator_cache_partition_binding_digest(
    cache_partition: &AuthenticatorCachePartitionProjection,
) -> Result<String, RuntimeGuardDigestError> {
    let digest = digest_canonical_bytes(authenticator_cache_partition_binding_canonical_bytes(
        cache_partition,
    )?)?;
    reject_authenticator_path_identity_digest_collision(&digest, &cache_partition.path_identity)?;
    Ok(digest)
}

/// Encode the exact validated v3 browser-state authority using
/// `ryuki-canonical-json-v1`.
pub fn authenticator_browser_state_authority_binding_canonical_bytes(
    authority: &AuthenticatorBrowserStateAuthorityProjection,
) -> Result<Vec<u8>, RuntimeGuardDigestError> {
    if !validate_authenticator_browser_state_authority_projection(authority) {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "authenticator browser-state authority binding",
        ));
    }
    canonical_projection_bytes(AuthenticatorBrowserStateAuthorityBindingDigestProjection {
        digest_contract: AUTHENTICATOR_BROWSER_STATE_AUTHORITY_BINDING_DIGEST_CONTRACT,
        browser_state_authority: authority,
    })
}

/// Digest the exact typed authority used by the browser credential replay
/// store binding in D and by independent live R measurement.
pub fn authenticator_browser_state_authority_binding_digest(
    authority: &AuthenticatorBrowserStateAuthorityProjection,
) -> Result<String, RuntimeGuardDigestError> {
    let digest = digest_canonical_bytes(
        authenticator_browser_state_authority_binding_canonical_bytes(authority)?,
    )?;
    if !valid_sha256_digest(&digest) {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "authenticator browser-state authority nonzero digest",
        ));
    }
    Ok(digest)
}

/// Encode one validated carrier protocol using `ryuki-canonical-json-v1`.
pub fn authenticator_protocol_binding_canonical_bytes(
    protocol_binding: &AuthenticatorProtocolBindingProjection,
) -> Result<Vec<u8>, RuntimeGuardDigestError> {
    validate_authenticator_protocol_binding_projection(protocol_binding)?;
    canonical_projection_bytes(AuthenticatorProtocolBindingDigestProjection {
        digest_contract: AUTHENTICATOR_PROTOCOL_BINDING_DIGEST_CONTRACT,
        protocol_binding,
    })
}

/// Digest the exact retained carrier protocol, independently separated from
/// provider, verifier, replay, derived-session key, and cookie authorities.
pub fn authenticator_protocol_binding_digest(
    protocol_binding: &AuthenticatorProtocolBindingProjection,
) -> Result<String, RuntimeGuardDigestError> {
    let digest = digest_canonical_bytes(authenticator_protocol_binding_canonical_bytes(
        protocol_binding,
    )?)?;
    reject_authenticator_path_identity_digest_collision(&digest, &protocol_binding.path_identity)?;
    if protocol_binding
        .replay
        .replay_store_binding_digest
        .as_ref()
        .is_some_and(|candidate| candidate == &digest)
        || protocol_binding
            .derived_session_authority
            .as_ref()
            .is_some_and(|authority| {
                authority.credential_key_identity_digest == digest
                    || authority.cookie_policy_binding_digest == digest
            })
        || protocol_binding
            .browser_exchange_authority
            .as_ref()
            .is_some_and(|authority| {
                [
                    &authority.authorization_endpoint_binding_digest,
                    &authority.token_endpoint_binding_digest,
                    &authority.redirect_uri_binding_digest,
                    &authority.client_id_binding_digest,
                    &authority.scopes_binding_digest,
                ]
                .contains(&&digest)
            })
    {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "authenticator protocol/key authority digest separation",
        ));
    }
    Ok(digest)
}

/// Reconcile both canonical preimages with one exact path in a validated R
/// projection. A live measurer must perform this check for every retained path
/// before treating either opaque digest in R as observed runtime evidence.
pub fn validate_authenticator_runtime_path_preimages(
    runtime_binding: &AuthenticatorRuntimeBindingProjection,
    cache_partition: &AuthenticatorCachePartitionProjection,
    protocol_binding: &AuthenticatorProtocolBindingProjection,
) -> Result<(), RuntimeGuardDigestError> {
    validate_authenticator_runtime_binding_projection(runtime_binding)?;
    validate_authenticator_cache_partition_projection(cache_partition)?;
    validate_authenticator_protocol_binding_projection(protocol_binding)?;

    let identity = &cache_partition.path_identity;
    let Some(path) = runtime_binding
        .credential_paths
        .iter()
        .find(|path| path.path_id == identity.path_id)
    else {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "authenticator preimage path identity",
        ));
    };
    let expected_role = match path.credential_profile.token_profile.as_str() {
        "jwt-access-token" => AuthenticatorRuntimePathRole::DirectBearer,
        "oidc-id-token" => AuthenticatorRuntimePathRole::BrowserDerivedSession,
        _ => {
            return Err(RuntimeGuardDigestError::InvalidProjection(
                "authenticator preimage path role",
            ));
        }
    };
    let cache_digest = authenticator_cache_partition_binding_digest(cache_partition)?;
    let protocol_digest = authenticator_protocol_binding_digest(protocol_binding)?;

    if cache_partition.path_identity != protocol_binding.path_identity
        || identity.provider_id != runtime_binding.provider.provider_id
        || identity.provider_configuration_version != runtime_binding.provider.configuration_version
        || identity.provider_policy_binding_digest != runtime_binding.provider_policy_binding_digest
        || identity.path_role != expected_role
        || identity.path_version != path.path_version
        || identity.verifier_id != path.verifier.verifier_id
        || identity.verifier_version != path.verifier.verifier_version
        || identity.token_profile != path.credential_profile.token_profile
        || identity.issuer_binding_digest != path.verifier.issuer_binding_digest
        || identity.audience_set_binding_digest != path.verifier.audience_set_binding_digest
        || identity.key_source_kind != path.verifier.key_source_kind
        || identity.key_source_binding_digest != path.verifier.key_source_binding_digest
        || cache_partition.retained_consumer_ids != path.retained_consumer_ids
        || protocol_binding.carrier != path.credential_profile.carrier
        || protocol_binding.proof_binding != path.credential_profile.proof_binding
        || protocol_binding.replay != path.credential_profile.replay
        || cache_digest != path.cache_partition_binding_digest
        || protocol_digest != path.protocol_binding_digest
        || cache_digest == protocol_digest
    {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "authenticator runtime path/preimage reconciliation",
        ));
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatorRuntimeBindingDocumentReference {
    pub document_id: String,
    pub document_version: u64,
    pub content_digest: String,
    pub artifact_locator: String,
}

/// Canonical provenance retained by credentials and sessions issued through
/// one exact authenticator path.
///
/// D, P, Q, and R remain independent inputs. The digest of this projection is
/// a fifth binding and must not alias any of them.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatorOriginProjection {
    pub deployment_id: String,
    pub trust_domain_id: String,
    pub tenant_id: Option<String>,
    pub provider_id: String,
    pub provider_configuration_version: u64,
    /// P: digest of the exact active provider configuration payload.
    pub provider_configuration_payload_digest: String,
    pub provider_lifecycle_record_version: u64,
    pub provider_lifecycle_state: ProviderLifecycleState,
    /// D: reference to the exact raw, value-free runtime-binding document.
    pub binding_document_reference: AuthenticatorRuntimeBindingDocumentReference,
    /// Q: digest of the provider policy after excluding only its D reference.
    pub provider_policy_binding_digest: String,
    /// R: digest of the retained authenticator runtime allocation.
    pub runtime_binding_digest: String,
    pub path_id: String,
    pub path_version: u64,
}

#[derive(Serialize)]
struct AuthenticatorOriginBindingDigestProjection<'a> {
    digest_contract: &'static str,
    origin: &'a AuthenticatorOriginProjection,
}

/// Encode one validated authenticator origin with `ryuki-canonical-json-v1`.
pub fn authenticator_origin_binding_canonical_bytes(
    origin: &AuthenticatorOriginProjection,
) -> Result<Vec<u8>, RuntimeGuardDigestError> {
    validate_authenticator_origin_projection(origin)?;
    canonical_projection_bytes(AuthenticatorOriginBindingDigestProjection {
        digest_contract: AUTHENTICATOR_ORIGIN_BINDING_DIGEST_CONTRACT,
        origin,
    })
}

/// Digest one canonical authenticator origin, preserving D/P/Q/R separation.
pub fn authenticator_origin_binding_digest(
    origin: &AuthenticatorOriginProjection,
) -> Result<String, RuntimeGuardDigestError> {
    let digest = digest_canonical_bytes(authenticator_origin_binding_canonical_bytes(origin)?)?;
    if [
        &origin.binding_document_reference.content_digest,
        &origin.provider_configuration_payload_digest,
        &origin.provider_policy_binding_digest,
        &origin.runtime_binding_digest,
    ]
    .contains(&&digest)
    {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "authenticator origin/D/P/Q/R digest separation",
        ));
    }
    Ok(digest)
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatorRuntimeOwnership {
    pub single_runtime_owner: bool,
    pub ambient_reconfiguration_allowed: bool,
}

/// Closed R projection foundation for one retained OIDC authenticator
/// allocation. It is not guard evidence until the provider D/P reference,
/// registered limits, complete derived-session path, and retained runtime
/// objects are independently reconciled by the production witness.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatorRuntimeBindingProjection {
    pub provider: ExpectedProviderBinding,
    /// D: reference to the exact raw, value-free binding document. The active
    /// provider payload P contains the same reference, while this independent
    /// copy is retained in the measured R preimage to prevent substitution.
    pub binding_document_reference: AuthenticatorRuntimeBindingDocumentReference,
    pub authenticator_kind: ProductionAuthenticatorKind,
    pub provider_policy_binding_digest: String,
    pub capability_ids: Vec<String>,
    pub credential_paths: Vec<AuthenticatorRuntimePathProjection>,
    pub ownership: AuthenticatorRuntimeOwnership,
}

#[derive(Serialize)]
struct AuthenticatorRuntimeBindingDigestProjection<'a> {
    digest_contract: &'static str,
    runtime_binding: &'a AuthenticatorRuntimeBindingProjection,
}

#[derive(Serialize)]
struct AuthenticatorProviderPolicyBindingProjection<'a> {
    digest_contract: &'static str,
    kind_config: &'a Value,
}

/// Canonically project an already schema-validated OIDC provider
/// `kind_config` into the independent provider-policy binding Q preimage.
///
/// Only the top-level `runtime_binding_ref` is excluded: that reference binds
/// P to D separately and including it here would make D's own content digest
/// recursive. A missing reference is accepted so callers can construct Q
/// before D exists. All other values, including array order, are preserved.
pub fn authenticator_provider_policy_binding_canonical_bytes(
    kind_config: &Value,
) -> Result<Vec<u8>, RuntimeGuardDigestError> {
    let mut kind_config = kind_config.clone();
    let object = kind_config
        .as_object_mut()
        .ok_or(RuntimeGuardDigestError::InvalidProjection(
            "authenticator provider kind_config must be an object",
        ))?;
    object.remove("runtime_binding_ref");

    canonical_projection_bytes(AuthenticatorProviderPolicyBindingProjection {
        digest_contract: AUTHENTICATOR_PROVIDER_POLICY_BINDING_DIGEST_CONTRACT,
        kind_config: &kind_config,
    })
}

/// Digest the exact canonical provider-policy binding Q preimage.
pub fn authenticator_provider_policy_binding_digest(
    kind_config: &Value,
) -> Result<String, RuntimeGuardDigestError> {
    digest_canonical_bytes(authenticator_provider_policy_binding_canonical_bytes(
        kind_config,
    )?)
}

pub fn authenticator_runtime_binding_canonical_bytes(
    binding: &AuthenticatorRuntimeBindingProjection,
) -> Result<Vec<u8>, RuntimeGuardDigestError> {
    validate_authenticator_runtime_binding_projection(binding)?;
    canonical_projection_bytes(AuthenticatorRuntimeBindingDigestProjection {
        digest_contract: AUTHENTICATOR_RUNTIME_BINDING_DIGEST_CONTRACT,
        runtime_binding: binding,
    })
}

pub fn authenticator_runtime_binding_digest(
    binding: &AuthenticatorRuntimeBindingProjection,
) -> Result<String, RuntimeGuardDigestError> {
    let digest = digest_canonical_bytes(authenticator_runtime_binding_canonical_bytes(binding)?)?;
    if digest == binding.binding_document_reference.content_digest
        || digest == binding.provider.configuration_payload_digest
        || digest == binding.provider_policy_binding_digest
    {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "authenticator D/P/Q/R digest separation",
        ));
    }
    Ok(digest)
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatorInventoryDigestError {
    #[error("authenticator inventory could not be projected as canonical JSON")]
    Projection,
}

#[derive(Serialize)]
struct AuthenticatorInventoryProjection<'a> {
    digest_contract: &'static str,
    authenticators: &'a [ExpectedAuthenticatorBinding],
}

/// Independently encode the exact sorted non-secret authenticator binding
/// inventory using `ryuki-canonical-json-v1`.
pub fn authenticator_inventory_canonical_bytes(
    authenticators: &[ExpectedAuthenticatorBinding],
) -> Result<Vec<u8>, AuthenticatorInventoryDigestError> {
    let projection = AuthenticatorInventoryProjection {
        digest_contract: AUTHENTICATOR_INVENTORY_DIGEST_CONTRACT,
        authenticators,
    };
    let value: Value = serde_json::to_value(projection)
        .map_err(|_| AuthenticatorInventoryDigestError::Projection)?;
    canonical_json_bytes(&value).map_err(|_| AuthenticatorInventoryDigestError::Projection)
}

/// Independently recompute the receipt/runtime digest for the exact sorted
/// non-secret authenticator binding inventory.
pub fn authenticator_inventory_digest(
    authenticators: &[ExpectedAuthenticatorBinding],
) -> Result<String, AuthenticatorInventoryDigestError> {
    let canonical = authenticator_inventory_canonical_bytes(authenticators)?;
    Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExpectedCookiePolicy {
    pub policy_id: String,
    pub cookie_name: String,
    pub secure: bool,
    pub http_only: bool,
    pub path: String,
    pub domain: Option<String>,
    pub same_site: CookieSameSitePolicy,
    pub policy_digest: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExpectedSigningPurpose {
    pub purpose_id: String,
    pub algorithm: SigningAlgorithm,
    pub custody_kind: ExternalKeyCustodyKind,
    pub key_identity_digest: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SigningAlgorithm {
    Ed25519,
    HmacSha256,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ExternalKeyCustodyKind {
    SecretProvider,
    Kms,
    Hsm,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ExternalSigningKeyDisposition {
    Active,
    VerifyOnly,
}

/// Non-secret identity of one exact external key version. A public-key digest
/// is used for asymmetric keys and a provider-authenticated opaque-metadata
/// digest for symmetric keys; raw key material is never serializable here.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalSigningKeyIdentity {
    pub provider: ExpectedProviderBinding,
    pub provider_runtime_binding_digest: String,
    pub deployment_id: String,
    pub trust_domain_id: String,
    pub protocol_version: String,
    pub purpose_id: String,
    pub algorithm: SigningAlgorithm,
    pub custody_kind: ExternalKeyCustodyKind,
    pub key_id: String,
    pub key_version: u64,
    pub public_or_opaque_metadata_digest: String,
    pub disposition: ExternalSigningKeyDisposition,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExpectedExternalSigningKeyVersion {
    pub key_identity_digest: String,
    pub identity: ExternalSigningKeyIdentity,
}

/// Complete runtime keyring for one signing purpose. The signed profile keeps
/// its stable summary shape; the live verifier constructs this additive
/// projection independently and compares its aggregate and active-key digests
/// with that summary.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalSigningPurposeBinding {
    pub purpose_id: String,
    pub algorithm: SigningAlgorithm,
    pub custody_kind: ExternalKeyCustodyKind,
    pub active_key_version: u64,
    pub keys: Vec<ExpectedExternalSigningKeyVersion>,
}

#[derive(Serialize)]
struct ExternalSigningKeyIdentityProjection<'a> {
    digest_contract: &'static str,
    key_identity: &'a ExternalSigningKeyIdentity,
}

#[derive(Serialize)]
struct ExternalSigningInventoryProjection<'a> {
    digest_contract: &'static str,
    purposes: &'a [ExternalSigningPurposeBinding],
}

pub fn external_signing_key_identity_canonical_bytes(
    identity: &ExternalSigningKeyIdentity,
) -> Result<Vec<u8>, RuntimeGuardDigestError> {
    validate_external_signing_key_identity_projection(identity)?;
    canonical_projection_bytes(ExternalSigningKeyIdentityProjection {
        digest_contract: EXTERNAL_SIGNING_KEY_IDENTITY_DIGEST_CONTRACT,
        key_identity: identity,
    })
}

pub fn external_signing_key_identity_digest(
    identity: &ExternalSigningKeyIdentity,
) -> Result<String, RuntimeGuardDigestError> {
    digest_canonical_bytes(external_signing_key_identity_canonical_bytes(identity)?)
}

pub fn external_signing_inventory_canonical_bytes(
    purposes: &[ExternalSigningPurposeBinding],
) -> Result<Vec<u8>, RuntimeGuardDigestError> {
    validate_external_signing_inventory_projection(purposes)?;
    canonical_projection_bytes(ExternalSigningInventoryProjection {
        digest_contract: EXTERNAL_SIGNING_INVENTORY_DIGEST_CONTRACT,
        purposes,
    })
}

pub fn external_signing_inventory_digest(
    purposes: &[ExternalSigningPurposeBinding],
) -> Result<String, RuntimeGuardDigestError> {
    digest_canonical_bytes(external_signing_inventory_canonical_bytes(purposes)?)
}

pub fn external_signing_active_key_identity_digest(
    purpose: &ExternalSigningPurposeBinding,
) -> Result<String, RuntimeGuardDigestError> {
    validate_external_signing_inventory_projection(std::slice::from_ref(purpose))?;
    purpose
        .keys
        .iter()
        .find(|key| key.identity.disposition == ExternalSigningKeyDisposition::Active)
        .map(|key| key.key_identity_digest.clone())
        .ok_or(RuntimeGuardDigestError::InvalidProjection(
            "external signing active-key selection",
        ))
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProductionDependencyPosture {
    Production,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProductionDependencyAuthorityMode {
    Live,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExpectedProductionDependencyBinding {
    pub component_id: String,
    pub implementation_id: String,
    pub implementation_version: String,
    pub production_posture: ProductionDependencyPosture,
    pub authority_mode: ProductionDependencyAuthorityMode,
    pub fallback_allowed: bool,
    pub component_binding_digest: String,
}

/// Cycle-free, value-free observation of one exact retained production
/// dependency allocation.
///
/// `authority_bindings` are produced by component-specific live verifiers
/// (PostgreSQL route/identity/storage/migrations, secret-provider runtime,
/// authenticator runtime, and so on). They must never contain this component
/// digest, the enclosing inventory digest, or the MockDependenciesDisabled
/// requirement/challenge: those values are computed only after every component
/// observation exists. The live API witness must additionally retain the
/// allocation measured by those verifiers; this serializable projection cannot
/// prove handle identity by itself.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProductionDependencyRuntimeBinding {
    pub component_id: String,
    pub implementation_id: String,
    pub implementation_version: String,
    pub production_posture: ProductionDependencyPosture,
    pub authority_mode: ProductionDependencyAuthorityMode,
    pub fallback_allowed: bool,
    pub authority_bindings: Vec<ProductionDependencyAuthorityBinding>,
    pub retained_consumer_ids: Vec<String>,
    pub ownership: ProductionDependencyRuntimeOwnership,
}

/// One independently domain-separated non-secret fact used to admit a
/// component. Multiple facts remain separately named instead of being
/// flattened into an operator-supplied opaque digest.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProductionDependencyAuthorityBinding {
    pub binding_id: String,
    pub binding_contract: String,
    pub binding_digest: String,
}

/// Ownership posture of the allocation measured by one dependency binding.
/// A production dependency cannot be independently reconstructed or switched
/// by an ambient consumer after the inventory is sealed.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProductionDependencyRuntimeOwnership {
    pub runtime_owner_id: String,
    pub single_runtime_owner: bool,
    pub ambient_reconfiguration_allowed: bool,
}

#[derive(Serialize)]
struct ProductionDependencyComponentBindingProjection<'a> {
    digest_contract: &'static str,
    component_binding: &'a ProductionDependencyRuntimeBinding,
}

/// One internally consistent measurement derived from the exact runtime
/// bindings. The required component ids and inventory digest cannot be
/// supplied independently or copied from a deployment receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasuredProductionDependencyInventory {
    pub component_bindings: Vec<ProductionDependencyRuntimeBinding>,
    pub dependencies: Vec<ExpectedProductionDependencyBinding>,
    pub required_component_ids: Vec<String>,
    pub dependency_inventory_digest: String,
}

pub fn production_dependency_component_binding_canonical_bytes(
    dependency: &ProductionDependencyRuntimeBinding,
) -> Result<Vec<u8>, RuntimeGuardDigestError> {
    validate_production_dependency_runtime_binding(dependency)?;
    canonical_projection_bytes(ProductionDependencyComponentBindingProjection {
        digest_contract: PRODUCTION_DEPENDENCY_COMPONENT_BINDING_DIGEST_CONTRACT,
        component_binding: dependency,
    })
}

pub fn production_dependency_component_binding_digest(
    dependency: &ProductionDependencyRuntimeBinding,
) -> Result<String, RuntimeGuardDigestError> {
    digest_canonical_bytes(production_dependency_component_binding_canonical_bytes(
        dependency,
    )?)
}

pub fn expected_production_dependency_binding(
    dependency: &ProductionDependencyRuntimeBinding,
) -> Result<ExpectedProductionDependencyBinding, RuntimeGuardDigestError> {
    Ok(ExpectedProductionDependencyBinding {
        component_id: dependency.component_id.clone(),
        implementation_id: dependency.implementation_id.clone(),
        implementation_version: dependency.implementation_version.clone(),
        production_posture: dependency.production_posture,
        authority_mode: dependency.authority_mode,
        fallback_allowed: dependency.fallback_allowed,
        component_binding_digest: production_dependency_component_binding_digest(dependency)?,
    })
}

/// Reject a copied or stale row even when its component digest is syntactically
/// valid. The expected row must be exactly the one derived from this live
/// component preimage.
pub fn validate_production_dependency_component_preimage(
    expected: &ExpectedProductionDependencyBinding,
    dependency: &ProductionDependencyRuntimeBinding,
) -> Result<(), RuntimeGuardDigestError> {
    if expected != &expected_production_dependency_binding(dependency)? {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "production dependency component/preimage reconciliation",
        ));
    }
    Ok(())
}

/// Derive the complete receipt-comparison projection from one independently
/// discovered, component-id-sorted retained-runtime inventory.
pub fn measure_production_dependency_inventory(
    dependencies: &[ProductionDependencyRuntimeBinding],
) -> Result<MeasuredProductionDependencyInventory, RuntimeGuardDigestError> {
    let unique_runtime_owner_ids = dependencies
        .iter()
        .map(|dependency| dependency.ownership.runtime_owner_id.as_str())
        .collect::<HashSet<_>>();
    if dependencies.is_empty()
        || !dependencies
            .windows(2)
            .all(|pair| pair[0].component_id < pair[1].component_id)
        || unique_runtime_owner_ids.len() != dependencies.len()
    {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "production dependency runtime inventory",
        ));
    }

    let measured = dependencies
        .iter()
        .map(expected_production_dependency_binding)
        .collect::<Result<Vec<_>, RuntimeGuardDigestError>>()?;
    let required_component_ids = measured
        .iter()
        .map(|dependency| dependency.component_id.clone())
        .collect::<Vec<_>>();
    let dependency_inventory_digest = production_dependency_inventory_digest(&measured)?;

    Ok(MeasuredProductionDependencyInventory {
        component_bindings: dependencies.to_vec(),
        dependencies: measured,
        required_component_ids,
        dependency_inventory_digest,
    })
}

#[derive(Serialize)]
struct ProductionDependencyInventoryProjection<'a> {
    digest_contract: &'static str,
    dependencies: &'a [ExpectedProductionDependencyBinding],
}

pub fn production_dependency_inventory_canonical_bytes(
    dependencies: &[ExpectedProductionDependencyBinding],
) -> Result<Vec<u8>, RuntimeGuardDigestError> {
    validate_production_dependency_inventory_projection(dependencies)?;
    canonical_projection_bytes(ProductionDependencyInventoryProjection {
        digest_contract: PRODUCTION_DEPENDENCY_INVENTORY_DIGEST_CONTRACT,
        dependencies,
    })
}

pub fn production_dependency_inventory_digest(
    dependencies: &[ExpectedProductionDependencyBinding],
) -> Result<String, RuntimeGuardDigestError> {
    digest_canonical_bytes(production_dependency_inventory_canonical_bytes(
        dependencies,
    )?)
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FirstOwnerAuthorityNamespace {
    pub state_contract_version: u64,
    pub deployment_id: String,
    pub trust_domain_ids: Vec<String>,
    pub tenancy_mode: TenancyMode,
    pub tenant_id: Option<String>,
    pub authority_id: String,
    pub authority_key_id: String,
    pub authority_public_key_fingerprint: String,
    pub authority_epoch: u64,
    pub namespace_id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FirstOwnerClosureStatus {
    Closed,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FirstOwnerClosureRecord {
    pub state_contract_version: u64,
    pub deployment_id: String,
    pub authority_namespace_digest: String,
    pub status: FirstOwnerClosureStatus,
    pub closure_event_id: String,
    pub authority_sequence: u64,
    pub first_owner_principal_id: String,
    pub claim_request_digest: String,
    pub capability_id: String,
    pub capability_expires_at: String,
    pub closed_at_not_before: String,
    pub closed_at_not_after: String,
    pub closure_certificate_digest: String,
}

/// The immutable closure facts authenticated by the external first-owner
/// authority. The certificate digest is deliberately absent because it hashes
/// the completed envelope, including the signature.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedFirstOwnerClosure {
    pub state_contract_version: u64,
    pub deployment_id: String,
    pub authority_namespace_digest: String,
    pub status: FirstOwnerClosureStatus,
    pub closure_event_id: String,
    pub authority_sequence: u64,
    pub first_owner_principal_id: String,
    pub claim_request_digest: String,
    pub capability_id: String,
    pub capability_expires_at: String,
    pub closed_at_not_before: String,
    pub closed_at_not_after: String,
}

/// One member of the closed, ordered privileged-domain assignment set.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedPrivilegedDomainAssignment {
    pub assignment_event_id: String,
    pub domain_id: String,
    pub principal_id: String,
}

/// Canonical deployment-owned proof that the one-time first-owner path closed.
///
/// `tenant_id` remains present inside `authority_namespace` to make the
/// deployment-owned namespace explicit: it must be JSON `null` in both
/// tenancy modes. `tenancy_mode` is still signed so a certificate cannot move
/// between deployment modes.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FirstOwnerClosureCertificate {
    pub schema_version: String,
    pub contract_kind: String,
    pub canonicalization: String,
    pub signature_algorithm: String,
    pub authority_namespace: FirstOwnerAuthorityNamespace,
    pub closure: SignedFirstOwnerClosure,
    pub privileged_domain_assignments: Vec<SignedPrivilegedDomainAssignment>,
    pub signature_base64: String,
}

/// Independently provisioned trust pins for pure certificate verification.
///
/// The public key and every identity field come from deployment configuration,
/// never from the certificate or a rollbackable contract directory.
#[derive(Debug, Clone, Copy)]
pub struct FirstOwnerCertificateAuthorityAnchor<'a> {
    pub authority_id: &'a str,
    pub authority_key_id: &'a str,
    pub public_key: &'a [u8; 32],
    pub public_key_fingerprint: &'a str,
    pub minimum_authority_epoch: u64,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum FirstOwnerClosureCertificateError {
    #[error("the first-owner closure certificate is invalid")]
    InvalidCertificate,
    #[error("the first-owner closure certificate is not exact canonical JSON")]
    NonCanonicalCertificate,
    #[error("the first-owner closure certificate signature representation is invalid")]
    InvalidSignatureRepresentation,
    #[error("the independently pinned first-owner authority binding is invalid")]
    InvalidAuthorityBinding,
    #[error("the first-owner closure certificate signature verification failed")]
    SignatureVerificationFailed,
}

/// Digest-only proof returned after timeless certificate verification.
///
/// Expiration is intentionally not part of this proof: a valid permanent
/// closure remains valid after its one-shot installation capability expires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFirstOwnerClosureCertificate {
    certificate_digest: String,
    authority_namespace_digest: String,
    closure_record_digest: String,
    signature_digest: String,
}

impl VerifiedFirstOwnerClosureCertificate {
    pub fn certificate_digest(&self) -> &str {
        &self.certificate_digest
    }

    pub fn authority_namespace_digest(&self) -> &str {
        &self.authority_namespace_digest
    }

    pub fn closure_record_digest(&self) -> &str {
        &self.closure_record_digest
    }

    pub fn signature_digest(&self) -> &str {
        &self.signature_digest
    }
}

#[derive(Serialize)]
struct UnsignedFirstOwnerClosureCertificate<'a> {
    schema_version: &'a str,
    contract_kind: &'a str,
    canonicalization: &'a str,
    signature_algorithm: &'a str,
    authority_namespace: &'a FirstOwnerAuthorityNamespace,
    closure: &'a SignedFirstOwnerClosure,
    privileged_domain_assignments: &'a [SignedPrivilegedDomainAssignment],
}

/// Parse only exact, duplicate-free `ryuki-canonical-json-v1` certificate
/// bytes. This helper performs no I/O and does not establish signature trust.
pub fn parse_first_owner_closure_certificate(
    bytes: &[u8],
) -> Result<FirstOwnerClosureCertificate, FirstOwnerClosureCertificateError> {
    if bytes.is_empty() || bytes.len() > FIRST_OWNER_CLOSURE_CERTIFICATE_MAX_BYTES {
        return Err(FirstOwnerClosureCertificateError::InvalidCertificate);
    }
    let value = parse_json_strict(bytes)
        .map_err(|_| FirstOwnerClosureCertificateError::InvalidCertificate)?;
    let canonical = canonical_json_bytes(&value)
        .map_err(|_| FirstOwnerClosureCertificateError::InvalidCertificate)?;
    if canonical != bytes {
        return Err(FirstOwnerClosureCertificateError::NonCanonicalCertificate);
    }
    let certificate = serde_json::from_value(value)
        .map_err(|_| FirstOwnerClosureCertificateError::InvalidCertificate)?;
    validate_first_owner_closure_certificate(&certificate)?;
    Ok(certificate)
}

/// Exact canonical bytes of the complete signed certificate.
pub fn first_owner_closure_certificate_canonical_bytes(
    certificate: &FirstOwnerClosureCertificate,
) -> Result<Vec<u8>, FirstOwnerClosureCertificateError> {
    validate_first_owner_closure_certificate(certificate)?;
    let value = serde_json::to_value(certificate)
        .map_err(|_| FirstOwnerClosureCertificateError::InvalidCertificate)?;
    canonical_json_bytes(&value).map_err(|_| FirstOwnerClosureCertificateError::InvalidCertificate)
}

/// SHA-256 of the exact canonical completed certificate, including signature.
pub fn first_owner_closure_certificate_digest(
    certificate: &FirstOwnerClosureCertificate,
) -> Result<String, FirstOwnerClosureCertificateError> {
    Ok(sha256_bytes_digest(
        &first_owner_closure_certificate_canonical_bytes(certificate)?,
    ))
}

/// SHA-256 of the canonical 64-byte Ed25519 signature representation.
pub fn first_owner_closure_certificate_signature_digest(
    certificate: &FirstOwnerClosureCertificate,
) -> Result<String, FirstOwnerClosureCertificateError> {
    Ok(sha256_bytes_digest(&decode_first_owner_signature(
        &certificate.signature_base64,
    )?))
}

/// Canonical unsigned JSON subject. `signature_base64` is omitted, not nulled.
pub fn first_owner_closure_certificate_unsigned_canonical_bytes(
    certificate: &FirstOwnerClosureCertificate,
) -> Result<Vec<u8>, FirstOwnerClosureCertificateError> {
    validate_first_owner_closure_certificate(certificate)?;
    let value = serde_json::to_value(UnsignedFirstOwnerClosureCertificate {
        schema_version: &certificate.schema_version,
        contract_kind: &certificate.contract_kind,
        canonicalization: &certificate.canonicalization,
        signature_algorithm: &certificate.signature_algorithm,
        authority_namespace: &certificate.authority_namespace,
        closure: &certificate.closure,
        privileged_domain_assignments: &certificate.privileged_domain_assignments,
    })
    .map_err(|_| FirstOwnerClosureCertificateError::InvalidCertificate)?;
    canonical_json_bytes(&value).map_err(|_| FirstOwnerClosureCertificateError::InvalidCertificate)
}

/// Exact two-frame Ed25519 preimage: an unsigned little-endian u64 length and
/// the UTF-8 domain, followed by the same framing for the canonical unsigned
/// certificate JSON.
pub fn first_owner_closure_certificate_signing_bytes(
    certificate: &FirstOwnerClosureCertificate,
) -> Result<Vec<u8>, FirstOwnerClosureCertificateError> {
    let canonical = first_owner_closure_certificate_unsigned_canonical_bytes(certificate)?;
    let domain = FIRST_OWNER_CLOSURE_CERTIFICATE_SIGNATURE_DOMAIN.as_bytes();
    let mut signing_bytes = Vec::with_capacity(16 + domain.len() + canonical.len());
    write_first_owner_frame(&mut signing_bytes, domain)?;
    write_first_owner_frame(&mut signing_bytes, &canonical)?;
    Ok(signing_bytes)
}

/// Build the durable closure-record projection from one complete certificate.
pub fn first_owner_closure_record_from_certificate(
    certificate: &FirstOwnerClosureCertificate,
) -> Result<FirstOwnerClosureRecord, FirstOwnerClosureCertificateError> {
    validate_first_owner_closure_certificate(certificate)?;
    let record = FirstOwnerClosureRecord {
        state_contract_version: certificate.closure.state_contract_version,
        deployment_id: certificate.closure.deployment_id.clone(),
        authority_namespace_digest: certificate.closure.authority_namespace_digest.clone(),
        status: certificate.closure.status,
        closure_event_id: certificate.closure.closure_event_id.clone(),
        authority_sequence: certificate.closure.authority_sequence,
        first_owner_principal_id: certificate.closure.first_owner_principal_id.clone(),
        claim_request_digest: certificate.closure.claim_request_digest.clone(),
        capability_id: certificate.closure.capability_id.clone(),
        capability_expires_at: certificate.closure.capability_expires_at.clone(),
        closed_at_not_before: certificate.closure.closed_at_not_before.clone(),
        closed_at_not_after: certificate.closure.closed_at_not_after.clone(),
        closure_certificate_digest: first_owner_closure_certificate_digest(certificate)?,
    };
    validate_first_owner_closure_record_projection(&record)
        .map_err(|_| FirstOwnerClosureCertificateError::InvalidCertificate)?;
    Ok(record)
}

/// Pure, timeless verification against an independently pinned Ed25519 key.
pub fn verify_first_owner_closure_certificate(
    certificate: &FirstOwnerClosureCertificate,
    authority: FirstOwnerCertificateAuthorityAnchor<'_>,
) -> Result<VerifiedFirstOwnerClosureCertificate, FirstOwnerClosureCertificateError> {
    validate_first_owner_closure_certificate(certificate)?;
    let key = validate_first_owner_certificate_authority(certificate, authority)?;
    let signature_bytes = decode_first_owner_signature(&certificate.signature_base64)?;
    let signature = Signature::from_bytes(&signature_bytes);
    key.verify_strict(
        &first_owner_closure_certificate_signing_bytes(certificate)?,
        &signature,
    )
    .map_err(|_| FirstOwnerClosureCertificateError::SignatureVerificationFailed)?;

    let certificate_digest = first_owner_closure_certificate_digest(certificate)?;
    let authority_namespace_digest =
        first_owner_authority_namespace_digest(&certificate.authority_namespace)
            .map_err(|_| FirstOwnerClosureCertificateError::InvalidCertificate)?;
    let closure_record = first_owner_closure_record_from_certificate(certificate)?;
    let closure_record_digest = first_owner_closure_record_digest(&closure_record)
        .map_err(|_| FirstOwnerClosureCertificateError::InvalidCertificate)?;
    Ok(VerifiedFirstOwnerClosureCertificate {
        certificate_digest,
        authority_namespace_digest,
        closure_record_digest,
        signature_digest: sha256_bytes_digest(&signature_bytes),
    })
}

/// Trusted-time gate for the one-shot installation ceremony.
///
/// The closure interval must have completed and the capability expiry is
/// exclusive. Permanent verification must use the timeless signature helper
/// above instead of reapplying this transient gate.
pub fn first_owner_closure_certificate_is_installable_at(
    certificate: &FirstOwnerClosureCertificate,
    trusted_now: DateTime<Utc>,
) -> Result<bool, FirstOwnerClosureCertificateError> {
    validate_first_owner_closure_certificate(certificate)?;
    let closed_at_not_after = parse_first_owner_timestamp(&certificate.closure.closed_at_not_after)
        .ok_or(FirstOwnerClosureCertificateError::InvalidCertificate)?;
    let capability_expires_at =
        parse_first_owner_timestamp(&certificate.closure.capability_expires_at)
            .ok_or(FirstOwnerClosureCertificateError::InvalidCertificate)?;
    Ok(trusted_now >= closed_at_not_after && trusted_now < capability_expires_at)
}

#[derive(Serialize)]
struct FirstOwnerAuthorityNamespaceProjection<'a> {
    digest_contract: &'static str,
    authority_namespace: &'a FirstOwnerAuthorityNamespace,
}

#[derive(Serialize)]
struct FirstOwnerClosureRecordProjection<'a> {
    digest_contract: &'static str,
    closure_record: &'a FirstOwnerClosureRecord,
}

pub fn first_owner_authority_namespace_canonical_bytes(
    namespace: &FirstOwnerAuthorityNamespace,
) -> Result<Vec<u8>, RuntimeGuardDigestError> {
    validate_first_owner_authority_namespace_projection(namespace)?;
    canonical_projection_bytes(FirstOwnerAuthorityNamespaceProjection {
        digest_contract: FIRST_OWNER_AUTHORITY_NAMESPACE_DIGEST_CONTRACT,
        authority_namespace: namespace,
    })
}

pub fn first_owner_authority_namespace_digest(
    namespace: &FirstOwnerAuthorityNamespace,
) -> Result<String, RuntimeGuardDigestError> {
    digest_canonical_bytes(first_owner_authority_namespace_canonical_bytes(namespace)?)
}

pub fn first_owner_closure_record_canonical_bytes(
    record: &FirstOwnerClosureRecord,
) -> Result<Vec<u8>, RuntimeGuardDigestError> {
    validate_first_owner_closure_record_projection(record)?;
    canonical_projection_bytes(FirstOwnerClosureRecordProjection {
        digest_contract: FIRST_OWNER_CLOSURE_RECORD_DIGEST_CONTRACT,
        closure_record: record,
    })
}

pub fn first_owner_closure_record_digest(
    record: &FirstOwnerClosureRecord,
) -> Result<String, RuntimeGuardDigestError> {
    digest_canonical_bytes(first_owner_closure_record_canonical_bytes(record)?)
}

fn validate_first_owner_closure_certificate(
    certificate: &FirstOwnerClosureCertificate,
) -> Result<(), FirstOwnerClosureCertificateError> {
    if certificate.schema_version != FIRST_OWNER_CLOSURE_CERTIFICATE_SCHEMA_VERSION
        || certificate.contract_kind != FIRST_OWNER_CLOSURE_CERTIFICATE_CONTRACT_KIND
        || certificate.canonicalization != FIRST_OWNER_CLOSURE_CERTIFICATE_CANONICALIZATION
        || certificate.signature_algorithm != FIRST_OWNER_CLOSURE_CERTIFICATE_SIGNATURE_ALGORITHM
        || certificate.authority_namespace.state_contract_version
            != FIRST_OWNER_STATE_CONTRACT_VERSION
        || certificate.closure.state_contract_version != FIRST_OWNER_STATE_CONTRACT_VERSION
        || certificate.authority_namespace.state_contract_version
            != certificate.closure.state_contract_version
        || certificate.authority_namespace.deployment_id != certificate.closure.deployment_id
        || certificate.authority_namespace.trust_domain_ids.len() > 64
    {
        return Err(FirstOwnerClosureCertificateError::InvalidCertificate);
    }
    validate_first_owner_authority_namespace_projection(&certificate.authority_namespace)
        .map_err(|_| FirstOwnerClosureCertificateError::InvalidCertificate)?;
    let namespace_digest = first_owner_authority_namespace_digest(&certificate.authority_namespace)
        .map_err(|_| FirstOwnerClosureCertificateError::InvalidCertificate)?;
    let closure = &certificate.closure;
    let capability_expires_at = parse_first_owner_timestamp(&closure.capability_expires_at);
    let closed_at_not_before = parse_first_owner_timestamp(&closure.closed_at_not_before);
    let closed_at_not_after = parse_first_owner_timestamp(&closure.closed_at_not_after);
    let valid_window = capability_expires_at
        .zip(closed_at_not_before)
        .zip(closed_at_not_after)
        .is_some_and(|((expires, not_before), not_after)| {
            not_before <= not_after && not_after < expires
        });
    if closure.authority_namespace_digest != namespace_digest
        || !valid_canonical_scoped_id(&closure.deployment_id, "deployment:")
        || !valid_canonical_scoped_id(&closure.closure_event_id, "first-owner-closure-event:")
        || closure.authority_sequence == 0
        || closure.authority_sequence > FIRST_OWNER_MAX_EXACT_JSON_INTEGER
        || !valid_canonical_scoped_id(&closure.first_owner_principal_id, "principal:")
        || !valid_sha256_digest(&closure.claim_request_digest)
        || !valid_canonical_scoped_id(&closure.capability_id, "first-owner-capability:")
        || !valid_window
    {
        return Err(FirstOwnerClosureCertificateError::InvalidCertificate);
    }

    let assignments = &certificate.privileged_domain_assignments;
    let unique_assignment_event_ids = assignments
        .iter()
        .map(|assignment| assignment.assignment_event_id.as_str())
        .collect::<HashSet<_>>();
    if assignments.len() != FIRST_OWNER_PRIVILEGED_DOMAINS.len()
        || !assignments
            .iter()
            .map(|assignment| assignment.domain_id.as_str())
            .eq(FIRST_OWNER_PRIVILEGED_DOMAINS)
        || unique_assignment_event_ids.len() != assignments.len()
        || assignments.iter().any(|assignment| {
            !valid_canonical_scoped_id(
                &assignment.assignment_event_id,
                "first-owner-assignment-event:",
            ) || assignment.assignment_event_id == closure.closure_event_id
                || !valid_canonical_scoped_id(&assignment.principal_id, "principal:")
                || assignment.principal_id != closure.first_owner_principal_id
        })
    {
        return Err(FirstOwnerClosureCertificateError::InvalidCertificate);
    }
    decode_first_owner_signature(&certificate.signature_base64)?;
    Ok(())
}

fn validate_first_owner_certificate_authority(
    certificate: &FirstOwnerClosureCertificate,
    authority: FirstOwnerCertificateAuthorityAnchor<'_>,
) -> Result<VerifyingKey, FirstOwnerClosureCertificateError> {
    if !valid_canonical_scoped_id(authority.authority_id, "first-owner-authority:")
        || !valid_canonical_scoped_id(authority.authority_key_id, "first-owner-authority-key:")
        || !valid_sha256_digest(authority.public_key_fingerprint)
        || authority.minimum_authority_epoch == 0
        || authority.minimum_authority_epoch > FIRST_OWNER_MAX_EXACT_JSON_INTEGER
    {
        return Err(FirstOwnerClosureCertificateError::InvalidAuthorityBinding);
    }
    let key = VerifyingKey::from_bytes(authority.public_key)
        .map_err(|_| FirstOwnerClosureCertificateError::InvalidAuthorityBinding)?;
    if key.is_weak()
        || sha256_bytes_digest(authority.public_key) != authority.public_key_fingerprint
        || certificate.authority_namespace.authority_id != authority.authority_id
        || certificate.authority_namespace.authority_key_id != authority.authority_key_id
        || certificate
            .authority_namespace
            .authority_public_key_fingerprint
            != authority.public_key_fingerprint
        || certificate.authority_namespace.authority_epoch < authority.minimum_authority_epoch
    {
        return Err(FirstOwnerClosureCertificateError::InvalidAuthorityBinding);
    }
    Ok(key)
}

fn decode_first_owner_signature(
    value: &str,
) -> Result<[u8; 64], FirstOwnerClosureCertificateError> {
    let decoded = BASE64_STANDARD
        .decode(value.as_bytes())
        .map_err(|_| FirstOwnerClosureCertificateError::InvalidSignatureRepresentation)?;
    let bytes: [u8; 64] = decoded
        .try_into()
        .map_err(|_| FirstOwnerClosureCertificateError::InvalidSignatureRepresentation)?;
    if BASE64_STANDARD.encode(bytes) != value {
        return Err(FirstOwnerClosureCertificateError::InvalidSignatureRepresentation);
    }
    Ok(bytes)
}

fn write_first_owner_frame(
    output: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), FirstOwnerClosureCertificateError> {
    let length = u64::try_from(bytes.len())
        .map_err(|_| FirstOwnerClosureCertificateError::InvalidCertificate)?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn sha256_bytes_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn parse_first_owner_timestamp(value: &str) -> Option<DateTime<Utc>> {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || bytes.iter().enumerate().any(|(index, byte)| {
            !matches!(index, 4 | 7 | 10 | 13 | 16 | 19) && !byte.is_ascii_digit()
        })
        || parse_first_owner_decimal_pair(bytes[11], bytes[12]) > 23
        || parse_first_owner_decimal_pair(bytes[14], bytes[15]) > 59
        || parse_first_owner_decimal_pair(bytes[17], bytes[18]) > 59
    {
        return None;
    }
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .filter(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Secs, true) == value)
}

fn parse_first_owner_decimal_pair(tens: u8, ones: u8) -> u8 {
    (tens - b'0') * 10 + (ones - b'0')
}

fn canonical_projection_bytes(
    projection: impl Serialize,
) -> Result<Vec<u8>, RuntimeGuardDigestError> {
    let value =
        serde_json::to_value(projection).map_err(|_| RuntimeGuardDigestError::Projection)?;
    canonical_json_bytes(&value).map_err(|_| RuntimeGuardDigestError::Projection)
}

fn digest_canonical_bytes(bytes: Vec<u8>) -> Result<String, RuntimeGuardDigestError> {
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn valid_sha256_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && hex.bytes().any(|byte| byte != b'0')
}

fn valid_canonical_runtime_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    (3..=255).contains(&bytes.len())
        && bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
}

fn strictly_sorted_unique_strings(values: &[String]) -> bool {
    !values.is_empty() && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn valid_provider_projection(provider: &ExpectedProviderBinding) -> bool {
    let mut errors = Vec::new();
    validate_provider_binding("runtime-guard provider", provider, &mut errors);
    errors.is_empty()
}

fn validate_postgresql_database_identity_projection(
    identity: &PostgresqlDatabaseIdentity,
) -> Result<(), RuntimeGuardDigestError> {
    let system_identifier_is_canonical = identity
        .cluster_system_identifier
        .parse::<u64>()
        .is_ok_and(|identifier| identifier > 0)
        && !identity.cluster_system_identifier.starts_with('0');
    if !valid_canonical_scoped_id(&identity.deployment_id, "deployment:")
        || !valid_canonical_scoped_id(&identity.trust_domain_id, "trust-domain:")
        || !valid_postgresql_identifier(&identity.database_name)
        || identity.database_name == "postgres"
        || identity.database_oid == 0
        || !system_identifier_is_canonical
        || !identity
            .server_address
            .parse::<IpAddr>()
            .is_ok_and(|address| address.to_string() == identity.server_address)
        || identity.server_port == 0
        || !identity.tls_enabled
        || !valid_canonical_runtime_identifier(&identity.tls_protocol)
        || !valid_canonical_runtime_identifier(&identity.tls_cipher_suite)
        || identity.tls_cipher_bits < 128
        || identity.server_major_version != 18
        || !identity.primary
        || !identity.writable
    {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "postgresql database identity",
        ));
    }
    Ok(())
}

fn validate_postgresql_provider_route_binding_projection(
    binding: &PostgresqlProviderRouteBinding,
) -> Result<(), RuntimeGuardDigestError> {
    let dns_is_canonical = !binding.endpoint_dns_name.is_empty()
        && binding.endpoint_dns_name.len() <= 253
        && !binding.endpoint_dns_name.ends_with('.')
        && binding.endpoint_dns_name.parse::<IpAddr>().is_err()
        && binding.endpoint_dns_name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        });
    if binding.route_mode != POSTGRESQL_PROVIDER_ROUTE_MODE_DIRECT_SESSION_V1
        || !dns_is_canonical
        || binding.endpoint_port == 0
        || !valid_sha256_digest(&binding.trust_anchor_bundle_digest)
        || !valid_sha256_digest(&binding.peer_leaf_certificate_digest)
    {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "postgresql provider route binding",
        ));
    }
    Ok(())
}

fn validate_postgresql_storage_binding_projection(
    bindings: &[PostgresqlStorageBinding],
) -> Result<(), RuntimeGuardDigestError> {
    let has_required_purpose_shape = matches!(bindings, [data] if data.purpose == PostgresqlStoragePurpose::Data)
        || matches!(bindings, [data, wal]
                if data.purpose == PostgresqlStoragePurpose::Data
                    && wal.purpose == PostgresqlStoragePurpose::Wal);
    if !has_required_purpose_shape
        || !bindings
            .windows(2)
            .all(|pair| pair[0].purpose < pair[1].purpose)
        || bindings.iter().any(|binding| {
            !valid_sha256_digest(&binding.provider_cluster_uid_digest)
                || !valid_sha256_digest(&binding.persistent_volume_claim_uid_digest)
                || !valid_sha256_digest(&binding.persistent_volume_uid_digest)
                || !valid_canonical_runtime_identifier(&binding.csi_driver)
                || !valid_sha256_digest(&binding.volume_handle_digest)
                || !valid_canonical_runtime_identifier(&binding.storage_class)
        })
    {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "postgresql storage bindings",
        ));
    }
    Ok(())
}

fn validate_postgresql_migration_inventory_projection(
    migrations: &[PostgresqlMigrationInventoryRow],
) -> Result<(), RuntimeGuardDigestError> {
    if migrations.is_empty()
        || !migrations
            .windows(2)
            .all(|pair| pair[0].version < pair[1].version)
        || migrations.iter().any(|migration| {
            migration.version == 0 || !valid_sha256_digest(&migration.checksum_digest)
        })
    {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "postgresql migration inventory",
        ));
    }
    Ok(())
}

fn validate_authenticator_runtime_path_identity_projection(
    identity: &AuthenticatorRuntimePathIdentityProjection,
) -> Result<(), RuntimeGuardDigestError> {
    let binding_digests = [
        identity.provider_policy_binding_digest.as_str(),
        identity.issuer_binding_digest.as_str(),
        identity.audience_set_binding_digest.as_str(),
        identity.key_source_binding_digest.as_str(),
    ];
    let distinct_binding_digests = binding_digests
        .iter()
        .copied()
        .collect::<HashSet<_>>()
        .len()
        == binding_digests.len();
    let role_token_profile_matches = matches!(
        (identity.path_role, identity.token_profile.as_str()),
        (
            AuthenticatorRuntimePathRole::DirectBearer,
            "jwt-access-token"
        ) | (
            AuthenticatorRuntimePathRole::BrowserDerivedSession,
            "oidc-id-token"
        )
    );

    if !valid_canonical_scoped_id(&identity.provider_id, "provider:")
        || identity.provider_configuration_version == 0
        || !valid_sha256_digest(&identity.provider_policy_binding_digest)
        || !valid_canonical_scoped_id(&identity.path_id, "authenticator-path:")
        || identity.path_version == 0
        || !valid_canonical_scoped_id(&identity.verifier_id, "authenticator-verifier:")
        || identity.verifier_version == 0
        || !role_token_profile_matches
        || !valid_sha256_digest(&identity.issuer_binding_digest)
        || !valid_sha256_digest(&identity.audience_set_binding_digest)
        || identity.key_source_kind != AuthenticatorKeySourceKind::JwtJwks
        || !valid_sha256_digest(&identity.key_source_binding_digest)
        || !distinct_binding_digests
    {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "authenticator runtime path identity",
        ));
    }
    Ok(())
}

fn reject_authenticator_path_identity_digest_collision(
    digest: &str,
    identity: &AuthenticatorRuntimePathIdentityProjection,
) -> Result<(), RuntimeGuardDigestError> {
    if [
        identity.provider_policy_binding_digest.as_str(),
        identity.issuer_binding_digest.as_str(),
        identity.audience_set_binding_digest.as_str(),
        identity.key_source_binding_digest.as_str(),
    ]
    .contains(&digest)
    {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "authenticator cache/protocol authority digest separation",
        ));
    }
    Ok(())
}

fn validate_authenticator_cache_partition_projection(
    cache_partition: &AuthenticatorCachePartitionProjection,
) -> Result<(), RuntimeGuardDigestError> {
    validate_authenticator_runtime_path_identity_projection(&cache_partition.path_identity)?;

    let kinds_are_sorted = !cache_partition.cache_kinds.is_empty()
        && cache_partition.cache_kinds.len() <= 16
        && cache_partition
            .cache_kinds
            .windows(2)
            .all(|pair| pair[0] < pair[1]);
    let has_kind = |required| cache_partition.cache_kinds.binary_search(&required).is_ok();
    let role_cache_inventory_matches = match cache_partition.path_identity.path_role {
        AuthenticatorRuntimePathRole::DirectBearer => {
            has_kind(AuthenticatorCacheKind::JwksKeySet)
                && !has_kind(AuthenticatorCacheKind::BrowserLoginState)
                && !has_kind(AuthenticatorCacheKind::DerivedSessionCredential)
                && !has_kind(AuthenticatorCacheKind::NonceReplay)
                && !has_kind(AuthenticatorCacheKind::TokenIntrospection)
        }
        AuthenticatorRuntimePathRole::BrowserDerivedSession => {
            has_kind(AuthenticatorCacheKind::BrowserLoginState)
                && has_kind(AuthenticatorCacheKind::DerivedSessionCredential)
                && has_kind(AuthenticatorCacheKind::JwksKeySet)
                && has_kind(AuthenticatorCacheKind::NonceReplay)
                && !has_kind(AuthenticatorCacheKind::TokenIntrospection)
        }
    };

    if !valid_canonical_scoped_id(
        &cache_partition.cache_owner_id,
        "authenticator-cache-owner:",
    ) || !valid_canonical_scoped_id(
        &cache_partition.cache_partition_id,
        "authenticator-cache-partition:",
    ) || cache_partition.cache_owner_id == cache_partition.cache_partition_id
        || !kinds_are_sorted
        || !role_cache_inventory_matches
        || cache_partition.retained_consumer_ids.len() > 128
        || !strictly_sorted_unique_strings(&cache_partition.retained_consumer_ids)
        || !cache_partition
            .retained_consumer_ids
            .iter()
            .all(|consumer| valid_canonical_scoped_id(consumer, "runtime-consumer:"))
    {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "authenticator cache partition binding",
        ));
    }
    Ok(())
}

fn validate_authenticator_browser_state_authority_projection(
    authority: &AuthenticatorBrowserStateAuthorityProjection,
) -> bool {
    valid_canonical_scoped_id(
        &authority.state_authority_id,
        "authenticator-state-authority:",
    ) && authority.state_authority_version > 0
        && authority.relation_name == AUTHENTICATOR_BROWSER_STATE_RELATION_V3
        && authority.writer_contract_setting == AUTHENTICATOR_BROWSER_STATE_CONTRACT_SETTING
        && authority.writer_contract_version == AUTHENTICATOR_BROWSER_STATE_CONTRACT_VERSION
        && authority.consume_operation == AUTHENTICATOR_BROWSER_STATE_CONSUME_OPERATION
        && authority.state_lifetime_limit_id == AUTHENTICATOR_BROWSER_STATE_LIFETIME_LIMIT_ID
        && authority.maximum_state_lifetime_seconds
            == AUTHENTICATOR_BROWSER_STATE_MAXIMUM_TTL_SECONDS
        && authority.pkce_method == AUTHENTICATOR_BROWSER_PKCE_METHOD_S256
        && authority.nonce_required
        && authority.browser_binding_required
        && authority.exact_origin_match_required
}

fn validate_authenticator_browser_exchange_authority_projection(
    authority: &AuthenticatorBrowserExchangeAuthorityProjection,
) -> bool {
    let binding_digests = [
        authority.authorization_endpoint_binding_digest.as_str(),
        authority.token_endpoint_binding_digest.as_str(),
        authority.redirect_uri_binding_digest.as_str(),
        authority.client_id_binding_digest.as_str(),
        authority.scopes_binding_digest.as_str(),
    ];
    let client_authentication_matches = matches!(
        (
            authority.client_authentication,
            authority.client_credential_present
        ),
        (AuthenticatorBrowserClientAuthentication::None, false)
            | (
                AuthenticatorBrowserClientAuthentication::ClientSecretPost,
                true
            )
    );

    valid_canonical_scoped_id(
        &authority.exchange_authority_id,
        "authenticator-exchange-authority:",
    ) && authority.exchange_authority_version > 0
        && binding_digests
            .iter()
            .all(|digest| valid_sha256_digest(digest))
        && binding_digests
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            .len()
            == binding_digests.len()
        && client_authentication_matches
        && authority.connect_timeout_milliseconds > 0
        && authority.request_timeout_milliseconds >= authority.connect_timeout_milliseconds
        && authority.response_maximum_bytes > 0
        && authority.https_required
        && !authority.redirects_allowed
        && !authority.ambient_proxy_allowed
        && authority.pkce_verifier_sent
        && authority.id_token_required
        && !authority.provider_tokens_persisted
        && !authority.provider_tokens_exposed
}

fn validate_authenticator_derived_session_authority_projection(
    authority: &AuthenticatorDerivedSessionAuthorityProjection,
) -> bool {
    valid_canonical_scoped_id(
        &authority.session_authority_id,
        "authenticator-session-authority:",
    ) && authority.session_authority_version > 0
        && authority.relation_name == AUTHENTICATOR_DERIVED_SESSION_RELATION
        && authority.credential_format == AUTHENTICATOR_DERIVED_SESSION_CREDENTIAL_FORMAT
        && authority.credential_verifier_algorithm
            == AUTHENTICATOR_DERIVED_SESSION_VERIFIER_ALGORITHM
        && valid_sha256_digest(&authority.credential_key_identity_digest)
        && authority.verifier_column_name == AUTHENTICATOR_DERIVED_SESSION_VERIFIER_COLUMN_V3
        && authority.session_maximum_age_limit_id
            == AUTHENTICATOR_BROWSER_SESSION_MAXIMUM_AGE_LIMIT_ID
        && authority.maximum_session_age_seconds > 0
        && authority.federated_authority_staleness_limit_id
            == AUTHENTICATOR_FEDERATED_AUTHORITY_STALENESS_LIMIT_ID
        && authority.maximum_federated_authority_staleness_seconds > 0
        && authority.maximum_federated_authority_staleness_seconds
            <= authority.maximum_session_age_seconds
        && authority.exact_origin_copy_required
        && valid_sha256_digest(&authority.cookie_policy_binding_digest)
        && authority.credential_key_identity_digest != authority.cookie_policy_binding_digest
}

fn validate_authenticator_protocol_binding_projection(
    protocol: &AuthenticatorProtocolBindingProjection,
) -> Result<(), RuntimeGuardDigestError> {
    validate_authenticator_runtime_path_identity_projection(&protocol.path_identity)?;
    let replay = &protocol.replay;
    let replay_store_valid = replay
        .replay_store_binding_digest
        .as_deref()
        .is_none_or(valid_sha256_digest);
    let mut authority_digests = vec![
        protocol
            .path_identity
            .provider_policy_binding_digest
            .as_str(),
        protocol.path_identity.issuer_binding_digest.as_str(),
        protocol.path_identity.audience_set_binding_digest.as_str(),
        protocol.path_identity.key_source_binding_digest.as_str(),
    ];
    if let Some(replay_store) = replay.replay_store_binding_digest.as_deref() {
        authority_digests.push(replay_store);
    }
    if let Some(exchange) = protocol.browser_exchange_authority.as_ref() {
        authority_digests.extend([
            exchange.authorization_endpoint_binding_digest.as_str(),
            exchange.token_endpoint_binding_digest.as_str(),
            exchange.redirect_uri_binding_digest.as_str(),
            exchange.client_id_binding_digest.as_str(),
            exchange.scopes_binding_digest.as_str(),
        ]);
    }
    if let Some(session) = protocol.derived_session_authority.as_ref() {
        authority_digests.extend([
            session.credential_key_identity_digest.as_str(),
            session.cookie_policy_binding_digest.as_str(),
        ]);
    }
    let authority_digests_are_domain_separated = authority_digests
        .iter()
        .copied()
        .collect::<HashSet<_>>()
        .len()
        == authority_digests.len();
    let browser_state_authority_binding_matches = match (
        replay.replay_store_binding_digest.as_deref(),
        protocol.browser_state_authority.as_ref(),
    ) {
        (Some(claimed), Some(authority)) => {
            authenticator_browser_state_authority_binding_digest(authority)
                .is_ok_and(|measured| measured == claimed)
        }
        (None, None) => true,
        _ => false,
    };
    let direct_bearer_path_is_valid = protocol.path_identity.path_role
        == AuthenticatorRuntimePathRole::DirectBearer
        && protocol.carrier == AuthenticatorCredentialCarrier::AuthorizationBearer
        && protocol.proof_binding == AuthenticatorProofBinding::Bearer
        && replay.credential_reuse == AuthenticatorCredentialReuse::ReusableUntilExpiry
        && replay
            .credential_lifetime_limit_id
            .as_deref()
            .is_some_and(|limit_id| valid_canonical_scoped_id(limit_id, "limit:"))
        && replay
            .maximum_credential_lifetime_seconds
            .is_some_and(|seconds| seconds > 0)
        && replay.sender_constraint == AuthenticatorSenderConstraint::None
        && replay.presentation_replay_defense == AuthenticatorPresentationReplayDefense::None
        && replay.nonce_binding == AuthenticatorNonceBinding::None
        && replay.replay_store_binding_digest.is_none()
        && protocol.browser_exchange_authority.is_none()
        && protocol.browser_state_authority.is_none()
        && protocol.derived_session_authority.is_none();
    let browser_derived_session = protocol.path_identity.path_role
        == AuthenticatorRuntimePathRole::BrowserDerivedSession
        && protocol.carrier == AuthenticatorCredentialCarrier::OauthCallback
        && protocol.proof_binding == AuthenticatorProofBinding::PkceS256
        && replay.credential_reuse == AuthenticatorCredentialReuse::SingleUse
        && replay.credential_lifetime_limit_id.is_none()
        && replay.maximum_credential_lifetime_seconds.is_none()
        && replay.sender_constraint == AuthenticatorSenderConstraint::None
        && replay.presentation_replay_defense
            == AuthenticatorPresentationReplayDefense::SingleUseState
        && replay.nonce_binding == AuthenticatorNonceBinding::OidcLogin
        && replay.replay_store_binding_digest.is_some()
        && protocol
            .browser_exchange_authority
            .as_ref()
            .is_some_and(validate_authenticator_browser_exchange_authority_projection)
        && browser_state_authority_binding_matches
        && protocol
            .derived_session_authority
            .as_ref()
            .is_some_and(validate_authenticator_derived_session_authority_projection);

    if !replay_store_valid
        || !authority_digests_are_domain_separated
        || !(direct_bearer_path_is_valid || browser_derived_session)
    {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "authenticator protocol binding",
        ));
    }
    Ok(())
}

fn validate_authenticator_runtime_binding_projection(
    binding: &AuthenticatorRuntimeBindingProjection,
) -> Result<(), RuntimeGuardDigestError> {
    if !valid_provider_projection(&binding.provider)
        || !matches!(
            binding.authenticator_kind,
            ProductionAuthenticatorKind::Oidc | ProductionAuthenticatorKind::OidcBroker
        )
        || !valid_canonical_scoped_id(
            &binding.binding_document_reference.document_id,
            "authenticator-runtime-binding:",
        )
        || binding.binding_document_reference.document_version == 0
        || !valid_sha256_digest(&binding.binding_document_reference.content_digest)
        || binding.binding_document_reference.content_digest
            == binding.provider.configuration_payload_digest
        || !valid_authenticator_binding_locator(
            &binding.binding_document_reference.artifact_locator,
        )
        || !valid_sha256_digest(&binding.provider_policy_binding_digest)
        || binding.binding_document_reference.content_digest
            == binding.provider_policy_binding_digest
        || binding.provider.configuration_payload_digest == binding.provider_policy_binding_digest
        || binding.capability_ids.is_empty()
        || binding.capability_ids.len() > 128
        || !valid_sorted_authenticator_identifiers(&binding.capability_ids)
        || !binding
            .capability_ids
            .iter()
            .all(|capability| matches!(capability.as_str(), "browser-sso" | "token-validation"))
        || binding.credential_paths.is_empty()
        || binding.credential_paths.len() > 32
        || !binding
            .credential_paths
            .windows(2)
            .all(|pair| pair[0].path_id < pair[1].path_id)
        || !binding.ownership.single_runtime_owner
        || binding.ownership.ambient_reconfiguration_allowed
    {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "authenticator runtime binding",
        ));
    }

    let mut verifier_ids = HashSet::new();
    let mut profile_ids = HashSet::new();
    let mut resolution_tuples = HashSet::new();
    let mut consumer_ids = HashSet::new();
    let mut cache_partition_digests = HashSet::new();
    let mut protocol_binding_digests = HashSet::new();
    let mut direct_bearer_path_count = 0_u8;
    let mut browser_derived_session_path_count = 0_u8;
    for path in &binding.credential_paths {
        let verifier = &path.verifier;
        let profile = &path.credential_profile;
        let replay_store_present = profile.replay.replay_store_binding_digest.is_some();
        let reusable_lifetime_valid = profile
            .replay
            .maximum_credential_lifetime_seconds
            .is_some_and(|seconds| seconds > 0)
            && profile
                .replay
                .credential_lifetime_limit_id
                .as_deref()
                .is_some_and(|limit_id| valid_canonical_scoped_id(limit_id, "limit:"));
        let replay_store_valid = profile
            .replay
            .replay_store_binding_digest
            .as_deref()
            .is_none_or(valid_sha256_digest);
        let bearer_profile = profile.token_profile == "jwt-access-token"
            && profile.carrier == AuthenticatorCredentialCarrier::AuthorizationBearer
            && profile.proof_binding == AuthenticatorProofBinding::Bearer
            && profile.replay.credential_reuse == AuthenticatorCredentialReuse::ReusableUntilExpiry
            && reusable_lifetime_valid
            && profile.replay.sender_constraint == AuthenticatorSenderConstraint::None
            && profile.replay.presentation_replay_defense
                == AuthenticatorPresentationReplayDefense::None
            && profile.replay.nonce_binding == AuthenticatorNonceBinding::None
            && !replay_store_present;
        let browser_profile = profile.token_profile == "oidc-id-token"
            && profile.carrier == AuthenticatorCredentialCarrier::OauthCallback
            && profile.proof_binding == AuthenticatorProofBinding::PkceS256
            && profile.replay.credential_reuse == AuthenticatorCredentialReuse::SingleUse
            && profile.replay.credential_lifetime_limit_id.is_none()
            && profile.replay.maximum_credential_lifetime_seconds.is_none()
            && profile.replay.sender_constraint == AuthenticatorSenderConstraint::None
            && profile.replay.presentation_replay_defense
                == AuthenticatorPresentationReplayDefense::SingleUseState
            && profile.replay.nonce_binding == AuthenticatorNonceBinding::OidcLogin
            && replay_store_present;
        let credential_profile_shape_valid = bearer_profile || browser_profile;
        direct_bearer_path_count += u8::from(bearer_profile);
        browser_derived_session_path_count += u8::from(browser_profile);
        let required_claim_shape_valid = authenticator_claim_flags_match(verifier)
            && verifier
                .required_claim_ids
                .binary_search(&verifier.provider_subject_claim_id)
                .is_ok()
            && match profile.token_profile.as_str() {
                "jwt-access-token" => {
                    verifier.key_source_kind == AuthenticatorKeySourceKind::JwtJwks
                        && verifier.expiration_required
                        && verifier.not_before_required
                        && verifier.issued_at_required
                        && !verifier.nonce_required
                        && authenticator_claims_include(
                            &verifier.required_claim_ids,
                            &["aud", "exp", "iat", "iss", "nbf", "sub"],
                        )
                }
                "oidc-id-token" => {
                    verifier.key_source_kind == AuthenticatorKeySourceKind::JwtJwks
                        && verifier.expiration_required
                        && verifier.not_before_required
                        && verifier.nonce_required
                        && authenticator_claims_include(
                            &verifier.required_claim_ids,
                            &["aud", "exp", "iss", "nbf", "nonce", "sub"],
                        )
                }
                _ => false,
            };

        if !valid_canonical_scoped_id(&path.path_id, "authenticator-path:")
            || path.path_version == 0
            || !valid_canonical_scoped_id(&verifier.verifier_id, "authenticator-verifier:")
            || !verifier_ids.insert(verifier.verifier_id.as_str())
            || verifier.verifier_version == 0
            || !valid_sha256_digest(&verifier.issuer_binding_digest)
            || !valid_sha256_digest(&verifier.audience_set_binding_digest)
            || verifier.accepted_algorithm_ids.len() > 16
            || !valid_sorted_authenticator_identifiers(&verifier.accepted_algorithm_ids)
            || verifier.accepted_algorithm_ids.as_slice() != ["rs256"]
            || verifier.required_claim_ids.len() > 64
            || !valid_sorted_authenticator_identifiers(&verifier.required_claim_ids)
            || !matches!(verifier.provider_subject_claim_id.as_str(), "oid" | "sub")
            || match binding.provider.adapter_kind.as_str() {
                "auth.entra-id" => verifier.provider_subject_claim_id != "oid",
                _ => verifier.provider_subject_claim_id != "sub",
            }
            || !valid_sha256_digest(&verifier.key_source_binding_digest)
            || !required_claim_shape_valid
            || !valid_canonical_scoped_id(&verifier.clock_skew_limit_id, "limit:")
            || verifier.redirects_allowed
            || !valid_canonical_scoped_id(&profile.profile_id, "credential-profile:")
            || !profile_ids.insert(profile.profile_id.as_str())
            || profile.profile_version == 0
            || !replay_store_valid
            || !credential_profile_shape_valid
            || !valid_sha256_digest(&path.cache_partition_binding_digest)
            || !cache_partition_digests.insert(path.cache_partition_binding_digest.as_str())
            || !valid_sha256_digest(&path.protocol_binding_digest)
            || path.cache_partition_binding_digest == path.protocol_binding_digest
            || !protocol_binding_digests.insert(path.protocol_binding_digest.as_str())
            || path.retained_consumer_ids.len() > 128
            || !strictly_sorted_unique_strings(&path.retained_consumer_ids)
            || !path
                .retained_consumer_ids
                .iter()
                .all(|consumer| valid_canonical_scoped_id(consumer, "runtime-consumer:"))
            || path
                .retained_consumer_ids
                .iter()
                .any(|consumer| !consumer_ids.insert(consumer.as_str()))
            || !resolution_tuples.insert((
                verifier.issuer_binding_digest.as_str(),
                profile.token_profile.as_str(),
            ))
        {
            return Err(RuntimeGuardDigestError::InvalidProjection(
                "authenticator runtime binding path",
            ));
        }
    }
    let declares_token_validation = binding
        .capability_ids
        .binary_search_by(|capability| capability.as_str().cmp("token-validation"))
        .is_ok();
    let declares_browser_sso = binding
        .capability_ids
        .binary_search_by(|capability| capability.as_str().cmp("browser-sso"))
        .is_ok();
    if direct_bearer_path_count > 1
        || browser_derived_session_path_count > 1
        || declares_token_validation != (direct_bearer_path_count == 1)
        || declares_browser_sso != (browser_derived_session_path_count == 1)
    {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "authenticator capability/path completeness",
        ));
    }
    Ok(())
}

fn validate_authenticator_origin_projection(
    origin: &AuthenticatorOriginProjection,
) -> Result<(), RuntimeGuardDigestError> {
    let document = &origin.binding_document_reference;
    let digests = [
        origin.provider_configuration_payload_digest.as_str(),
        document.content_digest.as_str(),
        origin.provider_policy_binding_digest.as_str(),
        origin.runtime_binding_digest.as_str(),
    ];
    let distinct_digests = digests.iter().copied().collect::<HashSet<_>>().len() == digests.len();
    let tenant_id_is_valid = origin
        .tenant_id
        .as_deref()
        .is_none_or(|tenant_id| valid_canonical_scoped_id(tenant_id, "tenant:"));

    if !valid_canonical_scoped_id(&origin.deployment_id, "deployment:")
        || !valid_canonical_scoped_id(&origin.trust_domain_id, "trust-domain:")
        || !tenant_id_is_valid
        || !valid_canonical_scoped_id(&origin.provider_id, "provider:")
        || origin.provider_configuration_version == 0
        || !valid_sha256_digest(&origin.provider_configuration_payload_digest)
        || origin.provider_lifecycle_record_version == 0
        || origin.provider_lifecycle_state != ProviderLifecycleState::Active
        || !valid_canonical_scoped_id(&document.document_id, "authenticator-runtime-binding:")
        || document.document_version == 0
        || !valid_sha256_digest(&document.content_digest)
        || !valid_authenticator_binding_locator(&document.artifact_locator)
        || !valid_sha256_digest(&origin.provider_policy_binding_digest)
        || !valid_sha256_digest(&origin.runtime_binding_digest)
        || !distinct_digests
        || !valid_canonical_scoped_id(&origin.path_id, "authenticator-path:")
        || origin.path_version == 0
    {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "authenticator origin binding",
        ));
    }
    Ok(())
}

fn valid_authenticator_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    (2..=96).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn valid_sorted_authenticator_identifiers(values: &[String]) -> bool {
    strictly_sorted_unique_strings(values)
        && values
            .iter()
            .all(|value| valid_authenticator_identifier(value))
}

fn authenticator_claims_include(claims: &[String], required: &[&str]) -> bool {
    required.iter().all(|required| {
        claims
            .binary_search_by(|claim| claim.as_str().cmp(required))
            .is_ok()
    })
}

fn authenticator_claim_flags_match(verifier: &AuthenticatorVerifierRuntimeProjection) -> bool {
    let contains = |claim: &str| {
        verifier
            .required_claim_ids
            .binary_search_by(|candidate| candidate.as_str().cmp(claim))
            .is_ok()
    };
    verifier.expiration_required == contains("exp")
        && verifier.not_before_required == contains("nbf")
        && verifier.issued_at_required == contains("iat")
        && verifier.nonce_required == contains("nonce")
}

fn valid_authenticator_binding_locator(value: &str) -> bool {
    let path = Path::new(value);
    !value.starts_with("json-pointer:")
        && !value.contains('\\')
        && !path.is_absolute()
        && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn validate_external_signing_key_identity_projection(
    identity: &ExternalSigningKeyIdentity,
) -> Result<(), RuntimeGuardDigestError> {
    if !valid_provider_projection(&identity.provider)
        || !valid_sha256_digest(&identity.provider_runtime_binding_digest)
        || !valid_canonical_scoped_id(&identity.deployment_id, "deployment:")
        || !valid_canonical_scoped_id(&identity.trust_domain_id, "trust-domain:")
        || !valid_canonical_runtime_identifier(&identity.protocol_version)
        || !valid_canonical_scoped_id(&identity.purpose_id, "signing-purpose:")
        || !valid_canonical_scoped_id(&identity.key_id, "signing-key:")
        || identity.key_version == 0
        || !valid_sha256_digest(&identity.public_or_opaque_metadata_digest)
    {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "external signing key identity",
        ));
    }
    Ok(())
}

fn validate_external_signing_inventory_projection(
    purposes: &[ExternalSigningPurposeBinding],
) -> Result<(), RuntimeGuardDigestError> {
    if purposes.is_empty()
        || !purposes
            .windows(2)
            .all(|pair| pair[0].purpose_id < pair[1].purpose_id)
    {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "external signing purpose inventory",
        ));
    }
    for purpose in purposes {
        if !valid_canonical_scoped_id(&purpose.purpose_id, "signing-purpose:")
            || purpose.active_key_version == 0
            || purpose.keys.is_empty()
            || !purpose
                .keys
                .windows(2)
                .all(|pair| pair[0].identity.key_version < pair[1].identity.key_version)
            || purpose
                .keys
                .iter()
                .map(|key| &key.identity.key_id)
                .collect::<HashSet<_>>()
                .len()
                != purpose.keys.len()
        {
            return Err(RuntimeGuardDigestError::InvalidProjection(
                "external signing purpose key versions",
            ));
        }
        let mut active_digest = None;
        for key in &purpose.keys {
            validate_external_signing_key_identity_projection(&key.identity)?;
            let recomputed = external_signing_key_identity_digest(&key.identity)?;
            if key.key_identity_digest != recomputed
                || key.identity.purpose_id != purpose.purpose_id
                || key.identity.algorithm != purpose.algorithm
                || key.identity.custody_kind != purpose.custody_kind
            {
                return Err(RuntimeGuardDigestError::InvalidProjection(
                    "external signing key cross-binding",
                ));
            }
            if key.identity.disposition == ExternalSigningKeyDisposition::Active {
                if active_digest.is_some() || key.identity.key_version != purpose.active_key_version
                {
                    return Err(RuntimeGuardDigestError::InvalidProjection(
                        "external signing active-key selection",
                    ));
                }
                active_digest = Some(recomputed);
            }
        }
        if active_digest.is_none() {
            return Err(RuntimeGuardDigestError::InvalidProjection(
                "external signing active-key selection",
            ));
        }
    }
    Ok(())
}

fn validate_production_dependency_inventory_projection(
    dependencies: &[ExpectedProductionDependencyBinding],
) -> Result<(), RuntimeGuardDigestError> {
    if dependencies.is_empty()
        || !dependencies
            .windows(2)
            .all(|pair| pair[0].component_id < pair[1].component_id)
        || dependencies.iter().any(|dependency| {
            !valid_canonical_scoped_id(&dependency.component_id, "runtime-component:")
                || !valid_canonical_scoped_id(
                    &dependency.implementation_id,
                    "runtime-implementation:",
                )
                || !valid_canonical_runtime_identifier(&dependency.implementation_version)
                || dependency.fallback_allowed
                || !valid_sha256_digest(&dependency.component_binding_digest)
        })
    {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "production dependency inventory",
        ));
    }
    Ok(())
}

fn validate_production_dependency_runtime_binding(
    dependency: &ProductionDependencyRuntimeBinding,
) -> Result<(), RuntimeGuardDigestError> {
    let unique_authority_binding_digests = dependency
        .authority_bindings
        .iter()
        .map(|binding| binding.binding_digest.as_str())
        .collect::<HashSet<_>>();
    if !valid_canonical_scoped_id(&dependency.component_id, "runtime-component:")
        || !valid_canonical_scoped_id(&dependency.implementation_id, "runtime-implementation:")
        || !valid_canonical_runtime_identifier(&dependency.implementation_version)
        || dependency.fallback_allowed
        || dependency.authority_bindings.is_empty()
        || dependency.authority_bindings.len() > 64
        || !dependency
            .authority_bindings
            .windows(2)
            .all(|pair| pair[0].binding_id < pair[1].binding_id)
        || unique_authority_binding_digests.len() != dependency.authority_bindings.len()
        || dependency.authority_bindings.iter().any(|binding| {
            !valid_canonical_scoped_id(&binding.binding_id, "runtime-binding:")
                || !valid_canonical_runtime_identifier(&binding.binding_contract)
                || binding.binding_contract
                    == PRODUCTION_DEPENDENCY_COMPONENT_BINDING_DIGEST_CONTRACT
                || binding.binding_contract == PRODUCTION_DEPENDENCY_INVENTORY_DIGEST_CONTRACT
                || binding.binding_contract == RUNTIME_GUARD_REQUIREMENT_BINDING_DIGEST_CONTRACT
                || binding.binding_contract
                    == RUNTIME_GUARD_SEMANTIC_CHALLENGE_BINDING_DIGEST_CONTRACT
                || !valid_sha256_digest(&binding.binding_digest)
        })
        || dependency.retained_consumer_ids.is_empty()
        || dependency.retained_consumer_ids.len() > 128
        || !strictly_sorted_unique_strings(&dependency.retained_consumer_ids)
        || !dependency
            .retained_consumer_ids
            .iter()
            .all(|consumer| valid_canonical_scoped_id(consumer, "runtime-consumer:"))
        || !valid_canonical_scoped_id(&dependency.ownership.runtime_owner_id, "runtime-owner:")
        || !dependency.ownership.single_runtime_owner
        || dependency.ownership.ambient_reconfiguration_allowed
    {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "production dependency runtime binding",
        ));
    }
    Ok(())
}

fn validate_first_owner_authority_namespace_projection(
    namespace: &FirstOwnerAuthorityNamespace,
) -> Result<(), RuntimeGuardDigestError> {
    if namespace.state_contract_version == 0
        || namespace.state_contract_version > FIRST_OWNER_MAX_EXACT_JSON_INTEGER
        || !valid_canonical_scoped_id(&namespace.deployment_id, "deployment:")
        || !strictly_sorted_unique_strings(&namespace.trust_domain_ids)
        || !namespace
            .trust_domain_ids
            .iter()
            .all(|trust_domain| valid_canonical_scoped_id(trust_domain, "trust-domain:"))
        // First-owner closure is deployment-owned. The tenancy mode remains
        // digest-bound, but no tenant may become the namespace authority in
        // either deployment mode.
        || namespace.tenant_id.is_some()
        || !valid_canonical_scoped_id(&namespace.authority_id, "first-owner-authority:")
        || !valid_canonical_scoped_id(
            &namespace.authority_key_id,
            "first-owner-authority-key:",
        )
        || !valid_sha256_digest(&namespace.authority_public_key_fingerprint)
        || namespace.authority_epoch == 0
        || namespace.authority_epoch > FIRST_OWNER_MAX_EXACT_JSON_INTEGER
        || !valid_canonical_scoped_id(&namespace.namespace_id, "first-owner-namespace:")
    {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "first-owner authority namespace",
        ));
    }
    Ok(())
}

fn validate_first_owner_closure_record_projection(
    record: &FirstOwnerClosureRecord,
) -> Result<(), RuntimeGuardDigestError> {
    // The durable PostgreSQL closure record stores an exact textual preimage
    // alongside TIMESTAMPTZ. Seconds-only UTC avoids precision loss and keeps
    // Rust and SQL acceptance domains identical.
    let capability_expires_at = parse_first_owner_timestamp(&record.capability_expires_at);
    let closed_at_not_before = parse_first_owner_timestamp(&record.closed_at_not_before);
    let closed_at_not_after = parse_first_owner_timestamp(&record.closed_at_not_after);
    let valid_window = capability_expires_at
        .zip(closed_at_not_before)
        .zip(closed_at_not_after)
        .is_some_and(|((expires, not_before), not_after)| {
            not_before <= not_after && not_after < expires
        });
    if record.state_contract_version == 0
        || record.state_contract_version > FIRST_OWNER_MAX_EXACT_JSON_INTEGER
        || !valid_canonical_scoped_id(&record.deployment_id, "deployment:")
        || !valid_sha256_digest(&record.authority_namespace_digest)
        || !valid_canonical_scoped_id(&record.closure_event_id, "first-owner-closure-event:")
        || record.authority_sequence == 0
        || record.authority_sequence > FIRST_OWNER_MAX_EXACT_JSON_INTEGER
        || !valid_canonical_scoped_id(&record.first_owner_principal_id, "principal:")
        || !valid_sha256_digest(&record.claim_request_digest)
        || !valid_canonical_scoped_id(&record.capability_id, "first-owner-capability:")
        || !valid_window
        || !valid_sha256_digest(&record.closure_certificate_digest)
    {
        return Err(RuntimeGuardDigestError::InvalidProjection(
            "first-owner closure record",
        ));
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum ProductionDatabaseProvider {
    #[serde(rename = "cloudnativepg")]
    CloudNativePg,
    #[serde(rename = "aws-rds")]
    AwsRds,
    #[serde(rename = "azure-postgresql")]
    AzurePostgresql,
    #[serde(rename = "gcp-cloud-sql")]
    GcpCloudSql,
}

impl RuntimeGuardExpectedValue {
    pub fn guard_id(&self) -> GuardId {
        match self {
            Self::DurablePostgresql { .. } => GuardId::DurablePostgresql,
            Self::ApprovedSecretProvider { .. } => GuardId::ApprovedSecretProvider,
            Self::HttpsPublicUrls { .. } => GuardId::HttpsPublicUrls,
            Self::SecureCookies { .. } => GuardId::SecureCookies,
            Self::NonDevelopmentAuthenticator { .. } => GuardId::NonDevelopmentAuthenticator,
            Self::ExternalSigningKeyMaterial { .. } => GuardId::ExternalSigningKeyMaterial,
            Self::MockDependenciesDisabled { .. } => GuardId::MockDependenciesDisabled,
            Self::FirstOwnerPathClosed { .. } => GuardId::FirstOwnerPathClosed,
        }
    }
}

impl DeploymentSecurityProfile {
    /// Validate structural cross-field invariants at an injected time.
    /// Artifact bytes, schema validity, and signature/provenance are checked by
    /// the loader; this method never authorizes startup or turns receipt-shaped
    /// metadata into trust.
    pub fn validate_structure_at(&self, now: DateTime<Utc>) -> Vec<String> {
        let mut errors = Vec::new();

        if self.schema_uri != DEPLOYMENT_SECURITY_PROFILE_SCHEMA_URI {
            errors.push("$schema must equal the canonical deployment profile schema URI".into());
        }
        if self.schema_version != DEPLOYMENT_SECURITY_PROFILE_SCHEMA_VERSION {
            errors.push("schema_version is unsupported".into());
        }
        if self.contract_kind != DEPLOYMENT_SECURITY_PROFILE_CONTRACT_KIND {
            errors.push("contract_kind must equal deployment-security-profile".into());
        }
        validate_id(
            &self.document_id,
            "deployment-security-profile:",
            "document_id",
            &mut errors,
        );
        validate_id(
            &self.deployment_id,
            "deployment:",
            "deployment_id",
            &mut errors,
        );
        for (label, value) in [
            ("document_version", self.document_version),
            (
                "deployment_profile_version",
                self.deployment_profile_version,
            ),
            (
                "platform_configuration_version",
                self.platform_configuration_version,
            ),
            ("policy_version", self.policy_version),
        ] {
            if value == 0 {
                errors.push(format!("{label} must be greater than zero"));
            }
        }

        match parse_timestamp(
            "lifecycle.effective_at",
            &self.lifecycle.effective_at,
            &mut errors,
        ) {
            Some(effective_at)
                if self.lifecycle.state == DocumentLifecycleState::Active && effective_at > now =>
            {
                errors.push("an active deployment profile cannot be future-dated".into());
            }
            _ => {}
        }
        if self.lifecycle.state == DocumentLifecycleState::Retired {
            errors.push("a retired deployment profile cannot be selected for startup".into());
        }

        if self.applicability.security_profiles.len() != 1
            || self.applicability.security_profiles[0] != self.security_profile
        {
            errors
                .push("applicability.security_profiles must exactly match security_profile".into());
        }
        if self.applicability.deployment_ids.len() != 1
            || self.applicability.deployment_ids[0] != self.deployment_id
        {
            errors.push("applicability.deployment_ids must exactly match deployment_id".into());
        }
        if !same_unique_strings(
            &self.applicability.enabled_feature_ids,
            &self.enabled_features,
        ) {
            errors.push(
                "applicability.enabled_feature_ids must exactly match enabled_features".into(),
            );
        }
        require_unique_strings("enabled_features", &self.enabled_features, &mut errors);

        self.validate_trust_topology(&mut errors);
        self.validate_references(&mut errors);
        self.validate_production_acceptance_reference(&mut errors);
        self.validate_runtime_guards(&mut errors);

        if let Some(overlay) = &self.migration_overlay {
            self.validate_overlay(overlay, now, &mut errors);
        }

        if self.security_profile.is_production() {
            if self.tenancy_mode != TenancyMode::SingleTenant {
                errors.push(
                    "production multi_tenant is blocked until complete tenant isolation is proven"
                        .into(),
                );
            }
            if self.lifecycle.state != DocumentLifecycleState::Active {
                errors.push("production requires an active deployment profile document".into());
            }
        }

        errors.sort();
        errors.dedup();
        errors
    }

    /// Validate whether this document may be selected for process startup.
    ///
    /// Production admission intentionally remains unavailable until the API
    /// loader verifies receipt signatures, provenance, expiry, artifact bytes,
    /// and live runtime facts. Receipt-shaped JSON alone is never sufficient.
    pub fn validate_for_startup(
        &self,
        expected: &StartupAdmissionContext,
        actual_profile_digest: &str,
        now: DateTime<Utc>,
    ) -> Vec<String> {
        let mut errors = self.validate_structure_at(now);

        validate_digest(
            "startup expected profile_digest",
            &expected.profile_digest,
            &mut errors,
        );
        validate_digest(
            "startup actual profile_digest",
            actual_profile_digest,
            &mut errors,
        );
        if actual_profile_digest != expected.profile_digest {
            errors
                .push("deployment profile digest does not match the pinned profile_digest".into());
        }
        if self.deployment_id != expected.deployment_id {
            errors.push("deployment profile does not match the pinned deployment_id".into());
        }
        if self.security_profile != expected.security_profile {
            errors.push("deployment profile does not match the pinned security_profile".into());
        }
        if self.lifecycle.state != DocumentLifecycleState::Active {
            errors.push("startup requires an active deployment profile document".into());
        }
        errors.sort();
        errors.dedup();
        errors
    }

    fn validate_trust_topology(&self, errors: &mut Vec<String>) {
        if self.trust_topology.trust_domain_ids.is_empty() {
            errors.push("trust_topology.trust_domain_ids must not be empty".into());
        }
        require_unique_strings(
            "trust_topology.trust_domain_ids",
            &self.trust_topology.trust_domain_ids,
            errors,
        );
        for id in &self.trust_topology.trust_domain_ids {
            validate_id(id, "trust-domain:", "trust_domain_id", errors);
        }
        match self.trust_topology.topology_kind {
            TrustTopologyKind::SingleTrustDomain => {
                if self.trust_topology.trust_domain_ids.len() != 1 {
                    errors.push("single_trust_domain requires exactly one trust domain".into());
                }
                if self.trust_topology.federation_policy_ref.is_some() {
                    errors.push("single_trust_domain forbids federation_policy_ref".into());
                }
            }
            TrustTopologyKind::FederatedTrustDomains => {
                if self.trust_topology.trust_domain_ids.len() < 2 {
                    errors
                        .push("federated_trust_domains requires at least two trust domains".into());
                }
                if self.trust_topology.federation_policy_ref.is_none() {
                    errors.push("federated_trust_domains requires federation_policy_ref".into());
                }
            }
        }
    }

    fn validate_references(&self, errors: &mut Vec<String>) {
        if let Some(reference) = &self.lifecycle.supersedes {
            validate_reference(
                "lifecycle.supersedes",
                reference,
                ArtifactKind::DeploymentSecurityProfile,
                "deployment-security-profile:",
                errors,
            );
            if reference.document_id != self.document_id {
                errors.push("lifecycle.supersedes must preserve document_id".into());
            }
            if reference.document_version >= self.document_version {
                errors.push("lifecycle.supersedes must reference a lower document_version".into());
            }
        }

        for (label, reference, expected_kind, expected_prefix) in [
            (
                "conformance_trust_root_registry_ref",
                &self.conformance_trust_root_registry_ref,
                ArtifactKind::ConformanceTrustRootRegistry,
                "conformance-trust-root-registry:",
            ),
            (
                "control_trace_ref",
                &self.control_trace_ref,
                ArtifactKind::ControlTrace,
                "control-trace:",
            ),
            (
                "provider_registry_ref",
                &self.provider_registry_ref,
                ArtifactKind::ProviderRegistry,
                "provider-registry:",
            ),
            (
                "action_resource_registry_ref",
                &self.action_resource_registry_ref,
                ArtifactKind::ActionResourceRegistry,
                "action-resource-registry:",
            ),
            (
                "security_limit_profile_ref",
                &self.security_limit_profile_ref,
                ArtifactKind::SecurityLimitProfile,
                "security-limit-profile:",
            ),
            (
                "control_plane_topology_ref",
                &self.control_plane_topology_ref,
                ArtifactKind::ControlPlaneTopology,
                "control-plane-topology:",
            ),
            (
                "egress_policy_ref",
                &self.egress_policy_ref,
                ArtifactKind::EgressPolicy,
                "egress-policy:",
            ),
            (
                "retention_policy_ref",
                &self.retention_policy_ref,
                ArtifactKind::RetentionPolicy,
                "retention-policy:",
            ),
        ] {
            validate_reference(label, reference, expected_kind, expected_prefix, errors);
        }
        if let Some(reference) = &self.trust_topology.federation_policy_ref {
            validate_reference(
                "trust_topology.federation_policy_ref",
                reference,
                ArtifactKind::FederationPolicy,
                "federation-policy:",
                errors,
            );
        }

        let lifecycle = &self.provider_lifecycle_snapshot_ref;
        validate_id(
            &lifecycle.document_id,
            "provider-registry:",
            "provider_lifecycle_snapshot_ref.document_id",
            errors,
        );
        validate_digest(
            "provider_lifecycle_snapshot_ref.content_digest",
            &lifecycle.content_digest,
            errors,
        );
        validate_locator(
            "provider_lifecycle_snapshot_ref.artifact_locator",
            &lifecycle.artifact_locator,
            errors,
        );
        if lifecycle.document_version == 0 {
            errors.push(
                "provider_lifecycle_snapshot_ref.document_version must be greater than zero".into(),
            );
        }
        if lifecycle.required_states.as_slice() != [ProviderLifecycleState::Active] {
            errors.push(
                "provider_lifecycle_snapshot_ref.required_states must be exactly [active]".into(),
            );
        }

        if lifecycle.document_id != self.provider_registry_ref.document_id
            || lifecycle.document_version != self.provider_registry_ref.document_version
            || lifecycle.content_digest != self.provider_registry_ref.content_digest
            || lifecycle.artifact_locator != self.provider_registry_ref.artifact_locator
        {
            errors.push(
                "provider lifecycle snapshot must bind the exact provider registry artifact".into(),
            );
        }
    }

    fn validate_runtime_guards(&self, errors: &mut Vec<String>) {
        if !self.runtime_guard_evidence.runtime_cross_check_required {
            errors.push("runtime_guard_evidence.runtime_cross_check_required must be true".into());
        }
        if self.security_profile.is_production() {
            if self.runtime_guard_evidence.mode != RuntimeGuardMode::ReceiptBound {
                errors.push("production runtime guards must be receipt_bound".into());
            }
            let actual = self
                .runtime_guard_evidence
                .guards
                .iter()
                .map(|guard| guard.guard_id)
                .collect::<HashSet<_>>();
            let expected = REQUIRED_PRODUCTION_GUARDS
                .into_iter()
                .collect::<HashSet<_>>();
            if actual != expected
                || self.runtime_guard_evidence.guards.len() != REQUIRED_PRODUCTION_GUARDS.len()
            {
                errors
                    .push("production requires exactly one receipt for every runtime guard".into());
            }
            for guard in &self.runtime_guard_evidence.guards {
                if guard.control_ids.is_empty() {
                    errors.push(format!(
                        "runtime guard {:?} has no control_ids",
                        guard.guard_id
                    ));
                }
                require_unique_strings("runtime guard control_ids", &guard.control_ids, errors);
                validate_reference(
                    "runtime guard receipt_ref",
                    &guard.receipt_ref,
                    ArtifactKind::PackageExitReceipt,
                    "package-exit-receipt:",
                    errors,
                );
                if guard.expected_value.guard_id() != guard.guard_id {
                    errors.push(format!(
                        "runtime guard {:?} carries the wrong typed expected value",
                        guard.guard_id
                    ));
                }
                validate_runtime_guard_expected_value(&guard.expected_value, errors);
                if let RuntimeGuardExpectedValue::FirstOwnerPathClosed { deployment_id, .. } =
                    &guard.expected_value
                    && deployment_id != &self.deployment_id
                {
                    errors.push(
                        "first-owner-path-closed deployment_id must equal the root deployment profile"
                            .into(),
                    );
                }
            }
        } else {
            if self.runtime_guard_evidence.mode != RuntimeGuardMode::NotApplicable {
                errors.push("non-production runtime guard mode must be not_applicable".into());
            }
            if !self.runtime_guard_evidence.guards.is_empty() {
                errors.push(
                    "non-production profiles must not carry production guard receipts".into(),
                );
            }
        }
    }

    fn validate_production_acceptance_reference(&self, errors: &mut Vec<String>) {
        match (
            self.security_profile.is_production(),
            &self.production_acceptance_receipt_ref,
        ) {
            (true, Some(reference)) => validate_reference(
                "production_acceptance_receipt_ref",
                reference,
                ArtifactKind::PackageExitReceipt,
                "package-exit-receipt:",
                errors,
            ),
            (true, None) => errors.push(
                "production requires an authoritative production_acceptance_receipt_ref".into(),
            ),
            (false, Some(_)) => errors.push(
                "non-production profiles must not carry a production acceptance receipt".into(),
            ),
            (false, None) => {}
        }
    }

    fn validate_overlay(
        &self,
        overlay: &MigrationOverlay,
        now: DateTime<Utc>,
        errors: &mut Vec<String>,
    ) {
        validate_id(
            &overlay.overlay_id,
            "migration-overlay:",
            "migration_overlay.overlay_id",
            errors,
        );
        if overlay.overlay_version == 0 {
            errors.push("migration_overlay.overlay_version must be greater than zero".into());
        }
        if overlay.security_profile != self.security_profile {
            errors.push("migration overlay profile must exactly match the root profile".into());
        }
        if !overlay.legacy_selector_present || !overlay.provider_registry_present {
            errors.push("migration overlay requires both conflicting authority selectors".into());
        }
        if overlay.grants_authority || overlay.live_execution_allowed {
            errors.push("migration overlay cannot grant authority or enable live execution".into());
        }
        match DateTime::parse_from_rfc3339(&overlay.retirement_deadline) {
            Ok(deadline) if deadline.with_timezone(&Utc) > now => {}
            Ok(_) => errors.push("migration overlay retirement_deadline has expired".into()),
            Err(_) => errors.push("migration overlay retirement_deadline is not RFC3339".into()),
        }
        if self.enabled_features.iter().any(|feature| {
            matches!(
                feature.as_str(),
                "live-execution" | "provider-live-execution"
            )
        }) {
            errors.push("migration overlay forbids live-execution features".into());
        }
        validate_reference(
            "migration_overlay.zero_consumer_receipt_ref",
            &overlay.zero_consumer_receipt_ref,
            ArtifactKind::PackageExitReceipt,
            "package-exit-receipt:",
            errors,
        );
    }
}

fn validate_reference(
    label: &str,
    reference: &VersionedContentReference,
    expected_kind: ArtifactKind,
    expected_prefix: &str,
    errors: &mut Vec<String>,
) {
    if reference.artifact_kind != expected_kind {
        errors.push(format!(
            "{label}.artifact_kind does not match {expected_kind:?}"
        ));
    }
    validate_id(
        &reference.document_id,
        expected_prefix,
        &format!("{label}.document_id"),
        errors,
    );
    if reference.document_version == 0 {
        errors.push(format!(
            "{label}.document_version must be greater than zero"
        ));
    }
    validate_digest(
        &format!("{label}.content_digest"),
        &reference.content_digest,
        errors,
    );
    validate_locator(
        &format!("{label}.artifact_locator"),
        &reference.artifact_locator,
        errors,
    );
    if expected_kind == ArtifactKind::PackageExitReceipt
        && !is_normalized_package_receipt_locator(&reference.artifact_locator)
    {
        errors.push(format!(
            "{label}.artifact_locator must be a normalized repository-relative JSON file"
        ));
    }
}

fn is_normalized_package_receipt_locator(value: &str) -> bool {
    if value.starts_with("json-pointer:") || value.contains('\\') {
        return false;
    }
    let path = Path::new(value);
    let components = path.components().collect::<Vec<_>>();
    components.len() >= 2
        && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        && components.iter().all(|component| {
            let Component::Normal(component) = component else {
                return false;
            };
            let Some(component) = component.to_str() else {
                return false;
            };
            let mut characters = component.chars();
            characters
                .next()
                .is_some_and(|character| character.is_ascii_alphanumeric())
                && characters.all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
                })
        })
}

fn require_positive_version(label: &str, value: u64, errors: &mut Vec<String>) {
    if value == 0 {
        errors.push(format!("{label} must be greater than zero"));
    }
}

fn valid_postgresql_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || *byte == b'_')
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

fn validate_canonical_token_set(label: &str, values: &[String], errors: &mut Vec<String>) {
    if values.is_empty() {
        errors.push(format!("{label} must not be empty"));
        return;
    }
    if !values.windows(2).all(|pair| pair[0] < pair[1]) {
        errors.push(format!("{label} must be strictly sorted and unique"));
    }
    if values.iter().any(|value| {
        let bytes = value.as_bytes();
        !(3..=127).contains(&bytes.len())
            || !bytes
                .first()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            || !bytes.iter().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
    }) {
        errors.push(format!("{label} contains a non-canonical token"));
    }
}

fn validate_namespaced_id_set(
    label: &str,
    values: &[String],
    prefix: &str,
    errors: &mut Vec<String>,
) {
    if values.is_empty() {
        errors.push(format!("{label} must not be empty"));
        return;
    }
    if !values.windows(2).all(|pair| pair[0] < pair[1]) {
        errors.push(format!("{label} must be strictly sorted and unique"));
    }
    for value in values {
        validate_id(value, prefix, label, errors);
    }
}

fn validate_secret_provider_binding_set(
    label: &str,
    providers: &[ExpectedSecretProviderBinding],
    errors: &mut Vec<String>,
) {
    if providers.is_empty() {
        errors.push(format!("{label} must not be empty"));
        return;
    }
    if !providers
        .windows(2)
        .all(|pair| pair[0].provider.provider_id < pair[1].provider.provider_id)
    {
        errors.push(format!(
            "{label} must be strictly sorted and unique by provider_id"
        ));
    }
    for provider in providers {
        validate_provider_binding(label, &provider.provider, errors);
        validate_digest(
            &format!("{label} runtime_binding_digest"),
            &provider.runtime_binding_digest,
            errors,
        );
    }
}

fn validate_provider_binding(
    label: &str,
    provider: &ExpectedProviderBinding,
    errors: &mut Vec<String>,
) {
    validate_id(
        &provider.provider_id,
        "provider:",
        &format!("{label} provider_id"),
        errors,
    );
    require_positive_version(
        &format!("{label} configuration_version"),
        provider.configuration_version,
        errors,
    );
    validate_digest(
        &format!("{label} configuration_payload_digest"),
        &provider.configuration_payload_digest,
        errors,
    );
    require_positive_version(
        &format!("{label} lifecycle_record_version"),
        provider.lifecycle_record_version,
        errors,
    );
    if provider.lifecycle_state != ProviderLifecycleState::Active {
        errors.push(format!("{label} lifecycle_state must be active"));
    }
    validate_id(
        &provider.capability_descriptor_id,
        "capability-descriptor:",
        &format!("{label} capability_descriptor_id"),
        errors,
    );
    require_positive_version(
        &format!("{label} capability_descriptor_version"),
        provider.capability_descriptor_version,
        errors,
    );
    for (field, value) in [
        ("adapter_kind", provider.adapter_kind.as_str()),
        ("adapter_version", provider.adapter_version.as_str()),
    ] {
        if value.is_empty()
            || value.len() > 127
            || !value
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            errors.push(format!("{label} {field} is not canonical"));
        }
    }
}

fn validate_cookie_policy_set(policies: &[ExpectedCookiePolicy], errors: &mut Vec<String>) {
    if policies.is_empty() {
        errors.push("secure-cookies policies must not be empty".into());
        return;
    }
    if !policies
        .windows(2)
        .all(|pair| pair[0].policy_id < pair[1].policy_id)
    {
        errors
            .push("secure-cookies policies must be strictly sorted and unique by policy_id".into());
    }
    for policy in policies {
        validate_id(
            &policy.policy_id,
            "cookie-policy:",
            "secure-cookies policy_id",
            errors,
        );
        if !valid_host_cookie_name(&policy.cookie_name)
            || !policy.secure
            || !policy.http_only
            || policy.path != "/"
            || policy.domain.is_some()
        {
            errors.push(
                "secure-cookies policies must use a canonical __Host- name with Secure, HttpOnly, Path=/, and no Domain"
                    .into(),
            );
        }
        validate_digest(
            "secure-cookies policy_digest",
            &policy.policy_digest,
            errors,
        );
    }
}

fn valid_host_cookie_name(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("__Host-") else {
        return false;
    };
    (3..=120).contains(&suffix.len())
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn validate_signing_purpose_set(purposes: &[ExpectedSigningPurpose], errors: &mut Vec<String>) {
    if purposes.is_empty() {
        errors.push("external-signing-key-material purposes must not be empty".into());
        return;
    }
    if !purposes
        .windows(2)
        .all(|pair| pair[0].purpose_id < pair[1].purpose_id)
    {
        errors.push(
            "external-signing-key-material purposes must be strictly sorted and unique by purpose_id"
                .into(),
        );
    }
    for purpose in purposes {
        validate_id(
            &purpose.purpose_id,
            "signing-purpose:",
            "external-signing-key-material purpose_id",
            errors,
        );
        validate_digest(
            "external-signing-key-material key_identity_digest",
            &purpose.key_identity_digest,
            errors,
        );
    }
}

pub(crate) fn validate_runtime_guard_expected_value(
    value: &RuntimeGuardExpectedValue,
    errors: &mut Vec<String>,
) {
    match value {
        RuntimeGuardExpectedValue::DurablePostgresql {
            server_major_version,
            attestation_profile_id,
            attestation_profile_version,
            attestation_profile_digest,
            provider_route_binding_digest,
            database_identity_digest,
            storage_binding_digest,
            migration_inventory_digest,
            application_role,
            migration_role,
            ..
        } => {
            if *server_major_version != 18 {
                errors
                    .push("durable-postgresql expected server_major_version must equal 18".into());
            }
            validate_id(
                attestation_profile_id,
                POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_ID_PREFIX,
                "durable-postgresql attestation_profile_id",
                errors,
            );
            require_positive_version(
                "durable-postgresql attestation_profile_version",
                *attestation_profile_version,
                errors,
            );
            validate_digest(
                "durable-postgresql attestation_profile_digest",
                attestation_profile_digest,
                errors,
            );
            for (label, digest) in [
                (
                    "provider_route_binding_digest",
                    provider_route_binding_digest,
                ),
                ("database_identity_digest", database_identity_digest),
                ("storage_binding_digest", storage_binding_digest),
                ("migration_inventory_digest", migration_inventory_digest),
            ] {
                validate_digest(&format!("durable-postgresql {label}"), digest, errors);
            }
            for (label, role) in [
                ("application_role", application_role),
                ("migration_role", migration_role),
            ] {
                if !valid_postgresql_identifier(role) || role == "postgres" {
                    errors.push(format!(
                        "durable-postgresql {label} must be a non-superuser canonical PostgreSQL identifier"
                    ));
                }
            }
            if application_role == migration_role {
                errors.push(
                    "durable-postgresql application_role and migration_role must be distinct"
                        .into(),
                );
            }
        }
        RuntimeGuardExpectedValue::ApprovedSecretProvider {
            provider_inventory_digest,
            providers,
            required_capability_ids,
        } => {
            validate_digest(
                "approved-secret-provider provider_inventory_digest",
                provider_inventory_digest,
                errors,
            );
            validate_secret_provider_binding_set(
                "approved-secret-provider providers",
                providers,
                errors,
            );
            validate_canonical_token_set(
                "approved-secret-provider required_capability_ids",
                required_capability_ids,
                errors,
            );
            match secret_provider_inventory_digest(providers, required_capability_ids) {
                Ok(recomputed) if &recomputed != provider_inventory_digest => errors.push(
                    "approved-secret-provider provider_inventory_digest does not equal the canonical ryuki-secret-provider-inventory-v1 projection"
                        .into(),
                ),
                Err(_) => errors.push(
                    "approved-secret-provider inventory could not be canonically projected".into(),
                ),
                Ok(_) => {}
            }
        }
        RuntimeGuardExpectedValue::HttpsPublicUrls {
            public_origin_set_digest,
            ingress_binding_digest,
            attestation_profile_id,
            attestation_profile_version,
            attestation_profile_digest,
        } => {
            validate_digest(
                "https-public-urls public_origin_set_digest",
                public_origin_set_digest,
                errors,
            );
            validate_digest(
                "https-public-urls ingress_binding_digest",
                ingress_binding_digest,
                errors,
            );
            validate_id(
                attestation_profile_id,
                INGRESS_ATTESTATION_PROFILE_ID_PREFIX,
                "https-public-urls attestation_profile_id",
                errors,
            );
            require_positive_version(
                "https-public-urls attestation_profile_version",
                *attestation_profile_version,
                errors,
            );
            validate_digest(
                "https-public-urls attestation_profile_digest",
                attestation_profile_digest,
                errors,
            );
        }
        RuntimeGuardExpectedValue::SecureCookies {
            policies,
            policy_inventory_digest,
        } => {
            validate_cookie_policy_set(policies, errors);
            validate_digest(
                "secure-cookies policy_inventory_digest",
                policy_inventory_digest,
                errors,
            );
        }
        RuntimeGuardExpectedValue::NonDevelopmentAuthenticator {
            authenticator_inventory_digest: expected_inventory_digest,
            authenticators,
        } => {
            validate_digest(
                "non-development-authenticator authenticator_inventory_digest",
                expected_inventory_digest,
                errors,
            );
            if authenticators.is_empty() {
                errors
                    .push("non-development-authenticator authenticators must not be empty".into());
            }
            if !authenticators
                .windows(2)
                .all(|pair| pair[0].provider.provider_id < pair[1].provider.provider_id)
            {
                errors.push(
                    "non-development-authenticator authenticators must be strictly sorted and unique by provider_id"
                        .into(),
                );
            }
            for authenticator in authenticators {
                validate_provider_binding(
                    "non-development-authenticator provider",
                    &authenticator.provider,
                    errors,
                );
                validate_digest(
                    "non-development-authenticator runtime_binding_digest",
                    &authenticator.runtime_binding_digest,
                    errors,
                );
                if authenticator.authenticator_kind.is_legacy_mechanism() {
                    errors.push(
                        "non-development-authenticator authenticator_kind must name an exact provider family; legacy mutual-tls and composite mechanism labels are not admissible"
                            .into(),
                    );
                }
            }
            if !authenticators
                .iter()
                .any(|authenticator| authenticator.authenticator_kind.is_human())
            {
                errors.push(
                    "non-development-authenticator requires at least one human oidc, oidc-broker, or passkey provider"
                        .into(),
                );
            }
            match authenticator_inventory_digest(authenticators) {
                Ok(recomputed) if &recomputed != expected_inventory_digest => errors.push(
                    "non-development-authenticator authenticator_inventory_digest does not equal the canonical ryuki-authenticator-inventory-v1 projection"
                        .into(),
                ),
                Err(_) => errors.push(
                    "non-development-authenticator inventory could not be canonically projected"
                        .into(),
                ),
                Ok(_) => {}
            }
        }
        RuntimeGuardExpectedValue::ExternalSigningKeyMaterial {
            signing_inventory_digest,
            purposes,
        } => {
            validate_digest(
                "external-signing-key-material signing_inventory_digest",
                signing_inventory_digest,
                errors,
            );
            validate_signing_purpose_set(purposes, errors);
        }
        RuntimeGuardExpectedValue::MockDependenciesDisabled {
            dependency_inventory_digest,
            required_component_ids,
        } => {
            validate_digest(
                "mock-dependencies-disabled dependency_inventory_digest",
                dependency_inventory_digest,
                errors,
            );
            validate_namespaced_id_set(
                "mock-dependencies-disabled required_component_ids",
                required_component_ids,
                "runtime-component:",
                errors,
            );
        }
        RuntimeGuardExpectedValue::FirstOwnerPathClosed {
            deployment_id,
            state_contract_version,
            authority_namespace_digest,
            closure_record_digest,
        } => {
            validate_id(
                deployment_id,
                "deployment:",
                "first-owner-path-closed deployment_id",
                errors,
            );
            require_positive_version(
                "first-owner-path-closed state_contract_version",
                *state_contract_version,
                errors,
            );
            validate_digest(
                "first-owner-path-closed authority_namespace_digest",
                authority_namespace_digest,
                errors,
            );
            validate_digest(
                "first-owner-path-closed closure_record_digest",
                closure_record_digest,
                errors,
            );
        }
    }
}

fn validate_id(value: &str, prefix: &str, label: &str, errors: &mut Vec<String>) {
    if !value.starts_with(prefix) {
        errors.push(format!("{label} must use the {prefix} namespace"));
        return;
    }
    if !valid_canonical_scoped_id(value, prefix) {
        errors.push(format!("{label} is not a canonical lowercase identifier"));
    }
}

pub(crate) fn valid_canonical_scoped_id(value: &str, prefix: &str) -> bool {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return false;
    };
    let bytes = suffix.as_bytes();
    (3..=127).contains(&bytes.len())
        && bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn validate_digest(label: &str, value: &str, errors: &mut Vec<String>) {
    let Some(hex) = value.strip_prefix("sha256:") else {
        errors.push(format!("{label} must be a sha256 digest"));
        return;
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        errors.push(format!(
            "{label} must contain 64 lowercase hexadecimal characters"
        ));
    } else if hex.bytes().all(|byte| byte == b'0') {
        errors.push(format!(
            "{label} must not use the unresolved all-zero digest"
        ));
    }
}

fn validate_locator(label: &str, value: &str, errors: &mut Vec<String>) {
    let path = Path::new(value);
    if value.starts_with("json-pointer:")
        || path.is_absolute()
        || value.is_empty()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        errors.push(format!("{label} must be a safe repository-relative path"));
    }
}

fn parse_timestamp(label: &str, value: &str, errors: &mut Vec<String>) -> Option<DateTime<Utc>> {
    if value.trim() != value {
        errors.push(format!("{label} must be a trimmed RFC3339 timestamp"));
        return None;
    }
    match DateTime::parse_from_rfc3339(value) {
        Ok(timestamp) => Some(timestamp.with_timezone(&Utc)),
        Err(_) => {
            errors.push(format!("{label} must be a trimmed RFC3339 timestamp"));
            None
        }
    }
}

fn require_unique_strings(label: &str, values: &[String], errors: &mut Vec<String>) {
    let unique = values.iter().collect::<HashSet<_>>();
    if unique.len() != values.len() {
        errors.push(format!("{label} contains duplicates"));
    }
}

fn same_unique_strings(left: &[String], right: &[String]) -> bool {
    let left_set = left.iter().collect::<HashSet<_>>();
    let right_set = right.iter().collect::<HashSet<_>>();
    left.len() == left_set.len() && right.len() == right_set.len() && left_set == right_set
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use chrono::TimeZone;
    use ed25519_dalek::{Signer as _, SigningKey};
    use serde_json::json;

    use super::*;

    const TEST_PROFILE_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static SECURITY_PROFILE_TEST_ENTROPY_COUNTER: AtomicU64 = AtomicU64::new(1);

    fn fixture() -> DeploymentSecurityProfile {
        serde_json::from_str(include_str!(
            "../../../catalog/security-contracts/v1/deployment-security-profile.implementation.json"
        ))
        .expect("checked-in profile must match the Rust contract")
    }

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 16, 12, 0, 0).unwrap()
    }

    fn fixture_digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn security_profile_test_entropy(label: &[u8]) -> [u8; 32] {
        let counter = SECURITY_PROFILE_TEST_ENTROPY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut hasher = Sha256::new();
        hasher.update(b"ryuki security-profile test entropy");
        hasher.update(label);
        hasher.update(std::process::id().to_le_bytes());
        hasher.update(counter.to_le_bytes());
        hasher.update(elapsed.to_le_bytes());
        hasher.finalize().into()
    }

    fn authenticator_browser_state_authority() -> AuthenticatorBrowserStateAuthorityProjection {
        AuthenticatorBrowserStateAuthorityProjection {
            state_authority_id: "authenticator-state-authority:oidc-login-state".into(),
            state_authority_version: 3,
            relation_name: "oidc_login_states_v3".into(),
            writer_contract_setting: "ryuki.oidc_login_state_contract".into(),
            writer_contract_version: 3,
            consume_operation: "delete-returning".into(),
            state_lifetime_limit_id: "limit:authenticator.browser-state-lifetime".into(),
            maximum_state_lifetime_seconds: 600,
            pkce_method: "s256".into(),
            nonce_required: true,
            browser_binding_required: true,
            exact_origin_match_required: true,
        }
    }

    fn authenticator_browser_state_authority_digest() -> String {
        authenticator_browser_state_authority_binding_digest(
            &authenticator_browser_state_authority(),
        )
        .unwrap()
    }

    fn assert_independent_canonical_golden(actual: Vec<u8>, expected: Value) {
        let expected = canonical_json_bytes(&expected).expect("golden JSON must canonicalize");
        assert_eq!(actual, expected);
    }

    fn expected_provider_binding(provider_id: &str) -> ExpectedProviderBinding {
        ExpectedProviderBinding {
            provider_id: provider_id.into(),
            configuration_version: 1,
            configuration_payload_digest: fixture_digest('1'),
            lifecycle_record_version: 1,
            lifecycle_state: ProviderLifecycleState::Active,
            capability_descriptor_id: "capability-descriptor:fixture-provider".into(),
            capability_descriptor_version: 1,
            adapter_kind: "fixture.provider".into(),
            adapter_version: "1.0.0".into(),
        }
    }

    fn all_secret_provider_bindings() -> Vec<ExpectedSecretProviderBinding> {
        [
            ("provider:fixture-secrets-primary", '2'),
            ("provider:fixture-secrets-secondary", '3'),
        ]
        .into_iter()
        .map(
            |(provider_id, runtime_digest_character)| ExpectedSecretProviderBinding {
                provider: expected_provider_binding(provider_id),
                runtime_binding_digest: fixture_digest(runtime_digest_character),
            },
        )
        .collect()
    }

    fn authenticator_runtime_binding(
        provider_id: &str,
        authenticator_kind: ProductionAuthenticatorKind,
    ) -> AuthenticatorRuntimeBindingProjection {
        let mut provider = expected_provider_binding(provider_id);
        provider.adapter_kind = "auth.entra-id".into();
        AuthenticatorRuntimeBindingProjection {
            provider,
            binding_document_reference: AuthenticatorRuntimeBindingDocumentReference {
                document_id: "authenticator-runtime-binding:fixture-oidc".into(),
                document_version: 1,
                content_digest: fixture_digest('2'),
                artifact_locator:
                    "catalog/security-contracts/v1/authenticator-runtime-binding.fixture.json"
                        .into(),
            },
            authenticator_kind,
            provider_policy_binding_digest: fixture_digest('b'),
            capability_ids: vec!["browser-sso".into(), "token-validation".into()],
            credential_paths: vec![
                AuthenticatorRuntimePathProjection {
                    path_id: "authenticator-path:api-bearer".into(),
                    path_version: 1,
                    verifier: AuthenticatorVerifierRuntimeProjection {
                        verifier_id: "authenticator-verifier:fixture-oidc-api-bearer".into(),
                        verifier_version: 1,
                        issuer_binding_digest: fixture_digest('3'),
                        audience_set_binding_digest: fixture_digest('4'),
                        accepted_algorithm_ids: vec!["rs256".into()],
                        required_claim_ids: vec![
                            "aud".into(),
                            "exp".into(),
                            "iat".into(),
                            "iss".into(),
                            "nbf".into(),
                            "oid".into(),
                            "sub".into(),
                        ],
                        provider_subject_claim_id: "oid".into(),
                        key_source_kind: AuthenticatorKeySourceKind::JwtJwks,
                        key_source_binding_digest: fixture_digest('5'),
                        expiration_required: true,
                        not_before_required: true,
                        issued_at_required: true,
                        nonce_required: false,
                        clock_skew_limit_id: "limit:authenticator.clock-skew".into(),
                        maximum_clock_skew_seconds: 60,
                        redirects_allowed: false,
                    },
                    credential_profile: AuthenticatorCredentialProfileRuntimeProjection {
                        profile_id: "credential-profile:fixture-oidc-api-bearer".into(),
                        profile_version: 1,
                        token_profile: "jwt-access-token".into(),
                        carrier: AuthenticatorCredentialCarrier::AuthorizationBearer,
                        proof_binding: AuthenticatorProofBinding::Bearer,
                        replay: AuthenticatorReplayRuntimeProjection {
                            credential_reuse: AuthenticatorCredentialReuse::ReusableUntilExpiry,
                            credential_lifetime_limit_id: Some(
                                "limit:authenticator.oidc-access-token-lifetime".into(),
                            ),
                            maximum_credential_lifetime_seconds: Some(3_600),
                            sender_constraint: AuthenticatorSenderConstraint::None,
                            presentation_replay_defense:
                                AuthenticatorPresentationReplayDefense::None,
                            nonce_binding: AuthenticatorNonceBinding::None,
                            replay_store_binding_digest: None,
                        },
                    },
                    cache_partition_binding_digest: fixture_digest('c'),
                    protocol_binding_digest: fixture_digest('6'),
                    retained_consumer_ids: vec![
                        "runtime-consumer:entra-bearer-request-admission".into(),
                    ],
                },
                AuthenticatorRuntimePathProjection {
                    path_id: "authenticator-path:browser-sso".into(),
                    path_version: 1,
                    verifier: AuthenticatorVerifierRuntimeProjection {
                        verifier_id: "authenticator-verifier:fixture-oidc-browser-sso".into(),
                        verifier_version: 1,
                        issuer_binding_digest: fixture_digest('3'),
                        audience_set_binding_digest: fixture_digest('7'),
                        accepted_algorithm_ids: vec!["rs256".into()],
                        required_claim_ids: vec![
                            "aud".into(),
                            "exp".into(),
                            "iss".into(),
                            "nbf".into(),
                            "nonce".into(),
                            "oid".into(),
                            "sub".into(),
                        ],
                        provider_subject_claim_id: "oid".into(),
                        key_source_kind: AuthenticatorKeySourceKind::JwtJwks,
                        key_source_binding_digest: fixture_digest('8'),
                        expiration_required: true,
                        not_before_required: true,
                        issued_at_required: false,
                        nonce_required: true,
                        clock_skew_limit_id: "limit:authenticator.clock-skew".into(),
                        maximum_clock_skew_seconds: 60,
                        redirects_allowed: false,
                    },
                    credential_profile: AuthenticatorCredentialProfileRuntimeProjection {
                        profile_id: "credential-profile:fixture-oidc-browser-sso".into(),
                        profile_version: 1,
                        token_profile: "oidc-id-token".into(),
                        carrier: AuthenticatorCredentialCarrier::OauthCallback,
                        proof_binding: AuthenticatorProofBinding::PkceS256,
                        replay: AuthenticatorReplayRuntimeProjection {
                            credential_reuse: AuthenticatorCredentialReuse::SingleUse,
                            credential_lifetime_limit_id: None,
                            maximum_credential_lifetime_seconds: None,
                            sender_constraint: AuthenticatorSenderConstraint::None,
                            presentation_replay_defense:
                                AuthenticatorPresentationReplayDefense::SingleUseState,
                            nonce_binding: AuthenticatorNonceBinding::OidcLogin,
                            replay_store_binding_digest: Some(
                                authenticator_browser_state_authority_digest(),
                            ),
                        },
                    },
                    cache_partition_binding_digest: fixture_digest('d'),
                    protocol_binding_digest: fixture_digest('a'),
                    retained_consumer_ids: vec!["runtime-consumer:entra-browser-sso".into()],
                },
            ],
            ownership: AuthenticatorRuntimeOwnership {
                single_runtime_owner: true,
                ambient_reconfiguration_allowed: false,
            },
        }
    }

    fn authenticator_origin_projection() -> AuthenticatorOriginProjection {
        AuthenticatorOriginProjection {
            deployment_id: "deployment:fixture".into(),
            trust_domain_id: "trust-domain:fixture".into(),
            tenant_id: Some("tenant:fixture".into()),
            provider_id: "provider:fixture-oidc".into(),
            provider_configuration_version: 7,
            provider_configuration_payload_digest: fixture_digest('1'),
            provider_lifecycle_record_version: 9,
            provider_lifecycle_state: ProviderLifecycleState::Active,
            binding_document_reference: AuthenticatorRuntimeBindingDocumentReference {
                document_id: "authenticator-runtime-binding:fixture-oidc".into(),
                document_version: 3,
                content_digest: fixture_digest('2'),
                artifact_locator:
                    "catalog/security-contracts/v1/authenticator-runtime-binding.fixture.json"
                        .into(),
            },
            provider_policy_binding_digest: fixture_digest('3'),
            runtime_binding_digest: fixture_digest('4'),
            path_id: "authenticator-path:browser-sso".into(),
            path_version: 5,
        }
    }

    fn authenticator_path_identity(
        role: AuthenticatorRuntimePathRole,
    ) -> AuthenticatorRuntimePathIdentityProjection {
        let (path, verifier, token_profile, audience, key_source) = match role {
            AuthenticatorRuntimePathRole::DirectBearer => {
                ("api-bearer", "api-bearer", "jwt-access-token", '3', '4')
            }
            AuthenticatorRuntimePathRole::BrowserDerivedSession => {
                ("browser-sso", "browser-sso", "oidc-id-token", '5', '6')
            }
        };
        AuthenticatorRuntimePathIdentityProjection {
            provider_id: "provider:fixture-oidc".into(),
            provider_configuration_version: 7,
            provider_policy_binding_digest: fixture_digest('1'),
            path_role: role,
            path_id: format!("authenticator-path:{path}"),
            path_version: 3,
            verifier_id: format!("authenticator-verifier:fixture-oidc-{verifier}"),
            verifier_version: 2,
            token_profile: token_profile.into(),
            issuer_binding_digest: fixture_digest('2'),
            audience_set_binding_digest: fixture_digest(audience),
            key_source_kind: AuthenticatorKeySourceKind::JwtJwks,
            key_source_binding_digest: fixture_digest(key_source),
        }
    }

    fn authenticator_cache_partition(
        role: AuthenticatorRuntimePathRole,
    ) -> AuthenticatorCachePartitionProjection {
        let (suffix, cache_kinds, consumer) = match role {
            AuthenticatorRuntimePathRole::DirectBearer => (
                "api-bearer",
                vec![AuthenticatorCacheKind::JwksKeySet],
                "runtime-consumer:entra-bearer-request-admission",
            ),
            AuthenticatorRuntimePathRole::BrowserDerivedSession => (
                "browser-sso",
                vec![
                    AuthenticatorCacheKind::BrowserLoginState,
                    AuthenticatorCacheKind::DerivedSessionCredential,
                    AuthenticatorCacheKind::JwksKeySet,
                    AuthenticatorCacheKind::NonceReplay,
                ],
                "runtime-consumer:entra-browser-sso",
            ),
        };
        AuthenticatorCachePartitionProjection {
            path_identity: authenticator_path_identity(role),
            cache_owner_id: format!("authenticator-cache-owner:{suffix}"),
            cache_partition_id: format!("authenticator-cache-partition:{suffix}"),
            cache_kinds,
            retained_consumer_ids: vec![consumer.into()],
        }
    }

    fn authenticator_protocol_binding(
        role: AuthenticatorRuntimePathRole,
    ) -> AuthenticatorProtocolBindingProjection {
        match role {
            AuthenticatorRuntimePathRole::DirectBearer => AuthenticatorProtocolBindingProjection {
                path_identity: authenticator_path_identity(role),
                carrier: AuthenticatorCredentialCarrier::AuthorizationBearer,
                proof_binding: AuthenticatorProofBinding::Bearer,
                replay: AuthenticatorReplayRuntimeProjection {
                    credential_reuse: AuthenticatorCredentialReuse::ReusableUntilExpiry,
                    credential_lifetime_limit_id: Some(
                        "limit:authenticator.oidc-access-token-lifetime".into(),
                    ),
                    maximum_credential_lifetime_seconds: Some(3_600),
                    sender_constraint: AuthenticatorSenderConstraint::None,
                    presentation_replay_defense: AuthenticatorPresentationReplayDefense::None,
                    nonce_binding: AuthenticatorNonceBinding::None,
                    replay_store_binding_digest: None,
                },
                browser_exchange_authority: None,
                browser_state_authority: None,
                derived_session_authority: None,
            },
            AuthenticatorRuntimePathRole::BrowserDerivedSession => {
                let browser_state_authority = authenticator_browser_state_authority();
                let replay_store_binding_digest =
                    authenticator_browser_state_authority_binding_digest(&browser_state_authority)
                        .unwrap();
                AuthenticatorProtocolBindingProjection {
                    path_identity: authenticator_path_identity(role),
                    carrier: AuthenticatorCredentialCarrier::OauthCallback,
                    proof_binding: AuthenticatorProofBinding::PkceS256,
                    replay: AuthenticatorReplayRuntimeProjection {
                        credential_reuse: AuthenticatorCredentialReuse::SingleUse,
                        credential_lifetime_limit_id: None,
                        maximum_credential_lifetime_seconds: None,
                        sender_constraint: AuthenticatorSenderConstraint::None,
                        presentation_replay_defense:
                            AuthenticatorPresentationReplayDefense::SingleUseState,
                        nonce_binding: AuthenticatorNonceBinding::OidcLogin,
                        replay_store_binding_digest: Some(replay_store_binding_digest),
                    },
                    browser_exchange_authority: Some(
                        AuthenticatorBrowserExchangeAuthorityProjection {
                            exchange_authority_id: "authenticator-exchange-authority:oidc-browser"
                                .into(),
                            exchange_authority_version: 2,
                            authorization_endpoint_binding_digest: fixture_digest('a'),
                            token_endpoint_binding_digest: fixture_digest('b'),
                            redirect_uri_binding_digest: fixture_digest('c'),
                            client_id_binding_digest: fixture_digest('d'),
                            scopes_binding_digest: fixture_digest('e'),
                            client_authentication:
                                AuthenticatorBrowserClientAuthentication::ClientSecretPost,
                            client_credential_present: true,
                            connect_timeout_milliseconds: 2_000,
                            request_timeout_milliseconds: 10_000,
                            response_maximum_bytes: 1_048_576,
                            https_required: true,
                            redirects_allowed: false,
                            ambient_proxy_allowed: false,
                            pkce_verifier_sent: true,
                            id_token_required: true,
                            provider_tokens_persisted: false,
                            provider_tokens_exposed: false,
                        },
                    ),
                    browser_state_authority: Some(browser_state_authority),
                    derived_session_authority: Some(
                        AuthenticatorDerivedSessionAuthorityProjection {
                            session_authority_id: "authenticator-session-authority:browser-session"
                                .into(),
                            session_authority_version: 3,
                            relation_name: "sessions".into(),
                            credential_format: "opaque-random-256-bit".into(),
                            credential_verifier_algorithm: "hmac-sha256".into(),
                            credential_key_identity_digest: fixture_digest('8'),
                            verifier_column_name: "session_bearer_verifier_v3".into(),
                            session_maximum_age_limit_id:
                                "limit:authenticator.browser-session-maximum-age".into(),
                            maximum_session_age_seconds: 28_800,
                            federated_authority_staleness_limit_id:
                                "limit:authenticator.federated-authority-staleness".into(),
                            maximum_federated_authority_staleness_seconds: 900,
                            exact_origin_copy_required: true,
                            cookie_policy_binding_digest: fixture_digest('9'),
                        },
                    ),
                }
            }
        }
    }

    fn authenticator_runtime_path_preimages(
        binding: &AuthenticatorRuntimeBindingProjection,
        path_index: usize,
        role: AuthenticatorRuntimePathRole,
    ) -> (
        AuthenticatorCachePartitionProjection,
        AuthenticatorProtocolBindingProjection,
    ) {
        let path = &binding.credential_paths[path_index];
        let identity = AuthenticatorRuntimePathIdentityProjection {
            provider_id: binding.provider.provider_id.clone(),
            provider_configuration_version: binding.provider.configuration_version,
            provider_policy_binding_digest: binding.provider_policy_binding_digest.clone(),
            path_role: role,
            path_id: path.path_id.clone(),
            path_version: path.path_version,
            verifier_id: path.verifier.verifier_id.clone(),
            verifier_version: path.verifier.verifier_version,
            token_profile: path.credential_profile.token_profile.clone(),
            issuer_binding_digest: path.verifier.issuer_binding_digest.clone(),
            audience_set_binding_digest: path.verifier.audience_set_binding_digest.clone(),
            key_source_kind: path.verifier.key_source_kind,
            key_source_binding_digest: path.verifier.key_source_binding_digest.clone(),
        };
        let mut cache = authenticator_cache_partition(role);
        cache.path_identity = identity.clone();
        cache.retained_consumer_ids = path.retained_consumer_ids.clone();
        let mut protocol = authenticator_protocol_binding(role);
        protocol.path_identity = identity;
        protocol.carrier = path.credential_profile.carrier;
        protocol.proof_binding = path.credential_profile.proof_binding;
        protocol.replay = path.credential_profile.replay.clone();
        if let Some(exchange) = protocol.browser_exchange_authority.as_mut() {
            exchange.token_endpoint_binding_digest = fixture_digest('4');
        }
        if let Some(session) = protocol.derived_session_authority.as_mut() {
            session.credential_key_identity_digest = fixture_digest('f');
            session.cookie_policy_binding_digest = fixture_digest('6');
        }
        (cache, protocol)
    }

    fn all_authenticator_classes() -> Vec<ExpectedAuthenticatorBinding> {
        [
            (
                "provider:fixture-api-token",
                ProductionAuthenticatorKind::ApiToken,
                'a',
            ),
            (
                "provider:fixture-local-webauthn",
                ProductionAuthenticatorKind::Passkey,
                'b',
            ),
            (
                "provider:fixture-oauth-service",
                ProductionAuthenticatorKind::OauthService,
                'c',
            ),
            (
                "provider:fixture-oidc",
                ProductionAuthenticatorKind::Oidc,
                'd',
            ),
            (
                "provider:fixture-oidc-broker",
                ProductionAuthenticatorKind::OidcBroker,
                'e',
            ),
            (
                "provider:fixture-workload",
                ProductionAuthenticatorKind::Workload,
                'f',
            ),
        ]
        .into_iter()
        .map(
            |(provider_id, authenticator_kind, runtime_digest_character)| {
                ExpectedAuthenticatorBinding {
                    provider: expected_provider_binding(provider_id),
                    authenticator_kind,
                    runtime_binding_digest: fixture_digest(runtime_digest_character),
                }
            },
        )
        .collect()
    }

    fn postgresql_database_identity(deployment_id: &str) -> PostgresqlDatabaseIdentity {
        PostgresqlDatabaseIdentity {
            deployment_id: deployment_id.into(),
            trust_domain_id: "trust-domain:fixture".into(),
            database_provider: ProductionDatabaseProvider::CloudNativePg,
            database_name: "ryuki".into(),
            database_oid: 16_384,
            cluster_system_identifier: "7482247594438774091".into(),
            server_address: "192.0.2.10".into(),
            server_port: 5432,
            tls_enabled: true,
            tls_protocol: "tlsv1.3".into(),
            tls_cipher_suite: "tls_aes_256_gcm_sha384".into(),
            tls_cipher_bits: 256,
            server_major_version: 18,
            primary: true,
            writable: true,
        }
    }

    fn postgresql_provider_route_binding() -> PostgresqlProviderRouteBinding {
        PostgresqlProviderRouteBinding {
            route_mode: POSTGRESQL_PROVIDER_ROUTE_MODE_DIRECT_SESSION_V1.into(),
            database_provider: ProductionDatabaseProvider::CloudNativePg,
            endpoint_dns_name: "postgresql-rw.database.svc.cluster.local".into(),
            endpoint_port: 5432,
            trust_anchor_bundle_digest: fixture_digest('1'),
            peer_leaf_certificate_digest: fixture_digest('2'),
        }
    }

    fn postgresql_storage_bindings() -> Vec<PostgresqlStorageBinding> {
        vec![
            PostgresqlStorageBinding {
                purpose: PostgresqlStoragePurpose::Data,
                provider_cluster_uid_digest: fixture_digest('2'),
                persistent_volume_claim_uid_digest: fixture_digest('3'),
                persistent_volume_uid_digest: fixture_digest('4'),
                csi_driver: "storage.csi.example.test".into(),
                volume_handle_digest: fixture_digest('5'),
                storage_class: "encrypted-rwo".into(),
            },
            PostgresqlStorageBinding {
                purpose: PostgresqlStoragePurpose::Wal,
                provider_cluster_uid_digest: fixture_digest('2'),
                persistent_volume_claim_uid_digest: fixture_digest('6'),
                persistent_volume_uid_digest: fixture_digest('7'),
                csi_driver: "storage.csi.example.test".into(),
                volume_handle_digest: fixture_digest('8'),
                storage_class: "encrypted-rwo".into(),
            },
        ]
    }

    fn postgresql_migrations() -> Vec<PostgresqlMigrationInventoryRow> {
        vec![
            PostgresqlMigrationInventoryRow {
                version: 181,
                checksum_digest: fixture_digest('9'),
            },
            PostgresqlMigrationInventoryRow {
                version: 182,
                checksum_digest: fixture_digest('a'),
            },
        ]
    }

    fn external_signing_purpose_binding(
        purpose_id: &str,
        algorithm: SigningAlgorithm,
        custody_kind: ExternalKeyCustodyKind,
        metadata_digest_character: char,
    ) -> ExternalSigningPurposeBinding {
        let identity = ExternalSigningKeyIdentity {
            provider: expected_provider_binding("provider:fixture-key-custodian"),
            provider_runtime_binding_digest: fixture_digest('b'),
            deployment_id: "deployment:fixture".into(),
            trust_domain_id: "trust-domain:fixture".into(),
            protocol_version: "1.0.0".into(),
            purpose_id: purpose_id.into(),
            algorithm,
            custody_kind,
            key_id: format!(
                "signing-key:{}-v1",
                purpose_id.strip_prefix("signing-purpose:").unwrap()
            ),
            key_version: 1,
            public_or_opaque_metadata_digest: fixture_digest(metadata_digest_character),
            disposition: ExternalSigningKeyDisposition::Active,
        };
        let key_identity_digest = external_signing_key_identity_digest(&identity)
            .expect("fixture signing identity must canonicalize");
        ExternalSigningPurposeBinding {
            purpose_id: purpose_id.into(),
            algorithm,
            custody_kind,
            active_key_version: 1,
            keys: vec![ExpectedExternalSigningKeyVersion {
                key_identity_digest,
                identity,
            }],
        }
    }

    fn production_dependency_runtime_bindings() -> Vec<ProductionDependencyRuntimeBinding> {
        vec![
            ProductionDependencyRuntimeBinding {
                component_id: "runtime-component:database".into(),
                implementation_id: "runtime-implementation:postgresql".into(),
                implementation_version: "18.0.0".into(),
                production_posture: ProductionDependencyPosture::Production,
                authority_mode: ProductionDependencyAuthorityMode::Live,
                fallback_allowed: false,
                authority_bindings: vec![
                    ProductionDependencyAuthorityBinding {
                        binding_id: "runtime-binding:database-identity".into(),
                        binding_contract: POSTGRESQL_DATABASE_IDENTITY_DIGEST_CONTRACT.into(),
                        binding_digest: fixture_digest('c'),
                    },
                    ProductionDependencyAuthorityBinding {
                        binding_id: "runtime-binding:provider-route".into(),
                        binding_contract: POSTGRESQL_PROVIDER_ROUTE_BINDING_DIGEST_CONTRACT.into(),
                        binding_digest: fixture_digest('d'),
                    },
                ],
                retained_consumer_ids: vec![
                    "runtime-consumer:api-audit".into(),
                    "runtime-consumer:api-requests".into(),
                ],
                ownership: ProductionDependencyRuntimeOwnership {
                    runtime_owner_id: "runtime-owner:api-database".into(),
                    single_runtime_owner: true,
                    ambient_reconfiguration_allowed: false,
                },
            },
            ProductionDependencyRuntimeBinding {
                component_id: "runtime-component:secret-provider".into(),
                implementation_id: "runtime-implementation:openbao".into(),
                implementation_version: "2.3.0".into(),
                production_posture: ProductionDependencyPosture::Production,
                authority_mode: ProductionDependencyAuthorityMode::Live,
                fallback_allowed: false,
                authority_bindings: vec![ProductionDependencyAuthorityBinding {
                    binding_id: "runtime-binding:secret-provider-runtime".into(),
                    binding_contract: SECRET_PROVIDER_RUNTIME_BINDING_DIGEST_CONTRACT.into(),
                    binding_digest: fixture_digest('e'),
                }],
                retained_consumer_ids: vec!["runtime-consumer:api-integrations".into()],
                ownership: ProductionDependencyRuntimeOwnership {
                    runtime_owner_id: "runtime-owner:api-secret-provider".into(),
                    single_runtime_owner: true,
                    ambient_reconfiguration_allowed: false,
                },
            },
        ]
    }

    fn first_owner_authority_namespace(deployment_id: &str) -> FirstOwnerAuthorityNamespace {
        FirstOwnerAuthorityNamespace {
            state_contract_version: 1,
            deployment_id: deployment_id.into(),
            trust_domain_ids: vec!["trust-domain:fixture".into()],
            tenancy_mode: TenancyMode::SingleTenant,
            tenant_id: None,
            authority_id: "first-owner-authority:fixture".into(),
            authority_key_id: "first-owner-authority-key:fixture".into(),
            authority_public_key_fingerprint: fixture_digest('e'),
            authority_epoch: 1,
            namespace_id: "first-owner-namespace:fixture".into(),
        }
    }

    fn first_owner_closure_record(
        deployment_id: &str,
        authority_namespace_digest: &str,
    ) -> FirstOwnerClosureRecord {
        FirstOwnerClosureRecord {
            state_contract_version: 1,
            deployment_id: deployment_id.into(),
            authority_namespace_digest: authority_namespace_digest.into(),
            status: FirstOwnerClosureStatus::Closed,
            closure_event_id: "first-owner-closure-event:fixture".into(),
            authority_sequence: 1,
            first_owner_principal_id: "principal:fixture-owner".into(),
            claim_request_digest: fixture_digest('f'),
            capability_id: "first-owner-capability:fixture".into(),
            capability_expires_at: "2026-07-16T01:00:00Z".into(),
            closed_at_not_before: "2026-07-16T00:00:00Z".into(),
            closed_at_not_after: "2026-07-16T00:00:01Z".into(),
            closure_certificate_digest: fixture_digest('1'),
        }
    }

    fn first_owner_certificate_fixture() -> (FirstOwnerClosureCertificate, SigningKey) {
        let signing_key = SigningKey::from_bytes(&security_profile_test_entropy(
            b"first-owner closure certificate signing key",
        ));
        let public_key = signing_key.verifying_key().to_bytes();
        let mut namespace = first_owner_authority_namespace("deployment:fixture");
        namespace.authority_public_key_fingerprint = sha256_bytes_digest(&public_key);
        let namespace_digest = first_owner_authority_namespace_digest(&namespace).unwrap();
        let mut certificate = FirstOwnerClosureCertificate {
            schema_version: FIRST_OWNER_CLOSURE_CERTIFICATE_SCHEMA_VERSION.into(),
            contract_kind: FIRST_OWNER_CLOSURE_CERTIFICATE_CONTRACT_KIND.into(),
            canonicalization: FIRST_OWNER_CLOSURE_CERTIFICATE_CANONICALIZATION.into(),
            signature_algorithm: FIRST_OWNER_CLOSURE_CERTIFICATE_SIGNATURE_ALGORITHM.into(),
            authority_namespace: namespace,
            closure: SignedFirstOwnerClosure {
                state_contract_version: FIRST_OWNER_STATE_CONTRACT_VERSION,
                deployment_id: "deployment:fixture".into(),
                authority_namespace_digest: namespace_digest,
                status: FirstOwnerClosureStatus::Closed,
                closure_event_id: "first-owner-closure-event:fixture".into(),
                authority_sequence: 1,
                first_owner_principal_id: "principal:fixture-owner".into(),
                claim_request_digest: fixture_digest('f'),
                capability_id: "first-owner-capability:fixture".into(),
                capability_expires_at: "2026-07-16T01:00:00Z".into(),
                closed_at_not_before: "2026-07-16T00:00:00Z".into(),
                closed_at_not_after: "2026-07-16T00:00:01Z".into(),
            },
            privileged_domain_assignments: FIRST_OWNER_PRIVILEGED_DOMAINS
                .iter()
                .enumerate()
                .map(|(index, domain_id)| SignedPrivilegedDomainAssignment {
                    assignment_event_id: format!("first-owner-assignment-event:event-{index}"),
                    domain_id: (*domain_id).into(),
                    principal_id: "principal:fixture-owner".into(),
                })
                .collect(),
            signature_base64: BASE64_STANDARD.encode([0_u8; 64]),
        };
        resign_first_owner_certificate(&mut certificate, &signing_key);
        (certificate, signing_key)
    }

    fn resign_first_owner_certificate(
        certificate: &mut FirstOwnerClosureCertificate,
        signing_key: &SigningKey,
    ) {
        certificate.signature_base64 = BASE64_STANDARD.encode([0_u8; 64]);
        let signature = signing_key.sign(
            &first_owner_closure_certificate_signing_bytes(certificate)
                .expect("certificate fixture must have valid signing semantics"),
        );
        certificate.signature_base64 = BASE64_STANDARD.encode(signature.to_bytes());
    }

    fn expected_guard_value(guard_id: GuardId, deployment_id: &str) -> RuntimeGuardExpectedValue {
        match guard_id {
            GuardId::DurablePostgresql => RuntimeGuardExpectedValue::DurablePostgresql {
                database_provider: ProductionDatabaseProvider::CloudNativePg,
                server_major_version: 18,
                attestation_profile_id: "postgresql-infrastructure-attestation-profile:fixture"
                    .into(),
                attestation_profile_version: 1,
                attestation_profile_digest: fixture_digest('1'),
                provider_route_binding_digest: fixture_digest('5'),
                database_identity_digest: fixture_digest('2'),
                storage_binding_digest: fixture_digest('3'),
                migration_inventory_digest: fixture_digest('4'),
                application_role: "ryuki_application".into(),
                migration_role: "ryuki_migrator".into(),
            },
            GuardId::ApprovedSecretProvider => RuntimeGuardExpectedValue::ApprovedSecretProvider {
                // Independent golden for the exact canonical positive fixture;
                // never derive an authority expectation from the rows it constrains.
                provider_inventory_digest:
                    "sha256:5212c7a278cf058f0dcda4cc4f9232a869460fba6ab3a8f431b52bdd77b7fa02".into(),
                providers: all_secret_provider_bindings(),
                required_capability_ids: vec!["secret-read".into(), "secret-renew".into()],
            },
            GuardId::HttpsPublicUrls => RuntimeGuardExpectedValue::HttpsPublicUrls {
                public_origin_set_digest: fixture_digest('5'),
                ingress_binding_digest: fixture_digest('6'),
                attestation_profile_id: "ingress-attestation-profile:fixture".into(),
                attestation_profile_version: 1,
                attestation_profile_digest: fixture_digest('7'),
            },
            GuardId::SecureCookies => RuntimeGuardExpectedValue::SecureCookies {
                policies: vec![ExpectedCookiePolicy {
                    policy_id: "cookie-policy:api-session".into(),
                    cookie_name: "__Host-ryuki_session".into(),
                    secure: true,
                    http_only: true,
                    path: "/".into(),
                    domain: None,
                    same_site: CookieSameSitePolicy::Lax,
                    policy_digest: fixture_digest('8'),
                }],
                policy_inventory_digest: fixture_digest('9'),
            },
            GuardId::NonDevelopmentAuthenticator => {
                let authenticators = vec![ExpectedAuthenticatorBinding {
                    provider: expected_provider_binding("provider:fixture-oidc"),
                    authenticator_kind: ProductionAuthenticatorKind::Oidc,
                    runtime_binding_digest: fixture_digest('a'),
                }];
                RuntimeGuardExpectedValue::NonDevelopmentAuthenticator {
                    authenticator_inventory_digest: authenticator_inventory_digest(&authenticators)
                        .expect("fixture authenticator inventory must canonicalize"),
                    authenticators,
                }
            }
            GuardId::ExternalSigningKeyMaterial => {
                RuntimeGuardExpectedValue::ExternalSigningKeyMaterial {
                    signing_inventory_digest: fixture_digest('b'),
                    purposes: vec![
                        ExpectedSigningPurpose {
                            purpose_id: "signing-purpose:control-plane-grants".into(),
                            algorithm: SigningAlgorithm::Ed25519,
                            custody_kind: ExternalKeyCustodyKind::Kms,
                            key_identity_digest: fixture_digest('c'),
                        },
                        ExpectedSigningPurpose {
                            purpose_id: "signing-purpose:session-credentials".into(),
                            algorithm: SigningAlgorithm::HmacSha256,
                            custody_kind: ExternalKeyCustodyKind::Hsm,
                            key_identity_digest: fixture_digest('d'),
                        },
                    ],
                }
            }
            GuardId::MockDependenciesDisabled => {
                RuntimeGuardExpectedValue::MockDependenciesDisabled {
                    dependency_inventory_digest: fixture_digest('e'),
                    required_component_ids: vec![
                        "runtime-component:database".into(),
                        "runtime-component:secret-provider".into(),
                    ],
                }
            }
            GuardId::FirstOwnerPathClosed => RuntimeGuardExpectedValue::FirstOwnerPathClosed {
                deployment_id: deployment_id.into(),
                state_contract_version: 1,
                authority_namespace_digest: fixture_digest('f'),
                closure_record_digest: fixture_digest('1'),
            },
        }
    }

    fn structurally_complete_production_profile() -> DeploymentSecurityProfile {
        let mut profile = fixture();
        profile.security_profile = SecurityProfile::Production;
        profile.applicability.security_profiles = vec![SecurityProfile::Production];
        profile.tenancy_mode = TenancyMode::SingleTenant;
        profile.lifecycle.state = DocumentLifecycleState::Active;
        profile.lifecycle.effective_at = "2026-07-16T00:00:00Z".into();
        profile.production_acceptance_receipt_ref = Some(VersionedContentReference {
            artifact_kind: ArtifactKind::PackageExitReceipt,
            document_id: "package-exit-receipt:sb-9-production-acceptance".into(),
            document_version: 1,
            content_digest:
                "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into(),
            artifact_locator: "receipts/sb-9-production-acceptance.json".into(),
        });
        profile.runtime_guard_evidence.mode = RuntimeGuardMode::ReceiptBound;
        let deployment_id = profile.deployment_id.clone();
        profile.runtime_guard_evidence.guards = REQUIRED_PRODUCTION_GUARDS
            .into_iter()
            .enumerate()
            .map(|(index, guard_id)| GuardEvidence {
                guard_id,
                control_ids: vec!["SB-CFG-01".into()],
                receipt_ref: VersionedContentReference {
                    artifact_kind: ArtifactKind::PackageExitReceipt,
                    document_id: format!("package-exit-receipt:fixture-{index}"),
                    document_version: 1,
                    content_digest: format!("sha256:{:064x}", index + 1),
                    artifact_locator: format!("receipts/fixture-{index}.json"),
                },
                expected_value: expected_guard_value(guard_id, &deployment_id),
            })
            .collect();
        profile
    }

    fn secret_guard_parts(
        profile: &mut DeploymentSecurityProfile,
    ) -> (
        &mut String,
        &mut Vec<ExpectedSecretProviderBinding>,
        &mut Vec<String>,
    ) {
        let guard = profile
            .runtime_guard_evidence
            .guards
            .iter_mut()
            .find(|guard| guard.guard_id == GuardId::ApprovedSecretProvider)
            .unwrap();
        let RuntimeGuardExpectedValue::ApprovedSecretProvider {
            provider_inventory_digest,
            providers,
            required_capability_ids,
        } = &mut guard.expected_value
        else {
            unreachable!()
        };
        (
            provider_inventory_digest,
            providers,
            required_capability_ids,
        )
    }

    fn durable_postgresql_attestation_profile_parts(
        profile: &mut DeploymentSecurityProfile,
    ) -> (&mut String, &mut u64, &mut String) {
        let guard = profile
            .runtime_guard_evidence
            .guards
            .iter_mut()
            .find(|guard| guard.guard_id == GuardId::DurablePostgresql)
            .unwrap();
        let RuntimeGuardExpectedValue::DurablePostgresql {
            attestation_profile_id,
            attestation_profile_version,
            attestation_profile_digest,
            ..
        } = &mut guard.expected_value
        else {
            unreachable!()
        };
        (
            attestation_profile_id,
            attestation_profile_version,
            attestation_profile_digest,
        )
    }

    fn durable_postgresql_provider_route_digest(
        profile: &mut DeploymentSecurityProfile,
    ) -> &mut String {
        let guard = profile
            .runtime_guard_evidence
            .guards
            .iter_mut()
            .find(|guard| guard.guard_id == GuardId::DurablePostgresql)
            .unwrap();
        let RuntimeGuardExpectedValue::DurablePostgresql {
            provider_route_binding_digest,
            ..
        } = &mut guard.expected_value
        else {
            unreachable!()
        };
        provider_route_binding_digest
    }

    #[test]
    fn checked_in_profile_round_trips_without_semantic_loss() {
        let raw: serde_json::Value = serde_json::from_str(include_str!(
            "../../../catalog/security-contracts/v1/deployment-security-profile.implementation.json"
        ))
        .unwrap();
        let typed = fixture();
        assert_eq!(serde_json::to_value(&typed).unwrap(), raw);
        assert_eq!(
            typed.validate_structure_at(fixed_now()),
            Vec::<String>::new()
        );
    }

    #[test]
    fn unknown_fields_and_unknown_profiles_are_rejected() {
        let mut raw = serde_json::to_value(fixture()).unwrap();
        raw.as_object_mut()
            .unwrap()
            .insert("fallback".into(), json!(true));
        assert!(serde_json::from_value::<DeploymentSecurityProfile>(raw).is_err());

        let mut raw = serde_json::to_value(fixture()).unwrap();
        raw["security_profile"] = json!("prod");
        assert!(serde_json::from_value::<DeploymentSecurityProfile>(raw).is_err());
    }

    #[test]
    fn production_multi_tenant_remains_representable_but_fails_admission() {
        let mut profile = fixture();
        profile.security_profile = SecurityProfile::Production;
        profile.applicability.security_profiles = vec![SecurityProfile::Production];
        profile.tenancy_mode = TenancyMode::MultiTenant;
        profile.lifecycle.state = DocumentLifecycleState::Active;

        let errors = profile.validate_structure_at(fixed_now());
        assert!(errors.iter().any(|error| error.contains("multi_tenant")));
        assert!(errors.iter().any(|error| error.contains("receipt_bound")));
    }

    #[test]
    fn production_guard_expected_values_are_closed_typed_and_non_downgradable() {
        let profile = structurally_complete_production_profile();
        assert!(
            profile.validate_structure_at(fixed_now()).is_empty(),
            "the complete typed guard fixture must be structurally valid"
        );

        let mut wrong_kind = profile.clone();
        wrong_kind.runtime_guard_evidence.guards[0].expected_value =
            expected_guard_value(GuardId::ApprovedSecretProvider, &wrong_kind.deployment_id);
        assert!(
            wrong_kind
                .validate_structure_at(fixed_now())
                .iter()
                .any(|error| error.contains("wrong typed expected value"))
        );

        let mut insecure_cookie = profile.clone();
        let cookie = insecure_cookie
            .runtime_guard_evidence
            .guards
            .iter_mut()
            .find(|guard| guard.guard_id == GuardId::SecureCookies)
            .unwrap();
        let RuntimeGuardExpectedValue::SecureCookies { policies, .. } = &mut cookie.expected_value
        else {
            unreachable!()
        };
        policies[0].secure = false;
        assert!(
            insecure_cookie
                .validate_structure_at(fixed_now())
                .iter()
                .any(|error| error.contains("Secure, HttpOnly"))
        );

        let mut malformed_cookie_name = profile.clone();
        let cookie = malformed_cookie_name
            .runtime_guard_evidence
            .guards
            .iter_mut()
            .find(|guard| guard.guard_id == GuardId::SecureCookies)
            .unwrap();
        let RuntimeGuardExpectedValue::SecureCookies { policies, .. } = &mut cookie.expected_value
        else {
            unreachable!()
        };
        policies[0].cookie_name = "__Host-bad?name".into();
        assert!(
            malformed_cookie_name
                .validate_structure_at(fixed_now())
                .iter()
                .any(|error| error.contains("canonical __Host- name"))
        );

        let mut malformed_adapter = profile.clone();
        let secret_provider = malformed_adapter
            .runtime_guard_evidence
            .guards
            .iter_mut()
            .find(|guard| guard.guard_id == GuardId::ApprovedSecretProvider)
            .unwrap();
        let RuntimeGuardExpectedValue::ApprovedSecretProvider { providers, .. } =
            &mut secret_provider.expected_value
        else {
            unreachable!()
        };
        providers[0].provider.adapter_kind = ".fixture".into();
        assert!(
            malformed_adapter
                .validate_structure_at(fixed_now())
                .iter()
                .any(|error| error.contains("adapter_kind is not canonical"))
        );

        let mut wrong_deployment = profile;
        let first_owner = wrong_deployment
            .runtime_guard_evidence
            .guards
            .iter_mut()
            .find(|guard| guard.guard_id == GuardId::FirstOwnerPathClosed)
            .unwrap();
        let RuntimeGuardExpectedValue::FirstOwnerPathClosed { deployment_id, .. } =
            &mut first_owner.expected_value
        else {
            unreachable!()
        };
        *deployment_id = "deployment:cross-wired-fixture".into();
        assert!(
            wrong_deployment
                .validate_structure_at(fixed_now())
                .iter()
                .any(|error| error.contains("must equal the root deployment profile"))
        );
    }

    #[test]
    fn durable_postgresql_requires_a_canonical_receipt_bound_attestation_profile() {
        let assert_invalid = |profile: DeploymentSecurityProfile, needle: &str| {
            let errors = profile.validate_structure_at(fixed_now());
            assert!(
                errors.iter().any(|error| error.contains(needle)),
                "expected {needle:?} in {errors:?}"
            );
        };

        let mut wrong_namespace = structurally_complete_production_profile();
        *durable_postgresql_attestation_profile_parts(&mut wrong_namespace).0 =
            "ingress-attestation-profile:fixture".into();
        assert_invalid(
            wrong_namespace,
            "must use the postgresql-infrastructure-attestation-profile: namespace",
        );

        let mut noncanonical_id = structurally_complete_production_profile();
        *durable_postgresql_attestation_profile_parts(&mut noncanonical_id).0 =
            "postgresql-infrastructure-attestation-profile:Fixture".into();
        assert_invalid(noncanonical_id, "is not a canonical lowercase identifier");

        let mut zero_version = structurally_complete_production_profile();
        *durable_postgresql_attestation_profile_parts(&mut zero_version).1 = 0;
        assert_invalid(
            zero_version,
            "durable-postgresql attestation_profile_version must be greater than zero",
        );

        let mut malformed_digest = structurally_complete_production_profile();
        *durable_postgresql_attestation_profile_parts(&mut malformed_digest).2 =
            "sha256:not-a-digest".into();
        assert_invalid(
            malformed_digest,
            "durable-postgresql attestation_profile_digest must contain 64 lowercase hexadecimal characters",
        );

        let mut unresolved_digest = structurally_complete_production_profile();
        *durable_postgresql_attestation_profile_parts(&mut unresolved_digest).2 =
            format!("sha256:{}", "0".repeat(64));
        assert_invalid(
            unresolved_digest,
            "durable-postgresql attestation_profile_digest must not use the unresolved all-zero digest",
        );

        let mut malformed_route_digest = structurally_complete_production_profile();
        *durable_postgresql_provider_route_digest(&mut malformed_route_digest) =
            "sha256:not-a-digest".into();
        assert_invalid(
            malformed_route_digest,
            "durable-postgresql provider_route_binding_digest must contain 64 lowercase hexadecimal characters",
        );

        let mut unresolved_route_digest = structurally_complete_production_profile();
        *durable_postgresql_provider_route_digest(&mut unresolved_route_digest) =
            format!("sha256:{}", "0".repeat(64));
        assert_invalid(
            unresolved_route_digest,
            "durable-postgresql provider_route_binding_digest must not use the unresolved all-zero digest",
        );
    }

    #[test]
    fn durable_postgresql_attestation_profile_fields_cannot_be_omitted() {
        let expected_value = expected_guard_value(GuardId::DurablePostgresql, "unused");
        for field in [
            "attestation_profile_id",
            "attestation_profile_version",
            "attestation_profile_digest",
            "provider_route_binding_digest",
        ] {
            let mut raw = serde_json::to_value(&expected_value).unwrap();
            raw.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<RuntimeGuardExpectedValue>(raw).is_err(),
                "omitting {field} must fail closed"
            );
        }
    }

    #[test]
    fn postgresql_digest_contracts_match_independent_goldens_and_reject_drifted_order() {
        let identity = postgresql_database_identity("deployment:fixture");
        assert_independent_canonical_golden(
            postgresql_database_identity_canonical_bytes(&identity).unwrap(),
            json!({
                "digest_contract": "ryuki-postgresql-database-identity-v1",
                "database_identity": {
                    "deployment_id": "deployment:fixture",
                    "trust_domain_id": "trust-domain:fixture",
                    "database_provider": "cloudnativepg",
                    "database_name": "ryuki",
                    "database_oid": 16384,
                    "cluster_system_identifier": "7482247594438774091",
                    "server_address": "192.0.2.10",
                    "server_port": 5432,
                    "tls_enabled": true,
                    "tls_protocol": "tlsv1.3",
                    "tls_cipher_suite": "tls_aes_256_gcm_sha384",
                    "tls_cipher_bits": 256,
                    "server_major_version": 18,
                    "primary": true,
                    "writable": true
                }
            }),
        );
        let identity_digest = postgresql_database_identity_digest(&identity).unwrap();
        let mut drifted_identity = identity.clone();
        drifted_identity.database_name = "ryuki_shadow".into();
        assert_ne!(
            postgresql_database_identity_digest(&drifted_identity).unwrap(),
            identity_digest
        );

        let route = postgresql_provider_route_binding();
        assert_independent_canonical_golden(
            postgresql_provider_route_binding_canonical_bytes(&route).unwrap(),
            json!({
                "digest_contract": "ryuki-postgresql-provider-route-binding-v1",
                "provider_route_binding": {
                    "route_mode": "direct-session-v1",
                    "database_provider": "cloudnativepg",
                    "endpoint_dns_name": "postgresql-rw.database.svc.cluster.local",
                    "endpoint_port": 5432,
                    "trust_anchor_bundle_digest": fixture_digest('1'),
                    "peer_leaf_certificate_digest": fixture_digest('2')
                }
            }),
        );
        let route_digest = postgresql_provider_route_binding_digest(&route).unwrap();
        let mut drifted_route = route.clone();
        drifted_route.endpoint_dns_name = "postgresql-ro.database.svc.cluster.local".into();
        assert_ne!(
            postgresql_provider_route_binding_digest(&drifted_route).unwrap(),
            route_digest
        );
        let mut substituted_leaf = route.clone();
        substituted_leaf.peer_leaf_certificate_digest = fixture_digest('9');
        assert_ne!(
            postgresql_provider_route_binding_digest(&substituted_leaf).unwrap(),
            route_digest
        );

        for invalid_route in [
            PostgresqlProviderRouteBinding {
                route_mode: "pooler-session-v1".into(),
                ..route.clone()
            },
            PostgresqlProviderRouteBinding {
                endpoint_dns_name: "PostgreSQL.example.test".into(),
                ..route.clone()
            },
            PostgresqlProviderRouteBinding {
                endpoint_dns_name: "postgresql.example.test.".into(),
                ..route.clone()
            },
            PostgresqlProviderRouteBinding {
                endpoint_dns_name: "192.0.2.10".into(),
                ..route.clone()
            },
            PostgresqlProviderRouteBinding {
                endpoint_port: 0,
                ..route.clone()
            },
            PostgresqlProviderRouteBinding {
                trust_anchor_bundle_digest: format!("sha256:{}", "0".repeat(64)),
                ..route.clone()
            },
            PostgresqlProviderRouteBinding {
                peer_leaf_certificate_digest: format!("sha256:{}", "0".repeat(64)),
                ..route.clone()
            },
        ] {
            assert!(
                postgresql_provider_route_binding_digest(&invalid_route).is_err(),
                "invalid PostgreSQL provider route must fail closed: {invalid_route:?}"
            );
        }

        let bindings = postgresql_storage_bindings();
        assert_independent_canonical_golden(
            postgresql_storage_binding_canonical_bytes(&bindings).unwrap(),
            json!({
                "digest_contract": "ryuki-postgresql-storage-binding-v1",
                "storage_bindings": [
                    {
                        "purpose": "data",
                        "provider_cluster_uid_digest": fixture_digest('2'),
                        "persistent_volume_claim_uid_digest": fixture_digest('3'),
                        "persistent_volume_uid_digest": fixture_digest('4'),
                        "csi_driver": "storage.csi.example.test",
                        "volume_handle_digest": fixture_digest('5'),
                        "storage_class": "encrypted-rwo"
                    },
                    {
                        "purpose": "wal",
                        "provider_cluster_uid_digest": fixture_digest('2'),
                        "persistent_volume_claim_uid_digest": fixture_digest('6'),
                        "persistent_volume_uid_digest": fixture_digest('7'),
                        "csi_driver": "storage.csi.example.test",
                        "volume_handle_digest": fixture_digest('8'),
                        "storage_class": "encrypted-rwo"
                    }
                ]
            }),
        );
        let binding_digest = postgresql_storage_binding_digest(&bindings).unwrap();
        let mut drifted_bindings = bindings.clone();
        drifted_bindings[0].volume_handle_digest = fixture_digest('f');
        assert_ne!(
            postgresql_storage_binding_digest(&drifted_bindings).unwrap(),
            binding_digest
        );
        drifted_bindings.swap(0, 1);
        assert!(postgresql_storage_binding_digest(&drifted_bindings).is_err());

        let data_only = vec![bindings[0].clone()];
        assert!(postgresql_storage_binding_digest(&data_only).is_ok());
        let wal_only = vec![bindings[1].clone()];
        assert!(postgresql_storage_binding_digest(&wal_only).is_err());

        let migrations = postgresql_migrations();
        assert_independent_canonical_golden(
            postgresql_migration_inventory_canonical_bytes(&migrations).unwrap(),
            json!({
                "digest_contract": "ryuki-postgresql-migration-inventory-v1",
                "migrations": [
                    {"version": 181, "checksum_digest": fixture_digest('9')},
                    {"version": 182, "checksum_digest": fixture_digest('a')}
                ]
            }),
        );
        let migration_digest = postgresql_migration_inventory_digest(&migrations).unwrap();
        let mut drifted_migrations = migrations.clone();
        drifted_migrations[0].checksum_digest = fixture_digest('b');
        assert_ne!(
            postgresql_migration_inventory_digest(&drifted_migrations).unwrap(),
            migration_digest
        );
        drifted_migrations.swap(0, 1);
        assert!(postgresql_migration_inventory_digest(&drifted_migrations).is_err());
    }

    #[test]
    fn authenticator_origin_binding_has_an_independent_canonical_golden() {
        let origin = authenticator_origin_projection();
        assert_independent_canonical_golden(
            authenticator_origin_binding_canonical_bytes(&origin).unwrap(),
            json!({
                "digest_contract": "ryuki-authenticator-origin-binding-v1",
                "origin": {
                    "deployment_id": "deployment:fixture",
                    "trust_domain_id": "trust-domain:fixture",
                    "tenant_id": "tenant:fixture",
                    "provider_id": "provider:fixture-oidc",
                    "provider_configuration_version": 7,
                    "provider_configuration_payload_digest": fixture_digest('1'),
                    "provider_lifecycle_record_version": 9,
                    "provider_lifecycle_state": "active",
                    "binding_document_reference": {
                        "document_id": "authenticator-runtime-binding:fixture-oidc",
                        "document_version": 3,
                        "content_digest": fixture_digest('2'),
                        "artifact_locator": "catalog/security-contracts/v1/authenticator-runtime-binding.fixture.json"
                    },
                    "provider_policy_binding_digest": fixture_digest('3'),
                    "runtime_binding_digest": fixture_digest('4'),
                    "path_id": "authenticator-path:browser-sso",
                    "path_version": 5
                }
            }),
        );

        let digest = authenticator_origin_binding_digest(&origin).unwrap();
        for separated_digest in [
            &origin.binding_document_reference.content_digest,
            &origin.provider_configuration_payload_digest,
            &origin.provider_policy_binding_digest,
            &origin.runtime_binding_digest,
        ] {
            assert_ne!(&digest, separated_digest);
        }
    }

    #[test]
    fn authenticator_origin_binding_changes_for_each_independent_leaf_mutation() {
        let origin = authenticator_origin_projection();
        let digest = authenticator_origin_binding_digest(&origin).unwrap();
        let mut mutations = Vec::new();

        let mut drifted = origin.clone();
        drifted.deployment_id = "deployment:fixture-next".into();
        mutations.push(("deployment_id", drifted));
        let mut drifted = origin.clone();
        drifted.trust_domain_id = "trust-domain:fixture-next".into();
        mutations.push(("trust_domain_id", drifted));
        let mut drifted = origin.clone();
        drifted.tenant_id = None;
        mutations.push(("tenant_id", drifted));
        let mut drifted = origin.clone();
        drifted.provider_id = "provider:fixture-oidc-next".into();
        mutations.push(("provider_id", drifted));
        let mut drifted = origin.clone();
        drifted.provider_configuration_version += 1;
        mutations.push(("provider_configuration_version", drifted));
        let mut drifted = origin.clone();
        drifted.provider_configuration_payload_digest = fixture_digest('5');
        mutations.push(("provider_configuration_payload_digest", drifted));
        let mut drifted = origin.clone();
        drifted.provider_lifecycle_record_version += 1;
        mutations.push(("provider_lifecycle_record_version", drifted));
        let mut drifted = origin.clone();
        drifted.binding_document_reference.document_id =
            "authenticator-runtime-binding:fixture-oidc-next".into();
        mutations.push(("binding_document_reference.document_id", drifted));
        let mut drifted = origin.clone();
        drifted.binding_document_reference.document_version += 1;
        mutations.push(("binding_document_reference.document_version", drifted));
        let mut drifted = origin.clone();
        drifted.binding_document_reference.content_digest = fixture_digest('6');
        mutations.push(("binding_document_reference.content_digest", drifted));
        let mut drifted = origin.clone();
        drifted.binding_document_reference.artifact_locator =
            "catalog/security-contracts/v1/authenticator-runtime-binding.fixture-next.json".into();
        mutations.push(("binding_document_reference.artifact_locator", drifted));
        let mut drifted = origin.clone();
        drifted.provider_policy_binding_digest = fixture_digest('7');
        mutations.push(("provider_policy_binding_digest", drifted));
        let mut drifted = origin.clone();
        drifted.runtime_binding_digest = fixture_digest('8');
        mutations.push(("runtime_binding_digest", drifted));
        let mut drifted = origin.clone();
        drifted.path_id = "authenticator-path:browser-sso-next".into();
        mutations.push(("path_id", drifted));
        let mut drifted = origin.clone();
        drifted.path_version += 1;
        mutations.push(("path_version", drifted));

        for (field, drifted) in mutations {
            assert_ne!(
                authenticator_origin_binding_digest(&drifted)
                    .unwrap_or_else(|error| panic!("valid {field} drift rejected: {error}")),
                digest,
                "{field} drift must change the origin binding digest"
            );
        }

        let mut inactive = origin;
        inactive.provider_lifecycle_state = ProviderLifecycleState::Draining;
        assert!(
            authenticator_origin_binding_digest(&inactive).is_err(),
            "provider_lifecycle_state drift must reject a non-active origin"
        );
    }

    #[test]
    fn authenticator_origin_binding_rejects_invalid_namespaces_versions_and_digests() {
        let origin = authenticator_origin_projection();
        let assert_rejected = |label: &str, candidate: &AuthenticatorOriginProjection| {
            assert!(
                authenticator_origin_binding_digest(candidate).is_err(),
                "invalid {label} must be rejected"
            );
        };

        let mut candidate = origin.clone();
        candidate.deployment_id = "trust-domain:fixture".into();
        assert_rejected("deployment namespace", &candidate);
        let mut candidate = origin.clone();
        candidate.trust_domain_id = "deployment:fixture".into();
        assert_rejected("trust-domain namespace", &candidate);
        let mut candidate = origin.clone();
        candidate.tenant_id = Some("provider:fixture".into());
        assert_rejected("tenant namespace", &candidate);
        let mut candidate = origin.clone();
        candidate.provider_id = "tenant:fixture".into();
        assert_rejected("provider namespace", &candidate);
        let mut candidate = origin.clone();
        candidate.binding_document_reference.document_id = "document:fixture".into();
        assert_rejected("binding-document namespace", &candidate);
        let mut candidate = origin.clone();
        candidate.path_id = "credential-profile:fixture".into();
        assert_rejected("path namespace", &candidate);
        let mut candidate = origin.clone();
        candidate.binding_document_reference.artifact_locator = "../fixture.json".into();
        assert_rejected("binding-document locator", &candidate);

        let mut candidate = origin.clone();
        candidate.provider_configuration_version = 0;
        assert_rejected("provider configuration version", &candidate);
        let mut candidate = origin.clone();
        candidate.provider_lifecycle_record_version = 0;
        assert_rejected("provider lifecycle record version", &candidate);
        let mut candidate = origin.clone();
        candidate.binding_document_reference.document_version = 0;
        assert_rejected("binding-document version", &candidate);
        let mut candidate = origin.clone();
        candidate.path_version = 0;
        assert_rejected("path version", &candidate);

        let mut malformed_digests = Vec::new();
        let mut candidate = origin.clone();
        candidate.provider_configuration_payload_digest = "sha256:invalid".into();
        malformed_digests.push(("P", candidate));
        let mut candidate = origin.clone();
        candidate.binding_document_reference.content_digest = "sha256:invalid".into();
        malformed_digests.push(("D", candidate));
        let mut candidate = origin.clone();
        candidate.provider_policy_binding_digest = "sha256:invalid".into();
        malformed_digests.push(("Q", candidate));
        let mut candidate = origin.clone();
        candidate.runtime_binding_digest = "sha256:invalid".into();
        malformed_digests.push(("R", candidate));
        for (label, candidate) in malformed_digests {
            assert_rejected(label, &candidate);
        }

        let mut collisions = Vec::new();
        let mut candidate = origin.clone();
        candidate.provider_configuration_payload_digest =
            candidate.binding_document_reference.content_digest.clone();
        collisions.push(("P/D", candidate));
        let mut candidate = origin.clone();
        candidate.provider_configuration_payload_digest =
            candidate.provider_policy_binding_digest.clone();
        collisions.push(("P/Q", candidate));
        let mut candidate = origin.clone();
        candidate.provider_configuration_payload_digest = candidate.runtime_binding_digest.clone();
        collisions.push(("P/R", candidate));
        let mut candidate = origin.clone();
        candidate.binding_document_reference.content_digest =
            candidate.provider_policy_binding_digest.clone();
        collisions.push(("D/Q", candidate));
        let mut candidate = origin.clone();
        candidate.binding_document_reference.content_digest =
            candidate.runtime_binding_digest.clone();
        collisions.push(("D/R", candidate));
        let mut candidate = origin;
        candidate.provider_policy_binding_digest = candidate.runtime_binding_digest.clone();
        collisions.push(("Q/R", candidate));
        for (label, candidate) in collisions {
            assert_rejected(label, &candidate);
        }
    }

    #[test]
    fn authenticator_browser_state_authority_has_an_independent_canonical_golden() {
        let authority =
            authenticator_protocol_binding(AuthenticatorRuntimePathRole::BrowserDerivedSession)
                .browser_state_authority
                .unwrap();
        assert_independent_canonical_golden(
            authenticator_browser_state_authority_binding_canonical_bytes(&authority).unwrap(),
            json!({
                "digest_contract":
                    "ryuki-authenticator-browser-state-authority-binding-v1",
                "browser_state_authority": {
                    "state_authority_id":
                        "authenticator-state-authority:oidc-login-state",
                    "state_authority_version": 3,
                    "relation_name": "oidc_login_states_v3",
                    "writer_contract_setting": "ryuki.oidc_login_state_contract",
                    "writer_contract_version": 3,
                    "consume_operation": "delete-returning",
                    "state_lifetime_limit_id":
                        "limit:authenticator.browser-state-lifetime",
                    "maximum_state_lifetime_seconds": 600,
                    "pkce_method": "s256",
                    "nonce_required": true,
                    "browser_binding_required": true,
                    "exact_origin_match_required": true
                }
            }),
        );
        let digest = authenticator_browser_state_authority_binding_digest(&authority).unwrap();
        assert!(valid_sha256_digest(&digest));
    }

    #[test]
    fn authenticator_browser_state_authority_binds_every_leaf_and_rejects_malformed_values() {
        let authority =
            authenticator_protocol_binding(AuthenticatorRuntimePathRole::BrowserDerivedSession)
                .browser_state_authority
                .unwrap();
        let digest = authenticator_browser_state_authority_binding_digest(&authority).unwrap();

        let mut mutable_leaf_changes = Vec::new();
        let mut candidate = authority.clone();
        candidate.state_authority_id = "authenticator-state-authority:oidc-login-state-next".into();
        mutable_leaf_changes.push(("state_authority_id", candidate));
        let mut candidate = authority.clone();
        candidate.state_authority_version += 1;
        mutable_leaf_changes.push(("state_authority_version", candidate));
        for (leaf, candidate) in mutable_leaf_changes {
            assert_ne!(
                authenticator_browser_state_authority_binding_digest(&candidate)
                    .unwrap_or_else(|error| panic!("valid {leaf} mutation rejected: {error}")),
                digest,
                "{leaf} mutation must change the browser-state authority digest"
            );
        }

        let mut malformed = Vec::new();
        let mut candidate = authority.clone();
        candidate.state_authority_id = "runtime-owner:fixture".into();
        malformed.push(("state_authority_id namespace", candidate));
        let mut candidate = authority.clone();
        candidate.state_authority_version = 0;
        malformed.push(("state_authority_version", candidate));
        let mut candidate = authority.clone();
        candidate.relation_name = "oidc_login_states".into();
        malformed.push(("relation_name", candidate));
        let mut candidate = authority.clone();
        candidate.writer_contract_setting = "ryuki.oidc_login_state_contract_v2".into();
        malformed.push(("writer_contract_setting", candidate));
        let mut candidate = authority.clone();
        candidate.writer_contract_version = 2;
        malformed.push(("writer_contract_version", candidate));
        let mut candidate = authority.clone();
        candidate.consume_operation = "select-delete".into();
        malformed.push(("consume_operation", candidate));
        let mut candidate = authority.clone();
        candidate.state_lifetime_limit_id = "runtime-limit:fixture".into();
        malformed.push(("state_lifetime_limit_id namespace", candidate));
        let mut candidate = authority.clone();
        candidate.state_lifetime_limit_id =
            "limit:authenticator.browser-state-lifetime-next".into();
        malformed.push(("state_lifetime_limit_id identity", candidate));
        let mut candidate = authority.clone();
        candidate.maximum_state_lifetime_seconds = 599;
        malformed.push(("maximum_state_lifetime_seconds", candidate));
        let mut candidate = authority.clone();
        candidate.pkce_method = "plain".into();
        malformed.push(("pkce_method", candidate));
        let mut candidate = authority.clone();
        candidate.nonce_required = false;
        malformed.push(("nonce_required", candidate));
        let mut candidate = authority.clone();
        candidate.browser_binding_required = false;
        malformed.push(("browser_binding_required", candidate));
        let mut candidate = authority.clone();
        candidate.exact_origin_match_required = false;
        malformed.push(("exact_origin_match_required", candidate));
        for (leaf, candidate) in malformed {
            assert!(
                authenticator_browser_state_authority_binding_digest(&candidate).is_err(),
                "malformed {leaf} must fail closed"
            );
        }

        let mut unknown = serde_json::to_value(authority).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("fallback_relation".into(), json!("oidc_login_states_v2"));
        assert!(
            serde_json::from_value::<AuthenticatorBrowserStateAuthorityProjection>(unknown)
                .is_err()
        );
    }

    #[test]
    fn authenticator_browser_authorities_require_exact_limit_identities_and_bounds() {
        assert_eq!(
            AUTHENTICATOR_BROWSER_STATE_LIFETIME_LIMIT_ID,
            "limit:authenticator.browser-state-lifetime"
        );
        assert_eq!(
            AUTHENTICATOR_BROWSER_SESSION_MAXIMUM_AGE_LIMIT_ID,
            "limit:authenticator.browser-session-maximum-age"
        );
        assert_eq!(
            AUTHENTICATOR_FEDERATED_AUTHORITY_STALENESS_LIMIT_ID,
            "limit:authenticator.federated-authority-staleness"
        );

        let state_authority = authenticator_browser_state_authority();
        for wrong_id in [
            AUTHENTICATOR_BROWSER_SESSION_MAXIMUM_AGE_LIMIT_ID,
            "limit:authenticator.browser-state-lifetime-next",
        ] {
            let mut candidate = state_authority.clone();
            candidate.state_lifetime_limit_id = wrong_id.into();
            assert!(
                authenticator_browser_state_authority_binding_digest(&candidate).is_err(),
                "validly shaped but noncanonical browser-state limit {wrong_id} must fail closed"
            );
        }
        let mut wrong_state_bound = state_authority;
        wrong_state_bound.maximum_state_lifetime_seconds =
            AUTHENTICATOR_BROWSER_STATE_MAXIMUM_TTL_SECONDS + 1;
        assert!(
            authenticator_browser_state_authority_binding_digest(&wrong_state_bound).is_err(),
            "browser-state lifetime must remain exactly 600 seconds"
        );

        let browser =
            authenticator_protocol_binding(AuthenticatorRuntimePathRole::BrowserDerivedSession);
        for (field, wrong_id) in [
            (
                "session maximum age",
                "limit:authenticator.browser-session-maximum-age-next",
            ),
            (
                "federated authority staleness",
                "limit:authenticator.federated-authority-staleness-next",
            ),
        ] {
            let mut candidate = browser.clone();
            let session = candidate.derived_session_authority.as_mut().unwrap();
            match field {
                "session maximum age" => session.session_maximum_age_limit_id = wrong_id.into(),
                "federated authority staleness" => {
                    session.federated_authority_staleness_limit_id = wrong_id.into();
                }
                _ => unreachable!(),
            }
            assert!(
                authenticator_protocol_binding_digest(&candidate).is_err(),
                "validly shaped but noncanonical {field} limit {wrong_id} must fail closed"
            );
        }

        let mut boundary = browser.clone();
        {
            let session = boundary.derived_session_authority.as_mut().unwrap();
            session.maximum_federated_authority_staleness_seconds =
                session.maximum_session_age_seconds;
        }
        assert!(authenticator_protocol_binding_digest(&boundary).is_ok());
        boundary
            .derived_session_authority
            .as_mut()
            .unwrap()
            .maximum_federated_authority_staleness_seconds += 1;
        assert!(authenticator_protocol_binding_digest(&boundary).is_err());

        let direct = authenticator_protocol_binding(AuthenticatorRuntimePathRole::DirectBearer);
        assert!(
            authenticator_protocol_binding_digest(&direct).is_ok(),
            "browser limit identities must not narrow the direct-bearer protocol"
        );
    }

    #[test]
    fn authenticator_cache_partition_has_an_independent_canonical_golden() {
        let cache = authenticator_cache_partition(AuthenticatorRuntimePathRole::DirectBearer);
        assert_independent_canonical_golden(
            authenticator_cache_partition_binding_canonical_bytes(&cache).unwrap(),
            json!({
                "digest_contract": "ryuki-authenticator-cache-partition-v1",
                "cache_partition": {
                    "path_identity": {
                        "provider_id": "provider:fixture-oidc",
                        "provider_configuration_version": 7,
                        "provider_policy_binding_digest": fixture_digest('1'),
                        "path_role": "direct-bearer",
                        "path_id": "authenticator-path:api-bearer",
                        "path_version": 3,
                        "verifier_id": "authenticator-verifier:fixture-oidc-api-bearer",
                        "verifier_version": 2,
                        "token_profile": "jwt-access-token",
                        "issuer_binding_digest": fixture_digest('2'),
                        "audience_set_binding_digest": fixture_digest('3'),
                        "key_source_kind": "jwt-jwks",
                        "key_source_binding_digest": fixture_digest('4')
                    },
                    "cache_owner_id": "authenticator-cache-owner:api-bearer",
                    "cache_partition_id": "authenticator-cache-partition:api-bearer",
                    "cache_kinds": ["jwks-key-set"],
                    "retained_consumer_ids": [
                        "runtime-consumer:entra-bearer-request-admission"
                    ]
                }
            }),
        );

        let digest = authenticator_cache_partition_binding_digest(&cache).unwrap();
        assert!(
            ![
                &cache.path_identity.provider_policy_binding_digest,
                &cache.path_identity.issuer_binding_digest,
                &cache.path_identity.audience_set_binding_digest,
                &cache.path_identity.key_source_binding_digest,
            ]
            .contains(&&digest)
        );
    }

    #[test]
    fn authenticator_protocol_has_an_independent_browser_canonical_golden() {
        let protocol =
            authenticator_protocol_binding(AuthenticatorRuntimePathRole::BrowserDerivedSession);
        let browser_state_digest = protocol
            .replay
            .replay_store_binding_digest
            .as_ref()
            .unwrap()
            .clone();
        assert_independent_canonical_golden(
            authenticator_protocol_binding_canonical_bytes(&protocol).unwrap(),
            json!({
                "digest_contract": "ryuki-authenticator-protocol-binding-v1",
                "protocol_binding": {
                    "path_identity": {
                        "provider_id": "provider:fixture-oidc",
                        "provider_configuration_version": 7,
                        "provider_policy_binding_digest": fixture_digest('1'),
                        "path_role": "browser-derived-session",
                        "path_id": "authenticator-path:browser-sso",
                        "path_version": 3,
                        "verifier_id": "authenticator-verifier:fixture-oidc-browser-sso",
                        "verifier_version": 2,
                        "token_profile": "oidc-id-token",
                        "issuer_binding_digest": fixture_digest('2'),
                        "audience_set_binding_digest": fixture_digest('5'),
                        "key_source_kind": "jwt-jwks",
                        "key_source_binding_digest": fixture_digest('6')
                    },
                    "carrier": "oauth-callback",
                    "proof_binding": "pkce-s256",
                    "replay": {
                        "credential_reuse": "single-use",
                        "credential_lifetime_limit_id": null,
                        "maximum_credential_lifetime_seconds": null,
                        "sender_constraint": "none",
                        "presentation_replay_defense": "single-use-state",
                        "nonce_binding": "oidc-login",
                        "replay_store_binding_digest": browser_state_digest
                    },
                    "browser_exchange_authority": {
                        "exchange_authority_id":
                            "authenticator-exchange-authority:oidc-browser",
                        "exchange_authority_version": 2,
                        "authorization_endpoint_binding_digest": fixture_digest('a'),
                        "token_endpoint_binding_digest": fixture_digest('b'),
                        "redirect_uri_binding_digest": fixture_digest('c'),
                        "client_id_binding_digest": fixture_digest('d'),
                        "scopes_binding_digest": fixture_digest('e'),
                        "client_authentication": "client-secret-post",
                        "client_credential_present": true,
                        "connect_timeout_milliseconds": 2000,
                        "request_timeout_milliseconds": 10000,
                        "response_maximum_bytes": 1048576,
                        "https_required": true,
                        "redirects_allowed": false,
                        "ambient_proxy_allowed": false,
                        "pkce_verifier_sent": true,
                        "id_token_required": true,
                        "provider_tokens_persisted": false,
                        "provider_tokens_exposed": false
                    },
                    "browser_state_authority": {
                        "state_authority_id":
                            "authenticator-state-authority:oidc-login-state",
                        "state_authority_version": 3,
                        "relation_name": "oidc_login_states_v3",
                        "writer_contract_setting": "ryuki.oidc_login_state_contract",
                        "writer_contract_version": 3,
                        "consume_operation": "delete-returning",
                        "state_lifetime_limit_id":
                            "limit:authenticator.browser-state-lifetime",
                        "maximum_state_lifetime_seconds": 600,
                        "pkce_method": "s256",
                        "nonce_required": true,
                        "browser_binding_required": true,
                        "exact_origin_match_required": true
                    },
                    "derived_session_authority": {
                        "session_authority_id":
                            "authenticator-session-authority:browser-session",
                        "session_authority_version": 3,
                        "relation_name": "sessions",
                        "credential_format": "opaque-random-256-bit",
                        "credential_verifier_algorithm": "hmac-sha256",
                        "credential_key_identity_digest": fixture_digest('8'),
                        "verifier_column_name": "session_bearer_verifier_v3",
                        "session_maximum_age_limit_id":
                            "limit:authenticator.browser-session-maximum-age",
                        "maximum_session_age_seconds": 28800,
                        "federated_authority_staleness_limit_id":
                            "limit:authenticator.federated-authority-staleness",
                        "maximum_federated_authority_staleness_seconds": 900,
                        "exact_origin_copy_required": true,
                        "cookie_policy_binding_digest": fixture_digest('9')
                    }
                }
            }),
        );

        let digest = authenticator_protocol_binding_digest(&protocol).unwrap();
        let exchange = protocol.browser_exchange_authority.as_ref().unwrap();
        let session = protocol.derived_session_authority.as_ref().unwrap();
        assert!(
            ![
                &protocol.path_identity.provider_policy_binding_digest,
                &protocol.path_identity.issuer_binding_digest,
                &protocol.path_identity.audience_set_binding_digest,
                &protocol.path_identity.key_source_binding_digest,
                protocol
                    .replay
                    .replay_store_binding_digest
                    .as_ref()
                    .unwrap(),
                &exchange.authorization_endpoint_binding_digest,
                &exchange.token_endpoint_binding_digest,
                &exchange.redirect_uri_binding_digest,
                &exchange.client_id_binding_digest,
                &exchange.scopes_binding_digest,
                &session.credential_key_identity_digest,
                &session.cookie_policy_binding_digest,
            ]
            .contains(&&digest)
        );
    }

    #[test]
    fn authenticator_cache_and_protocol_digests_bind_every_nonconstant_leaf() {
        let cache = authenticator_cache_partition(AuthenticatorRuntimePathRole::DirectBearer);
        let cache_digest = authenticator_cache_partition_binding_digest(&cache).unwrap();
        macro_rules! assert_cache_leaf_bound {
            ($label:literal, $mutate:expr) => {{
                let mut candidate = cache.clone();
                ($mutate)(&mut candidate);
                assert_ne!(
                    authenticator_cache_partition_binding_digest(&candidate).unwrap_or_else(
                        |error| panic!("valid {} mutation rejected: {error}", $label)
                    ),
                    cache_digest,
                    "{} mutation must change the cache binding digest",
                    $label
                );
            }};
        }
        assert_cache_leaf_bound!(
            "provider_id",
            |candidate: &mut AuthenticatorCachePartitionProjection| {
                candidate.path_identity.provider_id = "provider:fixture-oidc-next".into();
            }
        );
        assert_cache_leaf_bound!(
            "provider_configuration_version",
            |candidate: &mut AuthenticatorCachePartitionProjection| {
                candidate.path_identity.provider_configuration_version += 1;
            }
        );
        assert_cache_leaf_bound!(
            "provider_policy_binding_digest",
            |candidate: &mut AuthenticatorCachePartitionProjection| {
                candidate.path_identity.provider_policy_binding_digest = fixture_digest('f');
            }
        );
        assert_cache_leaf_bound!(
            "path_id",
            |candidate: &mut AuthenticatorCachePartitionProjection| {
                candidate.path_identity.path_id = "authenticator-path:api-bearer-next".into();
            }
        );
        assert_cache_leaf_bound!(
            "path_version",
            |candidate: &mut AuthenticatorCachePartitionProjection| {
                candidate.path_identity.path_version += 1;
            }
        );
        assert_cache_leaf_bound!(
            "verifier_id",
            |candidate: &mut AuthenticatorCachePartitionProjection| {
                candidate.path_identity.verifier_id =
                    "authenticator-verifier:fixture-oidc-api-bearer-next".into();
            }
        );
        assert_cache_leaf_bound!(
            "verifier_version",
            |candidate: &mut AuthenticatorCachePartitionProjection| {
                candidate.path_identity.verifier_version += 1;
            }
        );
        assert_cache_leaf_bound!(
            "issuer_binding_digest",
            |candidate: &mut AuthenticatorCachePartitionProjection| {
                candidate.path_identity.issuer_binding_digest = fixture_digest('f');
            }
        );
        assert_cache_leaf_bound!(
            "audience_set_binding_digest",
            |candidate: &mut AuthenticatorCachePartitionProjection| {
                candidate.path_identity.audience_set_binding_digest = fixture_digest('f');
            }
        );
        assert_cache_leaf_bound!(
            "key_source_binding_digest",
            |candidate: &mut AuthenticatorCachePartitionProjection| {
                candidate.path_identity.key_source_binding_digest = fixture_digest('f');
            }
        );
        assert_cache_leaf_bound!(
            "cache_owner_id",
            |candidate: &mut AuthenticatorCachePartitionProjection| {
                candidate.cache_owner_id = "authenticator-cache-owner:api-bearer-next".into();
            }
        );
        assert_cache_leaf_bound!(
            "cache_partition_id",
            |candidate: &mut AuthenticatorCachePartitionProjection| {
                candidate.cache_partition_id =
                    "authenticator-cache-partition:api-bearer-next".into();
            }
        );
        assert_cache_leaf_bound!(
            "cache_kinds",
            |candidate: &mut AuthenticatorCachePartitionProjection| {
                candidate
                    .cache_kinds
                    .push(AuthenticatorCacheKind::OidcDiscoveryDocument);
            }
        );
        assert_cache_leaf_bound!(
            "retained_consumer_ids",
            |candidate: &mut AuthenticatorCachePartitionProjection| {
                candidate.retained_consumer_ids =
                    vec!["runtime-consumer:entra-bearer-request-admission-next".into()];
            }
        );

        let protocol =
            authenticator_protocol_binding(AuthenticatorRuntimePathRole::BrowserDerivedSession);
        let protocol_digest = authenticator_protocol_binding_digest(&protocol).unwrap();
        macro_rules! assert_protocol_leaf_bound {
            ($label:literal, $mutate:expr) => {{
                let mut candidate = protocol.clone();
                ($mutate)(&mut candidate);
                if let Some(authority) = candidate.browser_state_authority.as_ref() {
                    candidate.replay.replay_store_binding_digest = Some(
                        authenticator_browser_state_authority_binding_digest(authority).unwrap(),
                    );
                }
                assert_ne!(
                    authenticator_protocol_binding_digest(&candidate).unwrap_or_else(
                        |error| panic!("valid {} mutation rejected: {error}", $label)
                    ),
                    protocol_digest,
                    "{} mutation must change the protocol binding digest",
                    $label
                );
            }};
        }
        assert_protocol_leaf_bound!(
            "provider_id",
            |candidate: &mut AuthenticatorProtocolBindingProjection| {
                candidate.path_identity.provider_id = "provider:fixture-oidc-next".into();
            }
        );
        assert_protocol_leaf_bound!(
            "provider_configuration_version",
            |candidate: &mut AuthenticatorProtocolBindingProjection| {
                candidate.path_identity.provider_configuration_version += 1;
            }
        );
        assert_protocol_leaf_bound!(
            "provider_policy_binding_digest",
            |candidate: &mut AuthenticatorProtocolBindingProjection| {
                candidate.path_identity.provider_policy_binding_digest = fixture_digest('f');
            }
        );
        assert_protocol_leaf_bound!(
            "path_id",
            |candidate: &mut AuthenticatorProtocolBindingProjection| {
                candidate.path_identity.path_id = "authenticator-path:browser-sso-next".into();
            }
        );
        assert_protocol_leaf_bound!(
            "path_version",
            |candidate: &mut AuthenticatorProtocolBindingProjection| {
                candidate.path_identity.path_version += 1;
            }
        );
        assert_protocol_leaf_bound!(
            "verifier_id",
            |candidate: &mut AuthenticatorProtocolBindingProjection| {
                candidate.path_identity.verifier_id =
                    "authenticator-verifier:fixture-oidc-browser-sso-next".into();
            }
        );
        assert_protocol_leaf_bound!(
            "verifier_version",
            |candidate: &mut AuthenticatorProtocolBindingProjection| {
                candidate.path_identity.verifier_version += 1;
            }
        );
        assert_protocol_leaf_bound!(
            "issuer_binding_digest",
            |candidate: &mut AuthenticatorProtocolBindingProjection| {
                candidate.path_identity.issuer_binding_digest = fixture_digest('f');
            }
        );
        assert_protocol_leaf_bound!(
            "audience_set_binding_digest",
            |candidate: &mut AuthenticatorProtocolBindingProjection| {
                candidate.path_identity.audience_set_binding_digest = fixture_digest('f');
            }
        );
        assert_protocol_leaf_bound!(
            "key_source_binding_digest",
            |candidate: &mut AuthenticatorProtocolBindingProjection| {
                candidate.path_identity.key_source_binding_digest = fixture_digest('f');
            }
        );
        assert_protocol_leaf_bound!(
            "exchange_authority_id",
            |candidate: &mut AuthenticatorProtocolBindingProjection| {
                candidate
                    .browser_exchange_authority
                    .as_mut()
                    .unwrap()
                    .exchange_authority_id =
                    "authenticator-exchange-authority:oidc-browser-next".into();
            }
        );
        assert_protocol_leaf_bound!(
            "exchange_authority_version",
            |candidate: &mut AuthenticatorProtocolBindingProjection| {
                candidate
                    .browser_exchange_authority
                    .as_mut()
                    .unwrap()
                    .exchange_authority_version += 1;
            }
        );
        for (label, field) in [
            ("authorization_endpoint_binding_digest", 0_u8),
            ("token_endpoint_binding_digest", 1),
            ("redirect_uri_binding_digest", 2),
            ("client_id_binding_digest", 3),
            ("scopes_binding_digest", 4),
        ] {
            let mut candidate = protocol.clone();
            let exchange = candidate.browser_exchange_authority.as_mut().unwrap();
            match field {
                0 => exchange.authorization_endpoint_binding_digest = fixture_digest('f'),
                1 => exchange.token_endpoint_binding_digest = fixture_digest('f'),
                2 => exchange.redirect_uri_binding_digest = fixture_digest('f'),
                3 => exchange.client_id_binding_digest = fixture_digest('f'),
                4 => exchange.scopes_binding_digest = fixture_digest('f'),
                _ => unreachable!(),
            }
            assert_ne!(
                authenticator_protocol_binding_digest(&candidate).unwrap(),
                protocol_digest,
                "{label} mutation must change the protocol binding digest"
            );
        }
        assert_protocol_leaf_bound!(
            "client_authentication",
            |candidate: &mut AuthenticatorProtocolBindingProjection| {
                let exchange = candidate.browser_exchange_authority.as_mut().unwrap();
                exchange.client_authentication = AuthenticatorBrowserClientAuthentication::None;
                exchange.client_credential_present = false;
            }
        );
        assert_protocol_leaf_bound!(
            "connect_timeout_milliseconds",
            |candidate: &mut AuthenticatorProtocolBindingProjection| {
                candidate
                    .browser_exchange_authority
                    .as_mut()
                    .unwrap()
                    .connect_timeout_milliseconds += 1;
            }
        );
        assert_protocol_leaf_bound!(
            "request_timeout_milliseconds",
            |candidate: &mut AuthenticatorProtocolBindingProjection| {
                candidate
                    .browser_exchange_authority
                    .as_mut()
                    .unwrap()
                    .request_timeout_milliseconds += 1;
            }
        );
        assert_protocol_leaf_bound!(
            "response_maximum_bytes",
            |candidate: &mut AuthenticatorProtocolBindingProjection| {
                candidate
                    .browser_exchange_authority
                    .as_mut()
                    .unwrap()
                    .response_maximum_bytes += 1;
            }
        );
        assert_protocol_leaf_bound!(
            "state_authority_id",
            |candidate: &mut AuthenticatorProtocolBindingProjection| {
                candidate
                    .browser_state_authority
                    .as_mut()
                    .unwrap()
                    .state_authority_id =
                    "authenticator-state-authority:oidc-login-state-next".into();
            }
        );
        assert_protocol_leaf_bound!(
            "state_authority_version",
            |candidate: &mut AuthenticatorProtocolBindingProjection| {
                candidate
                    .browser_state_authority
                    .as_mut()
                    .unwrap()
                    .state_authority_version += 1;
            }
        );
        assert_protocol_leaf_bound!(
            "session_authority_id",
            |candidate: &mut AuthenticatorProtocolBindingProjection| {
                candidate
                    .derived_session_authority
                    .as_mut()
                    .unwrap()
                    .session_authority_id =
                    "authenticator-session-authority:browser-session-next".into();
            }
        );
        assert_protocol_leaf_bound!(
            "session_authority_version",
            |candidate: &mut AuthenticatorProtocolBindingProjection| {
                candidate
                    .derived_session_authority
                    .as_mut()
                    .unwrap()
                    .session_authority_version += 1;
            }
        );
        assert_protocol_leaf_bound!(
            "credential_key_identity_digest",
            |candidate: &mut AuthenticatorProtocolBindingProjection| {
                candidate
                    .derived_session_authority
                    .as_mut()
                    .unwrap()
                    .credential_key_identity_digest = fixture_digest('f');
            }
        );
        assert_protocol_leaf_bound!(
            "maximum_session_age_seconds",
            |candidate: &mut AuthenticatorProtocolBindingProjection| {
                candidate
                    .derived_session_authority
                    .as_mut()
                    .unwrap()
                    .maximum_session_age_seconds += 1;
            }
        );
        assert_protocol_leaf_bound!(
            "maximum_federated_authority_staleness_seconds",
            |candidate: &mut AuthenticatorProtocolBindingProjection| {
                candidate
                    .derived_session_authority
                    .as_mut()
                    .unwrap()
                    .maximum_federated_authority_staleness_seconds += 1;
            }
        );
        assert_protocol_leaf_bound!(
            "cookie_policy_binding_digest",
            |candidate: &mut AuthenticatorProtocolBindingProjection| {
                candidate
                    .derived_session_authority
                    .as_mut()
                    .unwrap()
                    .cookie_policy_binding_digest = fixture_digest('f');
            }
        );

        let direct = authenticator_protocol_binding(AuthenticatorRuntimePathRole::DirectBearer);
        let direct_digest = authenticator_protocol_binding_digest(&direct).unwrap();
        let mut lifetime_limit_drift = direct.clone();
        lifetime_limit_drift.replay.credential_lifetime_limit_id =
            Some("limit:authenticator.oidc-access-token-lifetime-next".into());
        assert_ne!(
            authenticator_protocol_binding_digest(&lifetime_limit_drift).unwrap(),
            direct_digest
        );
        let mut lifetime_drift = direct;
        lifetime_drift.replay.maximum_credential_lifetime_seconds = Some(3_601);
        assert_ne!(
            authenticator_protocol_binding_digest(&lifetime_drift).unwrap(),
            direct_digest
        );
    }

    #[test]
    fn authenticator_runtime_paths_reconcile_exact_typed_preimages() {
        for (path_index, role) in [
            (0, AuthenticatorRuntimePathRole::DirectBearer),
            (1, AuthenticatorRuntimePathRole::BrowserDerivedSession),
        ] {
            let mut binding = authenticator_runtime_binding(
                "provider:fixture-oidc",
                ProductionAuthenticatorKind::Oidc,
            );
            let (cache, protocol) =
                authenticator_runtime_path_preimages(&binding, path_index, role);
            binding.credential_paths[path_index].cache_partition_binding_digest =
                authenticator_cache_partition_binding_digest(&cache).unwrap();
            binding.credential_paths[path_index].protocol_binding_digest =
                authenticator_protocol_binding_digest(&protocol).unwrap();
            validate_authenticator_runtime_path_preimages(&binding, &cache, &protocol).unwrap();

            let mut provider_substitution = cache.clone();
            provider_substitution
                .path_identity
                .provider_configuration_version += 1;
            binding.credential_paths[path_index].cache_partition_binding_digest =
                authenticator_cache_partition_binding_digest(&provider_substitution).unwrap();
            assert!(
                validate_authenticator_runtime_path_preimages(
                    &binding,
                    &provider_substitution,
                    &protocol,
                )
                .is_err(),
                "{role:?} provider substitution must fail reconciliation"
            );
        }

        let mut binding = authenticator_runtime_binding(
            "provider:fixture-oidc",
            ProductionAuthenticatorKind::Oidc,
        );
        let (mut cache, mut protocol) = authenticator_runtime_path_preimages(
            &binding,
            0,
            AuthenticatorRuntimePathRole::DirectBearer,
        );
        let forbidden_p = binding.provider.configuration_payload_digest.clone();
        cache.path_identity.provider_policy_binding_digest = forbidden_p.clone();
        protocol.path_identity.provider_policy_binding_digest = forbidden_p;
        binding.credential_paths[0].cache_partition_binding_digest =
            authenticator_cache_partition_binding_digest(&cache).unwrap();
        binding.credential_paths[0].protocol_binding_digest =
            authenticator_protocol_binding_digest(&protocol).unwrap();
        assert!(
            validate_authenticator_runtime_path_preimages(&binding, &cache, &protocol).is_err(),
            "P must never alias or fall back to Q in a path preimage"
        );
    }

    #[test]
    fn authenticator_cache_and_protocol_reject_malformed_and_role_confused_preimages() {
        let direct_cache =
            authenticator_cache_partition(AuthenticatorRuntimePathRole::DirectBearer);
        let mut malformed_caches = Vec::new();
        let mut candidate = direct_cache.clone();
        candidate.path_identity.provider_id = "deployment:fixture".into();
        malformed_caches.push(("provider namespace", candidate));
        let mut candidate = direct_cache.clone();
        candidate.path_identity.provider_configuration_version = 0;
        malformed_caches.push(("provider version", candidate));
        let mut candidate = direct_cache.clone();
        candidate.path_identity.provider_policy_binding_digest = "sha256:invalid".into();
        malformed_caches.push(("provider-policy digest", candidate));
        let mut candidate = direct_cache.clone();
        candidate.path_identity.issuer_binding_digest =
            candidate.path_identity.audience_set_binding_digest.clone();
        malformed_caches.push(("authority digest collision", candidate));
        let mut candidate = direct_cache.clone();
        candidate.path_identity.path_role = AuthenticatorRuntimePathRole::BrowserDerivedSession;
        malformed_caches.push(("path role/token profile confusion", candidate));
        let mut candidate = direct_cache.clone();
        candidate.path_identity.token_profile = "oidc-id-token".into();
        malformed_caches.push(("token profile/role confusion", candidate));
        let mut candidate = direct_cache.clone();
        candidate.path_identity.key_source_kind =
            AuthenticatorKeySourceKind::AuthenticatedIntrospection;
        malformed_caches.push(("key source confusion", candidate));
        let mut candidate = direct_cache.clone();
        candidate.cache_owner_id = "runtime-owner:fixture".into();
        malformed_caches.push(("cache owner namespace", candidate));
        let mut candidate = direct_cache.clone();
        candidate.cache_partition_id = candidate.cache_owner_id.clone();
        malformed_caches.push(("cache owner/partition substitution", candidate));
        let mut candidate = direct_cache.clone();
        candidate.cache_kinds.clear();
        malformed_caches.push(("empty cache inventory", candidate));
        let mut candidate = direct_cache.clone();
        candidate.cache_kinds = vec![
            AuthenticatorCacheKind::OidcDiscoveryDocument,
            AuthenticatorCacheKind::JwksKeySet,
        ];
        malformed_caches.push(("unsorted cache inventory", candidate));
        let mut candidate = direct_cache.clone();
        candidate.cache_kinds = vec![
            AuthenticatorCacheKind::JwksKeySet,
            AuthenticatorCacheKind::JwksKeySet,
        ];
        malformed_caches.push(("duplicate cache inventory", candidate));
        let mut candidate = direct_cache.clone();
        candidate
            .cache_kinds
            .insert(0, AuthenticatorCacheKind::BrowserLoginState);
        malformed_caches.push(("browser cache on bearer path", candidate));
        let mut candidate = direct_cache.clone();
        candidate.retained_consumer_ids.clear();
        malformed_caches.push(("empty consumer inventory", candidate));
        let mut candidate = direct_cache.clone();
        candidate.retained_consumer_ids = vec![
            "runtime-consumer:zeta".into(),
            "runtime-consumer:alpha".into(),
        ];
        malformed_caches.push(("unsorted consumer inventory", candidate));
        for (label, candidate) in malformed_caches {
            assert!(
                authenticator_cache_partition_binding_digest(&candidate).is_err(),
                "malformed {label} cache preimage must fail closed"
            );
        }

        let browser =
            authenticator_protocol_binding(AuthenticatorRuntimePathRole::BrowserDerivedSession);
        let mut direct = authenticator_protocol_binding(AuthenticatorRuntimePathRole::DirectBearer);
        direct.browser_exchange_authority = browser.browser_exchange_authority.clone();
        assert!(authenticator_protocol_binding_digest(&direct).is_err());
        let mut direct = authenticator_protocol_binding(AuthenticatorRuntimePathRole::DirectBearer);
        direct.browser_state_authority = browser.browser_state_authority.clone();
        assert!(authenticator_protocol_binding_digest(&direct).is_err());
        let mut direct = authenticator_protocol_binding(AuthenticatorRuntimePathRole::DirectBearer);
        direct.derived_session_authority = browser.derived_session_authority.clone();
        assert!(authenticator_protocol_binding_digest(&direct).is_err());

        for missing_arm in ["exchange", "state", "session"] {
            let mut candidate = browser.clone();
            match missing_arm {
                "exchange" => candidate.browser_exchange_authority = None,
                "state" => candidate.browser_state_authority = None,
                "session" => candidate.derived_session_authority = None,
                _ => unreachable!(),
            }
            assert!(
                authenticator_protocol_binding_digest(&candidate).is_err(),
                "browser protocol without {missing_arm} authority must fail closed"
            );
        }

        let invalid_leaf_mutations = [
            ("/path_identity/path_role", json!("direct-bearer")),
            ("/path_identity/token_profile", json!("jwt-access-token")),
            (
                "/path_identity/key_source_kind",
                json!("authenticated-introspection"),
            ),
            ("/carrier", json!("authorization-bearer")),
            ("/proof_binding", json!("bearer")),
            ("/replay/credential_reuse", json!("reusable-until-expiry")),
            (
                "/replay/credential_lifetime_limit_id",
                json!("limit:fixture"),
            ),
            ("/replay/maximum_credential_lifetime_seconds", json!(3600)),
            ("/replay/sender_constraint", json!("dpop")),
            ("/replay/presentation_replay_defense", json!("none")),
            ("/replay/nonce_binding", json!("none")),
            ("/replay/replay_store_binding_digest", Value::Null),
            (
                "/replay/replay_store_binding_digest",
                json!(fixture_digest('1')),
            ),
            (
                "/replay/replay_store_binding_digest",
                json!(fixture_digest('f')),
            ),
            (
                "/browser_exchange_authority/exchange_authority_id",
                json!("runtime-owner:fixture"),
            ),
            (
                "/browser_exchange_authority/exchange_authority_version",
                json!(0),
            ),
            (
                "/browser_exchange_authority/authorization_endpoint_binding_digest",
                json!("sha256:invalid"),
            ),
            (
                "/browser_exchange_authority/token_endpoint_binding_digest",
                json!(fixture_digest('a')),
            ),
            (
                "/browser_exchange_authority/token_endpoint_binding_digest",
                json!(fixture_digest('2')),
            ),
            (
                "/browser_exchange_authority/client_authentication",
                json!("none"),
            ),
            (
                "/browser_exchange_authority/client_credential_present",
                json!(false),
            ),
            (
                "/browser_exchange_authority/connect_timeout_milliseconds",
                json!(0),
            ),
            (
                "/browser_exchange_authority/request_timeout_milliseconds",
                json!(1000),
            ),
            (
                "/browser_exchange_authority/response_maximum_bytes",
                json!(0),
            ),
            ("/browser_exchange_authority/https_required", json!(false)),
            ("/browser_exchange_authority/redirects_allowed", json!(true)),
            (
                "/browser_exchange_authority/ambient_proxy_allowed",
                json!(true),
            ),
            (
                "/browser_exchange_authority/pkce_verifier_sent",
                json!(false),
            ),
            (
                "/browser_exchange_authority/id_token_required",
                json!(false),
            ),
            (
                "/browser_exchange_authority/provider_tokens_persisted",
                json!(true),
            ),
            (
                "/browser_exchange_authority/provider_tokens_exposed",
                json!(true),
            ),
            (
                "/browser_state_authority/state_authority_id",
                json!("runtime-owner:fixture"),
            ),
            ("/browser_state_authority/state_authority_version", json!(0)),
            (
                "/browser_state_authority/relation_name",
                json!("oidc_login_states"),
            ),
            (
                "/browser_state_authority/writer_contract_setting",
                json!("ryuki.oidc_login_state_contract_v2"),
            ),
            ("/browser_state_authority/writer_contract_version", json!(2)),
            (
                "/browser_state_authority/consume_operation",
                json!("select-delete"),
            ),
            (
                "/browser_state_authority/state_lifetime_limit_id",
                json!("runtime-limit:fixture"),
            ),
            (
                "/browser_state_authority/state_lifetime_limit_id",
                json!("limit:authenticator.browser-state-lifetime-next"),
            ),
            (
                "/browser_state_authority/maximum_state_lifetime_seconds",
                json!(599),
            ),
            ("/browser_state_authority/pkce_method", json!("plain")),
            ("/browser_state_authority/nonce_required", json!(false)),
            (
                "/browser_state_authority/browser_binding_required",
                json!(false),
            ),
            (
                "/browser_state_authority/exact_origin_match_required",
                json!(false),
            ),
            (
                "/derived_session_authority/session_authority_id",
                json!("runtime-owner:fixture"),
            ),
            (
                "/derived_session_authority/session_authority_version",
                json!(0),
            ),
            (
                "/derived_session_authority/relation_name",
                json!("auth_sessions"),
            ),
            (
                "/derived_session_authority/credential_format",
                json!("bearer-token"),
            ),
            (
                "/derived_session_authority/credential_verifier_algorithm",
                json!("sha256"),
            ),
            (
                "/derived_session_authority/credential_key_identity_digest",
                json!("sha256:invalid"),
            ),
            (
                "/derived_session_authority/credential_key_identity_digest",
                json!(fixture_digest('6')),
            ),
            (
                "/derived_session_authority/verifier_column_name",
                json!("bearer_verifier"),
            ),
            (
                "/derived_session_authority/session_maximum_age_limit_id",
                json!("runtime-limit:fixture"),
            ),
            (
                "/derived_session_authority/session_maximum_age_limit_id",
                json!("limit:authenticator.browser-session-maximum-age-next"),
            ),
            (
                "/derived_session_authority/maximum_session_age_seconds",
                json!(0),
            ),
            (
                "/derived_session_authority/federated_authority_staleness_limit_id",
                json!("limit:authenticator.browser-session-maximum-age"),
            ),
            (
                "/derived_session_authority/federated_authority_staleness_limit_id",
                json!("limit:authenticator.federated-authority-staleness-next"),
            ),
            (
                "/derived_session_authority/maximum_federated_authority_staleness_seconds",
                json!(28801),
            ),
            (
                "/derived_session_authority/exact_origin_copy_required",
                json!(false),
            ),
            (
                "/derived_session_authority/cookie_policy_binding_digest",
                json!(fixture_digest('8')),
            ),
        ];
        for (pointer, mutation) in invalid_leaf_mutations {
            let mut raw = serde_json::to_value(&browser).unwrap();
            *raw.pointer_mut(pointer)
                .unwrap_or_else(|| panic!("missing test pointer {pointer}")) = mutation;
            if let Ok(candidate) =
                serde_json::from_value::<AuthenticatorProtocolBindingProjection>(raw)
            {
                assert!(
                    authenticator_protocol_binding_digest(&candidate).is_err(),
                    "invalid {pointer} mutation must fail closed"
                );
            }
        }

        for required_arm in [
            "browser_exchange_authority",
            "browser_state_authority",
            "derived_session_authority",
        ] {
            let mut raw = serde_json::to_value(&browser).unwrap();
            raw.as_object_mut().unwrap().remove(required_arm);
            assert!(
                serde_json::from_value::<AuthenticatorProtocolBindingProjection>(raw).is_err(),
                "omitting explicit {required_arm} must fail closed"
            );
        }

        let mut unknown_cache = serde_json::to_value(&direct_cache).unwrap();
        unknown_cache
            .as_object_mut()
            .unwrap()
            .insert("fallback_partition".into(), json!(true));
        assert!(
            serde_json::from_value::<AuthenticatorCachePartitionProjection>(unknown_cache).is_err()
        );
        let mut legacy_p_alias = serde_json::to_value(&direct_cache).unwrap();
        let legacy_identity = legacy_p_alias["path_identity"].as_object_mut().unwrap();
        let q = legacy_identity
            .remove("provider_policy_binding_digest")
            .unwrap();
        legacy_identity.insert("provider_configuration_payload_digest".into(), q);
        assert!(
            serde_json::from_value::<AuthenticatorCachePartitionProjection>(legacy_p_alias)
                .is_err(),
            "the cyclic P field name must not deserialize as a Q alias"
        );
        let mut unknown_protocol = serde_json::to_value(browser).unwrap();
        unknown_protocol
            .as_object_mut()
            .unwrap()
            .insert("fallback_protocol".into(), json!(true));
        assert!(
            serde_json::from_value::<AuthenticatorProtocolBindingProjection>(unknown_protocol)
                .is_err()
        );
    }

    #[test]
    fn authenticator_runtime_binding_has_an_independent_golden_and_leaf_drift() {
        let binding = authenticator_runtime_binding(
            "provider:fixture-oidc",
            ProductionAuthenticatorKind::Oidc,
        );
        let browser_state_digest = authenticator_browser_state_authority_digest();
        assert_independent_canonical_golden(
            authenticator_runtime_binding_canonical_bytes(&binding).unwrap(),
            json!({
                "digest_contract": "ryuki-authenticator-runtime-binding-v2",
                "runtime_binding": {
                    "provider": {
                        "provider_id": "provider:fixture-oidc",
                        "configuration_version": 1,
                        "configuration_payload_digest": fixture_digest('1'),
                        "lifecycle_record_version": 1,
                        "lifecycle_state": "active",
                        "capability_descriptor_id": "capability-descriptor:fixture-provider",
                        "capability_descriptor_version": 1,
                        "adapter_kind": "auth.entra-id",
                        "adapter_version": "1.0.0"
                    },
                    "binding_document_reference": {
                        "document_id": "authenticator-runtime-binding:fixture-oidc",
                        "document_version": 1,
                        "content_digest": fixture_digest('2'),
                        "artifact_locator": "catalog/security-contracts/v1/authenticator-runtime-binding.fixture.json"
                    },
                    "authenticator_kind": "oidc",
                    "provider_policy_binding_digest": fixture_digest('b'),
                    "capability_ids": ["browser-sso", "token-validation"],
                    "credential_paths": [
                        {
                            "path_id": "authenticator-path:api-bearer",
                            "path_version": 1,
                            "verifier": {
                                "verifier_id": "authenticator-verifier:fixture-oidc-api-bearer",
                                "verifier_version": 1,
                                "issuer_binding_digest": fixture_digest('3'),
                                "audience_set_binding_digest": fixture_digest('4'),
                                "accepted_algorithm_ids": ["rs256"],
                                "required_claim_ids": ["aud", "exp", "iat", "iss", "nbf", "oid", "sub"],
                                "provider_subject_claim_id": "oid",
                                "key_source_kind": "jwt-jwks",
                                "key_source_binding_digest": fixture_digest('5'),
                                "expiration_required": true,
                                "not_before_required": true,
                                "issued_at_required": true,
                                "nonce_required": false,
                                "clock_skew_limit_id": "limit:authenticator.clock-skew",
                                "maximum_clock_skew_seconds": 60,
                                "redirects_allowed": false
                            },
                            "credential_profile": {
                                "profile_id": "credential-profile:fixture-oidc-api-bearer",
                                "profile_version": 1,
                                "token_profile": "jwt-access-token",
                                "carrier": "authorization-bearer",
                                "proof_binding": "bearer",
                                "replay": {
                                    "credential_reuse": "reusable-until-expiry",
                                    "credential_lifetime_limit_id": "limit:authenticator.oidc-access-token-lifetime",
                                    "maximum_credential_lifetime_seconds": 3600,
                                    "sender_constraint": "none",
                                    "presentation_replay_defense": "none",
                                    "nonce_binding": "none",
                                    "replay_store_binding_digest": null
                                }
                            },
                            "cache_partition_binding_digest": fixture_digest('c'),
                            "protocol_binding_digest": fixture_digest('6'),
                            "retained_consumer_ids": ["runtime-consumer:entra-bearer-request-admission"]
                        },
                        {
                            "path_id": "authenticator-path:browser-sso",
                            "path_version": 1,
                            "verifier": {
                                "verifier_id": "authenticator-verifier:fixture-oidc-browser-sso",
                                "verifier_version": 1,
                                "issuer_binding_digest": fixture_digest('3'),
                                "audience_set_binding_digest": fixture_digest('7'),
                                "accepted_algorithm_ids": ["rs256"],
                                "required_claim_ids": ["aud", "exp", "iss", "nbf", "nonce", "oid", "sub"],
                                "provider_subject_claim_id": "oid",
                                "key_source_kind": "jwt-jwks",
                                "key_source_binding_digest": fixture_digest('8'),
                                "expiration_required": true,
                                "not_before_required": true,
                                "issued_at_required": false,
                                "nonce_required": true,
                                "clock_skew_limit_id": "limit:authenticator.clock-skew",
                                "maximum_clock_skew_seconds": 60,
                                "redirects_allowed": false
                            },
                            "credential_profile": {
                                "profile_id": "credential-profile:fixture-oidc-browser-sso",
                                "profile_version": 1,
                                "token_profile": "oidc-id-token",
                                "carrier": "oauth-callback",
                                "proof_binding": "pkce-s256",
                                "replay": {
                                    "credential_reuse": "single-use",
                                    "credential_lifetime_limit_id": null,
                                    "maximum_credential_lifetime_seconds": null,
                                    "sender_constraint": "none",
                                    "presentation_replay_defense": "single-use-state",
                                    "nonce_binding": "oidc-login",
                                    "replay_store_binding_digest": browser_state_digest
                                }
                            },
                            "cache_partition_binding_digest": fixture_digest('d'),
                            "protocol_binding_digest": fixture_digest('a'),
                            "retained_consumer_ids": ["runtime-consumer:entra-browser-sso"]
                        }
                    ],
                    "ownership": {
                        "single_runtime_owner": true,
                        "ambient_reconfiguration_allowed": false
                    }
                }
            }),
        );
        let canonical = authenticator_runtime_binding_canonical_bytes(&binding).unwrap();
        let canonical_text = String::from_utf8(canonical).unwrap();
        assert!(!canonical_text.contains("identity.example"));
        assert!(!canonical_text.contains("tenant"));
        assert!(!canonical_text.contains("client"));

        let digest = authenticator_runtime_binding_digest(&binding).unwrap();
        let mut drifted = binding.clone();
        drifted.credential_paths[0]
            .verifier
            .maximum_clock_skew_seconds = 61;
        assert_ne!(
            authenticator_runtime_binding_digest(&drifted).unwrap(),
            digest
        );

        let mut reordered = binding.clone();
        reordered.credential_paths[0].retained_consumer_ids = vec![
            "runtime-consumer:zeta".into(),
            "runtime-consumer:alpha".into(),
        ];
        assert!(authenticator_runtime_binding_digest(&reordered).is_err());

        let mut reordered_paths = binding.clone();
        reordered_paths.credential_paths.swap(0, 1);
        assert!(authenticator_runtime_binding_digest(&reordered_paths).is_err());

        let mut duplicate_consumer = binding.clone();
        duplicate_consumer.credential_paths[1].retained_consumer_ids = duplicate_consumer
            .credential_paths[0]
            .retained_consumer_ids
            .clone();
        assert!(authenticator_runtime_binding_digest(&duplicate_consumer).is_err());

        let mut false_replay_claim = binding.clone();
        false_replay_claim.credential_paths[0]
            .credential_profile
            .replay
            .presentation_replay_defense = AuthenticatorPresentationReplayDefense::DurableJti;
        assert!(authenticator_runtime_binding_digest(&false_replay_claim).is_err());

        let mut coordinated_browser_relabel = binding.clone();
        coordinated_browser_relabel.credential_paths[0]
            .credential_profile
            .token_profile = "oidc-id-token".into();
        coordinated_browser_relabel.credential_paths[0]
            .credential_profile
            .carrier = AuthenticatorCredentialCarrier::OauthCallback;
        coordinated_browser_relabel.credential_paths[0]
            .credential_profile
            .proof_binding = AuthenticatorProofBinding::PkceS256;
        coordinated_browser_relabel.credential_paths[0]
            .credential_profile
            .replay = binding.credential_paths[1]
            .credential_profile
            .replay
            .clone();
        assert!(authenticator_runtime_binding_digest(&coordinated_browser_relabel).is_err());

        for required_claim in ["aud", "exp", "iat", "iss", "nbf", "sub"] {
            let mut missing_claim = binding.clone();
            missing_claim.credential_paths[0]
                .verifier
                .required_claim_ids
                .retain(|claim| claim != required_claim);
            assert!(
                authenticator_runtime_binding_digest(&missing_claim).is_err(),
                "missing {required_claim} must reject the access-token verifier"
            );
        }

        let mut missing_provider_subject = binding.clone();
        missing_provider_subject.credential_paths[0]
            .verifier
            .required_claim_ids
            .retain(|claim| claim != "oid");
        assert!(authenticator_runtime_binding_digest(&missing_provider_subject).is_err());

        let mut duplicate_cache_partition = binding.clone();
        duplicate_cache_partition.credential_paths[1].cache_partition_binding_digest =
            duplicate_cache_partition.credential_paths[0]
                .cache_partition_binding_digest
                .clone();
        assert!(authenticator_runtime_binding_digest(&duplicate_cache_partition).is_err());

        let mut duplicate_protocol_binding = binding.clone();
        duplicate_protocol_binding.credential_paths[1].protocol_binding_digest =
            duplicate_protocol_binding.credential_paths[0]
                .protocol_binding_digest
                .clone();
        assert!(authenticator_runtime_binding_digest(&duplicate_protocol_binding).is_err());

        let mut cache_protocol_collision = binding.clone();
        cache_protocol_collision.credential_paths[0].protocol_binding_digest =
            cache_protocol_collision.credential_paths[0]
                .cache_partition_binding_digest
                .clone();
        assert!(authenticator_runtime_binding_digest(&cache_protocol_collision).is_err());

        let mut unsupported_kind = binding.clone();
        unsupported_kind.authenticator_kind = ProductionAuthenticatorKind::Passkey;
        assert!(authenticator_runtime_binding_digest(&unsupported_kind).is_err());

        let mut empty_capabilities = binding.clone();
        empty_capabilities.capability_ids.clear();
        assert!(authenticator_runtime_binding_digest(&empty_capabilities).is_err());

        let mut unsupported_capability = binding.clone();
        unsupported_capability.capability_ids =
            vec!["password-auth".into(), "token-validation".into()];
        assert!(authenticator_runtime_binding_digest(&unsupported_capability).is_err());

        let mut unimplemented_dpop = binding.clone();
        unimplemented_dpop.credential_paths[0]
            .credential_profile
            .proof_binding = AuthenticatorProofBinding::Dpop;
        assert!(authenticator_runtime_binding_digest(&unimplemented_dpop).is_err());

        for confused_algorithm in ["none", "hs256"] {
            let mut algorithm_confusion = binding.clone();
            algorithm_confusion.credential_paths[0]
                .verifier
                .accepted_algorithm_ids = vec![confused_algorithm.into()];
            assert!(authenticator_runtime_binding_digest(&algorithm_confusion).is_err());
        }

        let mut generic_oidc_with_entra_subject = binding.clone();
        generic_oidc_with_entra_subject.provider.adapter_kind = "auth.generic-oidc".into();
        assert!(authenticator_runtime_binding_digest(&generic_oidc_with_entra_subject).is_err());
        for path in &mut generic_oidc_with_entra_subject.credential_paths {
            path.verifier.provider_subject_claim_id = "sub".into();
        }
        assert!(authenticator_runtime_binding_digest(&generic_oidc_with_entra_subject).is_ok());

        let mut bearer_only = binding.clone();
        bearer_only.credential_paths.truncate(1);
        assert!(
            authenticator_runtime_binding_digest(&bearer_only).is_err(),
            "browser-sso capability without a browser path must fail closed"
        );
        bearer_only.capability_ids = vec!["token-validation".into()];
        assert!(authenticator_runtime_binding_digest(&bearer_only).is_ok());
        let mut coordinated_relabel = bearer_only.clone();
        coordinated_relabel.credential_paths[0].verifier =
            binding.credential_paths[1].verifier.clone();
        coordinated_relabel.credential_paths[0].credential_profile =
            binding.credential_paths[1].credential_profile.clone();
        assert!(
            authenticator_runtime_binding_digest(&coordinated_relabel).is_err(),
            "a coordinated bearer/browser relabel under the bearer capability must fail closed"
        );

        let mut digest_collision = binding.clone();
        digest_collision.binding_document_reference.content_digest = digest_collision
            .provider
            .configuration_payload_digest
            .clone();
        assert!(authenticator_runtime_binding_digest(&digest_collision).is_err());

        let mut document_policy_collision = binding.clone();
        document_policy_collision
            .binding_document_reference
            .content_digest = document_policy_collision
            .provider_policy_binding_digest
            .clone();
        assert!(authenticator_runtime_binding_digest(&document_policy_collision).is_err());

        let mut provider_policy_collision = binding.clone();
        provider_policy_collision
            .provider
            .configuration_payload_digest = provider_policy_collision
            .provider_policy_binding_digest
            .clone();
        assert!(authenticator_runtime_binding_digest(&provider_policy_collision).is_err());

        let mut raw = serde_json::to_value(binding).unwrap();
        raw.as_object_mut()
            .unwrap()
            .insert("fallback".into(), json!(true));
        assert!(serde_json::from_value::<AuthenticatorRuntimeBindingProjection>(raw).is_err());

        let mut missing_explicit_null = serde_json::to_value(bearer_only).unwrap();
        missing_explicit_null["credential_paths"][0]["credential_profile"]["replay"]
            .as_object_mut()
            .unwrap()
            .remove("replay_store_binding_digest");
        assert!(
            serde_json::from_value::<AuthenticatorRuntimeBindingProjection>(missing_explicit_null)
                .is_err()
        );

        let v1 = json!({
            "provider": expected_provider_binding("provider:fixture-oidc"),
            "authenticator_kind": "oidc",
            "verifier": {},
            "credential_profile": {},
            "retained_consumer_ids": ["runtime-consumer:api-admission"],
            "ownership": {
                "single_runtime_owner": true,
                "ambient_reconfiguration_allowed": false
            }
        });
        assert!(serde_json::from_value::<AuthenticatorRuntimeBindingProjection>(v1).is_err());
    }

    #[test]
    fn authenticator_provider_policy_binding_is_exact_and_reference_independent() {
        let kind_config = json!({
            "configuration_kind": "oidc",
            "validation_mode": "jwt-jwks",
            "accepted_algorithms": ["RS256", "PS256"],
            "runtime_binding_ref": {
                "document_id": "authenticator-runtime-binding:fixture-oidc",
                "document_version": 1,
                "content_digest": fixture_digest('a'),
                "artifact_locator": "catalog/security-contracts/v1/authenticator-runtime-binding.fixture.json"
            }
        });

        assert_independent_canonical_golden(
            authenticator_provider_policy_binding_canonical_bytes(&kind_config).unwrap(),
            json!({
                "digest_contract": "ryuki-authenticator-provider-policy-binding-v1",
                "kind_config": {
                    "configuration_kind": "oidc",
                    "validation_mode": "jwt-jwks",
                    "accepted_algorithms": ["RS256", "PS256"]
                }
            }),
        );

        let digest = authenticator_provider_policy_binding_digest(&kind_config).unwrap();
        let mut reference_drift = kind_config.clone();
        reference_drift["runtime_binding_ref"]["content_digest"] =
            Value::String(fixture_digest('b'));
        assert_eq!(
            authenticator_provider_policy_binding_digest(&reference_drift).unwrap(),
            digest,
            "Q must exclude only the top-level D reference"
        );

        let mut leaf_drift = kind_config.clone();
        leaf_drift["validation_mode"] = json!("authenticated-introspection");
        assert_ne!(
            authenticator_provider_policy_binding_digest(&leaf_drift).unwrap(),
            digest,
            "every non-reference provider-policy leaf must remain bound"
        );

        let mut reordered_algorithms = kind_config.clone();
        reordered_algorithms["accepted_algorithms"] = json!(["PS256", "RS256"]);
        assert_ne!(
            authenticator_provider_policy_binding_digest(&reordered_algorithms).unwrap(),
            digest,
            "provider-policy arrays must not be normalized or reordered"
        );

        assert!(authenticator_provider_policy_binding_digest(&json!([])).is_err());
    }

    #[test]
    fn external_signing_contracts_bind_key_identity_keyring_and_active_selection() {
        let purpose = external_signing_purpose_binding(
            "signing-purpose:control-plane-grants",
            SigningAlgorithm::Ed25519,
            ExternalKeyCustodyKind::Kms,
            'c',
        );
        let identity = &purpose.keys[0].identity;
        let expected_identity = json!({
            "provider": {
                "provider_id": "provider:fixture-key-custodian",
                "configuration_version": 1,
                "configuration_payload_digest": fixture_digest('1'),
                "lifecycle_record_version": 1,
                "lifecycle_state": "active",
                "capability_descriptor_id": "capability-descriptor:fixture-provider",
                "capability_descriptor_version": 1,
                "adapter_kind": "fixture.provider",
                "adapter_version": "1.0.0"
            },
            "provider_runtime_binding_digest": fixture_digest('b'),
            "deployment_id": "deployment:fixture",
            "trust_domain_id": "trust-domain:fixture",
            "protocol_version": "1.0.0",
            "purpose_id": "signing-purpose:control-plane-grants",
            "algorithm": "ed25519",
            "custody_kind": "kms",
            "key_id": "signing-key:control-plane-grants-v1",
            "key_version": 1,
            "public_or_opaque_metadata_digest": fixture_digest('c'),
            "disposition": "active"
        });
        assert_independent_canonical_golden(
            external_signing_key_identity_canonical_bytes(identity).unwrap(),
            json!({
                "digest_contract": "ryuki-external-signing-key-identity-v1",
                "key_identity": expected_identity.clone()
            }),
        );
        assert_independent_canonical_golden(
            external_signing_inventory_canonical_bytes(std::slice::from_ref(&purpose)).unwrap(),
            json!({
                "digest_contract": "ryuki-external-signing-inventory-v1",
                "purposes": [{
                    "purpose_id": "signing-purpose:control-plane-grants",
                    "algorithm": "ed25519",
                    "custody_kind": "kms",
                    "active_key_version": 1,
                    "keys": [{
                        "key_identity_digest": purpose.keys[0].key_identity_digest.clone(),
                        "identity": expected_identity
                    }]
                }]
            }),
        );
        assert_eq!(
            external_signing_active_key_identity_digest(&purpose).unwrap(),
            purpose.keys[0].key_identity_digest.clone()
        );

        let original_inventory_digest =
            external_signing_inventory_digest(std::slice::from_ref(&purpose)).unwrap();
        let mut drifted = purpose.clone();
        drifted.keys[0].identity.public_or_opaque_metadata_digest = fixture_digest('d');
        assert!(
            external_signing_inventory_digest(std::slice::from_ref(&drifted)).is_err(),
            "a copied key-identity digest cannot authorize changed leaves"
        );
        drifted.keys[0].key_identity_digest =
            external_signing_key_identity_digest(&drifted.keys[0].identity).unwrap();
        assert_ne!(
            external_signing_inventory_digest(std::slice::from_ref(&drifted)).unwrap(),
            original_inventory_digest
        );

        let mut purposes = vec![
            purpose,
            external_signing_purpose_binding(
                "signing-purpose:session-credentials",
                SigningAlgorithm::HmacSha256,
                ExternalKeyCustodyKind::Hsm,
                'd',
            ),
        ];
        purposes.swap(0, 1);
        assert!(external_signing_inventory_digest(&purposes).is_err());
    }

    #[test]
    fn dependency_component_and_inventory_have_independent_canonical_goldens() {
        let runtime_bindings = production_dependency_runtime_bindings();
        assert_independent_canonical_golden(
            production_dependency_component_binding_canonical_bytes(&runtime_bindings[0]).unwrap(),
            json!({
                "digest_contract": "ryuki-production-dependency-component-binding-v1",
                "component_binding": {
                    "component_id": "runtime-component:database",
                    "implementation_id": "runtime-implementation:postgresql",
                    "implementation_version": "18.0.0",
                    "production_posture": "production",
                    "authority_mode": "live",
                    "fallback_allowed": false,
                    "authority_bindings": [
                        {
                            "binding_id": "runtime-binding:database-identity",
                            "binding_contract": "ryuki-postgresql-database-identity-v1",
                            "binding_digest": fixture_digest('c')
                        },
                        {
                            "binding_id": "runtime-binding:provider-route",
                            "binding_contract": "ryuki-postgresql-provider-route-binding-v1",
                            "binding_digest": fixture_digest('d')
                        }
                    ],
                    "retained_consumer_ids": [
                        "runtime-consumer:api-audit",
                        "runtime-consumer:api-requests"
                    ],
                    "ownership": {
                        "runtime_owner_id": "runtime-owner:api-database",
                        "single_runtime_owner": true,
                        "ambient_reconfiguration_allowed": false
                    }
                }
            }),
        );

        let measured = measure_production_dependency_inventory(&runtime_bindings).unwrap();
        let database_binding_digest =
            production_dependency_component_binding_digest(&runtime_bindings[0]).unwrap();
        let secret_provider_binding_digest =
            production_dependency_component_binding_digest(&runtime_bindings[1]).unwrap();
        assert_independent_canonical_golden(
            production_dependency_inventory_canonical_bytes(&measured.dependencies).unwrap(),
            json!({
                "digest_contract": "ryuki-production-dependency-inventory-v1",
                "dependencies": [
                    {
                        "component_id": "runtime-component:database",
                        "implementation_id": "runtime-implementation:postgresql",
                        "implementation_version": "18.0.0",
                        "production_posture": "production",
                        "authority_mode": "live",
                        "fallback_allowed": false,
                        "component_binding_digest": database_binding_digest
                    },
                    {
                        "component_id": "runtime-component:secret-provider",
                        "implementation_id": "runtime-implementation:openbao",
                        "implementation_version": "2.3.0",
                        "production_posture": "production",
                        "authority_mode": "live",
                        "fallback_allowed": false,
                        "component_binding_digest": secret_provider_binding_digest
                    }
                ]
            }),
        );
        assert_eq!(
            measured.required_component_ids,
            vec![
                "runtime-component:database".to_string(),
                "runtime-component:secret-provider".to_string(),
            ]
        );
        assert_eq!(
            measured.dependency_inventory_digest,
            production_dependency_inventory_digest(&measured.dependencies).unwrap()
        );
    }

    #[test]
    fn dependency_measurement_binds_every_runtime_leaf_and_fails_closed() {
        let dependencies = production_dependency_runtime_bindings();
        let original = measure_production_dependency_inventory(&dependencies).unwrap();

        for changed_identity in [
            {
                let mut candidate = dependencies.clone();
                candidate[0].component_id = "runtime-component:database-primary".into();
                candidate
            },
            {
                let mut candidate = dependencies.clone();
                candidate[0].implementation_id = "runtime-implementation:postgresql-proxy".into();
                candidate
            },
            {
                let mut candidate = dependencies.clone();
                candidate[0].implementation_version = "18.1.0".into();
                candidate
            },
            {
                let mut candidate = dependencies.clone();
                candidate[0].authority_bindings[0].binding_id =
                    "runtime-binding:database-identity-v2".into();
                candidate
            },
            {
                let mut candidate = dependencies.clone();
                candidate[0].ownership.runtime_owner_id = "runtime-owner:api-database-v2".into();
                candidate
            },
        ] {
            let changed = measure_production_dependency_inventory(&changed_identity)
                .expect("valid identity drift must remain measurable");
            assert_ne!(
                changed.dependency_inventory_digest,
                original.dependency_inventory_digest
            );
        }

        let mut drifted = dependencies.clone();
        drifted[0].authority_bindings[0].binding_digest = fixture_digest('f');
        let drifted_measurement = measure_production_dependency_inventory(&drifted).unwrap();
        assert_ne!(
            drifted_measurement.dependencies[0].component_binding_digest,
            original.dependencies[0].component_binding_digest
        );
        assert_ne!(
            drifted_measurement.dependency_inventory_digest,
            original.dependency_inventory_digest
        );

        let mut changed_consumer = dependencies.clone();
        changed_consumer[0].retained_consumer_ids[1] = "runtime-consumer:api-scheduler".into();
        assert_ne!(
            measure_production_dependency_inventory(&changed_consumer)
                .unwrap()
                .dependency_inventory_digest,
            original.dependency_inventory_digest
        );

        let mut reordered_consumers = dependencies.clone();
        reordered_consumers[0].retained_consumer_ids.swap(0, 1);
        assert!(measure_production_dependency_inventory(&reordered_consumers).is_err());

        let mut ambient_owner = dependencies.clone();
        ambient_owner[0].ownership.ambient_reconfiguration_allowed = true;
        assert!(measure_production_dependency_inventory(&ambient_owner).is_err());

        let mut shared_owner = dependencies.clone();
        shared_owner[0].ownership.single_runtime_owner = false;
        assert!(measure_production_dependency_inventory(&shared_owner).is_err());

        let mut recursive_contract = dependencies.clone();
        recursive_contract[0].authority_bindings[0].binding_contract =
            PRODUCTION_DEPENDENCY_INVENTORY_DIGEST_CONTRACT.into();
        assert!(measure_production_dependency_inventory(&recursive_contract).is_err());

        let mut reordered_authority = dependencies.clone();
        reordered_authority[0].authority_bindings.swap(0, 1);
        assert!(measure_production_dependency_inventory(&reordered_authority).is_err());

        let mut duplicate_authority_digest = dependencies.clone();
        duplicate_authority_digest[0].authority_bindings[1].binding_digest =
            duplicate_authority_digest[0].authority_bindings[0]
                .binding_digest
                .clone();
        assert!(measure_production_dependency_inventory(&duplicate_authority_digest).is_err());

        let mut duplicated_owner = dependencies.clone();
        duplicated_owner[1].ownership.runtime_owner_id =
            duplicated_owner[0].ownership.runtime_owner_id.clone();
        assert!(measure_production_dependency_inventory(&duplicated_owner).is_err());

        let mut invalid_consumer = dependencies.clone();
        invalid_consumer[0].retained_consumer_ids = vec!["api-audit".into()];
        assert!(measure_production_dependency_inventory(&invalid_consumer).is_err());

        let mut copied_outer_row = original.dependencies.clone();
        copied_outer_row[0].fallback_allowed = true;
        assert!(production_dependency_inventory_digest(&copied_outer_row).is_err());

        let mut stale_row = original.dependencies[0].clone();
        stale_row.component_binding_digest = fixture_digest('9');
        assert!(
            validate_production_dependency_component_preimage(&stale_row, &dependencies[0])
                .is_err()
        );
        let crosswired_row = original.dependencies[1].clone();
        assert!(
            validate_production_dependency_component_preimage(&crosswired_row, &dependencies[0])
                .is_err()
        );

        let mut reordered = dependencies;
        reordered.swap(0, 1);
        assert!(measure_production_dependency_inventory(&reordered).is_err());
        assert!(measure_production_dependency_inventory(&[]).is_err());
    }

    #[test]
    fn dependency_runtime_binding_rejects_derived_guard_contracts() {
        for forbidden_contract in [
            RUNTIME_GUARD_REQUIREMENT_BINDING_DIGEST_CONTRACT,
            RUNTIME_GUARD_SEMANTIC_CHALLENGE_BINDING_DIGEST_CONTRACT,
        ] {
            let mut dependency = production_dependency_runtime_bindings().remove(0);
            dependency.authority_bindings[0].binding_contract = forbidden_contract.into();

            assert_eq!(
                production_dependency_component_binding_canonical_bytes(&dependency),
                Err(RuntimeGuardDigestError::InvalidProjection(
                    "production dependency runtime binding"
                )),
                "derived guard contract {forbidden_contract} must not be admitted as an authority binding"
            );
        }
    }

    #[test]
    fn dependency_runtime_binding_requires_a_retained_consumer() {
        let mut dependency = production_dependency_runtime_bindings().remove(0);
        dependency.retained_consumer_ids.clear();

        assert_eq!(
            production_dependency_component_binding_canonical_bytes(&dependency),
            Err(RuntimeGuardDigestError::InvalidProjection(
                "production dependency runtime binding"
            ))
        );
    }

    #[test]
    fn first_owner_contracts_bind_namespace_and_immutable_closure_leaves() {
        let namespace = first_owner_authority_namespace("deployment:fixture");
        assert_independent_canonical_golden(
            first_owner_authority_namespace_canonical_bytes(&namespace).unwrap(),
            json!({
                "digest_contract": "ryuki-first-owner-authority-namespace-v1",
                "authority_namespace": {
                    "state_contract_version": 1,
                    "deployment_id": "deployment:fixture",
                    "trust_domain_ids": ["trust-domain:fixture"],
                    "tenancy_mode": "single_tenant",
                    "tenant_id": null,
                    "authority_id": "first-owner-authority:fixture",
                    "authority_key_id": "first-owner-authority-key:fixture",
                    "authority_public_key_fingerprint": fixture_digest('e'),
                    "authority_epoch": 1,
                    "namespace_id": "first-owner-namespace:fixture"
                }
            }),
        );
        let namespace_digest = first_owner_authority_namespace_digest(&namespace).unwrap();
        let closure = first_owner_closure_record("deployment:fixture", &namespace_digest);
        assert_independent_canonical_golden(
            first_owner_closure_record_canonical_bytes(&closure).unwrap(),
            json!({
                "digest_contract": "ryuki-first-owner-closure-record-v1",
                "closure_record": {
                    "state_contract_version": 1,
                    "deployment_id": "deployment:fixture",
                    "authority_namespace_digest": namespace_digest,
                    "status": "closed",
                    "closure_event_id": "first-owner-closure-event:fixture",
                    "authority_sequence": 1,
                    "first_owner_principal_id": "principal:fixture-owner",
                    "claim_request_digest": fixture_digest('f'),
                    "capability_id": "first-owner-capability:fixture",
                    "capability_expires_at": "2026-07-16T01:00:00Z",
                    "closed_at_not_before": "2026-07-16T00:00:00Z",
                    "closed_at_not_after": "2026-07-16T00:00:01Z",
                    "closure_certificate_digest": fixture_digest('1')
                }
            }),
        );
        let closure_digest = first_owner_closure_record_digest(&closure).unwrap();
        let mut drifted_closure = closure.clone();
        drifted_closure.claim_request_digest = fixture_digest('2');
        assert_ne!(
            first_owner_closure_record_digest(&drifted_closure).unwrap(),
            closure_digest
        );
        drifted_closure.closed_at_not_after = "2026-07-16T02:00:00Z".into();
        assert!(first_owner_closure_record_digest(&drifted_closure).is_err());

        let mut fractional_timestamp = closure.clone();
        fractional_timestamp.closed_at_not_after = "2026-07-16T00:00:01.001Z".into();
        assert!(first_owner_closure_record_digest(&fractional_timestamp).is_err());

        let mut maximum_sequence = closure.clone();
        maximum_sequence.authority_sequence = FIRST_OWNER_MAX_EXACT_JSON_INTEGER;
        assert!(first_owner_closure_record_digest(&maximum_sequence).is_ok());

        let mut oversized_sequence = closure;
        oversized_sequence.authority_sequence = FIRST_OWNER_MAX_EXACT_JSON_INTEGER + 1;
        assert!(first_owner_closure_record_digest(&oversized_sequence).is_err());

        let mut oversized_namespace = namespace.clone();
        oversized_namespace.authority_epoch = FIRST_OWNER_MAX_EXACT_JSON_INTEGER + 1;
        assert!(first_owner_authority_namespace_digest(&oversized_namespace).is_err());

        let mut maximum_namespace = namespace.clone();
        maximum_namespace.authority_epoch = FIRST_OWNER_MAX_EXACT_JSON_INTEGER;
        assert!(first_owner_authority_namespace_digest(&maximum_namespace).is_ok());

        let mut unsorted_namespace = namespace;
        unsorted_namespace.trust_domain_ids =
            vec!["trust-domain:zeta".into(), "trust-domain:alpha".into()];
        assert!(first_owner_authority_namespace_digest(&unsorted_namespace).is_err());
    }

    #[test]
    fn first_owner_certificate_has_exact_canonical_signature_and_digest_contracts() {
        let (certificate, signing_key) = first_owner_certificate_fixture();
        let public_key = signing_key.verifying_key().to_bytes();
        let public_key_fingerprint = sha256_bytes_digest(&public_key);
        let authority = FirstOwnerCertificateAuthorityAnchor {
            authority_id: "first-owner-authority:fixture",
            authority_key_id: "first-owner-authority-key:fixture",
            public_key: &public_key,
            public_key_fingerprint: &public_key_fingerprint,
            minimum_authority_epoch: 1,
        };

        let canonical = first_owner_closure_certificate_canonical_bytes(&certificate).unwrap();
        assert!(canonical.len() <= FIRST_OWNER_CLOSURE_CERTIFICATE_MAX_BYTES);
        assert_eq!(
            parse_first_owner_closure_certificate(&canonical).unwrap(),
            certificate
        );
        let verified = verify_first_owner_closure_certificate(&certificate, authority).unwrap();
        assert_eq!(
            verified.certificate_digest(),
            first_owner_closure_certificate_digest(&certificate).unwrap()
        );
        assert_eq!(
            verified.authority_namespace_digest(),
            certificate.closure.authority_namespace_digest
        );
        assert_eq!(
            verified.signature_digest(),
            first_owner_closure_certificate_signature_digest(&certificate).unwrap()
        );
        let closure_record = first_owner_closure_record_from_certificate(&certificate).unwrap();
        assert_eq!(
            verified.closure_record_digest(),
            first_owner_closure_record_digest(&closure_record).unwrap()
        );
        assert_eq!(
            closure_record.closure_certificate_digest,
            verified.certificate_digest()
        );

        let unsigned =
            first_owner_closure_certificate_unsigned_canonical_bytes(&certificate).unwrap();
        let signing_bytes = first_owner_closure_certificate_signing_bytes(&certificate).unwrap();
        let domain = FIRST_OWNER_CLOSURE_CERTIFICATE_SIGNATURE_DOMAIN.as_bytes();
        assert_eq!(
            &signing_bytes[..8],
            &(u64::try_from(domain.len()).unwrap()).to_le_bytes()
        );
        assert_eq!(&signing_bytes[8..8 + domain.len()], domain);
        let second_frame_offset = 8 + domain.len();
        assert_eq!(
            &signing_bytes[second_frame_offset..second_frame_offset + 8],
            &(u64::try_from(unsigned.len()).unwrap()).to_le_bytes()
        );
        assert_eq!(&signing_bytes[second_frame_offset + 8..], unsigned);
    }

    #[test]
    fn first_owner_signing_preimage_matches_a_fixed_manual_golden() {
        const GOLDEN_NAMESPACE_DIGEST: &str =
            "sha256:0de0f4059499e1296bf351368d6a1b91ba216289966e0c7620dcab63578cf0f1";
        const GOLDEN_UNSIGNED: &str = concat!(
            "{\"authority_namespace\":{\"authority_epoch\":7,",
            "\"authority_id\":\"first-owner-authority:golden\",",
            "\"authority_key_id\":\"first-owner-authority-key:golden\",",
            "\"authority_public_key_fingerprint\":\"sha256:",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",",
            "\"deployment_id\":\"deployment:golden\",",
            "\"namespace_id\":\"first-owner-namespace:golden\",",
            "\"state_contract_version\":1,\"tenancy_mode\":\"single_tenant\",",
            "\"tenant_id\":null,\"trust_domain_ids\":[\"trust-domain:golden\"]},",
            "\"canonicalization\":\"ryuki-canonical-json-v1\",",
            "\"closure\":{\"authority_namespace_digest\":\"",
            "sha256:0de0f4059499e1296bf351368d6a1b91ba216289966e0c7620dcab63578cf0f1\",",
            "\"authority_sequence\":11,",
            "\"capability_expires_at\":\"2026-08-03T12:05:00Z\",",
            "\"capability_id\":\"first-owner-capability:golden\",",
            "\"claim_request_digest\":\"sha256:",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",",
            "\"closed_at_not_after\":\"2026-08-03T12:00:01Z\",",
            "\"closed_at_not_before\":\"2026-08-03T12:00:00Z\",",
            "\"closure_event_id\":\"first-owner-closure-event:golden\",",
            "\"deployment_id\":\"deployment:golden\",",
            "\"first_owner_principal_id\":\"principal:golden-owner\",",
            "\"state_contract_version\":1,\"status\":\"closed\"},",
            "\"contract_kind\":\"first-owner-closure-certificate\",",
            "\"privileged_domain_assignments\":[",
            "{\"assignment_event_id\":\"first-owner-assignment-event:event-0\",",
            "\"domain_id\":\"audit-administration\",\"principal_id\":\"principal:golden-owner\"},",
            "{\"assignment_event_id\":\"first-owner-assignment-event:event-1\",",
            "\"domain_id\":\"identity-administration\",\"principal_id\":\"principal:golden-owner\"},",
            "{\"assignment_event_id\":\"first-owner-assignment-event:event-2\",",
            "\"domain_id\":\"live-execution-administration\",",
            "\"principal_id\":\"principal:golden-owner\"},",
            "{\"assignment_event_id\":\"first-owner-assignment-event:event-3\",",
            "\"domain_id\":\"policy-administration\",\"principal_id\":\"principal:golden-owner\"},",
            "{\"assignment_event_id\":\"first-owner-assignment-event:event-4\",",
            "\"domain_id\":\"secret-key-custody\",\"principal_id\":\"principal:golden-owner\"}],",
            "\"schema_version\":\"1.0.0\",\"signature_algorithm\":\"ed25519\"}"
        );
        let certificate = FirstOwnerClosureCertificate {
            schema_version: "1.0.0".into(),
            contract_kind: "first-owner-closure-certificate".into(),
            canonicalization: "ryuki-canonical-json-v1".into(),
            signature_algorithm: "ed25519".into(),
            authority_namespace: FirstOwnerAuthorityNamespace {
                state_contract_version: 1,
                deployment_id: "deployment:golden".into(),
                trust_domain_ids: vec!["trust-domain:golden".into()],
                tenancy_mode: TenancyMode::SingleTenant,
                tenant_id: None,
                authority_id: "first-owner-authority:golden".into(),
                authority_key_id: "first-owner-authority-key:golden".into(),
                authority_public_key_fingerprint: fixture_digest('a'),
                authority_epoch: 7,
                namespace_id: "first-owner-namespace:golden".into(),
            },
            closure: SignedFirstOwnerClosure {
                state_contract_version: 1,
                deployment_id: "deployment:golden".into(),
                authority_namespace_digest: GOLDEN_NAMESPACE_DIGEST.into(),
                status: FirstOwnerClosureStatus::Closed,
                closure_event_id: "first-owner-closure-event:golden".into(),
                authority_sequence: 11,
                first_owner_principal_id: "principal:golden-owner".into(),
                claim_request_digest: fixture_digest('b'),
                capability_id: "first-owner-capability:golden".into(),
                capability_expires_at: "2026-08-03T12:05:00Z".into(),
                closed_at_not_before: "2026-08-03T12:00:00Z".into(),
                closed_at_not_after: "2026-08-03T12:00:01Z".into(),
            },
            privileged_domain_assignments: vec![
                SignedPrivilegedDomainAssignment {
                    assignment_event_id: "first-owner-assignment-event:event-0".into(),
                    domain_id: "audit-administration".into(),
                    principal_id: "principal:golden-owner".into(),
                },
                SignedPrivilegedDomainAssignment {
                    assignment_event_id: "first-owner-assignment-event:event-1".into(),
                    domain_id: "identity-administration".into(),
                    principal_id: "principal:golden-owner".into(),
                },
                SignedPrivilegedDomainAssignment {
                    assignment_event_id: "first-owner-assignment-event:event-2".into(),
                    domain_id: "live-execution-administration".into(),
                    principal_id: "principal:golden-owner".into(),
                },
                SignedPrivilegedDomainAssignment {
                    assignment_event_id: "first-owner-assignment-event:event-3".into(),
                    domain_id: "policy-administration".into(),
                    principal_id: "principal:golden-owner".into(),
                },
                SignedPrivilegedDomainAssignment {
                    assignment_event_id: "first-owner-assignment-event:event-4".into(),
                    domain_id: "secret-key-custody".into(),
                    principal_id: "principal:golden-owner".into(),
                },
            ],
            signature_base64: BASE64_STANDARD.encode([0_u8; 64]),
        };

        assert_eq!(GOLDEN_UNSIGNED.len(), 1_950);
        assert_eq!(
            first_owner_closure_certificate_unsigned_canonical_bytes(&certificate).unwrap(),
            GOLDEN_UNSIGNED.as_bytes()
        );
        let mut expected =
            b"\x28\x00\x00\x00\x00\x00\x00\x00ryuki-v1/first-owner-closure-certificate\x9e\x07\x00\x00\x00\x00\x00\x00"
                .to_vec();
        expected.extend_from_slice(GOLDEN_UNSIGNED.as_bytes());
        assert_eq!(
            first_owner_closure_certificate_signing_bytes(&certificate).unwrap(),
            expected
        );
    }

    #[test]
    fn first_owner_certificate_schema_and_serde_close_every_object_shape() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../catalog/security-contracts/v1/first-owner-closure-certificate.schema.json"
        ))
        .expect("first-owner closure certificate schema must be JSON");
        let validator = jsonschema::draft202012::options()
            .build(&schema)
            .expect("first-owner closure certificate schema must compile");
        let (certificate, _) = first_owner_certificate_fixture();
        let value = serde_json::to_value(&certificate).unwrap();
        assert!(validator.is_valid(&value));

        let mut unknown = value.clone();
        unknown["unexpected"] = json!(true);
        assert!(!validator.is_valid(&unknown));
        let unknown_bytes = canonical_json_bytes(&unknown).unwrap();
        assert_eq!(
            parse_first_owner_closure_certificate(&unknown_bytes),
            Err(FirstOwnerClosureCertificateError::InvalidCertificate)
        );

        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove("contract_kind");
        assert!(!validator.is_valid(&missing));
        let missing_bytes = canonical_json_bytes(&missing).unwrap();
        assert_eq!(
            parse_first_owner_closure_certificate(&missing_bytes),
            Err(FirstOwnerClosureCertificateError::InvalidCertificate)
        );

        let canonical = first_owner_closure_certificate_canonical_bytes(&certificate).unwrap();
        let pretty = serde_json::to_vec_pretty(&certificate).unwrap();
        assert_eq!(
            parse_first_owner_closure_certificate(&pretty),
            Err(FirstOwnerClosureCertificateError::NonCanonicalCertificate)
        );
        let canonical_text = String::from_utf8(canonical).unwrap();
        let duplicate = canonical_text.replacen('{', "{\"schema_version\":\"1.0.0\",", 1);
        assert_eq!(
            parse_first_owner_closure_certificate(duplicate.as_bytes()),
            Err(FirstOwnerClosureCertificateError::InvalidCertificate)
        );

        let nested_duplicate = canonical_text.replacen(
            "\"authority_epoch\":1,",
            "\"authority_epoch\":1,\"authority_epoch\":1,",
            1,
        );
        assert_eq!(
            parse_first_owner_closure_certificate(nested_duplicate.as_bytes()),
            Err(FirstOwnerClosureCertificateError::InvalidCertificate)
        );
        assert_eq!(
            parse_first_owner_closure_certificate(&[]),
            Err(FirstOwnerClosureCertificateError::InvalidCertificate)
        );
        let oversized = vec![b' '; FIRST_OWNER_CLOSURE_CERTIFICATE_MAX_BYTES + 1];
        assert_eq!(
            parse_first_owner_closure_certificate(&oversized),
            Err(FirstOwnerClosureCertificateError::InvalidCertificate)
        );
    }

    #[test]
    fn first_owner_certificate_requires_the_exact_closed_domain_assignment_set() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../catalog/security-contracts/v1/first-owner-closure-certificate.schema.json"
        ))
        .unwrap();
        let validator = jsonschema::draft202012::options().build(&schema).unwrap();
        let (certificate, _) = first_owner_certificate_fixture();

        let mut reordered = certificate.clone();
        reordered.privileged_domain_assignments.reverse();
        assert!(first_owner_closure_certificate_canonical_bytes(&reordered).is_err());
        assert!(!validator.is_valid(&serde_json::to_value(&reordered).unwrap()));

        let mut duplicate_domain = certificate.clone();
        duplicate_domain.privileged_domain_assignments[1].domain_id =
            FIRST_OWNER_PRIVILEGED_DOMAINS[0].into();
        assert!(first_owner_closure_certificate_canonical_bytes(&duplicate_domain).is_err());
        assert!(!validator.is_valid(&serde_json::to_value(&duplicate_domain).unwrap()));

        let mut duplicate_event = certificate.clone();
        duplicate_event.privileged_domain_assignments[1].assignment_event_id = duplicate_event
            .privileged_domain_assignments[0]
            .assignment_event_id
            .clone();
        assert!(first_owner_closure_certificate_canonical_bytes(&duplicate_event).is_err());

        let mut wrong_principal = certificate;
        wrong_principal.privileged_domain_assignments[4].principal_id =
            "principal:substituted-owner".into();
        assert!(first_owner_closure_certificate_canonical_bytes(&wrong_principal).is_err());
    }

    #[test]
    fn first_owner_namespace_is_deployment_owned_in_both_tenancy_modes() {
        let (mut certificate, signing_key) = first_owner_certificate_fixture();
        certificate.authority_namespace.tenancy_mode = TenancyMode::MultiTenant;
        certificate.authority_namespace.tenant_id = None;
        certificate.closure.authority_namespace_digest =
            first_owner_authority_namespace_digest(&certificate.authority_namespace).unwrap();
        resign_first_owner_certificate(&mut certificate, &signing_key);
        assert!(first_owner_closure_certificate_canonical_bytes(&certificate).is_ok());

        let public_key = signing_key.verifying_key().to_bytes();
        let public_key_fingerprint = sha256_bytes_digest(&public_key);
        verify_first_owner_closure_certificate(
            &certificate,
            FirstOwnerCertificateAuthorityAnchor {
                authority_id: "first-owner-authority:fixture",
                authority_key_id: "first-owner-authority-key:fixture",
                public_key: &public_key,
                public_key_fingerprint: &public_key_fingerprint,
                minimum_authority_epoch: 1,
            },
        )
        .unwrap();

        certificate.authority_namespace.tenant_id = Some("tenant:forbidden".into());
        assert!(first_owner_authority_namespace_digest(&certificate.authority_namespace).is_err());
        assert!(first_owner_closure_certificate_canonical_bytes(&certificate).is_err());
    }

    #[test]
    fn first_owner_certificate_rejects_every_privileged_identifier_prefix_substitution() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../catalog/security-contracts/v1/first-owner-closure-certificate.schema.json"
        ))
        .unwrap();
        let validator = jsonschema::draft202012::options().build(&schema).unwrap();
        let (certificate, _) = first_owner_certificate_fixture();
        let assert_rejected = |candidate: &FirstOwnerClosureCertificate| {
            assert!(first_owner_closure_certificate_canonical_bytes(candidate).is_err());
            assert!(!validator.is_valid(&serde_json::to_value(candidate).unwrap()));
        };

        let mut wrong_authority = certificate.clone();
        wrong_authority.authority_namespace.authority_id = "runtime-authority:fixture".into();
        assert_rejected(&wrong_authority);

        let mut wrong_authority_key = certificate.clone();
        wrong_authority_key.authority_namespace.authority_key_id =
            "runtime-authority-key:fixture".into();
        assert_rejected(&wrong_authority_key);

        let mut wrong_namespace = certificate.clone();
        wrong_namespace.authority_namespace.namespace_id = "runtime-namespace:fixture".into();
        assert_rejected(&wrong_namespace);

        let mut wrong_closure_event = certificate.clone();
        wrong_closure_event.closure.closure_event_id = "domain-event:fixture".into();
        assert_rejected(&wrong_closure_event);

        let mut wrong_capability = certificate.clone();
        wrong_capability.closure.capability_id = "capability:fixture".into();
        assert_rejected(&wrong_capability);

        let mut wrong_principal = certificate.clone();
        wrong_principal.closure.first_owner_principal_id = "subject:fixture-owner".into();
        for assignment in &mut wrong_principal.privileged_domain_assignments {
            assignment.principal_id = "subject:fixture-owner".into();
        }
        assert_rejected(&wrong_principal);

        let mut wrong_assignment_event = certificate;
        wrong_assignment_event.privileged_domain_assignments[0].assignment_event_id =
            "domain-event:assignment".into();
        assert_rejected(&wrong_assignment_event);
    }

    #[test]
    fn first_owner_certificate_rejects_noncanonical_scalars_and_counter_bounds() {
        let (certificate, _) = first_owner_certificate_fixture();

        let mut invalid_signature = certificate.clone();
        invalid_signature.signature_base64 = "A".repeat(88);
        assert_eq!(
            first_owner_closure_certificate_canonical_bytes(&invalid_signature),
            Err(FirstOwnerClosureCertificateError::InvalidSignatureRepresentation)
        );

        let mut fractional_timestamp = certificate.clone();
        fractional_timestamp.closure.closed_at_not_after = "2026-07-16T00:00:01.001Z".into();
        assert!(first_owner_closure_certificate_canonical_bytes(&fractional_timestamp).is_err());

        let mut offset_timestamp = certificate.clone();
        offset_timestamp.closure.closed_at_not_after = "2026-07-16T02:00:01+02:00".into();
        assert!(first_owner_closure_certificate_canonical_bytes(&offset_timestamp).is_err());

        let mut invalid_timestamp = certificate.clone();
        invalid_timestamp.closure.closed_at_not_after = "2026-02-30T00:00:01Z".into();
        assert!(first_owner_closure_certificate_canonical_bytes(&invalid_timestamp).is_err());

        let mut leap_second = certificate.clone();
        leap_second.closure.closed_at_not_after = "2026-07-16T00:00:60Z".into();
        assert!(first_owner_closure_certificate_canonical_bytes(&leap_second).is_err());

        let mut zero_digest = certificate.clone();
        zero_digest.closure.claim_request_digest = fixture_digest('0');
        assert!(first_owner_closure_certificate_canonical_bytes(&zero_digest).is_err());

        let mut uppercase_digest = certificate.clone();
        uppercase_digest.closure.claim_request_digest = format!("sha256:{}", "A".repeat(64));
        assert!(first_owner_closure_certificate_canonical_bytes(&uppercase_digest).is_err());

        let mut zero_counter = certificate.clone();
        zero_counter.closure.authority_sequence = 0;
        assert!(first_owner_closure_certificate_canonical_bytes(&zero_counter).is_err());

        let mut maximum_counter = certificate.clone();
        maximum_counter.closure.authority_sequence = FIRST_OWNER_MAX_EXACT_JSON_INTEGER;
        assert!(first_owner_closure_certificate_canonical_bytes(&maximum_counter).is_ok());

        let mut oversized_counter = certificate;
        oversized_counter.closure.authority_sequence = FIRST_OWNER_MAX_EXACT_JSON_INTEGER + 1;
        assert!(first_owner_closure_certificate_canonical_bytes(&oversized_counter).is_err());
    }

    #[test]
    fn first_owner_signature_verification_uses_only_independent_exact_pins() {
        let (certificate, signing_key) = first_owner_certificate_fixture();
        let public_key = signing_key.verifying_key().to_bytes();
        let public_key_fingerprint = sha256_bytes_digest(&public_key);
        let authority = |minimum_authority_epoch| FirstOwnerCertificateAuthorityAnchor {
            authority_id: "first-owner-authority:fixture",
            authority_key_id: "first-owner-authority-key:fixture",
            public_key: &public_key,
            public_key_fingerprint: &public_key_fingerprint,
            minimum_authority_epoch,
        };
        assert!(verify_first_owner_closure_certificate(&certificate, authority(1)).is_ok());
        assert_eq!(
            verify_first_owner_closure_certificate(&certificate, authority(2)),
            Err(FirstOwnerClosureCertificateError::InvalidAuthorityBinding)
        );
        assert_eq!(
            verify_first_owner_closure_certificate(
                &certificate,
                FirstOwnerCertificateAuthorityAnchor {
                    authority_id: "first-owner-authority:substituted",
                    authority_key_id: "first-owner-authority-key:fixture",
                    public_key: &public_key,
                    public_key_fingerprint: &public_key_fingerprint,
                    minimum_authority_epoch: 1,
                },
            ),
            Err(FirstOwnerClosureCertificateError::InvalidAuthorityBinding)
        );
        assert_eq!(
            verify_first_owner_closure_certificate(
                &certificate,
                FirstOwnerCertificateAuthorityAnchor {
                    authority_id: "first-owner-authority:fixture",
                    authority_key_id: "first-owner-authority-key:substituted",
                    public_key: &public_key,
                    public_key_fingerprint: &public_key_fingerprint,
                    minimum_authority_epoch: 1,
                },
            ),
            Err(FirstOwnerClosureCertificateError::InvalidAuthorityBinding)
        );

        let mut forged_signature = certificate.clone();
        forged_signature.signature_base64 = BASE64_STANDARD.encode([0x42_u8; 64]);
        assert_eq!(
            verify_first_owner_closure_certificate(&forged_signature, authority(1)),
            Err(FirstOwnerClosureCertificateError::SignatureVerificationFailed)
        );

        let wrong_fingerprint = fixture_digest('a');
        assert_eq!(
            verify_first_owner_closure_certificate(
                &certificate,
                FirstOwnerCertificateAuthorityAnchor {
                    authority_id: "first-owner-authority:fixture",
                    authority_key_id: "first-owner-authority-key:fixture",
                    public_key: &public_key,
                    public_key_fingerprint: &wrong_fingerprint,
                    minimum_authority_epoch: 1,
                },
            ),
            Err(FirstOwnerClosureCertificateError::InvalidAuthorityBinding)
        );

        let mut weak_public_key = [0_u8; 32];
        // Canonical Edwards identity encoding: valid Ed25519 bytes, but a
        // small-order key that must never be admitted as an authority.
        weak_public_key[0] = 1;
        assert!(
            VerifyingKey::from_bytes(&weak_public_key)
                .unwrap()
                .is_weak()
        );
        let weak_fingerprint = sha256_bytes_digest(&weak_public_key);
        let mut weak_key_certificate = certificate;
        weak_key_certificate
            .authority_namespace
            .authority_public_key_fingerprint = weak_fingerprint.clone();
        weak_key_certificate.closure.authority_namespace_digest =
            first_owner_authority_namespace_digest(&weak_key_certificate.authority_namespace)
                .unwrap();
        assert_eq!(
            verify_first_owner_closure_certificate(
                &weak_key_certificate,
                FirstOwnerCertificateAuthorityAnchor {
                    authority_id: "first-owner-authority:fixture",
                    authority_key_id: "first-owner-authority-key:fixture",
                    public_key: &weak_public_key,
                    public_key_fingerprint: &weak_fingerprint,
                    minimum_authority_epoch: 1,
                },
            ),
            Err(FirstOwnerClosureCertificateError::InvalidAuthorityBinding)
        );
    }

    #[test]
    fn first_owner_install_capability_has_an_exclusive_expiry_boundary() {
        let (certificate, _) = first_owner_certificate_fixture();
        let instant = |hour, minute, second| {
            Utc.with_ymd_and_hms(2026, 7, 16, hour, minute, second)
                .unwrap()
        };
        assert!(
            !first_owner_closure_certificate_is_installable_at(&certificate, instant(0, 0, 0))
                .unwrap()
        );
        assert!(
            first_owner_closure_certificate_is_installable_at(&certificate, instant(0, 0, 1))
                .unwrap()
        );
        assert!(
            first_owner_closure_certificate_is_installable_at(&certificate, instant(0, 59, 59))
                .unwrap()
        );
        assert!(
            !first_owner_closure_certificate_is_installable_at(&certificate, instant(1, 0, 0))
                .unwrap()
        );
    }

    #[test]
    fn secret_provider_inventory_canonical_bytes_and_digest_match_independent_goldens() {
        let providers = all_secret_provider_bindings();
        let required_capability_ids = vec!["secret-read".into(), "secret-renew".into()];
        let canonical =
            secret_provider_inventory_canonical_bytes(&providers, &required_capability_ids)
                .unwrap();
        let expected = concat!(
            "{\"digest_contract\":\"ryuki-secret-provider-inventory-v1\",\"providers\":[",
            "{\"provider\":{\"adapter_kind\":\"fixture.provider\",",
            "\"adapter_version\":\"1.0.0\",",
            "\"capability_descriptor_id\":\"capability-descriptor:fixture-provider\",",
            "\"capability_descriptor_version\":1,",
            "\"configuration_payload_digest\":\"sha256:",
            "1111111111111111111111111111111111111111111111111111111111111111\",",
            "\"configuration_version\":1,\"lifecycle_record_version\":1,",
            "\"lifecycle_state\":\"active\",",
            "\"provider_id\":\"provider:fixture-secrets-primary\"},",
            "\"runtime_binding_digest\":\"sha256:",
            "2222222222222222222222222222222222222222222222222222222222222222\"},",
            "{\"provider\":{\"adapter_kind\":\"fixture.provider\",",
            "\"adapter_version\":\"1.0.0\",",
            "\"capability_descriptor_id\":\"capability-descriptor:fixture-provider\",",
            "\"capability_descriptor_version\":1,",
            "\"configuration_payload_digest\":\"sha256:",
            "1111111111111111111111111111111111111111111111111111111111111111\",",
            "\"configuration_version\":1,\"lifecycle_record_version\":1,",
            "\"lifecycle_state\":\"active\",",
            "\"provider_id\":\"provider:fixture-secrets-secondary\"},",
            "\"runtime_binding_digest\":\"sha256:",
            "3333333333333333333333333333333333333333333333333333333333333333\"}],",
            "\"required_capability_ids\":[\"secret-read\",\"secret-renew\"]}"
        );

        assert_eq!(canonical, expected.as_bytes());
        assert_eq!(
            secret_provider_inventory_digest(&providers, &required_capability_ids).unwrap(),
            "sha256:5212c7a278cf058f0dcda4cc4f9232a869460fba6ab3a8f431b52bdd77b7fa02"
        );
    }

    #[test]
    fn secret_provider_guard_rejects_inventory_membership_order_and_digest_drift() {
        let assert_invalid = |profile: DeploymentSecurityProfile, needle: &str| {
            let errors = profile.validate_structure_at(fixed_now());
            assert!(
                errors.iter().any(|error| error.contains(needle)),
                "expected {needle:?} in {errors:?}"
            );
        };

        let mut missing = structurally_complete_production_profile();
        secret_guard_parts(&mut missing).1.remove(0);
        assert_invalid(missing, "does not equal the canonical");

        let mut empty = structurally_complete_production_profile();
        secret_guard_parts(&mut empty).1.clear();
        assert_invalid(empty, "providers must not be empty");

        let mut extra = structurally_complete_production_profile();
        let extra_binding = ExpectedSecretProviderBinding {
            provider: expected_provider_binding("provider:fixture-secrets-tertiary"),
            runtime_binding_digest: fixture_digest('4'),
        };
        secret_guard_parts(&mut extra).1.push(extra_binding);
        assert_invalid(extra, "does not equal the canonical");

        let mut reordered = structurally_complete_production_profile();
        secret_guard_parts(&mut reordered).1.swap(0, 1);
        assert_invalid(reordered, "strictly sorted and unique by provider_id");

        let mut duplicate = structurally_complete_production_profile();
        let (_, providers, _) = secret_guard_parts(&mut duplicate);
        providers[1].provider = providers[0].provider.clone();
        assert_invalid(duplicate, "strictly sorted and unique by provider_id");

        let mut runtime_drift = structurally_complete_production_profile();
        secret_guard_parts(&mut runtime_drift).1[0].runtime_binding_digest = fixture_digest('9');
        assert_invalid(runtime_drift, "does not equal the canonical");

        let mut zero_runtime = structurally_complete_production_profile();
        secret_guard_parts(&mut zero_runtime).1[0].runtime_binding_digest = fixture_digest('0');
        assert_invalid(zero_runtime, "unresolved all-zero digest");

        let mut inventory_drift = structurally_complete_production_profile();
        *secret_guard_parts(&mut inventory_drift).0 = fixture_digest('f');
        assert_invalid(inventory_drift, "does not equal the canonical");

        let mut capability_drift = structurally_complete_production_profile();
        secret_guard_parts(&mut capability_drift).2[0] = "secret-admin".into();
        assert_invalid(capability_drift, "does not equal the canonical");

        let mut capability_reordered = structurally_complete_production_profile();
        secret_guard_parts(&mut capability_reordered).2.swap(0, 1);
        assert_invalid(capability_reordered, "strictly sorted and unique");

        let mut provider_substitution = structurally_complete_production_profile();
        secret_guard_parts(&mut provider_substitution).1[0]
            .provider
            .configuration_payload_digest = fixture_digest('8');
        assert_invalid(provider_substitution, "does not equal the canonical");
    }

    #[test]
    fn secret_provider_binding_requires_runtime_and_inventory_digests() {
        let provider = serde_json::to_value(expected_provider_binding(
            "provider:fixture-secrets-primary",
        ))
        .unwrap();
        assert!(
            serde_json::from_value::<ExpectedSecretProviderBinding>(json!({
                "provider": provider
            }))
            .is_err()
        );

        let mut expected_value = serde_json::to_value(expected_guard_value(
            GuardId::ApprovedSecretProvider,
            "unused",
        ))
        .unwrap();
        expected_value
            .as_object_mut()
            .unwrap()
            .remove("provider_inventory_digest");
        assert!(serde_json::from_value::<RuntimeGuardExpectedValue>(expected_value).is_err());
    }

    #[test]
    fn authenticator_inventory_digest_has_an_independent_six_class_golden() {
        let authenticators = all_authenticator_classes();
        let digest = authenticator_inventory_digest(&authenticators).unwrap();

        assert_eq!(
            digest,
            "sha256:23fb7bb3600280774c80985c20b6da77719b3b2b287ef5523247f60b38b39ac6"
        );

        let mut runtime_drift = authenticators;
        runtime_drift[0].runtime_binding_digest = fixture_digest('9');
        assert_ne!(
            authenticator_inventory_digest(&runtime_drift).unwrap(),
            digest
        );
    }

    #[test]
    fn authenticator_inventory_canonical_bytes_match_independent_golden() {
        let authenticators = vec![ExpectedAuthenticatorBinding {
            provider: expected_provider_binding("provider:fixture-oidc"),
            authenticator_kind: ProductionAuthenticatorKind::Oidc,
            runtime_binding_digest: fixture_digest('a'),
        }];
        let canonical = authenticator_inventory_canonical_bytes(&authenticators).unwrap();
        let expected = concat!(
            "{\"authenticators\":[{\"authenticator_kind\":\"oidc\",\"provider\":{",
            "\"adapter_kind\":\"fixture.provider\",\"adapter_version\":\"1.0.0\",",
            "\"capability_descriptor_id\":\"capability-descriptor:fixture-provider\",",
            "\"capability_descriptor_version\":1,",
            "\"configuration_payload_digest\":\"sha256:",
            "1111111111111111111111111111111111111111111111111111111111111111\",",
            "\"configuration_version\":1,\"lifecycle_record_version\":1,",
            "\"lifecycle_state\":\"active\",\"provider_id\":\"provider:fixture-oidc\"},",
            "\"runtime_binding_digest\":\"sha256:",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}],",
            "\"digest_contract\":\"ryuki-authenticator-inventory-v1\"}"
        );

        assert_eq!(canonical, expected.as_bytes());
        assert_eq!(
            authenticator_inventory_digest(&authenticators).unwrap(),
            "sha256:7d6e6f71af0b642cce32d0bb8caaf9bdf99ee6ee2ca71b6afd3a86bfdd403153"
        );
    }

    #[test]
    fn authenticator_guard_rejects_missing_human_legacy_labels_and_digest_drift() {
        let mut profile = structurally_complete_production_profile();
        let guard = profile
            .runtime_guard_evidence
            .guards
            .iter_mut()
            .find(|guard| guard.guard_id == GuardId::NonDevelopmentAuthenticator)
            .unwrap();
        let RuntimeGuardExpectedValue::NonDevelopmentAuthenticator {
            authenticator_inventory_digest,
            authenticators,
        } = &mut guard.expected_value
        else {
            unreachable!()
        };

        authenticators[0].authenticator_kind = ProductionAuthenticatorKind::Workload;
        *authenticator_inventory_digest =
            super::authenticator_inventory_digest(authenticators).unwrap();
        let errors = profile.validate_structure_at(fixed_now());
        assert!(
            errors
                .iter()
                .any(|error| error.contains("at least one human"))
        );

        let mut legacy = structurally_complete_production_profile();
        let guard = legacy
            .runtime_guard_evidence
            .guards
            .iter_mut()
            .find(|guard| guard.guard_id == GuardId::NonDevelopmentAuthenticator)
            .unwrap();
        let RuntimeGuardExpectedValue::NonDevelopmentAuthenticator {
            authenticator_inventory_digest,
            authenticators,
        } = &mut guard.expected_value
        else {
            unreachable!()
        };
        authenticators[0].authenticator_kind = ProductionAuthenticatorKind::Composite;
        *authenticator_inventory_digest =
            super::authenticator_inventory_digest(authenticators).unwrap();
        let errors = legacy.validate_structure_at(fixed_now());
        assert!(
            errors
                .iter()
                .any(|error| error.contains("legacy mutual-tls"))
        );

        let mut drifted = structurally_complete_production_profile();
        let guard = drifted
            .runtime_guard_evidence
            .guards
            .iter_mut()
            .find(|guard| guard.guard_id == GuardId::NonDevelopmentAuthenticator)
            .unwrap();
        let RuntimeGuardExpectedValue::NonDevelopmentAuthenticator { authenticators, .. } =
            &mut guard.expected_value
        else {
            unreachable!()
        };
        authenticators[0].runtime_binding_digest = fixture_digest('9');
        let errors = drifted.validate_structure_at(fixed_now());
        assert!(
            errors
                .iter()
                .any(|error| error.contains("does not equal the canonical"))
        );
    }

    #[test]
    fn authenticator_binding_requires_runtime_digest_but_parses_legacy_kind_for_denial() {
        let provider =
            serde_json::to_value(expected_provider_binding("provider:fixture-legacy")).unwrap();
        let missing_runtime_digest = json!({
            "provider": provider,
            "authenticator_kind": "oidc"
        });
        assert!(
            serde_json::from_value::<ExpectedAuthenticatorBinding>(missing_runtime_digest).is_err()
        );

        let legacy: ExpectedAuthenticatorBinding = serde_json::from_value(json!({
            "provider": expected_provider_binding("provider:fixture-legacy"),
            "authenticator_kind": "mutual-tls",
            "runtime_binding_digest": fixture_digest('8')
        }))
        .expect("legacy mechanism labels remain parser-visible for deterministic denial");
        assert!(legacy.authenticator_kind.is_legacy_mechanism());
    }

    #[test]
    fn migration_overlay_is_profile_bound_non_authoritative_and_time_bounded() {
        let mut profile = fixture();
        profile.migration_overlay = Some(MigrationOverlay {
            overlay_id: "migration-overlay:test-legacy-auth".into(),
            overlay_version: 1,
            security_profile: SecurityProfile::Test,
            authority_source: MigrationAuthoritySource::LegacyAuthMode,
            legacy_selector_present: true,
            provider_registry_present: true,
            retirement_deadline: "2026-07-17T00:00:00+00:00".into(),
            conflict_telemetry_name: "security.migration.conflict".into(),
            grants_authority: false,
            live_execution_allowed: false,
            zero_consumer_receipt_ref: VersionedContentReference {
                artifact_kind: ArtifactKind::PackageExitReceipt,
                document_id: "package-exit-receipt:test-overlay-retirement".into(),
                document_version: 1,
                content_digest:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                artifact_locator: "receipts/test-overlay-retirement.json".into(),
            },
        });
        assert!(profile.validate_structure_at(fixed_now()).is_empty());

        profile
            .migration_overlay
            .as_mut()
            .unwrap()
            .retirement_deadline = "2026-07-16T11:59:59Z".into();
        assert!(
            profile
                .validate_structure_at(fixed_now())
                .iter()
                .any(|error| error.contains("expired"))
        );
    }

    #[test]
    fn zero_digest_and_parent_traversal_are_rejected() {
        let mut profile = fixture();
        profile.provider_registry_ref.content_digest = format!("sha256:{}", "0".repeat(64));
        profile.provider_registry_ref.artifact_locator = "../provider.json".into();
        let errors = profile.validate_structure_at(fixed_now());
        assert!(errors.iter().any(|error| error.contains("all-zero")));
        assert!(
            errors
                .iter()
                .any(|error| error.contains("repository-relative"))
        );
    }

    #[test]
    fn startup_context_prevents_profile_self_downgrade() {
        let profile = fixture();
        let errors = profile.validate_for_startup(
            &StartupAdmissionContext {
                deployment_id: profile.deployment_id.clone(),
                security_profile: SecurityProfile::Production,
                profile_digest: TEST_PROFILE_DIGEST.into(),
            },
            TEST_PROFILE_DIGEST,
            fixed_now(),
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("pinned security_profile"))
        );
    }

    #[test]
    fn structurally_complete_production_profile_reaches_external_closure_gate() {
        let profile = structurally_complete_production_profile();
        assert!(profile.validate_structure_at(fixed_now()).is_empty());

        let errors = profile.validate_for_startup(
            &StartupAdmissionContext {
                deployment_id: profile.deployment_id.clone(),
                security_profile: SecurityProfile::Production,
                profile_digest: TEST_PROFILE_DIGEST.into(),
            },
            TEST_PROFILE_DIGEST,
            fixed_now(),
        );
        assert!(errors.is_empty());
    }

    #[test]
    fn production_acceptance_receipt_is_required_only_for_production() {
        let mut production = structurally_complete_production_profile();
        production.production_acceptance_receipt_ref = None;
        assert!(
            production
                .validate_structure_at(fixed_now())
                .iter()
                .any(|error| error.contains("production_acceptance_receipt_ref"))
        );

        let mut pointer_root = structurally_complete_production_profile();
        pointer_root
            .production_acceptance_receipt_ref
            .as_mut()
            .expect("production root")
            .artifact_locator = "json-pointer:#/receipts/sb-9".into();
        assert!(
            pointer_root
                .validate_structure_at(fixed_now())
                .iter()
                .any(|error| error.contains("normalized repository-relative JSON file"))
        );

        let mut non_production = fixture();
        non_production.production_acceptance_receipt_ref = Some(VersionedContentReference {
            artifact_kind: ArtifactKind::PackageExitReceipt,
            document_id: "package-exit-receipt:forbidden-test-authority".into(),
            document_version: 1,
            content_digest:
                "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".into(),
            artifact_locator: "receipts/forbidden-test-authority.json".into(),
        });
        assert!(
            non_production
                .validate_structure_at(fixed_now())
                .iter()
                .any(|error| error.contains("must not carry"))
        );
    }

    #[test]
    fn provider_projection_requires_only_active_state() {
        let mut profile = fixture();
        profile.provider_lifecycle_snapshot_ref.required_states =
            vec![ProviderLifecycleState::Quarantined];
        assert!(
            profile
                .validate_structure_at(fixed_now())
                .iter()
                .any(|error| error.contains("exactly [active]"))
        );
    }

    #[test]
    fn startup_rejects_malformed_profile_digests() {
        let profile = fixture();
        let errors = profile.validate_for_startup(
            &StartupAdmissionContext {
                deployment_id: profile.deployment_id.clone(),
                security_profile: profile.security_profile,
                profile_digest: "SHA256:not-lowercase".into(),
            },
            "sha256:GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
            fixed_now(),
        );

        assert!(
            errors
                .iter()
                .any(|error| error == "startup expected profile_digest must be a sha256 digest")
        );
        assert!(errors.iter().any(|error| {
            error
                == "startup actual profile_digest must contain 64 lowercase hexadecimal characters"
        }));
    }

    #[test]
    fn startup_rejects_zero_profile_digests() {
        let profile = fixture();
        let zero_digest = format!("sha256:{}", "0".repeat(64));
        let errors = profile.validate_for_startup(
            &StartupAdmissionContext {
                deployment_id: profile.deployment_id.clone(),
                security_profile: profile.security_profile,
                profile_digest: zero_digest.clone(),
            },
            &zero_digest,
            fixed_now(),
        );

        assert!(errors.iter().any(|error| {
            error == "startup expected profile_digest must not use the unresolved all-zero digest"
        }));
        assert!(errors.iter().any(|error| {
            error == "startup actual profile_digest must not use the unresolved all-zero digest"
        }));
    }

    #[test]
    fn startup_rejects_a_profile_digest_that_does_not_match_its_pin() {
        let profile = fixture();
        let errors = profile.validate_for_startup(
            &StartupAdmissionContext {
                deployment_id: profile.deployment_id.clone(),
                security_profile: profile.security_profile,
                profile_digest: TEST_PROFILE_DIGEST.into(),
            },
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            fixed_now(),
        );

        assert!(errors.iter().any(|error| {
            error == "deployment profile digest does not match the pinned profile_digest"
        }));
    }

    #[test]
    fn active_profiles_cannot_be_future_dated() {
        let mut profile = fixture();
        profile.lifecycle.state = DocumentLifecycleState::Active;
        profile.lifecycle.effective_at = "2026-07-16T12:00:01Z".into();
        assert!(
            profile
                .validate_structure_at(fixed_now())
                .iter()
                .any(|error| error.contains("future-dated"))
        );
    }

    #[test]
    fn supersedes_is_same_document_lower_version_and_safe() {
        let mut profile = fixture();
        profile.document_version = 2;
        profile.lifecycle.supersedes = Some(VersionedContentReference {
            artifact_kind: ArtifactKind::DeploymentSecurityProfile,
            document_id: profile.document_id.clone(),
            document_version: 1,
            content_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            artifact_locator: "catalog/security-contracts/v1/profile-v1.json".into(),
        });
        assert!(profile.validate_structure_at(fixed_now()).is_empty());

        let supersedes = profile.lifecycle.supersedes.as_mut().unwrap();
        supersedes.document_version = 2;
        supersedes.artifact_locator = "../profile-v1.json".into();
        let errors = profile.validate_structure_at(fixed_now());
        assert!(
            errors
                .iter()
                .any(|error| error.contains("lower document_version"))
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("repository-relative"))
        );
    }
}
