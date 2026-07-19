use std::collections::HashSet;
use std::path::{Component, Path};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::conformance_trust::canonical_json_bytes;

pub const DEPLOYMENT_SECURITY_PROFILE_SCHEMA_URI: &str =
    "https://ryuki.io/schemas/security-contracts/v1/deployment-security-profile.schema.json";
pub const DEPLOYMENT_SECURITY_PROFILE_SCHEMA_VERSION: &str = "1.0.0";
pub const DEPLOYMENT_SECURITY_PROFILE_CONTRACT_KIND: &str = "deployment-security-profile";
pub const SECRET_PROVIDER_INVENTORY_DIGEST_CONTRACT: &str = "ryuki-secret-provider-inventory-v1";
pub const SECRET_PROVIDER_RUNTIME_BINDING_DIGEST_CONTRACT: &str =
    "ryuki-secret-provider-runtime-binding-v1";
pub const AUTHENTICATOR_INVENTORY_DIGEST_CONTRACT: &str = "ryuki-authenticator-inventory-v1";
pub const AUTHENTICATOR_RUNTIME_BINDING_DIGEST_CONTRACT: &str =
    "ryuki-authenticator-runtime-binding-v1";

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
            for (label, digest) in [
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
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    const TEST_PROFILE_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

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

    fn expected_guard_value(guard_id: GuardId, deployment_id: &str) -> RuntimeGuardExpectedValue {
        match guard_id {
            GuardId::DurablePostgresql => RuntimeGuardExpectedValue::DurablePostgresql {
                database_provider: ProductionDatabaseProvider::CloudNativePg,
                server_major_version: 18,
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
