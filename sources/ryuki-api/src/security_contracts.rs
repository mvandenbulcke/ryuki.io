//! Content-addressed deployment security admission.
//!
//! This module deliberately performs only local, bounded reads. Schemas are
//! embedded in the binary and external `$ref` retrieval is denied. Production
//! remains unavailable until trusted closure receipts and live runtime facts
//! can be verified; structural JSON can never promote itself to authority.

#[path = "production_dependencies.rs"]
mod production_dependencies;

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use jsonschema::{Retrieve, Uri};
use rand::{rngs::OsRng, RngCore};
use ryuki_core::config::{AuthMode, RyukiConfig};
use ryuki_core::conformance_closure::{
    derive_production_conformance_closure_context, verify_control_trace_artifact,
    verify_production_conformance_closure, ProductionConformanceClosureInputs,
    VerifiedConformanceClosure, VerifiedRuntimeGuardRequirement,
};
use ryuki_core::conformance_trust::{
    canonical_json_bytes, ConformanceArtifactCandidate, ConformanceCheckpointAuthorityAnchor,
    ConformanceProductionRootRef, ConformanceRegistryArtifact, ConformanceTrustAnchor,
    ConformanceTrustScope, ConformanceTrustedTimeWindow, ConformanceVerificationContext,
    EvidenceTier, ValidatedConformanceRegistryLineage, VerifiedConformanceArtifact,
    VerifiedConformanceProductionRoot, VerifiedConformanceTrustCheckpoint,
};
use ryuki_core::cookie_policy::RetainedCookiePolicySet;
use ryuki_core::deployed_workload::{
    build_deployed_workload_attestation_request, verify_deployed_workload_attestation,
    DeployedWorkloadAuthorityAnchor, ExpectedDeployedWorkload, VerifiedDeployedWorkload,
    MAX_DEPLOYED_WORKLOAD_REQUEST_BYTES, MAX_DEPLOYED_WORKLOAD_RESPONSE_BYTES,
};
use ryuki_core::postgresql_infrastructure::{
    build_postgresql_infrastructure_attestation_request, postgresql_attestation_request_tag,
    postgresql_tls_channel_binding_digest, verify_postgresql_infrastructure_attestation,
    ExpectedPostgresqlInfrastructure, PostgresqlInfrastructureAuthorityAnchor,
    PostgresqlSessionBinding, PostgresqlSessionPurpose, PostgresqlTlsChannelBinding,
    VerifiedPostgresqlInfrastructureAttestation, MAX_POSTGRESQL_INFRASTRUCTURE_REQUEST_BYTES,
    MAX_POSTGRESQL_INFRASTRUCTURE_RESPONSE_BYTES,
};
use ryuki_core::production_applicability::validate_exact_implementation_applicability;
use ryuki_core::production_build::{
    BuildComponent, BuildSelectorDisposition, ProductionBuildManifest, ShippedAdapter,
};
use ryuki_core::production_deployment_applicability::{
    ActiveProviderApplicabilityClaim, ActiveProviderRegistryApplicabilityClaim,
    DeploymentCheckpointApplicabilityClaim, ProductionDeploymentApplicabilityClaims,
    ProviderMandatoryBaselineClaim, SecurityLimitApplicabilityClaim,
};
use ryuki_core::public_ingress::{
    build_public_ingress_attestation_request, verify_public_ingress_attestation,
    ExpectedPublicIngress, PublicIngressAuthorityAnchor,
    VerifiedHttpsPublicUrlsWitness as VerifiedPublicIngressAttestation,
    MAX_PUBLIC_INGRESS_REQUEST_BYTES, MAX_PUBLIC_INGRESS_RESPONSE_BYTES,
};
use ryuki_core::security_profile::{
    authenticator_provider_policy_binding_digest, authenticator_runtime_binding_digest,
    secret_provider_inventory_digest, ArtifactKind, AuthenticatorCredentialCarrier,
    AuthenticatorCredentialProfileRuntimeProjection, AuthenticatorCredentialReuse,
    AuthenticatorKeySourceKind, AuthenticatorNonceBinding, AuthenticatorPresentationReplayDefense,
    AuthenticatorProofBinding, AuthenticatorRuntimeBindingDocumentReference,
    AuthenticatorRuntimeBindingProjection, AuthenticatorRuntimeOwnership,
    AuthenticatorRuntimePathProjection, AuthenticatorSenderConstraint,
    AuthenticatorVerifierRuntimeProjection, DeploymentSecurityProfile, ExpectedProviderBinding,
    ExpectedSecretProviderBinding, GuardId, MigrationAuthoritySource, ProductionAuthenticatorKind,
    ProductionDatabaseProvider, ProviderLifecycleState, RuntimeGuardExpectedValue, SecurityProfile,
    StartupAdmissionContext, TenancyMode, VersionedContentReference,
    AUTHENTICATOR_BROWSER_SESSION_MAXIMUM_AGE_LIMIT_ID,
    AUTHENTICATOR_BROWSER_STATE_LIFETIME_LIMIT_ID, AUTHENTICATOR_BROWSER_STATE_MAXIMUM_TTL_SECONDS,
    AUTHENTICATOR_FEDERATED_AUTHORITY_STALENESS_LIMIT_ID,
    AUTHENTICATOR_PROVIDER_POLICY_BINDING_DIGEST_CONTRACT,
    SECRET_PROVIDER_RUNTIME_BINDING_DIGEST_CONTRACT,
};
#[cfg(test)]
use ryuki_core::security_profile::{
    AUTHENTICATOR_CACHE_PARTITION_BINDING_DIGEST_CONTRACT,
    AUTHENTICATOR_PROTOCOL_BINDING_DIGEST_CONTRACT,
};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

use crate::boundary::authority_transport::{
    AuthorityTransportBounds, AuthorityTransportDeadlines, AuthorityTransportHardLimits,
    UnixAuthorityTransport,
};
use crate::boundary::trust_checkpoint_transport::{
    TrustCheckpointTransportBounds, UnixTrustCheckpointTransport,
};

const PRODUCTION_RUNTIME_GUARD_CHALLENGE_DIGEST_CONTRACT: &str =
    "ryuki-production-runtime-guard-challenge-v1";
const MAXIMUM_AUTHORITY_BINDING_DIGEST_CONTRACT: &str = "ryuki-maximum-authority-binding-v1";
const AUTHENTICATOR_CLOCK_SKEW_LIMIT_ID: &str = "limit:authenticator.clock-skew";
const AUTHENTICATOR_OIDC_ACCESS_TOKEN_LIFETIME_LIMIT_ID: &str =
    "limit:authenticator.oidc-access-token-lifetime";

pub(crate) const SECURITY_CONTRACT_ROOT_ENV: &str = "RYUKI_SECURITY_CONTRACT_ROOT";
pub(crate) const SECURITY_PROFILE_PATH_ENV: &str = "RYUKI_DEPLOYMENT_SECURITY_PROFILE_PATH";
pub(crate) const SECURITY_PROFILE_DIGEST_ENV: &str = "RYUKI_DEPLOYMENT_SECURITY_PROFILE_DIGEST";
pub(crate) const CONFORMANCE_TRUST_ROOT_REGISTRY_PATH_ENV: &str =
    "RYUKI_CONFORMANCE_TRUST_ROOT_REGISTRY_PATH";
pub(crate) const CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST_ENV: &str =
    "RYUKI_CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST";
pub(crate) const CONFORMANCE_TRUST_CHECKPOINT_SOCKET_ENV: &str =
    "RYUKI_CONFORMANCE_TRUST_CHECKPOINT_SOCKET";
pub(crate) const CONFORMANCE_TRUST_CHECKPOINT_AUTHORITY_ID_ENV: &str =
    "RYUKI_CONFORMANCE_TRUST_CHECKPOINT_AUTHORITY_ID";
pub(crate) const CONFORMANCE_TRUST_CHECKPOINT_KEY_ID_ENV: &str =
    "RYUKI_CONFORMANCE_TRUST_CHECKPOINT_KEY_ID";
pub(crate) const CONFORMANCE_TRUST_CHECKPOINT_PUBLIC_KEY_BASE64_ENV: &str =
    "RYUKI_CONFORMANCE_TRUST_CHECKPOINT_PUBLIC_KEY_BASE64";
pub(crate) const CONFORMANCE_TRUST_CHECKPOINT_PUBLIC_KEY_FINGERPRINT_ENV: &str =
    "RYUKI_CONFORMANCE_TRUST_CHECKPOINT_PUBLIC_KEY_FINGERPRINT";
pub(crate) const CONFORMANCE_TRUST_CHECKPOINT_MIN_AUTHORITY_EPOCH_ENV: &str =
    "RYUKI_CONFORMANCE_TRUST_CHECKPOINT_MIN_AUTHORITY_EPOCH";
pub(crate) const DEPLOYED_WORKLOAD_ATTESTATION_SOCKET_ENV: &str =
    "RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_SOCKET";
pub(crate) const DEPLOYED_WORKLOAD_ATTESTATION_AUTHORITY_ID_ENV: &str =
    "RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_AUTHORITY_ID";
pub(crate) const DEPLOYED_WORKLOAD_ATTESTATION_KEY_ID_ENV: &str =
    "RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_KEY_ID";
pub(crate) const DEPLOYED_WORKLOAD_ATTESTATION_PUBLIC_KEY_BASE64_ENV: &str =
    "RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_PUBLIC_KEY_BASE64";
pub(crate) const DEPLOYED_WORKLOAD_ATTESTATION_PUBLIC_KEY_FINGERPRINT_ENV: &str =
    "RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_PUBLIC_KEY_FINGERPRINT";
pub(crate) const DEPLOYED_WORKLOAD_ATTESTATION_MIN_AUTHORITY_EPOCH_ENV: &str =
    "RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_MIN_AUTHORITY_EPOCH";
pub(crate) const DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_ID_ENV: &str =
    "RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_ID";
pub(crate) const DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_VERSION_ENV: &str =
    "RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_VERSION";
pub(crate) const DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_DIGEST_ENV: &str =
    "RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_DIGEST";
pub(crate) const EXPECTED_WORKLOAD_ID_ENV: &str = "RYUKI_EXPECTED_WORKLOAD_ID";
pub(crate) const PUBLIC_INGRESS_ATTESTATION_SOCKET_ENV: &str =
    "RYUKI_PUBLIC_INGRESS_ATTESTATION_SOCKET";
pub(crate) const PUBLIC_INGRESS_ATTESTATION_AUTHORITY_ID_ENV: &str =
    "RYUKI_PUBLIC_INGRESS_ATTESTATION_AUTHORITY_ID";
pub(crate) const PUBLIC_INGRESS_ATTESTATION_KEY_ID_ENV: &str =
    "RYUKI_PUBLIC_INGRESS_ATTESTATION_KEY_ID";
pub(crate) const PUBLIC_INGRESS_ATTESTATION_PUBLIC_KEY_BASE64_ENV: &str =
    "RYUKI_PUBLIC_INGRESS_ATTESTATION_PUBLIC_KEY_BASE64";
pub(crate) const PUBLIC_INGRESS_ATTESTATION_PUBLIC_KEY_FINGERPRINT_ENV: &str =
    "RYUKI_PUBLIC_INGRESS_ATTESTATION_PUBLIC_KEY_FINGERPRINT";
pub(crate) const PUBLIC_INGRESS_ATTESTATION_MIN_AUTHORITY_EPOCH_ENV: &str =
    "RYUKI_PUBLIC_INGRESS_ATTESTATION_MIN_AUTHORITY_EPOCH";
pub(crate) const PUBLIC_INGRESS_ATTESTATION_PROFILE_ID_ENV: &str =
    "RYUKI_PUBLIC_INGRESS_ATTESTATION_PROFILE_ID";
pub(crate) const PUBLIC_INGRESS_ATTESTATION_PROFILE_VERSION_ENV: &str =
    "RYUKI_PUBLIC_INGRESS_ATTESTATION_PROFILE_VERSION";
pub(crate) const PUBLIC_INGRESS_ATTESTATION_PROFILE_DIGEST_ENV: &str =
    "RYUKI_PUBLIC_INGRESS_ATTESTATION_PROFILE_DIGEST";
pub(crate) const POSTGRESQL_INFRASTRUCTURE_ATTESTATION_SOCKET_ENV: &str =
    "RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_SOCKET";
pub(crate) const POSTGRESQL_INFRASTRUCTURE_ATTESTATION_AUTHORITY_ID_ENV: &str =
    "RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_AUTHORITY_ID";
pub(crate) const POSTGRESQL_INFRASTRUCTURE_ATTESTATION_KEY_ID_ENV: &str =
    "RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_KEY_ID";
pub(crate) const POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_BASE64_ENV: &str =
    "RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_BASE64";
pub(crate) const POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_FINGERPRINT_ENV: &str =
    "RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_FINGERPRINT";
pub(crate) const POSTGRESQL_INFRASTRUCTURE_ATTESTATION_MIN_AUTHORITY_EPOCH_ENV: &str =
    "RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_MIN_AUTHORITY_EPOCH";
pub(crate) const POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_ID_ENV: &str =
    "RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_ID";
pub(crate) const POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_VERSION_ENV: &str =
    "RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_VERSION";
pub(crate) const POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_DIGEST_ENV: &str =
    "RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_DIGEST";
pub(crate) const FIRST_OWNER_AUTHORITY_ID_ENV: &str = "RYUKI_FIRST_OWNER_AUTHORITY_ID";
pub(crate) const FIRST_OWNER_AUTHORITY_KEY_ID_ENV: &str = "RYUKI_FIRST_OWNER_AUTHORITY_KEY_ID";
pub(crate) const FIRST_OWNER_AUTHORITY_PUBLIC_KEY_BASE64_ENV: &str =
    "RYUKI_FIRST_OWNER_AUTHORITY_PUBLIC_KEY_BASE64";
pub(crate) const FIRST_OWNER_AUTHORITY_PUBLIC_KEY_FINGERPRINT_ENV: &str =
    "RYUKI_FIRST_OWNER_AUTHORITY_PUBLIC_KEY_FINGERPRINT";
pub(crate) const FIRST_OWNER_AUTHORITY_MIN_EPOCH_ENV: &str =
    "RYUKI_FIRST_OWNER_AUTHORITY_MIN_EPOCH";
pub(crate) const FIRST_OWNER_CLOSURE_CERTIFICATE_PATH_ENV: &str =
    "RYUKI_FIRST_OWNER_CLOSURE_CERTIFICATE_PATH";
pub(crate) const FIRST_OWNER_CLOSURE_CERTIFICATE_DIGEST_ENV: &str =
    "RYUKI_FIRST_OWNER_CLOSURE_CERTIFICATE_DIGEST";
pub(crate) const PRODUCTION_BUILD_MANIFEST_PATH_ENV: &str = "RYUKI_PRODUCTION_BUILD_MANIFEST_PATH";
pub(crate) const PRODUCTION_BUILD_MANIFEST_DIGEST_ENV: &str =
    "RYUKI_PRODUCTION_BUILD_MANIFEST_DIGEST";
pub(crate) const EXPECTED_DEPLOYMENT_ID_ENV: &str = "RYUKI_EXPECTED_DEPLOYMENT_ID";
pub(crate) const SECURITY_PROFILE_ENV: &str = "RYUKI_SECURITY_PROFILE";

const MAX_PROFILE_BYTES: u64 = 1024 * 1024;
const MAX_PRODUCTION_BUILD_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RUNTIME_EXECUTABLE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
// Allows the complete 4,096-document conformance set plus bounded supporting
// profile, registry, policy, topology, and evidence-index artifacts.
const MAX_DOCUMENTS: usize = 8192;
const MAX_REFERENCE_DEPTH: usize = 32;
const MAX_REFERENCE_BINDINGS: usize = 16_384;
const MAX_JSON_DEPTH: usize = 64;
// A complete applicability projection can legitimately exceed 4,096 rows
// (for example 141 active traces across roughly 95 shipped subjects). Raw-byte
// and schema limits remain the primary allocation bounds.
const MAX_JSON_NODES: usize = 262_144;
const MAX_JSON_ARRAY_ITEMS: usize = 16_384;
const MAX_JSON_OBJECT_MEMBERS: usize = 4_096;
const ED25519_AUTHORITY_PUBLIC_KEY_BYTES: usize = 32;
const MAX_EXACT_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_AUTHORITY_SOCKET_PATH_BYTES: usize = 103;
const MAX_CHECKPOINT_DOCUMENT_DIGESTS: usize = 4096;
const CHECKPOINT_TRANSPORT_PHASE_DEADLINE: Duration = Duration::from_secs(10);
const DEPLOYED_WORKLOAD_TRANSPORT_PHASE_DEADLINE: Duration = Duration::from_secs(10);
const MAX_DEPLOYED_WORKLOAD_TRANSPORT_PHASE_DEADLINE: Duration = Duration::from_secs(30);
const PUBLIC_INGRESS_TRANSPORT_PHASE_DEADLINE: Duration = Duration::from_secs(10);
const MAX_PUBLIC_INGRESS_TRANSPORT_PHASE_DEADLINE: Duration = Duration::from_secs(30);
const POSTGRESQL_INFRASTRUCTURE_TRANSPORT_PHASE_DEADLINE: Duration = Duration::from_secs(10);
const MAX_POSTGRESQL_INFRASTRUCTURE_TRANSPORT_PHASE_DEADLINE: Duration = Duration::from_secs(30);

const PROFILE_SCHEMA: &str =
    include_str!("../../../catalog/security-contracts/v1/deployment-security-profile.schema.json");
const CONFORMANCE_TRUST_ROOT_REGISTRY_SCHEMA: &str = include_str!(
    "../../../catalog/security-contracts/v1/conformance-trust-root-registry.schema.json"
);
const CONTROL_TRACE_SCHEMA: &str =
    include_str!("../../../catalog/security-contracts/v1/control-trace.schema.json");
const CONFORMANCE_BUNDLE_SCHEMA: &str =
    include_str!("../../../catalog/security-contracts/v1/conformance-bundle.schema.json");
const PROVIDER_SCHEMA: &str =
    include_str!("../../../catalog/security-contracts/v1/provider-registry.schema.json");
const AUTHENTICATOR_RUNTIME_BINDING_SCHEMA: &str = include_str!(
    "../../../catalog/security-contracts/v1/authenticator-runtime-binding.schema.json"
);
const SECRET_PROVIDER_RUNTIME_BINDING_SCHEMA: &str = include_str!(
    "../../../catalog/security-contracts/v1/secret-provider-runtime-binding.schema.json"
);
const ACTION_SCHEMA: &str =
    include_str!("../../../catalog/security-contracts/v1/action-resource-registry.schema.json");
const LIMIT_SCHEMA: &str =
    include_str!("../../../catalog/security-contracts/v1/security-limit-profile.schema.json");
const PACKAGE_EXIT_RECEIPT_SCHEMA: &str =
    include_str!("../../../catalog/security-contracts/v1/package-exit-receipt.schema.json");
const PRODUCTION_BUILD_MANIFEST_SCHEMA: &str =
    include_str!("../../../catalog/security-contracts/v1/production-build-manifest.schema.json");
const FIRST_OWNER_CLOSURE_CERTIFICATE_SCHEMA: &str = include_str!(
    "../../../catalog/security-contracts/v1/first-owner-closure-certificate.schema.json"
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StartupTrustCheckpointAuthorityPins {
    pub(crate) socket_path: PathBuf,
    pub(crate) authority_id: String,
    pub(crate) key_id: String,
    pub(crate) public_key_base64: String,
    pub(crate) public_key_fingerprint: String,
    pub(crate) minimum_authority_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StartupDeployedWorkloadAttestationPins {
    pub(crate) socket_path: PathBuf,
    pub(crate) authority_id: String,
    pub(crate) key_id: String,
    pub(crate) public_key_base64: String,
    pub(crate) public_key_fingerprint: String,
    pub(crate) minimum_authority_epoch: u64,
    pub(crate) measurement_profile_id: String,
    pub(crate) measurement_profile_version: u64,
    pub(crate) measurement_profile_digest: String,
    pub(crate) workload_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StartupPublicIngressAttestationPins {
    pub(crate) socket_path: PathBuf,
    pub(crate) authority_id: String,
    pub(crate) key_id: String,
    pub(crate) public_key_base64: String,
    pub(crate) public_key_fingerprint: String,
    pub(crate) minimum_authority_epoch: u64,
    pub(crate) attestation_profile_id: String,
    pub(crate) attestation_profile_version: u64,
    pub(crate) attestation_profile_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StartupPostgresqlInfrastructureAttestationPins {
    pub(crate) socket_path: PathBuf,
    pub(crate) authority_id: String,
    pub(crate) key_id: String,
    pub(crate) public_key_base64: String,
    pub(crate) public_key_fingerprint: String,
    pub(crate) minimum_authority_epoch: u64,
    pub(crate) attestation_profile_id: String,
    pub(crate) attestation_profile_version: u64,
    pub(crate) attestation_profile_digest: String,
}

/// Independently provisioned trust anchor for the permanent first-owner
/// closure certificate. It has no runtime-discovered defaults and is never
/// sourced from the rollbackable security-contract root or database row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StartupFirstOwnerAuthorityPins {
    pub(crate) authority_id: String,
    pub(crate) key_id: String,
    pub(crate) public_key_base64: String,
    pub(crate) public_key_fingerprint: String,
    pub(crate) minimum_authority_epoch: u64,
}

/// Detached one-shot installation input for production apply-only mode.
///
/// The pair is parsed without touching the path. Only the later migration
/// admission boundary may open and consume it, after all independent runtime
/// prerequisites have passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StartupFirstOwnerClosureCertificatePins {
    pub(crate) path: PathBuf,
    pub(crate) digest: String,
}

/// Detached build identity selected by independently governed deployment
/// configuration. The manifest deliberately lives outside the rollbackable
/// security-contract root and is bound by the digest supplied here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StartupProductionBuildManifestPins {
    pub(crate) path: PathBuf,
    pub(crate) digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StartupSecurityPins {
    pub(crate) contract_root: PathBuf,
    pub(crate) profile_path: PathBuf,
    pub(crate) profile_digest: String,
    pub(crate) conformance_trust_root_registry_path: PathBuf,
    pub(crate) conformance_trust_root_registry_digest: String,
    pub(crate) conformance_trust_checkpoint_authority: Option<StartupTrustCheckpointAuthorityPins>,
    pub(crate) deployed_workload_attestation: Option<StartupDeployedWorkloadAttestationPins>,
    pub(crate) public_ingress_attestation: Option<StartupPublicIngressAttestationPins>,
    pub(crate) postgresql_infrastructure_attestation:
        Option<StartupPostgresqlInfrastructureAttestationPins>,
    pub(crate) first_owner_authority: Option<StartupFirstOwnerAuthorityPins>,
    pub(crate) first_owner_closure_certificate: Option<StartupFirstOwnerClosureCertificatePins>,
    pub(crate) production_build_manifest: Option<StartupProductionBuildManifestPins>,
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
        validate_json_relative_path(SECURITY_PROFILE_PATH_ENV, &profile_path)?;

        let profile_digest = required_unicode(&mut get, SECURITY_PROFILE_DIGEST_ENV)?;
        validate_digest_pin(SECURITY_PROFILE_DIGEST_ENV, &profile_digest)?;

        let conformance_trust_root_registry_path_raw =
            required_unicode(&mut get, CONFORMANCE_TRUST_ROOT_REGISTRY_PATH_ENV)?;
        let conformance_trust_root_registry_path =
            PathBuf::from(&conformance_trust_root_registry_path_raw);
        validate_json_relative_path(
            CONFORMANCE_TRUST_ROOT_REGISTRY_PATH_ENV,
            &conformance_trust_root_registry_path,
        )?;

        let conformance_trust_root_registry_digest =
            required_unicode(&mut get, CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST_ENV)?;
        validate_digest_pin(
            CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST_ENV,
            &conformance_trust_root_registry_digest,
        )?;

        let conformance_trust_checkpoint_authority = optional_trust_checkpoint_authority(&mut get)?;
        let deployed_workload_attestation = optional_deployed_workload_attestation(&mut get)?;
        let public_ingress_attestation = optional_public_ingress_attestation(&mut get)?;
        let postgresql_infrastructure_attestation =
            optional_postgresql_infrastructure_attestation(&mut get)?;
        let first_owner_authority = optional_first_owner_authority(&mut get)?;
        let first_owner_closure_certificate = optional_first_owner_closure_certificate(&mut get)?;
        let production_build_manifest = optional_production_build_manifest(&mut get)?;

        if let Some(postgresql) = postgresql_infrastructure_attestation.as_ref() {
            let other_authorities = [
                conformance_trust_checkpoint_authority.as_ref().map(|pins| {
                    (
                        "conformance trust-checkpoint",
                        pins.socket_path.as_path(),
                        pins.public_key_fingerprint.as_str(),
                    )
                }),
                deployed_workload_attestation.as_ref().map(|pins| {
                    (
                        "deployed-workload attestation",
                        pins.socket_path.as_path(),
                        pins.public_key_fingerprint.as_str(),
                    )
                }),
                public_ingress_attestation.as_ref().map(|pins| {
                    (
                        "public-ingress attestation",
                        pins.socket_path.as_path(),
                        pins.public_key_fingerprint.as_str(),
                    )
                }),
            ];
            for (label, socket_path, public_key_fingerprint) in
                other_authorities.into_iter().flatten()
            {
                if postgresql.socket_path.as_path() == socket_path {
                    return Err(format!(
                        "{POSTGRESQL_INFRASTRUCTURE_ATTESTATION_SOCKET_ENV} must use a distinct Unix socket from the {label} authority"
                    ));
                }
                if postgresql.public_key_fingerprint.as_str() == public_key_fingerprint {
                    return Err(format!(
                        "{POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_FINGERPRINT_ENV} must use a cryptographically distinct key from the {label} authority"
                    ));
                }
            }
        }

        if let Some(first_owner) = first_owner_authority.as_ref() {
            let other_authorities = [
                conformance_trust_checkpoint_authority.as_ref().map(|pins| {
                    (
                        "conformance trust-checkpoint",
                        pins.public_key_fingerprint.as_str(),
                    )
                }),
                deployed_workload_attestation.as_ref().map(|pins| {
                    (
                        "deployed-workload attestation",
                        pins.public_key_fingerprint.as_str(),
                    )
                }),
                public_ingress_attestation.as_ref().map(|pins| {
                    (
                        "public-ingress attestation",
                        pins.public_key_fingerprint.as_str(),
                    )
                }),
                postgresql_infrastructure_attestation.as_ref().map(|pins| {
                    (
                        "PostgreSQL-infrastructure attestation",
                        pins.public_key_fingerprint.as_str(),
                    )
                }),
            ];
            for (label, public_key_fingerprint) in other_authorities.into_iter().flatten() {
                if first_owner.public_key_fingerprint == public_key_fingerprint {
                    return Err(format!(
                        "{FIRST_OWNER_AUTHORITY_PUBLIC_KEY_FINGERPRINT_ENV} must use a cryptographically distinct key from the {label} authority"
                    ));
                }
            }
        }

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
        if security_profile.is_production() && conformance_trust_checkpoint_authority.is_none() {
            return Err(format!(
                "production {SECURITY_PROFILE_ENV} requires the complete independently governed conformance trust-checkpoint authority binding beginning with {CONFORMANCE_TRUST_CHECKPOINT_SOCKET_ENV}"
            ));
        }
        if security_profile.is_production() && production_build_manifest.is_none() {
            return Err(format!(
                "production {SECURITY_PROFILE_ENV} requires the complete independently pinned build-manifest binding beginning with {PRODUCTION_BUILD_MANIFEST_PATH_ENV}"
            ));
        }
        if security_profile.is_production() && deployed_workload_attestation.is_none() {
            return Err(format!(
                "production {SECURITY_PROFILE_ENV} requires the complete independently pinned deployed-workload attestation binding beginning with {DEPLOYED_WORKLOAD_ATTESTATION_SOCKET_ENV}"
            ));
        }
        if security_profile.is_production() && public_ingress_attestation.is_none() {
            return Err(format!(
                "production {SECURITY_PROFILE_ENV} requires the complete independently pinned public-ingress attestation binding beginning with {PUBLIC_INGRESS_ATTESTATION_SOCKET_ENV}"
            ));
        }
        if security_profile.is_production() && postgresql_infrastructure_attestation.is_none() {
            return Err(format!(
                "production {SECURITY_PROFILE_ENV} requires the complete independently pinned PostgreSQL-infrastructure attestation binding beginning with {POSTGRESQL_INFRASTRUCTURE_ATTESTATION_SOCKET_ENV}"
            ));
        }
        if security_profile.is_production() && first_owner_authority.is_none() {
            return Err(format!(
                "production {SECURITY_PROFILE_ENV} requires the complete independently pinned first-owner authority binding beginning with {FIRST_OWNER_AUTHORITY_ID_ENV}"
            ));
        }
        if !security_profile.is_production() && production_build_manifest.is_some() {
            return Err(format!(
                "{PRODUCTION_BUILD_MANIFEST_PATH_ENV} and {PRODUCTION_BUILD_MANIFEST_DIGEST_ENV} are production-only and must be unset for {profile_raw}"
            ));
        }
        if !security_profile.is_production() && deployed_workload_attestation.is_some() {
            return Err(format!(
                "the deployed-workload attestation binding beginning with {DEPLOYED_WORKLOAD_ATTESTATION_SOCKET_ENV} is production-only and must be unset for {profile_raw}"
            ));
        }
        if !security_profile.is_production() && public_ingress_attestation.is_some() {
            return Err(format!(
                "the public-ingress attestation binding beginning with {PUBLIC_INGRESS_ATTESTATION_SOCKET_ENV} is production-only and must be unset for {profile_raw}"
            ));
        }
        if !security_profile.is_production() && postgresql_infrastructure_attestation.is_some() {
            return Err(format!(
                "the PostgreSQL-infrastructure attestation binding beginning with {POSTGRESQL_INFRASTRUCTURE_ATTESTATION_SOCKET_ENV} is production-only and must be unset for {profile_raw}"
            ));
        }
        if !security_profile.is_production() && first_owner_authority.is_some() {
            return Err(format!(
                "the first-owner authority binding beginning with {FIRST_OWNER_AUTHORITY_ID_ENV} is production-only and must be unset for {profile_raw}"
            ));
        }
        if !security_profile.is_production() && first_owner_closure_certificate.is_some() {
            return Err(format!(
                "{FIRST_OWNER_CLOSURE_CERTIFICATE_PATH_ENV} and {FIRST_OWNER_CLOSURE_CERTIFICATE_DIGEST_ENV} are production apply-only inputs and must be unset for {profile_raw}"
            ));
        }

        Ok(Self {
            contract_root,
            profile_path,
            profile_digest,
            conformance_trust_root_registry_path,
            conformance_trust_root_registry_digest,
            conformance_trust_checkpoint_authority,
            deployed_workload_attestation,
            public_ingress_attestation,
            postgresql_infrastructure_attestation,
            first_owner_authority,
            first_owner_closure_certificate,
            production_build_manifest,
            deployment_id,
            security_profile,
        })
    }

    /// The detached certificate is one-shot apply-only input. Serving and
    /// verify-only processes must not retain even its path/digest pins.
    pub(crate) fn validate_first_owner_certificate_mode(
        &self,
        mode: crate::database::MigrationStartupMode,
    ) -> Result<(), String> {
        if self.first_owner_closure_certificate.is_some()
            && mode != crate::database::MigrationStartupMode::ApplyOnly
        {
            Err(format!(
                "{FIRST_OWNER_CLOSURE_CERTIFICATE_PATH_ENV} and {FIRST_OWNER_CLOSURE_CERTIFICATE_DIGEST_ENV} may be configured only for exact apply-only mode"
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ContentReferenceBinding {
    document_id: String,
    document_version: u64,
    content_digest: String,
    artifact_locator: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConformanceRegistryPredecessorReference {
    artifact_kind: String,
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
struct ProviderCapabilityDescriptorBinding {
    descriptor_id: String,
    descriptor_version: u64,
    adapter_kind: String,
    adapter_version: String,
    advertised_capabilities: Vec<String>,
    mandatory_baseline_ref: ContentReferenceBinding,
    implementation_applicable: bool,
    production_eligible: bool,
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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OidcKindConfig {
    configuration_kind: String,
    runtime_binding_ref: ContentReferenceBinding,
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

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AuthenticatorProviderPolicyBinding {
    digest_contract: String,
    binding_digest: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AuthenticatorDigestBinding {
    digest_contract: String,
    binding_digest: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AuthenticatorCredentialPathDocument {
    path_id: String,
    path_version: u64,
    verifier: AuthenticatorVerifierRuntimeProjection,
    credential_profile: AuthenticatorCredentialProfileRuntimeProjection,
    cache_partition: AuthenticatorDigestBinding,
    protocol_binding: AuthenticatorDigestBinding,
    retained_consumer_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AuthenticatorRuntimeBindingDocument {
    #[serde(rename = "$schema")]
    schema_uri: String,
    schema_version: String,
    contract_kind: String,
    document_id: String,
    document_version: u64,
    value_free: bool,
    provider_id: String,
    provider_configuration_version: u64,
    deployment_id: String,
    trust_domain_id: String,
    capability_descriptor_id: String,
    capability_descriptor_version: u64,
    adapter_kind: String,
    adapter_version: String,
    authenticator_kind: String,
    provider_policy: AuthenticatorProviderPolicyBinding,
    capability_ids: Vec<String>,
    credential_paths: Vec<AuthenticatorCredentialPathDocument>,
    ownership: AuthenticatorRuntimeOwnership,
}

/// Exact value-free authenticator document authenticated by the OIDC provider
/// configuration. This is D and its typed interpretation; it is deliberately
/// not runtime measurement R or production guard evidence.
pub(crate) struct VerifiedAuthenticatorRuntimeBinding {
    reference: ContentReferenceBinding,
    raw_bytes: Box<[u8]>,
    document: AuthenticatorRuntimeBindingDocument,
}

impl fmt::Debug for VerifiedAuthenticatorRuntimeBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedAuthenticatorRuntimeBinding")
            .field("document_id", &self.document.document_id)
            .field("document_version", &self.document.document_version)
            .field("content_digest", &self.reference.content_digest)
            .field("byte_len", &self.raw_bytes.len())
            .field("provider_id", &self.document.provider_id)
            .field(
                "provider_configuration_version",
                &self.document.provider_configuration_version,
            )
            .finish_non_exhaustive()
    }
}

impl VerifiedAuthenticatorRuntimeBinding {
    /// Re-hash and losslessly reparse the exact authenticated document bytes.
    /// A cached typed value is never sufficient to preserve D.
    fn verify_integrity(&self) -> Result<(), String> {
        self.reference.validate()?;
        if self.raw_bytes.is_empty() || raw_digest(&self.raw_bytes) != self.reference.content_digest
        {
            return Err(
                "retained authenticator runtime-binding bytes no longer match their exact digest"
                    .into(),
            );
        }
        let exact_value = parse_json_strict(&self.raw_bytes).map_err(|error| {
            format!("retained authenticator runtime-binding JSON is invalid: {error}")
        })?;
        validate_against_schema(
            "retained authenticator runtime binding",
            AUTHENTICATOR_RUNTIME_BINDING_SCHEMA,
            &exact_value,
        )?;
        let reparsed = serde_json::from_value::<AuthenticatorRuntimeBindingDocument>(exact_value)
            .map_err(|error| {
            format!("retained authenticator runtime binding is not losslessly typed: {error}")
        })?;
        reparsed.validate()?;
        if reparsed != self.document {
            return Err(
                "retained authenticator runtime-binding bytes differ from the sealed typed document"
                    .into(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct SecurityLimitScopeBinding {
    kind: String,
    dimensions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct SecurityLimitHardBoundsBinding {
    minimum: Number,
    maximum: Number,
    minimum_inclusive: bool,
    maximum_inclusive: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct SecurityLimitOverrideDimensionBinding {
    dimension: String,
    value: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct SecurityLimitOverrideBinding {
    override_id: String,
    selected_value: Number,
    scope_dimensions: Vec<SecurityLimitOverrideDimensionBinding>,
    tightens_only: bool,
}

/// Typed subset of one schema-validated security-limit row. The complete
/// document remains retained as exact JSON alongside these enforcement fields,
/// so fields irrelevant to authenticator limit resolution cannot be silently
/// rewritten or discarded.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct SecurityLimitRowBinding {
    limit_id: String,
    category: String,
    selected_value: Number,
    published_default: Number,
    unit: String,
    scope: SecurityLimitScopeBinding,
    hard_bounds: SecurityLimitHardBoundsBinding,
    enforcement_status: String,
    overrides: Vec<SecurityLimitOverrideBinding>,
    #[serde(default)]
    lifecycle: Option<String>,
    #[serde(default)]
    applicability_expression: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SecurityLimitDeploymentSelection {
    deployment_id: String,
    security_profile: SecurityProfile,
    enabled_features: BTreeSet<String>,
    admitted_at: DateTime<Utc>,
}

impl SecurityLimitDeploymentSelection {
    fn from_profile(profile: &DeploymentSecurityProfile, admitted_at: DateTime<Utc>) -> Self {
        Self {
            deployment_id: profile.deployment_id.clone(),
            security_profile: profile.security_profile,
            enabled_features: profile.enabled_features.iter().cloned().collect(),
            admitted_at,
        }
    }
}

/// Exact active security-limit authority selected by the deployment profile.
///
/// The raw bytes, their content reference, the strict parsed document and the
/// typed enforcement rows are retained together. This object is deliberately
/// opaque: callers can resolve a closed authenticator policy, but cannot build
/// a parallel numeric authority from configuration.
pub(crate) struct VerifiedSecurityLimitProfile {
    reference: VersionedContentReference,
    raw_bytes: Box<[u8]>,
    document: Value,
    limits: Box<[SecurityLimitRowBinding]>,
    selection: SecurityLimitDeploymentSelection,
}

impl fmt::Debug for VerifiedSecurityLimitProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedSecurityLimitProfile")
            .field("document_id", &self.reference.document_id)
            .field("document_version", &self.reference.document_version)
            .field("content_digest", &self.reference.content_digest)
            .field("byte_len", &self.raw_bytes.len())
            .field("limit_count", &self.limits.len())
            .finish_non_exhaustive()
    }
}

impl VerifiedSecurityLimitProfile {
    fn seal(
        reference: VersionedContentReference,
        raw_bytes: Vec<u8>,
        traversed_document: &Value,
        selection: SecurityLimitDeploymentSelection,
    ) -> Result<Self, String> {
        if reference.artifact_kind != ArtifactKind::SecurityLimitProfile
            || reference.document_version == 0
        {
            return Err(
                "security-limit profile reference has the wrong artifact kind or version".into(),
            );
        }
        validate_digest_pin(
            "security-limit profile reference digest",
            &reference.content_digest,
        )?;
        validate_relative_path(
            "security-limit profile reference locator",
            Path::new(&reference.artifact_locator),
        )?;
        if raw_bytes.is_empty() || raw_digest(&raw_bytes) != reference.content_digest {
            return Err(
                "security-limit profile exact bytes do not match the selected reference".into(),
            );
        }
        let document = parse_json_strict(&raw_bytes)
            .map_err(|error| format!("security-limit profile JSON is invalid: {error}"))?;
        validate_against_schema("security limit profile", LIMIT_SCHEMA, &document)?;
        if &document != traversed_document {
            return Err(
                "security-limit profile exact bytes differ from the verified traversal".into(),
            );
        }
        let limits = typed_security_limit_rows(&document)?;
        let verified = Self {
            reference,
            raw_bytes: raw_bytes.into_boxed_slice(),
            document,
            limits,
            selection,
        };
        verified.verify_integrity()?;
        Ok(verified)
    }

    pub(crate) fn verify_integrity(&self) -> Result<(), String> {
        if self.reference.artifact_kind != ArtifactKind::SecurityLimitProfile
            || self.reference.document_version == 0
        {
            return Err(
                "retained security-limit profile reference has the wrong artifact kind or version"
                    .into(),
            );
        }
        validate_digest_pin(
            "retained security-limit profile digest",
            &self.reference.content_digest,
        )?;
        if self.raw_bytes.is_empty() || raw_digest(&self.raw_bytes) != self.reference.content_digest
        {
            return Err(
                "retained security-limit profile bytes no longer match their exact digest".into(),
            );
        }
        let reparsed = parse_json_strict(&self.raw_bytes)
            .map_err(|error| format!("retained security-limit profile JSON is invalid: {error}"))?;
        validate_against_schema("retained security limit profile", LIMIT_SCHEMA, &reparsed)?;
        if reparsed != self.document || typed_security_limit_rows(&reparsed)? != self.limits {
            return Err(
                "retained security-limit profile bytes differ from the sealed typed document"
                    .into(),
            );
        }
        validate_security_limit_profile_identity(&self.reference, &reparsed, &self.selection)
    }

    fn resolve_exact_seconds_limit(
        &self,
        limit_id: &str,
        scope: &AuthenticatorLimitResolutionScope<'_>,
    ) -> Result<ResolvedSecondsLimit, String> {
        self.verify_integrity()?;
        let matches = self
            .limits
            .iter()
            .filter(|limit| limit.limit_id == limit_id)
            .collect::<Vec<_>>();
        let limit = match matches.as_slice() {
            [limit] => *limit,
            [] => {
                return Err(format!(
                    "active security-limit profile omits required authenticator limit {limit_id}"
                ));
            }
            _ => {
                return Err(format!(
                    "active security-limit profile duplicates authenticator limit {limit_id}"
                ));
            }
        };
        if limit.category != "ttl" || limit.unit != "seconds" {
            return Err(format!(
                "authenticator limit {limit_id} must use category ttl and unit seconds"
            ));
        }
        if limit.enforcement_status != "enforced" || limit.lifecycle.as_deref() != Some("active") {
            return Err(format!(
                "authenticator limit {limit_id} must be active and fully enforced"
            ));
        }
        if limit.applicability_expression.as_deref() != Some("always") {
            return Err(format!(
                "authenticator limit {limit_id} must have exact always applicability"
            ));
        }
        let expected_scope_dimensions =
            BTreeSet::from(["deployment_id", "provider_id", "trust_domain_id"]);
        let actual_scope_dimensions = limit
            .scope
            .dimensions
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if limit.scope.kind != "provider"
            || actual_scope_dimensions != expected_scope_dimensions
            || limit.scope.dimensions.len() != expected_scope_dimensions.len()
        {
            return Err(format!(
                "authenticator limit {limit_id} must use the exact provider/deployment/trust-domain scope"
            ));
        }

        let minimum = exact_limit_integer(&limit.hard_bounds.minimum, limit_id, "hard minimum")?;
        let maximum = exact_limit_integer(&limit.hard_bounds.maximum, limit_id, "hard maximum")?;
        validate_limit_bounds(
            limit_id,
            minimum,
            maximum,
            limit.hard_bounds.minimum_inclusive,
            limit.hard_bounds.maximum_inclusive,
        )?;
        let published_default =
            exact_limit_integer(&limit.published_default, limit_id, "published default")?;
        validate_limit_value(
            limit_id,
            "published default",
            published_default,
            minimum,
            maximum,
            limit.hard_bounds.minimum_inclusive,
            limit.hard_bounds.maximum_inclusive,
        )?;
        let selected = exact_limit_integer(&limit.selected_value, limit_id, "selected value")?;
        validate_limit_value(
            limit_id,
            "selected value",
            selected,
            minimum,
            maximum,
            limit.hard_bounds.minimum_inclusive,
            limit.hard_bounds.maximum_inclusive,
        )?;

        let mut override_ids = BTreeSet::new();
        let mut matching_override: Option<(&str, u64)> = None;
        for candidate in &limit.overrides {
            if !override_ids.insert(candidate.override_id.as_str()) {
                return Err(format!(
                    "authenticator limit {limit_id} repeats override {}",
                    candidate.override_id
                ));
            }
            if !candidate.tightens_only {
                return Err(format!(
                    "authenticator limit {limit_id} override {} is not tightening-only",
                    candidate.override_id
                ));
            }
            let value = exact_limit_integer(
                &candidate.selected_value,
                limit_id,
                "override selected value",
            )?;
            validate_limit_value(
                limit_id,
                "override selected value",
                value,
                minimum,
                maximum,
                limit.hard_bounds.minimum_inclusive,
                limit.hard_bounds.maximum_inclusive,
            )?;
            if value >= selected {
                return Err(format!(
                    "authenticator limit {limit_id} override {} does not strictly tighten the selected maximum",
                    candidate.override_id
                ));
            }

            let mut dimensions = BTreeSet::new();
            let mut applies = true;
            for dimension in &candidate.scope_dimensions {
                if !dimensions.insert(dimension.dimension.as_str()) {
                    return Err(format!(
                        "authenticator limit {limit_id} override {} repeats scope dimension {}",
                        candidate.override_id, dimension.dimension
                    ));
                }
                let expected = match dimension.dimension.as_str() {
                    "deployment_id" => scope.deployment_id,
                    "provider_id" => scope.provider_id,
                    "trust_domain_id" => scope.trust_domain_id,
                    unsupported => {
                        return Err(format!(
                            "authenticator limit {limit_id} override {} uses unsupported scope dimension {unsupported}",
                            candidate.override_id
                        ));
                    }
                };
                applies &= dimension.value == expected;
            }
            if dimensions.is_empty() {
                return Err(format!(
                    "authenticator limit {limit_id} override {} has no scope",
                    candidate.override_id
                ));
            }
            if applies {
                if matching_override.is_some() {
                    return Err(format!(
                        "authenticator limit {limit_id} has ambiguous applicable overrides"
                    ));
                }
                matching_override = Some((candidate.override_id.as_str(), value));
            }
        }

        let (applied_override_id, effective_seconds) = matching_override
            .map(|(override_id, value)| (Some(override_id.to_owned()), value))
            .unwrap_or((None, selected));
        Ok(ResolvedSecondsLimit {
            limit_id: limit_id.to_owned(),
            effective_seconds,
            applied_override_id,
        })
    }

    #[cfg(test)]
    fn content_digest(&self) -> &str {
        &self.reference.content_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedSecondsLimit {
    limit_id: String,
    effective_seconds: u64,
    applied_override_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedAuthenticatorBearerLimitValues {
    provider_id: String,
    path_id: String,
    clock_skew: ResolvedSecondsLimit,
    credential_lifetime: ResolvedSecondsLimit,
}

struct AuthenticatorLimitResolutionScope<'a> {
    deployment_id: &'a str,
    trust_domain_id: &'a str,
    provider_id: &'a str,
}

/// Closed limit authority for the exact retained Entra bearer verifier.
/// Clones share this allocation through `Arc`; there is no public constructor
/// and no caller-supplied numeric fallback.
pub(crate) struct ResolvedAuthenticatorBearerLimits {
    security_limit_profile: Arc<VerifiedSecurityLimitProfile>,
    runtime_binding: Arc<VerifiedAuthenticatorRuntimeBinding>,
    values: ResolvedAuthenticatorBearerLimitValues,
}

impl fmt::Debug for ResolvedAuthenticatorBearerLimits {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedAuthenticatorBearerLimits")
            .field("provider_id", &self.values.provider_id)
            .field("path_id", &self.values.path_id)
            .field(
                "clock_skew_override_id",
                &self.values.clock_skew.applied_override_id,
            )
            .field(
                "credential_lifetime_override_id",
                &self.values.credential_lifetime.applied_override_id,
            )
            .field("security_limit_profile", &"[RETAINED]")
            .field("runtime_binding", &"[RETAINED]")
            .finish_non_exhaustive()
    }
}

impl ResolvedAuthenticatorBearerLimits {
    fn seal(
        security_limit_profile: Arc<VerifiedSecurityLimitProfile>,
        runtime_binding: Arc<VerifiedAuthenticatorRuntimeBinding>,
        provider_id: &str,
    ) -> Result<Arc<Self>, String> {
        let values = resolve_entra_bearer_limit_values(
            &security_limit_profile,
            &runtime_binding,
            provider_id,
        )?;
        let resolved = Arc::new(Self {
            security_limit_profile,
            runtime_binding,
            values,
        });
        resolved.verify_integrity()?;
        Ok(resolved)
    }

    pub(crate) fn clock_skew_limit_id(&self) -> &str {
        &self.values.clock_skew.limit_id
    }

    pub(crate) fn maximum_clock_skew_seconds(&self) -> u64 {
        self.values.clock_skew.effective_seconds
    }

    pub(crate) fn credential_lifetime_limit_id(&self) -> &str {
        &self.values.credential_lifetime.limit_id
    }

    pub(crate) fn maximum_credential_lifetime_seconds(&self) -> u64 {
        self.values.credential_lifetime.effective_seconds
    }

    #[cfg(test)]
    pub(crate) fn provider_id(&self) -> &str {
        &self.values.provider_id
    }

    #[cfg(test)]
    pub(crate) fn path_id(&self) -> &str {
        &self.values.path_id
    }

    #[cfg(test)]
    pub(crate) fn security_limit_profile_content_digest(&self) -> &str {
        self.security_limit_profile.content_digest()
    }

    pub(crate) fn verify_integrity(&self) -> Result<(), String> {
        self.security_limit_profile.verify_integrity()?;
        self.runtime_binding.verify_integrity()?;
        let remeasured = resolve_entra_bearer_limit_values(
            &self.security_limit_profile,
            &self.runtime_binding,
            &self.values.provider_id,
        )?;
        if remeasured != self.values {
            return Err(
                "retained authenticator bearer limits differ from exact D/profile remeasurement"
                    .into(),
            );
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn remeasures_exact_values(&self) -> bool {
        self.verify_integrity().is_ok()
    }

    #[cfg(test)]
    pub(crate) fn fixture(clock_skew_seconds: u64, maximum_lifetime_seconds: u64) -> Arc<Self> {
        let security_limit_profile = Arc::new(fixture_security_limit_profile(
            clock_skew_seconds,
            maximum_lifetime_seconds,
        ));
        let runtime_binding = Arc::new(fixture_authenticator_runtime_binding(
            clock_skew_seconds,
            maximum_lifetime_seconds,
        ));
        Self::seal(
            security_limit_profile,
            runtime_binding,
            "provider:fixture-entra",
        )
        .expect("canonical authenticator bearer limit fixture must resolve")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedAuthenticatorBrowserLimitValues {
    provider_id: String,
    path_id: String,
    clock_skew: ResolvedSecondsLimit,
    state_lifetime: ResolvedSecondsLimit,
    session_maximum_age: ResolvedSecondsLimit,
    federated_authority_staleness: ResolvedSecondsLimit,
}

/// Closed limit authority for the exact Entra browser ID-token path and its
/// derived session. Browser credentials deliberately have no bearer
/// credential-lifetime arm.
pub(crate) struct ResolvedAuthenticatorBrowserLimits {
    security_limit_profile: Arc<VerifiedSecurityLimitProfile>,
    runtime_binding: Arc<VerifiedAuthenticatorRuntimeBinding>,
    values: ResolvedAuthenticatorBrowserLimitValues,
}

impl fmt::Debug for ResolvedAuthenticatorBrowserLimits {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedAuthenticatorBrowserLimits")
            .field("provider_id", &self.values.provider_id)
            .field("path_id", &self.values.path_id)
            .field(
                "clock_skew_override_id",
                &self.values.clock_skew.applied_override_id,
            )
            .field(
                "state_lifetime_override_id",
                &self.values.state_lifetime.applied_override_id,
            )
            .field(
                "session_maximum_age_override_id",
                &self.values.session_maximum_age.applied_override_id,
            )
            .field(
                "federated_authority_staleness_override_id",
                &self
                    .values
                    .federated_authority_staleness
                    .applied_override_id,
            )
            .field("security_limit_profile", &"[RETAINED]")
            .field("runtime_binding", &"[RETAINED]")
            .finish_non_exhaustive()
    }
}

impl ResolvedAuthenticatorBrowserLimits {
    fn seal(
        security_limit_profile: Arc<VerifiedSecurityLimitProfile>,
        runtime_binding: Arc<VerifiedAuthenticatorRuntimeBinding>,
        provider_id: &str,
    ) -> Result<Arc<Self>, String> {
        let values = resolve_entra_browser_limit_values(
            &security_limit_profile,
            &runtime_binding,
            provider_id,
        )?;
        let resolved = Arc::new(Self {
            security_limit_profile,
            runtime_binding,
            values,
        });
        resolved.verify_integrity()?;
        Ok(resolved)
    }

    pub(crate) fn clock_skew_limit_id(&self) -> &str {
        &self.values.clock_skew.limit_id
    }

    pub(crate) fn maximum_clock_skew_seconds(&self) -> u64 {
        self.values.clock_skew.effective_seconds
    }

    pub(crate) fn state_lifetime_limit_id(&self) -> &str {
        &self.values.state_lifetime.limit_id
    }

    pub(crate) fn maximum_state_lifetime_seconds(&self) -> u64 {
        self.values.state_lifetime.effective_seconds
    }

    pub(crate) fn session_maximum_age_limit_id(&self) -> &str {
        &self.values.session_maximum_age.limit_id
    }

    pub(crate) fn maximum_session_age_seconds(&self) -> u64 {
        self.values.session_maximum_age.effective_seconds
    }

    pub(crate) fn federated_authority_staleness_limit_id(&self) -> &str {
        &self.values.federated_authority_staleness.limit_id
    }

    pub(crate) fn maximum_federated_authority_staleness_seconds(&self) -> u64 {
        self.values.federated_authority_staleness.effective_seconds
    }

    #[cfg(test)]
    pub(crate) fn provider_id(&self) -> &str {
        &self.values.provider_id
    }

    #[cfg(test)]
    pub(crate) fn path_id(&self) -> &str {
        &self.values.path_id
    }

    pub(crate) fn verify_integrity(&self) -> Result<(), String> {
        self.security_limit_profile.verify_integrity()?;
        self.runtime_binding.verify_integrity()?;
        let remeasured = resolve_entra_browser_limit_values(
            &self.security_limit_profile,
            &self.runtime_binding,
            &self.values.provider_id,
        )?;
        if remeasured != self.values {
            return Err(
                "retained authenticator browser limits differ from exact D/profile remeasurement"
                    .into(),
            );
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn remeasures_exact_values(&self) -> bool {
        self.verify_integrity().is_ok()
    }

    #[cfg(test)]
    pub(crate) fn fixture(clock_skew_seconds: u64) -> Arc<Self> {
        let session = ryuki_core::config::SessionConfig::default();
        Self::fixture_with_session_policy(
            clock_skew_seconds,
            session.cookie_max_age_secs,
            session.federated_authority_max_staleness_secs,
        )
    }

    #[cfg(test)]
    pub(crate) fn fixture_with_session_policy(
        clock_skew_seconds: u64,
        maximum_session_age_seconds: u64,
        maximum_federated_authority_staleness_seconds: u64,
    ) -> Arc<Self> {
        Self::seal(
            Arc::new(fixture_security_limit_profile_with_browser_limits(
                clock_skew_seconds,
                3_600,
                maximum_session_age_seconds,
                maximum_federated_authority_staleness_seconds,
            )),
            Arc::new(fixture_authenticator_runtime_binding(
                clock_skew_seconds,
                3_600,
            )),
            "provider:fixture-entra",
        )
        .expect("canonical authenticator browser limit fixture must resolve")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedAuthenticatorPathMetadata {
    path_id: String,
    path_version: u64,
}

fn declared_entra_runtime_binding_projection(
    binding_document_reference: &AuthenticatorRuntimeBindingDocumentReference,
    document: &AuthenticatorRuntimeBindingDocument,
    provider_configuration_payload_digest: &str,
    provider_lifecycle_record_version: u64,
    provider_policy_binding_digest: &str,
) -> Result<AuthenticatorRuntimeBindingProjection, String> {
    if document.authenticator_kind != "oidc" {
        return Err("declared Entra runtime-binding projection must remain OIDC".into());
    }
    let credential_paths = document
        .credential_paths
        .iter()
        .map(|path| AuthenticatorRuntimePathProjection {
            path_id: path.path_id.clone(),
            path_version: path.path_version,
            verifier: path.verifier.clone(),
            credential_profile: path.credential_profile.clone(),
            cache_partition_binding_digest: path.cache_partition.binding_digest.clone(),
            protocol_binding_digest: path.protocol_binding.binding_digest.clone(),
            retained_consumer_ids: path.retained_consumer_ids.clone(),
        })
        .collect::<Vec<_>>();
    let projection = AuthenticatorRuntimeBindingProjection {
        provider: ExpectedProviderBinding {
            provider_id: document.provider_id.clone(),
            configuration_version: document.provider_configuration_version,
            configuration_payload_digest: provider_configuration_payload_digest.to_owned(),
            lifecycle_record_version: provider_lifecycle_record_version,
            lifecycle_state: ProviderLifecycleState::Active,
            capability_descriptor_id: document.capability_descriptor_id.clone(),
            capability_descriptor_version: document.capability_descriptor_version,
            adapter_kind: document.adapter_kind.clone(),
            adapter_version: document.adapter_version.clone(),
        },
        binding_document_reference: binding_document_reference.clone(),
        authenticator_kind: ProductionAuthenticatorKind::Oidc,
        provider_policy_binding_digest: provider_policy_binding_digest.to_owned(),
        capability_ids: document.capability_ids.clone(),
        credential_paths,
        ownership: document.ownership.clone(),
    };
    // This call validates the complete canonical declared projection. Its
    // digest is intentionally discarded: only a separately observed runtime
    // allocation may supply measured R.
    authenticator_runtime_binding_digest(&projection).map_err(|error| {
        format!("declared Entra runtime-binding projection is invalid: {error}")
    })?;
    Ok(projection)
}

/// One closed selection of the active Entra provider declaration, its exact D
/// allocation, independently recomputed provider policy Q, and the limit
/// authorities resolved from that same D/profile pair.
///
/// This is startup configuration authority only. It deliberately makes no
/// claim about a measured runtime allocation and is not a production guard
/// witness.
pub(crate) struct ResolvedEntraAuthenticatorAuthority {
    deployment_id: String,
    trust_domain_id: String,
    tenant_id: Option<String>,
    provider_id: String,
    provider_configuration_version: u64,
    provider_configuration_payload_digest: String,
    provider_lifecycle_record_version: u64,
    provider_lifecycle_state: ProviderLifecycleState,
    binding_document_reference: AuthenticatorRuntimeBindingDocumentReference,
    provider_policy_binding_digest: String,
    oidc_configuration: OidcKindConfig,
    declared_runtime_binding_projection: AuthenticatorRuntimeBindingProjection,
    security_limit_profile: Arc<VerifiedSecurityLimitProfile>,
    runtime_binding: Arc<VerifiedAuthenticatorRuntimeBinding>,
    bearer_limits: Arc<ResolvedAuthenticatorBearerLimits>,
    browser_limits: Option<Arc<ResolvedAuthenticatorBrowserLimits>>,
    bearer_path: ResolvedAuthenticatorPathMetadata,
    browser_path: Option<ResolvedAuthenticatorPathMetadata>,
}

impl fmt::Debug for ResolvedEntraAuthenticatorAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedEntraAuthenticatorAuthority")
            .field("deployment_id", &self.deployment_id)
            .field("trust_domain_id", &self.trust_domain_id)
            .field("tenant_id", &self.tenant_id)
            .field("provider_id", &self.provider_id)
            .field(
                "provider_configuration_version",
                &self.provider_configuration_version,
            )
            .field(
                "provider_lifecycle_record_version",
                &self.provider_lifecycle_record_version,
            )
            .field("provider_lifecycle_state", &self.provider_lifecycle_state)
            .field(
                "binding_document_reference",
                &self.binding_document_reference,
            )
            .field("bearer_path", &self.bearer_path)
            .field("browser_path", &self.browser_path)
            .field("security_limit_profile", &"[RETAINED]")
            .field("runtime_binding", &"[RETAINED]")
            .field("bearer_limits", &"[RETAINED]")
            .field(
                "browser_limits",
                &self.browser_limits.as_ref().map(|_| "[RETAINED]"),
            )
            .finish_non_exhaustive()
    }
}

impl ResolvedEntraAuthenticatorAuthority {
    fn seal(
        deployment_id: &str,
        tenant_id: Option<&str>,
        security_limit_profile: Arc<VerifiedSecurityLimitProfile>,
        provider: &ActiveProviderConfiguration,
        runtime_binding: Arc<VerifiedAuthenticatorRuntimeBinding>,
        bearer_limits: Arc<ResolvedAuthenticatorBearerLimits>,
        browser_limits: Option<Arc<ResolvedAuthenticatorBrowserLimits>>,
    ) -> Result<Arc<Self>, String> {
        security_limit_profile.verify_integrity()?;
        runtime_binding.verify_integrity()?;
        bearer_limits.verify_integrity()?;
        if let Some(browser_limits) = &browser_limits {
            browser_limits.verify_integrity()?;
        }

        let ActiveProviderKindConfig::Oidc {
            configuration,
            verified_runtime_binding,
        } = &provider.kind_config
        else {
            return Err("active Entra authenticator authority requires an OIDC provider".into());
        };
        if !Arc::ptr_eq(verified_runtime_binding, &runtime_binding) {
            return Err(
                "active Entra provider and authority retain different D allocations".into(),
            );
        }
        if !Arc::ptr_eq(
            &security_limit_profile,
            &bearer_limits.security_limit_profile,
        ) || !Arc::ptr_eq(&runtime_binding, &bearer_limits.runtime_binding)
        {
            return Err(
                "active Entra bearer limits do not retain the authority's exact D/profile allocations"
                    .into(),
            );
        }
        if browser_limits.as_ref().is_some_and(|browser_limits| {
            !Arc::ptr_eq(
                &security_limit_profile,
                &browser_limits.security_limit_profile,
            ) || !Arc::ptr_eq(&runtime_binding, &browser_limits.runtime_binding)
        }) {
            return Err(
                "active Entra browser limits do not retain the authority's exact D/profile allocations"
                    .into(),
            );
        }

        let document = &runtime_binding.document;
        if provider.kind != "oidc"
            || provider.capability_descriptor.adapter_kind != "auth.entra-id"
            || provider.provider_id != document.provider_id
            || provider.config_version != document.provider_configuration_version
            || provider.trust_domain_id != document.trust_domain_id
            || deployment_id != document.deployment_id
            || provider.active_lifecycle_record_version == 0
            || provider.capability_descriptor.descriptor_id != document.capability_descriptor_id
            || provider.capability_descriptor.descriptor_version
                != document.capability_descriptor_version
            || provider.capability_descriptor.adapter_kind != document.adapter_kind
            || provider.capability_descriptor.adapter_version != document.adapter_version
            || runtime_binding.reference.document_id != document.document_id
            || runtime_binding.reference.document_version != document.document_version
        {
            return Err(
                "active Entra provider metadata differs from its exact runtime-binding D".into(),
            );
        }
        if configuration.runtime_binding_ref != runtime_binding.reference {
            return Err(
                "active Entra provider configuration does not reference the retained D".into(),
            );
        }
        validate_digest_pin(
            "active Entra provider configuration payload digest",
            &provider.payload_digest,
        )?;
        let oidc_configuration_value =
            serde_json::to_value(configuration.as_ref()).map_err(|error| {
                format!("active Entra OIDC policy could not be reprojected: {error}")
            })?;
        let provider_policy_binding_digest = authenticator_provider_policy_binding_digest(
            &oidc_configuration_value,
        )
        .map_err(|error| {
            format!(
                "active Entra provider-policy digest could not be independently recomputed: {error}"
            )
        })?;
        if document.provider_policy.digest_contract
            != AUTHENTICATOR_PROVIDER_POLICY_BINDING_DIGEST_CONTRACT
            || document.provider_policy.binding_digest != provider_policy_binding_digest
        {
            return Err(
                "active Entra provider policy Q differs from its independently recomputed policy"
                    .into(),
            );
        }
        let d_digest = &runtime_binding.reference.content_digest;
        let p_digest = &provider.payload_digest;
        let q_digest = &provider_policy_binding_digest;
        if d_digest == p_digest || d_digest == q_digest || p_digest == q_digest {
            return Err("active Entra authority violates D/P/Q digest separation".into());
        }

        let binding_document_reference = AuthenticatorRuntimeBindingDocumentReference {
            document_id: runtime_binding.reference.document_id.clone(),
            document_version: runtime_binding.reference.document_version,
            content_digest: runtime_binding.reference.content_digest.clone(),
            artifact_locator: runtime_binding.reference.artifact_locator.clone(),
        };
        let declared_runtime_binding_projection = declared_entra_runtime_binding_projection(
            &binding_document_reference,
            document,
            &provider.payload_digest,
            provider.active_lifecycle_record_version,
            &provider_policy_binding_digest,
        )?;
        let bearer_paths = document
            .credential_paths
            .iter()
            .filter(|path| path.credential_profile.token_profile == "jwt-access-token")
            .collect::<Vec<_>>();
        let bearer_path = match bearer_paths.as_slice() {
            [path] if path.path_id == bearer_limits.values.path_id => {
                ResolvedAuthenticatorPathMetadata {
                    path_id: path.path_id.clone(),
                    path_version: path.path_version,
                }
            }
            _ => {
                return Err(
                    "active Entra D has ambiguous or mismatched bearer path authority".into(),
                );
            }
        };

        let browser_paths = document
            .credential_paths
            .iter()
            .filter(|path| path.credential_profile.token_profile == "oidc-id-token")
            .collect::<Vec<_>>();
        let browser_path = match (browser_paths.as_slice(), &browser_limits) {
            ([], None) => None,
            ([path], Some(browser_limits)) if path.path_id == browser_limits.values.path_id => {
                Some(ResolvedAuthenticatorPathMetadata {
                    path_id: path.path_id.clone(),
                    path_version: path.path_version,
                })
            }
            ([], Some(_)) => {
                return Err(
                    "active Entra browser limits have no corresponding browser path in D".into(),
                );
            }
            ([_], None) => {
                return Err(
                    "active Entra browser path has no resolved browser limit authority".into(),
                );
            }
            _ => {
                return Err(
                    "active Entra D has ambiguous or mismatched browser path authority".into(),
                );
            }
        };

        let resolved = Arc::new(Self {
            deployment_id: deployment_id.to_owned(),
            trust_domain_id: provider.trust_domain_id.clone(),
            tenant_id: tenant_id.map(str::to_owned),
            provider_id: provider.provider_id.clone(),
            provider_configuration_version: provider.config_version,
            provider_configuration_payload_digest: provider.payload_digest.clone(),
            provider_lifecycle_record_version: provider.active_lifecycle_record_version,
            provider_lifecycle_state: ProviderLifecycleState::Active,
            binding_document_reference,
            provider_policy_binding_digest,
            oidc_configuration: configuration.as_ref().clone(),
            declared_runtime_binding_projection,
            security_limit_profile,
            runtime_binding,
            bearer_limits,
            browser_limits,
            bearer_path,
            browser_path,
        });
        resolved.verify_integrity()?;
        Ok(resolved)
    }

    pub(crate) fn deployment_id(&self) -> &str {
        &self.deployment_id
    }

    pub(crate) fn trust_domain_id(&self) -> &str {
        &self.trust_domain_id
    }

    pub(crate) fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }

    pub(crate) fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub(crate) fn provider_configuration_version(&self) -> u64 {
        self.provider_configuration_version
    }

    pub(crate) fn provider_configuration_payload_digest(&self) -> &str {
        &self.provider_configuration_payload_digest
    }

    pub(crate) fn provider_lifecycle_record_version(&self) -> u64 {
        self.provider_lifecycle_record_version
    }

    pub(crate) fn provider_lifecycle_state(&self) -> ProviderLifecycleState {
        self.provider_lifecycle_state
    }

    pub(crate) fn binding_document_reference(
        &self,
    ) -> &AuthenticatorRuntimeBindingDocumentReference {
        &self.binding_document_reference
    }

    pub(crate) fn verified_runtime_binding(&self) -> &Arc<VerifiedAuthenticatorRuntimeBinding> {
        &self.runtime_binding
    }

    pub(crate) fn provider_policy_binding_digest(&self) -> &str {
        &self.provider_policy_binding_digest
    }

    /// Full declaration-side expectation reconstructed from exact D plus the
    /// selected active provider P/lifecycle and independently recomputed Q.
    /// Callers must compare this with their own live observation; this value is
    /// never a runtime measurement by itself.
    pub(crate) fn declared_runtime_binding_projection(
        &self,
    ) -> &AuthenticatorRuntimeBindingProjection {
        &self.declared_runtime_binding_projection
    }

    pub(crate) fn bearer_limits(&self) -> &Arc<ResolvedAuthenticatorBearerLimits> {
        &self.bearer_limits
    }

    pub(crate) fn browser_limits(&self) -> Option<&Arc<ResolvedAuthenticatorBrowserLimits>> {
        self.browser_limits.as_ref()
    }

    pub(crate) fn bearer_path_id(&self) -> &str {
        &self.bearer_path.path_id
    }

    pub(crate) fn bearer_path_version(&self) -> u64 {
        self.bearer_path.path_version
    }

    pub(crate) fn browser_path_id(&self) -> Option<&str> {
        self.browser_path.as_ref().map(|path| path.path_id.as_str())
    }

    pub(crate) fn browser_path_version(&self) -> Option<u64> {
        self.browser_path.as_ref().map(|path| path.path_version)
    }

    /// Build a test-only authority through the same closed seal used by
    /// startup. The declaration is derived from the supplied live Entra
    /// configuration; no independently configurable D/P/Q test knobs exist.
    #[cfg(test)]
    pub(crate) fn fixture(
        config: &RyukiConfig,
        clock_skew_seconds: u64,
        maximum_lifetime_seconds: u64,
        browser_required: bool,
    ) -> Arc<Self> {
        assert_eq!(
            config.auth_mode,
            AuthMode::EntraId,
            "Entra authority fixtures require entra-id mode"
        );
        assert!(
            !config.entra_tenant_id.is_empty() && !config.entra_client_id.is_empty(),
            "Entra authority fixtures require tenant and client identity"
        );
        let mut binding_value: Value = serde_json::from_slice(
            &fixture_authenticator_runtime_binding(clock_skew_seconds, maximum_lifetime_seconds)
                .raw_bytes,
        )
        .expect("fixture D must remain exact JSON");
        if browser_required {
            binding_value["capability_ids"] =
                serde_json::json!(["browser-sso", "token-validation"]);
        } else {
            binding_value["capability_ids"] = serde_json::json!(["token-validation"]);
            binding_value["credential_paths"]
                .as_array_mut()
                .expect("fixture D paths")
                .retain(|path| path["credential_profile"]["token_profile"] != "oidc-id-token");
        }

        // Construct the real bearer validator once against provisional exact
        // limits, then carry only its value-free observation into D.
        let provisional_binding = Arc::new(fixture_verified_authenticator_runtime_binding(
            binding_value.clone(),
        ));
        let provisional_profile = Arc::new(fixture_security_limit_profile_with_browser_limits(
            clock_skew_seconds,
            maximum_lifetime_seconds,
            config.session.cookie_max_age_secs,
            config.session.federated_authority_max_staleness_secs,
        ));
        let provisional_bearer_limits = ResolvedAuthenticatorBearerLimits::seal(
            provisional_profile,
            provisional_binding,
            "provider:fixture-entra",
        )
        .expect("fixture bearer limits must resolve");
        let bearer_observation = crate::entra_auth::EntraTokenValidator::from_app_config(
            &config.entra_tenant_id,
            &config.entra_client_id,
            &config.entra_authority,
            config.entra_jwks_ttl_secs,
            provisional_bearer_limits,
        )
        .runtime_observation();
        let bearer_path = binding_value["credential_paths"]
            .as_array_mut()
            .expect("fixture D paths")
            .iter_mut()
            .find(|path| path["credential_profile"]["token_profile"] == "jwt-access-token")
            .expect("fixture D bearer path");
        bearer_path["verifier"]["issuer_binding_digest"] =
            serde_json::json!(bearer_observation.issuer_authority_binding_digest());
        bearer_path["verifier"]["audience_set_binding_digest"] =
            serde_json::json!(bearer_observation.audience_client_binding_digest());
        bearer_path["verifier"]["key_source_binding_digest"] =
            serde_json::json!(bearer_observation.key_source_binding_digest());

        let reference_digest = |label: &str, values: &[&str]| {
            let projection = serde_json::json!({
                "fixture_binding": label,
                "values": values,
            });
            raw_digest(
                &canonical_json_bytes(&projection)
                    .expect("fixture reference projection must canonicalize"),
            )
        };
        bearer_path["cache_partition"]["binding_digest"] = serde_json::json!(reference_digest(
            "entra-bearer-cache",
            &[
                bearer_observation.issuer_authority_binding_digest(),
                bearer_observation.audience_client_binding_digest(),
                bearer_observation.key_source_binding_digest(),
            ],
        ));
        bearer_path["protocol_binding"]["binding_digest"] = serde_json::json!(reference_digest(
            "entra-bearer-protocol",
            &[
                bearer_observation.clock_skew_limit_id(),
                bearer_observation.credential_lifetime_limit_id(),
            ],
        ));

        if browser_required {
            let mut authority = reqwest::Url::parse(&config.entra_authority)
                .expect("fixture Entra authority must be a URL");
            let endpoint = |authority: &reqwest::Url, segments: &[&str]| {
                let mut endpoint = authority.clone();
                let mut path = endpoint
                    .path_segments_mut()
                    .expect("fixture Entra authority must be a base URL");
                path.pop_if_empty();
                for segment in segments {
                    path.push(segment);
                }
                drop(path);
                endpoint.to_string()
            };
            authority.set_query(None);
            authority.set_fragment(None);
            let issuer = endpoint(&authority, &[&config.entra_tenant_id, "v2.0"]);
            let jwks = endpoint(
                &authority,
                &[&config.entra_tenant_id, "discovery", "v2.0", "keys"],
            );
            let browser_observation = crate::oidc_callback::OidcIdTokenValidator::new(
                jwks,
                issuer,
                config.entra_client_id.clone(),
                clock_skew_seconds,
            )
            .runtime_observation();
            let network_jwks = browser_observation
                .network_jwks()
                .expect("fixture browser validator must retain network JWKS");
            let browser_key_source_digest = reference_digest(
                "entra-browser-jwks",
                &[
                    network_jwks.endpoint_binding_digest(),
                    &network_jwks.cache_ttl().as_secs().to_string(),
                    &network_jwks.refresh_cooldown().as_secs().to_string(),
                    &network_jwks.maximum_cached_keys().to_string(),
                    &network_jwks.maximum_response_bytes().to_string(),
                    &network_jwks.endpoint_https_only().to_string(),
                    &network_jwks.redirects_allowed().to_string(),
                    &network_jwks.ambient_proxy_allowed().to_string(),
                    &network_jwks.connect_timeout().as_millis().to_string(),
                    &network_jwks.request_timeout().as_millis().to_string(),
                ],
            );
            let browser_path = binding_value["credential_paths"]
                .as_array_mut()
                .expect("fixture D paths")
                .iter_mut()
                .find(|path| path["credential_profile"]["token_profile"] == "oidc-id-token")
                .expect("fixture D browser path");
            browser_path["verifier"]["issuer_binding_digest"] =
                serde_json::json!(browser_observation.issuer_binding_digest());
            browser_path["verifier"]["audience_set_binding_digest"] =
                serde_json::json!(browser_observation.audience_binding_digest());
            browser_path["verifier"]["key_source_binding_digest"] =
                serde_json::json!(browser_key_source_digest);
            browser_path["verifier"]["required_claim_ids"] =
                serde_json::json!(["aud", "exp", "iss", "nbf", "nonce", "oid", "sub"]);
            browser_path["verifier"]["issued_at_required"] = serde_json::json!(false);
            browser_path["cache_partition"]["binding_digest"] =
                serde_json::json!(reference_digest(
                    "entra-browser-cache",
                    &[
                        browser_observation.issuer_binding_digest(),
                        browser_observation.audience_binding_digest(),
                        network_jwks.endpoint_binding_digest(),
                    ],
                ));
            browser_path["protocol_binding"]["binding_digest"] =
                serde_json::json!(reference_digest(
                    "entra-browser-protocol",
                    &[
                        &config.entra_redirect_uri,
                        bearer_observation.clock_skew_limit_id(),
                        "pkce-s256",
                        "single-use-state",
                    ],
                ));
        }

        let provisional_reference = ContentReferenceBinding {
            document_id: "authenticator-runtime-binding:fixture-entra".into(),
            document_version: 1,
            content_digest: raw_digest(
                &serde_json::to_vec(&binding_value).expect("fixture D must serialize"),
            ),
            artifact_locator:
                "catalog/security-contracts/v1/authenticator-runtime-binding.test.json".into(),
        };
        let mut oidc_configuration =
            fixture_entra_oidc_configuration(config, provisional_reference, &reference_digest);
        let q = authenticator_provider_policy_binding_digest(
            &serde_json::to_value(&oidc_configuration)
                .expect("fixture OIDC configuration must serialize"),
        )
        .expect("fixture Q must derive");
        binding_value["provider_policy"]["binding_digest"] = serde_json::json!(q);
        let runtime_binding = Arc::new(fixture_verified_authenticator_runtime_binding(
            binding_value,
        ));
        oidc_configuration.runtime_binding_ref = runtime_binding.reference.clone();
        let p_projection = serde_json::json!({
            "provider_id": "provider:fixture-entra",
            "configuration_version": 1,
            "trust_domain_id": "trust-domain:fixture-authenticator",
            "lifecycle_record_version": 3,
            "kind_config": &oidc_configuration,
        });
        let p = raw_digest(
            &canonical_json_bytes(&p_projection)
                .expect("fixture provider payload projection must canonicalize"),
        );
        let capability_ids = runtime_binding.document.capability_ids.clone();
        let mut provider = ActiveProviderConfiguration {
            provider_id: "provider:fixture-entra".into(),
            config_version: 1,
            payload_digest: p,
            kind: "oidc".into(),
            trust_domain_id: "trust-domain:fixture-authenticator".into(),
            active_lifecycle_record_version: 3,
            capability_descriptor: ProviderCapabilityDescriptorBinding {
                descriptor_id: "capability-descriptor:fixture-entra".into(),
                descriptor_version: 1,
                adapter_kind: "auth.entra-id".into(),
                adapter_version: "1.0.0".into(),
                advertised_capabilities: capability_ids,
                mandatory_baseline_ref: ContentReferenceBinding {
                    document_id: "mandatory-baseline:fixture-entra".into(),
                    document_version: 1,
                    content_digest: reference_digest(
                        "entra-mandatory-baseline",
                        &["oidc", "jwt-jwks", "rs256"],
                    ),
                    artifact_locator:
                        "catalog/security-contracts/v1/mandatory-baseline.fixture.json".into(),
                },
                implementation_applicable: true,
                production_eligible: true,
            },
            credential_refs: Vec::new(),
            kind_config: ActiveProviderKindConfig::Oidc {
                configuration: Box::new(oidc_configuration),
                verified_runtime_binding: Arc::clone(&runtime_binding),
            },
        };
        let security_limit_profile = Arc::new(fixture_security_limit_profile_with_browser_limits(
            clock_skew_seconds,
            maximum_lifetime_seconds,
            config.session.cookie_max_age_secs,
            config.session.federated_authority_max_staleness_secs,
        ));
        let bearer_limits = ResolvedAuthenticatorBearerLimits::seal(
            Arc::clone(&security_limit_profile),
            Arc::clone(&runtime_binding),
            &provider.provider_id,
        )
        .expect("fixture bearer limits must seal");
        let browser_limits = browser_required
            .then(|| {
                ResolvedAuthenticatorBrowserLimits::seal(
                    Arc::clone(&security_limit_profile),
                    Arc::clone(&runtime_binding),
                    &provider.provider_id,
                )
            })
            .transpose()
            .expect("fixture browser limits must seal");
        let provisional_authority = Self::seal(
            "deployment:fixture-authenticator",
            None,
            Arc::clone(&security_limit_profile),
            &provider,
            Arc::clone(&runtime_binding),
            Arc::clone(&bearer_limits),
            browser_limits.as_ref().map(Arc::clone),
        )
        .expect("provisional fixture Entra authority must satisfy resolver invariants");

        // Construct the same concrete objects that production measures, then
        // replace every provisional D path with the canonical live projection.
        // Q excludes only D's top-level reference, so these preimages remain
        // stable when final D and P are re-hashed below.
        let bearer_validator = crate::entra_auth::EntraTokenValidator::from_app_config(
            &config.entra_tenant_id,
            &config.entra_client_id,
            &config.entra_authority,
            config.entra_jwks_ttl_secs,
            Arc::clone(provisional_authority.bearer_limits()),
        );
        let mut runtime_config = config.clone();
        if runtime_config.session.credential_hmac_key.is_empty() {
            runtime_config.session.credential_hmac_key = hex::encode(rand::random::<[u8; 32]>());
        }
        if browser_required && runtime_config.entra_redirect_uri.is_empty() {
            // Some negative constructor tests intentionally request a dormant
            // browser declaration. Give only the synthetic measurement object
            // a valid redirect so D can still be canonically projected; the
            // real config remains empty and is rejected by runtime admission.
            runtime_config.entra_redirect_uri =
                "https://fixture.invalid/entra/callback".to_string();
        }
        let derived_session_credentials =
            crate::session_credentials::DerivedSessionCredentialRuntime::from_admitted_config(
                &runtime_config.session,
            )
            .expect("fixture session authority must construct");
        let cookie_runtime =
            crate::cookie_runtime::ApiCookieRuntime::from_admitted_config(&runtime_config, true)
                .expect("fixture production cookie authority must construct");
        let entra_sso_dependencies = crate::entra_sso::EntraSsoDeps::from_app_config(
            &runtime_config,
            provisional_authority.browser_limits().map(Arc::clone),
            Arc::clone(&derived_session_credentials),
            Arc::clone(&cookie_runtime),
        );
        let measured_paths = crate::authenticator_runtime::fixture_measured_entra_paths(
            &provisional_authority,
            &bearer_validator,
            &entra_sso_dependencies,
            &derived_session_credentials,
            &cookie_runtime,
        )
        .expect("fixture authenticator paths must use canonical live preimages");
        let mut final_binding_value: Value =
            serde_json::from_slice(&runtime_binding.raw_bytes).expect("provisional fixture D JSON");
        fixture_replace_authenticator_path(
            &mut final_binding_value,
            &measured_paths.direct_bearer_path,
        );
        match (browser_required, measured_paths.browser.as_ref()) {
            (true, Some(browser)) => {
                fixture_replace_authenticator_path(&mut final_binding_value, browser)
            }
            (false, None) => {}
            _ => panic!("fixture browser declaration and live measurement differ"),
        }
        let runtime_binding = Arc::new(fixture_verified_authenticator_runtime_binding(
            final_binding_value,
        ));
        let ActiveProviderKindConfig::Oidc {
            configuration,
            verified_runtime_binding,
        } = &mut provider.kind_config
        else {
            panic!("fixture Entra provider must retain OIDC configuration")
        };
        configuration.runtime_binding_ref = runtime_binding.reference.clone();
        *verified_runtime_binding = Arc::clone(&runtime_binding);
        let p_projection = serde_json::json!({
            "provider_id": "provider:fixture-entra",
            "configuration_version": 1,
            "trust_domain_id": "trust-domain:fixture-authenticator",
            "lifecycle_record_version": 3,
            "kind_config": configuration.as_ref(),
        });
        provider.payload_digest = raw_digest(
            &canonical_json_bytes(&p_projection)
                .expect("final fixture provider payload projection must canonicalize"),
        );
        let bearer_limits = ResolvedAuthenticatorBearerLimits::seal(
            Arc::clone(&security_limit_profile),
            Arc::clone(&runtime_binding),
            &provider.provider_id,
        )
        .expect("final fixture bearer limits must seal");
        let browser_limits = browser_required
            .then(|| {
                ResolvedAuthenticatorBrowserLimits::seal(
                    Arc::clone(&security_limit_profile),
                    Arc::clone(&runtime_binding),
                    &provider.provider_id,
                )
            })
            .transpose()
            .expect("final fixture browser limits must seal");
        Self::seal(
            "deployment:fixture-authenticator",
            None,
            security_limit_profile,
            &provider,
            runtime_binding,
            bearer_limits,
            browser_limits,
        )
        .expect("fixture Entra authority must satisfy the production resolver invariants")
    }

    pub(crate) fn verify_integrity(&self) -> Result<(), String> {
        self.security_limit_profile.verify_integrity()?;
        self.runtime_binding.verify_integrity()?;
        self.bearer_limits.verify_integrity()?;
        if !Arc::ptr_eq(
            &self.security_limit_profile,
            &self.bearer_limits.security_limit_profile,
        ) || !Arc::ptr_eq(&self.runtime_binding, &self.bearer_limits.runtime_binding)
        {
            return Err("retained Entra bearer limits lost the exact D/profile allocations".into());
        }
        if let Some(browser_limits) = &self.browser_limits {
            browser_limits.verify_integrity()?;
            if !Arc::ptr_eq(
                &self.security_limit_profile,
                &browser_limits.security_limit_profile,
            ) || !Arc::ptr_eq(&self.runtime_binding, &browser_limits.runtime_binding)
            {
                return Err(
                    "retained Entra browser limits lost the exact D/profile allocations".into(),
                );
            }
        }
        let oidc_configuration =
            serde_json::to_value(&self.oidc_configuration).map_err(|error| {
                format!("retained Entra OIDC policy could not be reprojected: {error}")
            })?;
        let remeasured_q = authenticator_provider_policy_binding_digest(&oidc_configuration)
            .map_err(|error| {
                format!("retained Entra provider-policy Q could not be recomputed: {error}")
            })?;
        let document = &self.runtime_binding.document;
        if self.oidc_configuration.runtime_binding_ref != self.runtime_binding.reference
            || remeasured_q != self.provider_policy_binding_digest
            || document.provider_policy.binding_digest != self.provider_policy_binding_digest
            || self.binding_document_reference.document_id
                != self.runtime_binding.reference.document_id
            || self.binding_document_reference.document_version
                != self.runtime_binding.reference.document_version
            || self.binding_document_reference.content_digest
                != self.runtime_binding.reference.content_digest
            || self.binding_document_reference.artifact_locator
                != self.runtime_binding.reference.artifact_locator
            || self.binding_document_reference.document_id != document.document_id
            || self.binding_document_reference.document_version != document.document_version
            || self.provider_id != document.provider_id
            || self.provider_configuration_version != document.provider_configuration_version
            || self.deployment_id != document.deployment_id
            || self.trust_domain_id != document.trust_domain_id
            || self.provider_lifecycle_record_version == 0
            || self.provider_lifecycle_state != ProviderLifecycleState::Active
        {
            return Err("retained Entra authority differs from its sealed D/P/Q metadata".into());
        }
        validate_digest_pin(
            "retained Entra provider configuration payload digest",
            &self.provider_configuration_payload_digest,
        )?;
        let d_digest = &self.binding_document_reference.content_digest;
        let p_digest = &self.provider_configuration_payload_digest;
        let q_digest = &self.provider_policy_binding_digest;
        if d_digest == p_digest || d_digest == q_digest || p_digest == q_digest {
            return Err("retained Entra authority violates D/P/Q digest separation".into());
        }
        let reprojected = declared_entra_runtime_binding_projection(
            &self.binding_document_reference,
            document,
            &self.provider_configuration_payload_digest,
            self.provider_lifecycle_record_version,
            &self.provider_policy_binding_digest,
        )?;
        if reprojected != self.declared_runtime_binding_projection {
            return Err(
                "retained Entra declared projection differs from exact D/P/Q authority".into(),
            );
        }
        let retained_bearer_paths = document
            .credential_paths
            .iter()
            .filter(|path| path.credential_profile.token_profile == "jwt-access-token")
            .collect::<Vec<_>>();
        match retained_bearer_paths.as_slice() {
            [document_path]
                if self.bearer_path.path_version > 0
                    && self.bearer_path.path_id == self.bearer_limits.values.path_id
                    && self.bearer_path.path_id == document_path.path_id
                    && self.bearer_path.path_version == document_path.path_version => {}
            _ => {
                return Err(
                    "retained Entra bearer path differs from its exact limit authority".into(),
                );
            }
        }
        let retained_browser_paths = document
            .credential_paths
            .iter()
            .filter(|path| path.credential_profile.token_profile == "oidc-id-token")
            .collect::<Vec<_>>();
        match (
            retained_browser_paths.as_slice(),
            &self.browser_path,
            &self.browser_limits,
        ) {
            ([], None, None) => {}
            ([document_path], Some(path), Some(limits))
                if path.path_version > 0
                    && path.path_id == limits.values.path_id
                    && path.path_id == document_path.path_id
                    && path.path_version == document_path.path_version => {}
            _ => {
                return Err(
                    "retained Entra browser path differs from its exact limit authority".into(),
                );
            }
        }
        Ok(())
    }
}

fn typed_security_limit_rows(document: &Value) -> Result<Box<[SecurityLimitRowBinding]>, String> {
    serde_json::from_value::<Vec<SecurityLimitRowBinding>>(
        document
            .get("limits")
            .cloned()
            .ok_or_else(|| "security-limit profile omits limits".to_string())?,
    )
    .map(Vec::into_boxed_slice)
    .map_err(|error| format!("security-limit profile rows are not losslessly typed: {error}"))
}

fn validate_security_limit_profile_identity(
    reference: &VersionedContentReference,
    document: &Value,
    selection: &SecurityLimitDeploymentSelection,
) -> Result<(), String> {
    if document.get("contract_kind").and_then(Value::as_str) != Some("security-limit-profile")
        || document.get("document_id").and_then(Value::as_str)
            != Some(reference.document_id.as_str())
        || document.get("document_version").and_then(Value::as_u64)
            != Some(reference.document_version)
    {
        return Err(
            "security-limit profile identity differs from its exact selected reference".into(),
        );
    }
    let lifecycle = document
        .get("lifecycle")
        .ok_or_else(|| "security-limit profile omits lifecycle".to_string())?;
    let lifecycle_state = lifecycle
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| "security-limit profile omits lifecycle.state".to_string())?;
    let effective_at = DateTime::parse_from_rfc3339(
        lifecycle
            .get("effective_at")
            .and_then(Value::as_str)
            .ok_or_else(|| "security-limit profile omits lifecycle.effective_at".to_string())?,
    )
    .map_err(|_| "security-limit profile lifecycle.effective_at is invalid".to_string())?
    .with_timezone(&Utc);
    if effective_at > selection.admitted_at {
        return Err("security-limit profile lifecycle is future-dated".into());
    }
    let applicability = document
        .get("applicability")
        .ok_or_else(|| "security-limit profile omits applicability".to_string())?;
    let evaluation_scope = applicability
        .get("evaluation_scope")
        .and_then(Value::as_str)
        .ok_or_else(|| "security-limit profile omits applicability evaluation scope".to_string())?;
    let security_profiles = string_set(applicability.get("security_profiles"));
    if !security_profiles.contains(selection.security_profile.as_str()) {
        return Err(
            "security-limit profile is not applicable to the selected security profile".into(),
        );
    }
    if selection.security_profile.is_production() {
        if lifecycle_state != "active" || evaluation_scope != "deployment" {
            return Err(
                "production security-limit profile must retain active deployment applicability"
                    .into(),
            );
        }
        let deployment_ids = string_set(applicability.get("deployment_ids"));
        if deployment_ids.len() != 1 || !deployment_ids.contains(selection.deployment_id.as_str()) {
            return Err(
                "security-limit profile deployment applicability does not match the workload root"
                    .into(),
            );
        }
        for feature in string_set(applicability.get("enabled_feature_ids")) {
            if !selection.enabled_features.contains(feature) {
                return Err(format!(
                    "security-limit profile requires unselected feature {feature}"
                ));
            }
        }
    } else if !matches!(lifecycle_state, "active" | "implementation_only")
        || !matches!(evaluation_scope, "deployment" | "implementation")
    {
        return Err(
            "non-production security-limit profile has an inadmissible lifecycle or applicability scope"
                .into(),
        );
    }
    Ok(())
}

fn exact_limit_integer(number: &Number, limit_id: &str, label: &str) -> Result<u64, String> {
    number.as_u64().ok_or_else(|| {
        format!("authenticator limit {limit_id} {label} must be an exact nonnegative integer")
    })
}

fn validate_limit_bounds(
    limit_id: &str,
    minimum: u64,
    maximum: u64,
    minimum_inclusive: bool,
    maximum_inclusive: bool,
) -> Result<(), String> {
    if minimum > maximum || (minimum == maximum && (!minimum_inclusive || !maximum_inclusive)) {
        return Err(format!(
            "authenticator limit {limit_id} has empty or inverted hard bounds"
        ));
    }
    Ok(())
}

fn validate_limit_value(
    limit_id: &str,
    label: &str,
    value: u64,
    minimum: u64,
    maximum: u64,
    minimum_inclusive: bool,
    maximum_inclusive: bool,
) -> Result<(), String> {
    if value < minimum
        || value > maximum
        || (value == minimum && !minimum_inclusive)
        || (value == maximum && !maximum_inclusive)
    {
        return Err(format!(
            "authenticator limit {limit_id} {label} {value} is outside its exact hard bounds"
        ));
    }
    Ok(())
}

fn resolve_entra_bearer_limit_values(
    security_limit_profile: &VerifiedSecurityLimitProfile,
    runtime_binding: &VerifiedAuthenticatorRuntimeBinding,
    provider_id: &str,
) -> Result<ResolvedAuthenticatorBearerLimitValues, String> {
    security_limit_profile.verify_integrity()?;
    runtime_binding.verify_integrity()?;
    let document = &runtime_binding.document;
    if document.adapter_kind != "auth.entra-id"
        || document.authenticator_kind != "oidc"
        || document.provider_id != provider_id
    {
        return Err(
            "authenticator bearer limits require the exact active Entra OIDC binding".into(),
        );
    }
    if security_limit_profile.selection.deployment_id != document.deployment_id {
        return Err(
            "authenticator bearer D and security-limit profile identify different deployments"
                .into(),
        );
    }
    let bearer_paths = document
        .credential_paths
        .iter()
        .filter(|path| path.credential_profile.token_profile == "jwt-access-token")
        .collect::<Vec<_>>();
    let bearer_path = match bearer_paths.as_slice() {
        [path] => *path,
        [] => return Err("active Entra binding omits its bearer credential path".into()),
        _ => return Err("active Entra binding has ambiguous bearer credential paths".into()),
    };
    let verifier = &bearer_path.verifier;
    let replay = &bearer_path.credential_profile.replay;
    if verifier.clock_skew_limit_id != AUTHENTICATOR_CLOCK_SKEW_LIMIT_ID
        || replay.credential_lifetime_limit_id.as_deref()
            != Some(AUTHENTICATOR_OIDC_ACCESS_TOKEN_LIFETIME_LIMIT_ID)
    {
        return Err(
            "active Entra bearer path does not reference the canonical authenticator limit ids"
                .into(),
        );
    }
    let scope = AuthenticatorLimitResolutionScope {
        deployment_id: &document.deployment_id,
        trust_domain_id: &document.trust_domain_id,
        provider_id: &document.provider_id,
    };
    let clock_skew = security_limit_profile
        .resolve_exact_seconds_limit(AUTHENTICATOR_CLOCK_SKEW_LIMIT_ID, &scope)?;
    let credential_lifetime = security_limit_profile
        .resolve_exact_seconds_limit(AUTHENTICATOR_OIDC_ACCESS_TOKEN_LIFETIME_LIMIT_ID, &scope)?;
    if clock_skew.effective_seconds != u64::from(verifier.maximum_clock_skew_seconds) {
        return Err(
            "active Entra bearer D clock-skew maximum differs from the resolved security limit"
                .into(),
        );
    }
    if replay.maximum_credential_lifetime_seconds != Some(credential_lifetime.effective_seconds) {
        return Err(
            "active Entra bearer D credential-lifetime maximum differs from the resolved security limit"
                .into(),
        );
    }
    Ok(ResolvedAuthenticatorBearerLimitValues {
        provider_id: provider_id.to_owned(),
        path_id: bearer_path.path_id.clone(),
        clock_skew,
        credential_lifetime,
    })
}

fn resolve_entra_browser_limit_values(
    security_limit_profile: &VerifiedSecurityLimitProfile,
    runtime_binding: &VerifiedAuthenticatorRuntimeBinding,
    provider_id: &str,
) -> Result<ResolvedAuthenticatorBrowserLimitValues, String> {
    security_limit_profile.verify_integrity()?;
    runtime_binding.verify_integrity()?;
    let document = &runtime_binding.document;
    if document.adapter_kind != "auth.entra-id"
        || document.authenticator_kind != "oidc"
        || document.provider_id != provider_id
        || security_limit_profile.selection.deployment_id != document.deployment_id
    {
        return Err("authenticator browser limits require the exact active Entra OIDC binding and deployment".into());
    }
    let browser_paths = document
        .credential_paths
        .iter()
        .filter(|path| path.credential_profile.token_profile == "oidc-id-token")
        .collect::<Vec<_>>();
    let browser_path = match browser_paths.as_slice() {
        [path] => *path,
        [] => return Err("active Entra binding omits its browser ID-token credential path".into()),
        _ => {
            return Err(
                "active Entra binding has ambiguous browser ID-token credential paths".into(),
            );
        }
    };
    let verifier = &browser_path.verifier;
    let replay = &browser_path.credential_profile.replay;
    if verifier.clock_skew_limit_id != AUTHENTICATOR_CLOCK_SKEW_LIMIT_ID {
        return Err(
            "active Entra browser path does not reference the canonical clock-skew limit id".into(),
        );
    }
    if replay.credential_lifetime_limit_id.is_some()
        || replay.maximum_credential_lifetime_seconds.is_some()
    {
        return Err(
            "active Entra browser path must not apply bearer credential-lifetime limits".into(),
        );
    }
    let scope = AuthenticatorLimitResolutionScope {
        deployment_id: &document.deployment_id,
        trust_domain_id: &document.trust_domain_id,
        provider_id: &document.provider_id,
    };
    let clock_skew = security_limit_profile
        .resolve_exact_seconds_limit(AUTHENTICATOR_CLOCK_SKEW_LIMIT_ID, &scope)?;
    let state_lifetime = security_limit_profile
        .resolve_exact_seconds_limit(AUTHENTICATOR_BROWSER_STATE_LIFETIME_LIMIT_ID, &scope)?;
    let session_maximum_age = security_limit_profile
        .resolve_exact_seconds_limit(AUTHENTICATOR_BROWSER_SESSION_MAXIMUM_AGE_LIMIT_ID, &scope)?;
    let federated_authority_staleness = security_limit_profile.resolve_exact_seconds_limit(
        AUTHENTICATOR_FEDERATED_AUTHORITY_STALENESS_LIMIT_ID,
        &scope,
    )?;
    if clock_skew.effective_seconds != u64::from(verifier.maximum_clock_skew_seconds) {
        return Err(
            "active Entra browser D clock-skew maximum differs from the resolved security limit"
                .into(),
        );
    }
    if state_lifetime.effective_seconds != AUTHENTICATOR_BROWSER_STATE_MAXIMUM_TTL_SECONDS {
        return Err(format!(
            "active Entra browser state lifetime must resolve exactly to {AUTHENTICATOR_BROWSER_STATE_MAXIMUM_TTL_SECONDS} seconds"
        ));
    }
    if session_maximum_age.effective_seconds == 0
        || federated_authority_staleness.effective_seconds == 0
    {
        return Err(
            "active Entra browser session maximum age and federated-authority staleness must be positive"
                .into(),
        );
    }
    if session_maximum_age.effective_seconds > ryuki_core::config::MAX_SESSION_COOKIE_AGE_SECS {
        return Err(format!(
            "active Entra browser session maximum age exceeds the {} second runtime cap",
            ryuki_core::config::MAX_SESSION_COOKIE_AGE_SECS
        ));
    }
    if federated_authority_staleness.effective_seconds > session_maximum_age.effective_seconds {
        return Err(
            "active Entra federated-authority staleness exceeds the browser session maximum age"
                .into(),
        );
    }
    Ok(ResolvedAuthenticatorBrowserLimitValues {
        provider_id: provider_id.to_owned(),
        path_id: browser_path.path_id.clone(),
        clock_skew,
        state_lifetime,
        session_maximum_age,
        federated_authority_staleness,
    })
}

#[cfg(test)]
fn fixture_security_limit_profile(
    clock_skew_seconds: u64,
    maximum_lifetime_seconds: u64,
) -> VerifiedSecurityLimitProfile {
    let session = ryuki_core::config::SessionConfig::default();
    fixture_security_limit_profile_with_browser_limits(
        clock_skew_seconds,
        maximum_lifetime_seconds,
        session.cookie_max_age_secs,
        session.federated_authority_max_staleness_secs,
    )
}

#[cfg(test)]
fn fixture_security_limit_profile_with_browser_limits(
    clock_skew_seconds: u64,
    maximum_lifetime_seconds: u64,
    maximum_session_age_seconds: u64,
    maximum_federated_authority_staleness_seconds: u64,
) -> VerifiedSecurityLimitProfile {
    let mut document: Value = serde_json::from_str(include_str!(
        "../../../catalog/security-contracts/v1/security-limit-profile.implementation.json"
    ))
    .expect("repository security-limit fixture must be valid JSON");
    document["lifecycle"]["state"] = Value::String("active".into());
    document["applicability"] = serde_json::json!({
        "evaluation_scope": "deployment",
        "security_profiles": ["test"],
        "deployment_ids": ["deployment:fixture-authenticator"],
        "enabled_feature_ids": ["authenticator-runtime-admission"]
    });
    document["limits"] = serde_json::json!([
        fixture_authenticator_limit_row(
            AUTHENTICATOR_CLOCK_SKEW_LIMIT_ID,
            clock_skew_seconds,
            0,
            clock_skew_seconds.max(300),
        ),
        fixture_authenticator_limit_row(
            AUTHENTICATOR_OIDC_ACCESS_TOKEN_LIFETIME_LIMIT_ID,
            maximum_lifetime_seconds,
            1,
            maximum_lifetime_seconds.max(86_400),
        ),
        fixture_authenticator_limit_row(
            AUTHENTICATOR_BROWSER_STATE_LIFETIME_LIMIT_ID,
            AUTHENTICATOR_BROWSER_STATE_MAXIMUM_TTL_SECONDS,
            AUTHENTICATOR_BROWSER_STATE_MAXIMUM_TTL_SECONDS,
            AUTHENTICATOR_BROWSER_STATE_MAXIMUM_TTL_SECONDS,
        ),
        fixture_authenticator_limit_row(
            AUTHENTICATOR_BROWSER_SESSION_MAXIMUM_AGE_LIMIT_ID,
            maximum_session_age_seconds,
            1,
            ryuki_core::config::MAX_SESSION_COOKIE_AGE_SECS,
        ),
        fixture_authenticator_limit_row(
            AUTHENTICATOR_FEDERATED_AUTHORITY_STALENESS_LIMIT_ID,
            maximum_federated_authority_staleness_seconds,
            1,
            3_600,
        )
    ]);
    fixture_verified_security_limit_profile(document)
}

#[cfg(test)]
fn fixture_authenticator_limit_row(
    limit_id: &str,
    selected_value: u64,
    minimum: u64,
    maximum: u64,
) -> Value {
    serde_json::json!({
        "limit_id": limit_id,
        "category": "ttl",
        "description": "Test-only exact authenticator runtime limit.",
        "selected_value": selected_value,
        "published_default": selected_value,
        "unit": "seconds",
        "scope": {
            "kind": "provider",
            "dimensions": ["deployment_id", "provider_id", "trust_domain_id"]
        },
        "hard_bounds": {
            "minimum": minimum,
            "maximum": maximum,
            "minimum_inclusive": true,
            "maximum_inclusive": true
        },
        "owner": "api-security",
        "value_change_authority": {
            "authority_id": "authority:runtime-security-config",
            "owning_team": "platform-security",
            "required_controls": ["review", "step-up"]
        },
        "bound_change_authority": {
            "authority_id": "authority:security-contract-bounds",
            "owning_team": "platform-security",
            "required_controls": ["review", "maker-checker", "contract-revision", "new-conformance-evidence"]
        },
        "failure_projection": {
            "mode": "fail-feature-readiness",
            "stable_code": "AUTHENTICATOR_LIMIT_INVALID",
            "retryable": false,
            "queueing_allowed": false,
            "value_free": true
        },
        "telemetry": {
            "metric_name": "ryuki_authenticator_limit",
            "cardinality": "constant",
            "value_free": true
        },
        "procedures": {
            "value_change": "procedure:security-limit-value-change-v1",
            "bound_change": "procedure:security-limit-bound-change-v1",
            "rollback": "procedure:security-limit-rollback-v1",
            "evidence_requirements": ["evidence-requirement:boundary-and-plus-one-v1"]
        },
        "enforcement_status": "enforced",
        "source_binding": {
            "source_file": "sources/ryuki-api/src/security_contracts.rs",
            "source_symbol": match limit_id {
                AUTHENTICATOR_CLOCK_SKEW_LIMIT_ID => "ResolvedAuthenticatorBearerLimits::maximum_clock_skew_seconds",
                AUTHENTICATOR_OIDC_ACCESS_TOKEN_LIFETIME_LIMIT_ID => "ResolvedAuthenticatorBearerLimits::maximum_credential_lifetime_seconds",
                AUTHENTICATOR_BROWSER_STATE_LIFETIME_LIMIT_ID => "ResolvedAuthenticatorBrowserLimits::maximum_state_lifetime_seconds",
                AUTHENTICATOR_BROWSER_SESSION_MAXIMUM_AGE_LIMIT_ID => "ResolvedAuthenticatorBrowserLimits::maximum_session_age_seconds",
                AUTHENTICATOR_FEDERATED_AUTHORITY_STALENESS_LIMIT_ID => "ResolvedAuthenticatorBrowserLimits::maximum_federated_authority_staleness_seconds",
                _ => "ResolvedAuthenticatorBrowserLimits",
            }
        },
        "overrides": [],
        "lifecycle": "active",
        "applicability_expression": "always"
    })
}

#[cfg(test)]
fn fixture_verified_security_limit_profile(document: Value) -> VerifiedSecurityLimitProfile {
    let raw_bytes = serde_json::to_vec(&document)
        .expect("test security-limit profile must serialize to exact JSON");
    let reference = VersionedContentReference {
        artifact_kind: ArtifactKind::SecurityLimitProfile,
        document_id: document["document_id"]
            .as_str()
            .expect("test security-limit profile document id")
            .to_owned(),
        document_version: document["document_version"]
            .as_u64()
            .expect("test security-limit profile document version"),
        content_digest: raw_digest(&raw_bytes),
        artifact_locator: "catalog/security-contracts/v1/security-limit-profile.test.json".into(),
    };
    let admitted_at = DateTime::parse_from_rfc3339("2030-01-01T00:00:00Z")
        .expect("test admission timestamp")
        .with_timezone(&Utc);
    VerifiedSecurityLimitProfile::seal(
        reference,
        raw_bytes,
        &document,
        SecurityLimitDeploymentSelection {
            deployment_id: "deployment:fixture-authenticator".into(),
            security_profile: SecurityProfile::Test,
            enabled_features: BTreeSet::from(["authenticator-runtime-admission".into()]),
            admitted_at,
        },
    )
    .expect("test security-limit profile must retain exact authority")
}

#[cfg(test)]
fn fixture_authenticator_runtime_binding(
    clock_skew_seconds: u64,
    maximum_lifetime_seconds: u64,
) -> VerifiedAuthenticatorRuntimeBinding {
    let maximum_clock_skew_seconds = u32::try_from(clock_skew_seconds)
        .expect("test authenticator clock skew must fit the D contract");
    let digest = |character: char| format!("sha256:{}", character.to_string().repeat(64));
    let mut document_value = serde_json::json!({
        "$schema": "https://ryuki.io/schemas/security-contracts/v1/authenticator-runtime-binding.schema.json",
        "schema_version": "1.0.0",
        "contract_kind": "authenticator-runtime-binding",
        "document_id": "authenticator-runtime-binding:fixture-entra",
        "document_version": 1,
        "value_free": true,
        "provider_id": "provider:fixture-entra",
        "provider_configuration_version": 1,
        "deployment_id": "deployment:fixture-authenticator",
        "trust_domain_id": "trust-domain:fixture-authenticator",
        "capability_descriptor_id": "capability-descriptor:fixture-entra",
        "capability_descriptor_version": 1,
        "adapter_kind": "auth.entra-id",
        "adapter_version": "1.0.0",
        "authenticator_kind": "oidc",
        "provider_policy": {
            "digest_contract": AUTHENTICATOR_PROVIDER_POLICY_BINDING_DIGEST_CONTRACT,
            "binding_digest": digest('f')
        },
        "capability_ids": ["browser-sso", "token-validation"],
        "credential_paths": [{
            "path_id": "authenticator-path:api-bearer",
            "path_version": 1,
            "verifier": {
                "verifier_id": "authenticator-verifier:api-bearer",
                "verifier_version": 1,
                "issuer_binding_digest": digest('1'),
                "audience_set_binding_digest": digest('2'),
                "accepted_algorithm_ids": ["rs256"],
                "required_claim_ids": ["aud", "exp", "iat", "iss", "nbf", "oid", "sub"],
                "provider_subject_claim_id": "oid",
                "key_source_kind": "jwt-jwks",
                "key_source_binding_digest": digest('3'),
                "expiration_required": true,
                "not_before_required": true,
                "issued_at_required": true,
                "nonce_required": false,
                "clock_skew_limit_id": AUTHENTICATOR_CLOCK_SKEW_LIMIT_ID,
                "maximum_clock_skew_seconds": maximum_clock_skew_seconds,
                "redirects_allowed": false
            },
            "credential_profile": {
                "profile_id": "credential-profile:api-bearer",
                "profile_version": 1,
                "token_profile": "jwt-access-token",
                "carrier": "authorization-bearer",
                "proof_binding": "bearer",
                "replay": {
                    "credential_reuse": "reusable-until-expiry",
                    "credential_lifetime_limit_id": AUTHENTICATOR_OIDC_ACCESS_TOKEN_LIFETIME_LIMIT_ID,
                    "maximum_credential_lifetime_seconds": maximum_lifetime_seconds,
                    "sender_constraint": "none",
                    "presentation_replay_defense": "none",
                    "nonce_binding": "none",
                    "replay_store_binding_digest": null
                }
            },
            "cache_partition": {
                "digest_contract": "ryuki-authenticator-cache-partition-v1",
                "binding_digest": digest('4')
            },
            "protocol_binding": {
                "digest_contract": "ryuki-authenticator-protocol-binding-v1",
                "binding_digest": digest('5')
            },
            "retained_consumer_ids": ["runtime-consumer:entra-bearer-request-admission"]
        }],
        "ownership": {
            "single_runtime_owner": true,
            "ambient_reconfiguration_allowed": false
        }
    });
    let mut browser_path = document_value["credential_paths"][0].clone();
    browser_path["path_id"] = serde_json::json!("authenticator-path:browser-sso");
    browser_path["verifier"]["verifier_id"] =
        serde_json::json!("authenticator-verifier:browser-sso");
    browser_path["verifier"]["required_claim_ids"] =
        serde_json::json!(["aud", "exp", "iat", "iss", "nbf", "nonce", "oid", "sub"]);
    browser_path["verifier"]["nonce_required"] = serde_json::json!(true);
    browser_path["credential_profile"]["profile_id"] =
        serde_json::json!("credential-profile:browser-sso");
    browser_path["credential_profile"]["token_profile"] = serde_json::json!("oidc-id-token");
    browser_path["credential_profile"]["carrier"] = serde_json::json!("oauth-callback");
    browser_path["credential_profile"]["proof_binding"] = serde_json::json!("pkce-s256");
    browser_path["credential_profile"]["replay"] = serde_json::json!({
        "credential_reuse": "single-use",
        "credential_lifetime_limit_id": null,
        "maximum_credential_lifetime_seconds": null,
        "sender_constraint": "none",
        "presentation_replay_defense": "single-use-state",
        "nonce_binding": "oidc-login",
        "replay_store_binding_digest": digest('6')
    });
    browser_path["cache_partition"]["binding_digest"] = serde_json::json!(digest('7'));
    browser_path["protocol_binding"]["binding_digest"] = serde_json::json!(digest('8'));
    browser_path["retained_consumer_ids"] =
        serde_json::json!(["runtime-consumer:entra-browser-sso"]);
    document_value["credential_paths"]
        .as_array_mut()
        .expect("test authenticator paths")
        .push(browser_path);

    fixture_verified_authenticator_runtime_binding(document_value)
}

#[cfg(test)]
fn fixture_verified_authenticator_runtime_binding(
    document_value: Value,
) -> VerifiedAuthenticatorRuntimeBinding {
    let raw_bytes = serde_json::to_vec(&document_value)
        .expect("test authenticator runtime binding must serialize");
    let reference = ContentReferenceBinding {
        document_id: "authenticator-runtime-binding:fixture-entra".into(),
        document_version: 1,
        content_digest: raw_digest(&raw_bytes),
        artifact_locator: "catalog/security-contracts/v1/authenticator-runtime-binding.test.json"
            .into(),
    };
    let document = serde_json::from_value::<AuthenticatorRuntimeBindingDocument>(document_value)
        .expect("test authenticator runtime binding must be typed");
    document
        .validate()
        .expect("test authenticator runtime binding must be semantically valid");
    let verified = VerifiedAuthenticatorRuntimeBinding {
        reference,
        raw_bytes: raw_bytes.into_boxed_slice(),
        document,
    };
    verified
        .verify_integrity()
        .expect("test authenticator runtime-binding exact bytes must verify");
    verified
}

#[cfg(test)]
fn fixture_replace_authenticator_path(
    document: &mut Value,
    measured: &AuthenticatorRuntimePathProjection,
) {
    let path = document["credential_paths"]
        .as_array_mut()
        .expect("fixture D credential paths")
        .iter_mut()
        .find(|path| {
            path["credential_profile"]["token_profile"].as_str()
                == Some(measured.credential_profile.token_profile.as_str())
        })
        .expect("fixture D must contain the measured token profile");
    path["path_id"] = serde_json::json!(&measured.path_id);
    path["path_version"] = serde_json::json!(measured.path_version);
    path["verifier"] =
        serde_json::to_value(&measured.verifier).expect("measured verifier must serialize");
    path["credential_profile"] = serde_json::to_value(&measured.credential_profile)
        .expect("measured credential profile must serialize");
    path["cache_partition"] = serde_json::json!({
        "digest_contract": AUTHENTICATOR_CACHE_PARTITION_BINDING_DIGEST_CONTRACT,
        "binding_digest": &measured.cache_partition_binding_digest,
    });
    path["protocol_binding"] = serde_json::json!({
        "digest_contract": AUTHENTICATOR_PROTOCOL_BINDING_DIGEST_CONTRACT,
        "binding_digest": &measured.protocol_binding_digest,
    });
    path["retained_consumer_ids"] = serde_json::json!(&measured.retained_consumer_ids);
}

#[cfg(test)]
fn fixture_entra_oidc_configuration(
    config: &RyukiConfig,
    runtime_binding_ref: ContentReferenceBinding,
    reference_digest: &impl Fn(&str, &[&str]) -> String,
) -> OidcKindConfig {
    let reference = |document_id: &str, artifact_locator: &str, label: &str, values: &[&str]| {
        ContentReferenceBinding {
            document_id: document_id.into(),
            document_version: 1,
            content_digest: reference_digest(label, values),
            artifact_locator: artifact_locator.into(),
        }
    };
    OidcKindConfig {
        configuration_kind: "oidc".into(),
        runtime_binding_ref,
        issuer_ref: reference(
            "issuer:fixture-entra",
            "catalog/security-contracts/v1/issuer.fixture.json",
            "entra-issuer",
            &[&config.entra_authority, &config.entra_tenant_id],
        ),
        endpoint_policy_ref: reference(
            "endpoint-policy:fixture-entra",
            "catalog/security-contracts/v1/endpoint-policy.fixture.json",
            "entra-endpoint-policy",
            &[
                &config.entra_authority,
                &config.entra_tenant_id,
                &config.entra_jwks_ttl_secs.to_string(),
            ],
        ),
        validation_mode: "jwt-jwks".into(),
        client_id_ref: reference(
            "client-id:fixture-entra",
            "catalog/security-contracts/v1/client-id.fixture.json",
            "entra-client",
            &[&config.entra_client_id],
        ),
        client_authentication_method: "none".into(),
        accepted_audiences_ref: reference(
            "accepted-audiences:fixture-entra",
            "catalog/security-contracts/v1/accepted-audiences.fixture.json",
            "entra-audiences",
            &[
                &config.entra_client_id,
                &format!("api://{}", config.entra_client_id),
            ],
        ),
        accepted_algorithms: vec!["RS256".into()],
        redirect_policy_ref: reference(
            "redirect-policy:fixture-entra",
            "catalog/security-contracts/v1/redirect-policy.fixture.json",
            "entra-redirect",
            &[&config.entra_redirect_uri],
        ),
        claim_mapping_ref: reference(
            "claim-mapping:fixture-entra",
            "catalog/security-contracts/v1/claim-mapping.fixture.json",
            "entra-claim-mapping",
            &["oid", "name", "preferred_username", "roles"],
        ),
        assurance_mapping_ref: reference(
            "assurance-mapping:fixture-entra",
            "catalog/security-contracts/v1/assurance-mapping.fixture.json",
            "entra-assurance-mapping",
            &["signed-oidc", "provider-active"],
        ),
        logout_mode: "provider-session".into(),
        lifecycle_mode: "provider-registry".into(),
        revocation_mode: "provider-registry".into(),
    }
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityProviderKindConfig {
    configuration_kind: String,
    /// Runtime adapter selector. This is independently projected from the
    /// kind-specific provider configuration and must exactly match the
    /// capability descriptor's attested adapter identity.
    adapter_kind: String,
    #[serde(default)]
    runtime_binding_ref: Option<ContentReferenceBinding>,
    #[serde(default)]
    endpoint_policy_ref: Option<ContentReferenceBinding>,
    #[serde(default)]
    authentication_ref: Option<ContentReferenceBinding>,
    #[serde(default)]
    capability_policy_ref: Option<ContentReferenceBinding>,
    #[serde(default)]
    rotation_policy_ref: Option<ContentReferenceBinding>,
    #[serde(default)]
    revocation_policy_ref: Option<ContentReferenceBinding>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SecretProviderBackendCompatibilityProfile {
    profile_id: String,
    profile_version: u64,
    digest_contract: String,
    binding_digest: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SecretProviderTransportBinding {
    endpoint_base_url_binding_digest: String,
    ca_trust_binding_digest: String,
    https_required: bool,
    redirects_allowed: bool,
    ambient_proxy_allowed: bool,
    built_in_roots_allowed: bool,
    connect_timeout_millis: u64,
    request_timeout_millis: u64,
    response_body_max_bytes: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SecretProviderCredentialSourceBinding {
    kind: String,
    identity_binding_digest: String,
    audience_binding_digest: String,
    token_path_binding_digest: String,
    provider_authentication_digest_contract: String,
    provider_authentication_binding_digest: String,
    static_bearer_allowed: bool,
    exported_bearer_allowed: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SecretProviderCapabilityBinding {
    capability_id: String,
    semantic_version: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SecretProviderRuntimeOwnershipBinding {
    single_runtime_owner: bool,
    ambient_reconfiguration_allowed: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SecretProviderRuntimeBindingDocument {
    #[serde(rename = "$schema")]
    schema_uri: String,
    schema_version: String,
    contract_kind: String,
    document_id: String,
    document_version: u64,
    value_free: bool,
    provider_id: String,
    provider_configuration_version: u64,
    deployment_id: String,
    trust_domain_id: String,
    capability_descriptor_id: String,
    capability_descriptor_version: u64,
    adapter_kind: String,
    adapter_version: String,
    protocol_version: String,
    backend_compatibility_profile: SecretProviderBackendCompatibilityProfile,
    transport: SecretProviderTransportBinding,
    credential_source: SecretProviderCredentialSourceBinding,
    capability_bindings: Vec<SecretProviderCapabilityBinding>,
    retained_consumer_ids: Vec<String>,
    ownership: SecretProviderRuntimeOwnershipBinding,
}

/// Exact value-free secret-provider binding authenticated by the provider
/// configuration's content reference. This projection deliberately contains
/// neither secret material nor any runtime/inventory digest that could create
/// a D -> P -> R -> I hash cycle.
pub(crate) struct VerifiedSecretProviderRuntimeBinding {
    reference: ContentReferenceBinding,
    raw_bytes: Box<[u8]>,
    document: SecretProviderRuntimeBindingDocument,
}

impl fmt::Debug for VerifiedSecretProviderRuntimeBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedSecretProviderRuntimeBinding")
            .field("document_id", &self.document.document_id)
            .field("document_version", &self.document.document_version)
            .field("content_digest", &self.reference.content_digest)
            .field("byte_len", &self.raw_bytes.len())
            .field("provider_id", &self.document.provider_id)
            .field(
                "provider_configuration_version",
                &self.document.provider_configuration_version,
            )
            .finish_non_exhaustive()
    }
}

impl VerifiedSecretProviderRuntimeBinding {
    pub(crate) fn provider_id(&self) -> &str {
        &self.document.provider_id
    }

    pub(crate) fn provider_configuration_version(&self) -> u64 {
        self.document.provider_configuration_version
    }

    pub(crate) fn deployment_id(&self) -> &str {
        &self.document.deployment_id
    }

    pub(crate) fn trust_domain_id(&self) -> &str {
        &self.document.trust_domain_id
    }

    /// Re-hash and losslessly reparse the exact authenticated bytes retained
    /// for the process lifetime. A matching typed document alone is not enough:
    /// D is the digest of these exact bytes and remains a distinct input to R.
    fn verify_integrity(&self) -> Result<(), String> {
        self.reference.validate()?;
        if self.raw_bytes.is_empty() || raw_digest(&self.raw_bytes) != self.reference.content_digest
        {
            return Err(
                "retained secret-provider runtime-binding bytes no longer match their exact digest"
                    .into(),
            );
        }
        let exact_value = parse_json_strict(&self.raw_bytes).map_err(|error| {
            format!("retained secret-provider runtime-binding JSON is invalid: {error}")
        })?;
        validate_against_schema(
            "retained secret-provider runtime binding",
            SECRET_PROVIDER_RUNTIME_BINDING_SCHEMA,
            &exact_value,
        )?;
        let reparsed = serde_json::from_value::<SecretProviderRuntimeBindingDocument>(exact_value)
            .map_err(|error| {
                format!("retained secret-provider runtime binding is not losslessly typed: {error}")
            })?;
        reparsed.validate()?;
        if reparsed != self.document {
            return Err(
                "retained secret-provider runtime-binding bytes differ from the sealed typed document"
                    .into(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
enum ActiveProviderKindConfig {
    DevelopmentFixture(Box<DevelopmentFixtureKindConfig>),
    Oidc {
        configuration: Box<OidcKindConfig>,
        verified_runtime_binding: Arc<VerifiedAuthenticatorRuntimeBinding>,
    },
    LocalWebauthn(Box<LocalWebauthnKindConfig>),
    SecretService {
        configuration: Box<CapabilityProviderKindConfig>,
        verified_runtime_binding: Option<Arc<VerifiedSecretProviderRuntimeBinding>>,
    },
    CapabilityProvider(Box<CapabilityProviderKindConfig>),
    /// These provider kinds have no kind-specific runtime adapter selector in
    /// the v1 contract. Keeping this variant closed to that exact set prevents
    /// an adapter-bearing capability provider from being treated as opaque.
    NonAdapterProvider {
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
    trust_domain_id: String,
    active_lifecycle_record_version: u64,
    capability_descriptor: ProviderCapabilityDescriptorBinding,
    credential_refs: Vec<CredentialReferenceBinding>,
    kind_config: ActiveProviderKindConfig,
}

#[derive(Debug)]
struct RuntimeBuildIdentity {
    source_revision: String,
    component: BuildComponent,
    executable_digest: String,
    executable_byte_length: u64,
    shipped_adapters: Vec<ShippedAdapter>,
    selector_dispositions: Vec<BuildSelectorDisposition>,
}

struct ProductionBuildManifestCandidate {
    source_path: PathBuf,
    raw_bytes: Box<[u8]>,
    raw_digest: String,
    document: ProductionBuildManifest,
}

impl fmt::Debug for ProductionBuildManifestCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionBuildManifestCandidate")
            .field("source_path", &self.source_path)
            .field("raw_digest", &self.raw_digest)
            .field("document_id", &self.document.document_id)
            .field("document_version", &self.document.document_version)
            .field("byte_len", &self.raw_bytes.len())
            .finish()
    }
}

/// Opaque non-cloneable aggregate binding the detached manifest's exact raw
/// bytes to deployment pins, the running executable, the compiled selector
/// inventory, and the exact independently derived implementation applicability
/// inventory for the content-addressed ControlTrace.
///
/// This capability closes build identity and build-side applicability only. It
/// is intentionally insufficient for deployment/provider applicability,
/// semantic receipt closure, OCI deployment provenance, or production runtime
/// admission. The manifest's OCI subject remains a pinned external declaration
/// until a later deployment proof binds it to the running workload.
pub(crate) struct PinnedProductionBuildManifest {
    source_path: PathBuf,
    raw_bytes: Box<[u8]>,
    raw_digest: String,
    document: ProductionBuildManifest,
}

impl fmt::Debug for PinnedProductionBuildManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedProductionBuildManifest")
            .field("source_path", &self.source_path)
            .field("raw_digest", &self.raw_digest)
            .field("document_id", &self.document.document_id)
            .field("document_version", &self.document.document_version)
            .field("byte_len", &self.raw_bytes.len())
            .finish()
    }
}

/// Non-cloneable proof that semantic conformance, the measured running build,
/// the exact pinned profile bytes, and the independently attested deployed
/// workload are one production identity.
///
/// This is deliberately still not serving authority: the later runtime
/// admission layer must consume it together with all eight receipt-bound live
/// guard witnesses.
pub(crate) struct VerifiedProductionBoundary {
    conformance: VerifiedConformanceClosure,
    deployed_workload: VerifiedDeployedWorkload,
    pinned_build: PinnedProductionBuildManifest,
    profile_raw_bytes: Box<[u8]>,
    profile_raw_digest: String,
    runtime_guard_challenge_digests: Box<[String]>,
}

pub(crate) struct VerifiedProductionRuntimeGuardChallenge<'a> {
    requirement: &'a VerifiedRuntimeGuardRequirement,
    challenge_binding_digest: &'a str,
}

impl VerifiedProductionRuntimeGuardChallenge<'_> {
    pub(crate) fn guard_id(&self) -> GuardId {
        self.requirement.guard_id()
    }

    pub(crate) fn expected_value(&self) -> &RuntimeGuardExpectedValue {
        self.requirement.expected_value()
    }

    pub(crate) fn requirement_digest(&self) -> &str {
        self.requirement.requirement_digest()
    }

    pub(crate) fn challenge_binding_digest(&self) -> &str {
        self.challenge_binding_digest
    }
}

impl fmt::Debug for VerifiedProductionBoundary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedProductionBoundary")
            .field("closure_digest", &self.conformance.closure_digest())
            .field("deployment_id", &self.conformance.deployment_id())
            .field("trust_domain_id", &self.conformance.trust_domain_id())
            .field("source_revision", &self.conformance.source_revision())
            .field("artifact_digest", &self.conformance.artifact_digest())
            .field("build_manifest_raw_digest", &self.pinned_build.raw_digest)
            .field("profile_raw_digest", &self.profile_raw_digest)
            .field("profile_byte_len", &self.profile_raw_bytes.len())
            .field(
                "runtime_guard_challenge_count",
                &self.runtime_guard_challenge_digests.len(),
            )
            .field(
                "workload_response_digest",
                &self.deployed_workload.response_digest(),
            )
            .field(
                "semantic_valid_until",
                &self.conformance.semantic_valid_until(),
            )
            .field(
                "workload_valid_until",
                &self.deployed_workload.valid_until(),
            )
            .finish()
    }
}

impl VerifiedProductionBoundary {
    fn seal(
        conformance: VerifiedConformanceClosure,
        deployed_workload: VerifiedDeployedWorkload,
        pinned_build: PinnedProductionBuildManifest,
        profile_raw_bytes: Box<[u8]>,
        profile_raw_digest: String,
        trusted_now: ConformanceTrustedTimeWindow,
    ) -> Result<Self, String> {
        if profile_raw_bytes.is_empty()
            || raw_digest(&profile_raw_bytes) != profile_raw_digest
            || conformance.deployment_profile_raw_digest() != profile_raw_digest
        {
            return Err(
                "production boundary profile bytes differ from the independent startup digest pin"
                    .into(),
            );
        }
        let exact_profile_value = parse_json_strict(&profile_raw_bytes)
            .map_err(|error| format!("production boundary profile JSON is invalid: {error}"))?;
        let exact_profile: DeploymentSecurityProfile = serde_json::from_value(exact_profile_value)
            .map_err(|error| {
                format!("production boundary profile is not losslessly typed: {error}")
            })?;
        if conformance.deployment_profile() != &exact_profile {
            return Err(
                "semantic closure deployment profile differs from the exact pinned profile bytes"
                    .into(),
            );
        }
        if conformance.production_build_manifest() != &pinned_build.document {
            return Err(
                "semantic closure build manifest differs from the exact pinned build manifest"
                    .into(),
            );
        }
        if conformance.deployment_id() != deployed_workload.deployment_id()
            || conformance.trust_domain_id() != deployed_workload.trust_domain_id()
            || conformance.source_revision() != pinned_build.document.source.revision
            || conformance.artifact_digest() != pinned_build.document.oci_subject.content_digest
            || deployed_workload.oci_subject_kind()
                != pinned_build.document.oci_subject.subject_kind
            || deployed_workload.oci_repository() != pinned_build.document.oci_subject.repository
            || deployed_workload.oci_subject_digest()
                != pinned_build.document.oci_subject.content_digest
            || deployed_workload.runtime_executable_digest()
                != pinned_build.document.runtime_executable.content_digest
            || deployed_workload.runtime_executable_byte_length()
                != pinned_build.document.runtime_executable.byte_length
        {
            return Err(
                "semantic closure, pinned build, and deployed-workload proof do not identify one exact production workload"
                    .into(),
            );
        }
        conformance
            .ensure_fresh(trusted_now)
            .map_err(|error| format!("production semantic closure is stale: {error}"))?;
        deployed_workload
            .ensure_fresh(trusted_now)
            .map_err(|error| format!("production deployed-workload proof is stale: {error}"))?;
        if conformance.runtime_guard_requirements().len() != 8 {
            return Err(
                "production semantic closure lost the exact eight runtime guard requirements"
                    .into(),
            );
        }
        let runtime_guard_challenge_digests = conformance
            .runtime_guard_requirements()
            .iter()
            .map(|requirement| {
                production_runtime_guard_challenge_digest(requirement, &deployed_workload)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice();
        Ok(Self {
            conformance,
            deployed_workload,
            pinned_build,
            profile_raw_bytes,
            profile_raw_digest,
            runtime_guard_challenge_digests,
        })
    }

    fn ensure_fresh(&self, trusted_now: ConformanceTrustedTimeWindow) -> Result<(), String> {
        self.conformance
            .ensure_fresh(trusted_now)
            .map_err(|error| format!("production semantic closure is no longer fresh: {error}"))?;
        self.deployed_workload
            .ensure_fresh(trusted_now)
            .map_err(|error| {
                format!("production deployed-workload proof is no longer fresh: {error}")
            })
    }

    pub(crate) fn runtime_guard_challenges(
        &self,
    ) -> impl ExactSizeIterator<Item = VerifiedProductionRuntimeGuardChallenge<'_>> + '_ {
        self.conformance
            .runtime_guard_requirements()
            .iter()
            .zip(self.runtime_guard_challenge_digests.iter())
            .map(|(requirement, challenge_binding_digest)| {
                VerifiedProductionRuntimeGuardChallenge {
                    requirement,
                    challenge_binding_digest,
                }
            })
    }
}

fn production_runtime_guard_challenge_digest(
    requirement: &VerifiedRuntimeGuardRequirement,
    deployed_workload: &VerifiedDeployedWorkload,
) -> Result<String, String> {
    let projection = serde_json::json!({
        "digest_contract": PRODUCTION_RUNTIME_GUARD_CHALLENGE_DIGEST_CONTRACT,
        "semantic_challenge_binding_digest": requirement.semantic_challenge_binding_digest(),
        "requirement_digest": requirement.requirement_digest(),
        "workload": {
            "response_digest": deployed_workload.response_digest(),
            "deployment_id": deployed_workload.deployment_id(),
            "trust_domain_id": deployed_workload.trust_domain_id(),
            "workload_id": deployed_workload.workload_id(),
            "authority": {
                "authority_id": deployed_workload.authority_id(),
                "key_id": deployed_workload.authority_key_id(),
                "public_key_fingerprint": deployed_workload.authority_public_key_fingerprint(),
                "authority_epoch": deployed_workload.authority_epoch(),
                "authority_revision": deployed_workload.authority_revision(),
            },
            "measurement_profile": {
                "profile_id": deployed_workload.measurement_profile_id(),
                "profile_version": deployed_workload.measurement_profile_version(),
                "content_digest": deployed_workload.measurement_profile_digest(),
            },
            "measurement_sequence": deployed_workload.measurement_sequence(),
            "workload_instance_binding_digest": deployed_workload.workload_instance_binding_digest(),
            "observed_at": {
                "not_before": deployed_workload.observed_at_not_before(),
                "not_after": deployed_workload.observed_at_not_after(),
            },
            "valid_until": deployed_workload.valid_until(),
            "deployed_oci_subject": {
                "subject_kind": deployed_workload.oci_subject_kind(),
                "repository": deployed_workload.oci_repository(),
                "content_digest": deployed_workload.oci_subject_digest(),
            },
            "resolved_image_manifest_digest": deployed_workload.resolved_manifest_digest(),
            "peer_executable": {
                "content_digest": deployed_workload.runtime_executable_digest(),
                "byte_length": deployed_workload.runtime_executable_byte_length(),
            },
        },
    });
    let canonical = canonical_json_bytes(&projection).map_err(|error| {
        format!("cannot canonicalize production runtime guard challenge: {error}")
    })?;
    Ok(raw_digest(&canonical))
}

const REMAINING_PRODUCTION_RUNTIME_GUARDS: [GuardId; 2] = [
    GuardId::ExternalSigningKeyMaterial,
    GuardId::MockDependenciesDisabled,
];

/// Non-cloneable publication capability emitted only by the complete
/// eight-witness runtime aggregate. Owning a DurablePostgresql witness alone is
/// deliberately insufficient to publish the retained pool.
#[allow(dead_code)]
pub(crate) struct CompleteProductionRuntimeAdmissionToken {
    durable_postgresql_runtime: crate::database::RetainedPostgresqlRuntime,
}

impl fmt::Debug for CompleteProductionRuntimeAdmissionToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompleteProductionRuntimeAdmissionToken")
            .field("durable_postgresql_runtime", &"[RETAINED]")
            .finish_non_exhaustive()
    }
}

#[allow(dead_code)]
impl CompleteProductionRuntimeAdmissionToken {
    pub(crate) fn retains_durable_postgresql_runtime(
        &self,
        candidate: &crate::database::RetainedPostgresqlRuntime,
    ) -> bool {
        self.durable_postgresql_runtime.same_runtime(candidate)
    }
}

// HttpsPublicUrls, SecureCookies, ApprovedSecretProvider,
// NonDevelopmentAuthenticator, DurablePostgresql, and FirstOwnerPathClosed
// have live production verifiers. The remaining two nominal witness types and the final
// eight-witness aggregate stay under this temporary dead-code allowance until
// their guard-specific verifiers are implemented.
#[allow(dead_code)]
mod runtime_admission {
    use super::*;

    const MAX_RUNTIME_GUARD_WITNESS_LIFETIME_SECONDS: i64 = 300;

    /// Redacted, stable failure categories for the final production runtime
    /// admission boundary. Values measured from live systems and raw authority
    /// responses are intentionally absent from every variant.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
    pub(super) enum ProductionRuntimeAdmissionError {
        #[error("production runtime admission received an inverted trusted-time interval")]
        InvalidTrustedTimeWindow,
        #[error("production runtime admission rejected a trusted-time rollback")]
        TrustedTimeRollback,
        #[error("production runtime admission rejected a stale production boundary")]
        BoundaryStale,
        #[error(
            "production runtime guard challenge set has {observed} entries instead of exactly eight"
        )]
        CorruptChallengeCount { observed: usize },
        #[error("production runtime guard challenge set is corrupt for {guard_id:?}")]
        CorruptChallengeSet { guard_id: GuardId },
        #[error(
            "production runtime guard kind mismatch: expected {expected:?}, observed {observed:?}"
        )]
        GuardKindMismatch {
            expected: GuardId,
            observed: GuardId,
        },
        #[error("production runtime guard requirement binding mismatch for {guard_id:?}")]
        RequirementBindingMismatch { guard_id: GuardId },
        #[error("production runtime guard workload challenge mismatch for {guard_id:?}")]
        ChallengeBindingMismatch { guard_id: GuardId },
        #[error("production runtime guard expected-value mismatch for {guard_id:?}")]
        ExpectedValueMismatch { guard_id: GuardId },
        #[error("production runtime guard observation window is invalid for {guard_id:?}")]
        InvalidObservationWindow { guard_id: GuardId },
        #[error("production runtime guard witness is stale for {guard_id:?}")]
        WitnessStale { guard_id: GuardId },
        #[error("production runtime guard live measurement failed for {guard_id:?}")]
        GuardMeasurementFailed { guard_id: GuardId },
    }

    /// Private output of one guard-specific live verifier. Future production
    /// verifier modules must measure the supplied handle and construct this
    /// value themselves; there is intentionally no constructor from a boolean,
    /// caller-authored receipt, or public expected value.
    struct VerifiedRuntimeGuardObservation<H> {
        guard_id: GuardId,
        observed_value: RuntimeGuardExpectedValue,
        requirement_digest: String,
        challenge_binding_digest: String,
        observed_at_not_before: DateTime<Utc>,
        observed_at_not_after: DateTime<Utc>,
        valid_until: DateTime<Utc>,
        handle: H,
    }

    /// One non-cloneable witness core. It retains the exact live handle whose
    /// measured facts matched the receipt-bound expectation and workload-bound
    /// challenge. Custom Debug deliberately omits both the handle and measured
    /// value.
    struct VerifiedProductionRuntimeGuardWitness<H> {
        guard_id: GuardId,
        observed_value: RuntimeGuardExpectedValue,
        requirement_digest: String,
        challenge_binding_digest: String,
        observed_at_not_before: DateTime<Utc>,
        observed_at_not_after: DateTime<Utc>,
        valid_until: DateTime<Utc>,
        handle: H,
    }

    impl<H> fmt::Debug for VerifiedProductionRuntimeGuardWitness<H> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("VerifiedProductionRuntimeGuardWitness")
                .field("guard_id", &self.guard_id)
                .field("requirement_digest", &self.requirement_digest)
                .field("challenge_binding_digest", &self.challenge_binding_digest)
                .field("observed_at_not_before", &self.observed_at_not_before)
                .field("observed_at_not_after", &self.observed_at_not_after)
                .field("valid_until", &self.valid_until)
                .field("handle", &"[RETAINED]")
                .finish()
        }
    }

    impl<H> VerifiedProductionRuntimeGuardWitness<H> {
        fn seal(
            boundary: &VerifiedProductionBoundary,
            expected_guard_id: GuardId,
            observation: VerifiedRuntimeGuardObservation<H>,
            trusted_now: ConformanceTrustedTimeWindow,
        ) -> Result<Self, ProductionRuntimeAdmissionError> {
            if observation.guard_id != expected_guard_id {
                return Err(ProductionRuntimeAdmissionError::GuardKindMismatch {
                    expected: expected_guard_id,
                    observed: observation.guard_id,
                });
            }
            let observed_kind = observation.observed_value.guard_id();
            if observed_kind != expected_guard_id {
                return Err(ProductionRuntimeAdmissionError::GuardKindMismatch {
                    expected: expected_guard_id,
                    observed: observed_kind,
                });
            }
            let witness = Self {
                guard_id: observation.guard_id,
                observed_value: observation.observed_value,
                requirement_digest: observation.requirement_digest,
                challenge_binding_digest: observation.challenge_binding_digest,
                observed_at_not_before: observation.observed_at_not_before,
                observed_at_not_after: observation.observed_at_not_after,
                valid_until: observation.valid_until,
                handle: observation.handle,
            };
            witness.recheck(boundary, expected_guard_id, trusted_now)?;
            Ok(witness)
        }

        fn recheck(
            &self,
            boundary: &VerifiedProductionBoundary,
            expected_guard_id: GuardId,
            trusted_now: ConformanceTrustedTimeWindow,
        ) -> Result<(), ProductionRuntimeAdmissionError> {
            validate_trusted_time(trusted_now)?;
            boundary
                .ensure_fresh(trusted_now)
                .map_err(|_| ProductionRuntimeAdmissionError::BoundaryStale)?;
            if self.guard_id != expected_guard_id {
                return Err(ProductionRuntimeAdmissionError::GuardKindMismatch {
                    expected: expected_guard_id,
                    observed: self.guard_id,
                });
            }
            let observed_kind = self.observed_value.guard_id();
            if observed_kind != expected_guard_id {
                return Err(ProductionRuntimeAdmissionError::GuardKindMismatch {
                    expected: expected_guard_id,
                    observed: observed_kind,
                });
            }
            let challenge = exact_challenge(boundary, expected_guard_id)?;
            if self.requirement_digest != challenge.requirement_digest() {
                return Err(
                    ProductionRuntimeAdmissionError::RequirementBindingMismatch {
                        guard_id: expected_guard_id,
                    },
                );
            }
            if self.challenge_binding_digest != challenge.challenge_binding_digest() {
                return Err(ProductionRuntimeAdmissionError::ChallengeBindingMismatch {
                    guard_id: expected_guard_id,
                });
            }
            if &self.observed_value != challenge.expected_value() {
                return Err(ProductionRuntimeAdmissionError::ExpectedValueMismatch {
                    guard_id: expected_guard_id,
                });
            }
            if self.observed_at_not_before > self.observed_at_not_after
                || self.observed_at_not_after > trusted_now.not_before
                || self.valid_until <= self.observed_at_not_after
                || self
                    .valid_until
                    .signed_duration_since(self.observed_at_not_before)
                    > chrono::TimeDelta::seconds(MAX_RUNTIME_GUARD_WITNESS_LIFETIME_SECONDS)
            {
                return Err(ProductionRuntimeAdmissionError::InvalidObservationWindow {
                    guard_id: expected_guard_id,
                });
            }
            if trusted_now.not_after >= self.valid_until {
                return Err(ProductionRuntimeAdmissionError::WitnessStale {
                    guard_id: expected_guard_id,
                });
            }
            Ok(())
        }

        fn handle(&self) -> &H {
            &self.handle
        }
    }

    fn validate_trusted_time(
        trusted_now: ConformanceTrustedTimeWindow,
    ) -> Result<(), ProductionRuntimeAdmissionError> {
        if trusted_now.not_before > trusted_now.not_after {
            Err(ProductionRuntimeAdmissionError::InvalidTrustedTimeWindow)
        } else {
            Ok(())
        }
    }

    pub(super) fn exact_challenge(
        boundary: &VerifiedProductionBoundary,
        guard_id: GuardId,
    ) -> Result<VerifiedProductionRuntimeGuardChallenge<'_>, ProductionRuntimeAdmissionError> {
        let mut matches = boundary
            .runtime_guard_challenges()
            .filter(|challenge| challenge.guard_id() == guard_id);
        let challenge = matches
            .next()
            .ok_or(ProductionRuntimeAdmissionError::CorruptChallengeSet { guard_id })?;
        if matches.next().is_some() {
            return Err(ProductionRuntimeAdmissionError::CorruptChallengeSet { guard_id });
        }
        Ok(challenge)
    }

    macro_rules! define_nominal_guard_witness {
        ($name:ident, $guard_id:expr) => {
            pub(super) struct $name<H>(VerifiedProductionRuntimeGuardWitness<H>);

            impl<H> fmt::Debug for $name<H> {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter
                        .debug_tuple(stringify!($name))
                        .field(&self.0)
                        .finish()
                }
            }

            impl<H> $name<H> {
                fn from_verified_observation(
                    boundary: &VerifiedProductionBoundary,
                    observation: VerifiedRuntimeGuardObservation<H>,
                    trusted_now: ConformanceTrustedTimeWindow,
                ) -> Result<Self, ProductionRuntimeAdmissionError> {
                    VerifiedProductionRuntimeGuardWitness::seal(
                        boundary,
                        $guard_id,
                        observation,
                        trusted_now,
                    )
                    .map(Self)
                }

                fn recheck(
                    &self,
                    boundary: &VerifiedProductionBoundary,
                    trusted_now: ConformanceTrustedTimeWindow,
                ) -> Result<(), ProductionRuntimeAdmissionError> {
                    self.0.recheck(boundary, $guard_id, trusted_now)
                }

                pub(super) fn handle(&self) -> &H {
                    self.0.handle()
                }

                #[cfg(test)]
                #[allow(clippy::too_many_arguments)]
                pub(super) fn seal_test_observation(
                    boundary: &VerifiedProductionBoundary,
                    observed_value: RuntimeGuardExpectedValue,
                    requirement_digest: String,
                    challenge_binding_digest: String,
                    observed_at_not_before: DateTime<Utc>,
                    observed_at_not_after: DateTime<Utc>,
                    valid_until: DateTime<Utc>,
                    handle: H,
                    trusted_now: ConformanceTrustedTimeWindow,
                ) -> Result<Self, ProductionRuntimeAdmissionError> {
                    Self::from_verified_observation(
                        boundary,
                        VerifiedRuntimeGuardObservation {
                            guard_id: $guard_id,
                            observed_value,
                            requirement_digest,
                            challenge_binding_digest,
                            observed_at_not_before,
                            observed_at_not_after,
                            valid_until,
                            handle,
                        },
                        trusted_now,
                    )
                }
            }
        };
    }

    define_nominal_guard_witness!(
        VerifiedDurablePostgresqlGuardWitness,
        GuardId::DurablePostgresql
    );
    define_nominal_guard_witness!(
        VerifiedApprovedSecretProviderGuardWitness,
        GuardId::ApprovedSecretProvider
    );
    define_nominal_guard_witness!(
        VerifiedHttpsPublicUrlsGuardWitness,
        GuardId::HttpsPublicUrls
    );
    define_nominal_guard_witness!(VerifiedSecureCookiesGuardWitness, GuardId::SecureCookies);
    define_nominal_guard_witness!(
        VerifiedNonDevelopmentAuthenticatorGuardWitness,
        GuardId::NonDevelopmentAuthenticator
    );
    define_nominal_guard_witness!(
        VerifiedExternalSigningKeyMaterialGuardWitness,
        GuardId::ExternalSigningKeyMaterial
    );
    define_nominal_guard_witness!(
        VerifiedMockDependenciesDisabledGuardWitness,
        GuardId::MockDependenciesDisabled
    );
    define_nominal_guard_witness!(
        VerifiedFirstOwnerPathClosedGuardWitness,
        GuardId::FirstOwnerPathClosed
    );

    /// Exact process-lifetime PostgreSQL authority retained after the
    /// DurablePostgresql guard seals. The local proof owns the measured,
    /// unpublished application pool; `infrastructure` retains the same Arc
    /// whose signed provider facts were used by that local proof.
    pub(super) struct VerifiedDurablePostgresqlRuntimeHandle {
        local: crate::database::VerifiedLocalDurablePostgresqlRuntime,
        infrastructure: Arc<VerifiedPostgresqlInfrastructureAttestation>,
    }

    impl fmt::Debug for VerifiedDurablePostgresqlRuntimeHandle {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("VerifiedDurablePostgresqlRuntimeHandle")
                .field("local", &self.local)
                .field("infrastructure", &"[RETAINED-SIGNED-PROOF]")
                .finish()
        }
    }

    impl VerifiedDurablePostgresqlRuntimeHandle {
        pub(super) fn runtime(&self) -> &crate::database::RetainedPostgresqlRuntime {
            self.local.runtime()
        }
    }

    pub(super) type VerifiedDurablePostgresqlRuntimeWitness =
        VerifiedDurablePostgresqlGuardWitness<VerifiedDurablePostgresqlRuntimeHandle>;

    fn durable_postgresql_measurement_failed() -> ProductionRuntimeAdmissionError {
        ProductionRuntimeAdmissionError::GuardMeasurementFailed {
            guard_id: GuardId::DurablePostgresql,
        }
    }

    fn verified_postgresql_proof_matches_durable_challenge(
        boundary: &VerifiedProductionBoundary,
        infrastructure: &VerifiedPostgresqlInfrastructureAttestation,
    ) -> Result<(), ProductionRuntimeAdmissionError> {
        let measurement_failed = durable_postgresql_measurement_failed;
        infrastructure
            .verify_integrity()
            .map_err(|_| measurement_failed())?;
        if infrastructure.session_purpose() != PostgresqlSessionPurpose::ApplicationServing {
            return Err(measurement_failed());
        }
        let challenge = exact_challenge(boundary, GuardId::DurablePostgresql)?;
        let RuntimeGuardExpectedValue::DurablePostgresql {
            database_provider,
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
        } = challenge.expected_value()
        else {
            return Err(ProductionRuntimeAdmissionError::GuardKindMismatch {
                expected: GuardId::DurablePostgresql,
                observed: challenge.expected_value().guard_id(),
            });
        };
        if infrastructure.deployment_id() != boundary.deployed_workload.deployment_id()
            || infrastructure.trust_domain_id() != boundary.deployed_workload.trust_domain_id()
            || infrastructure.workload_id() != boundary.deployed_workload.workload_id()
            || infrastructure.source_revision() != boundary.conformance.source_revision()
            || infrastructure.artifact_digest() != boundary.deployed_workload.oci_subject_digest()
            || infrastructure.workload_instance_binding_digest()
                != boundary
                    .deployed_workload
                    .workload_instance_binding_digest()
            || infrastructure.requirement_digest() != challenge.requirement_digest()
            || infrastructure.challenge_binding_digest() != challenge.challenge_binding_digest()
            || infrastructure.database_provider() != *database_provider
            || infrastructure.server_major_version() != *server_major_version
            || infrastructure.attestation_profile_id() != attestation_profile_id.as_str()
            || infrastructure.attestation_profile_version() != *attestation_profile_version
            || infrastructure.attestation_profile_digest() != attestation_profile_digest.as_str()
            || infrastructure.provider_route_binding_digest()
                != provider_route_binding_digest.as_str()
            || infrastructure.database_identity_digest() != database_identity_digest.as_str()
            || infrastructure.storage_binding_digest() != storage_binding_digest.as_str()
            || infrastructure.migration_inventory_digest() != migration_inventory_digest.as_str()
            || infrastructure.application_role() != application_role.as_str()
            || infrastructure.migration_role() != migration_role.as_str()
        {
            return Err(measurement_failed());
        }
        Ok(())
    }

    fn validate_durable_postgresql_runtime_handle(
        boundary: &VerifiedProductionBoundary,
        handle: &VerifiedDurablePostgresqlRuntimeHandle,
    ) -> Result<RuntimeGuardExpectedValue, ProductionRuntimeAdmissionError> {
        let measurement_failed = durable_postgresql_measurement_failed;
        verified_postgresql_proof_matches_durable_challenge(boundary, &handle.infrastructure)?;
        handle
            .local
            .recheck_integrity()
            .map_err(|_| measurement_failed())?;
        if !handle
            .local
            .retains_infrastructure_attestation(&handle.infrastructure)
        {
            return Err(measurement_failed());
        }
        let challenge = exact_challenge(boundary, GuardId::DurablePostgresql)?;
        if handle.local.observed_value() != challenge.expected_value() {
            return Err(ProductionRuntimeAdmissionError::ExpectedValueMismatch {
                guard_id: GuardId::DurablePostgresql,
            });
        }
        Ok(handle.local.observed_value().clone())
    }

    pub(super) fn seal_durable_postgresql_guard(
        boundary: &VerifiedProductionBoundary,
        local: crate::database::VerifiedLocalDurablePostgresqlRuntime,
        infrastructure: Arc<VerifiedPostgresqlInfrastructureAttestation>,
        trusted_now: ConformanceTrustedTimeWindow,
    ) -> Result<VerifiedDurablePostgresqlRuntimeWitness, ProductionRuntimeAdmissionError> {
        let observed_at_not_before = infrastructure.observed_at_not_before();
        let observed_at_not_after = infrastructure.observed_at_not_after();
        let valid_until = infrastructure.valid_until();
        let requirement_digest = infrastructure.requirement_digest().to_owned();
        let challenge_binding_digest = infrastructure.challenge_binding_digest().to_owned();
        let handle = VerifiedDurablePostgresqlRuntimeHandle {
            local,
            infrastructure,
        };
        let observed_value = validate_durable_postgresql_runtime_handle(boundary, &handle)?;
        VerifiedDurablePostgresqlGuardWitness::from_verified_observation(
            boundary,
            VerifiedRuntimeGuardObservation {
                guard_id: GuardId::DurablePostgresql,
                observed_value,
                requirement_digest,
                challenge_binding_digest,
                observed_at_not_before,
                observed_at_not_after,
                valid_until,
                handle,
            },
            trusted_now,
        )
    }

    pub(super) fn recheck_durable_postgresql_guard(
        boundary: &VerifiedProductionBoundary,
        witness: &VerifiedDurablePostgresqlRuntimeWitness,
        trusted_now: ConformanceTrustedTimeWindow,
    ) -> Result<(), ProductionRuntimeAdmissionError> {
        witness
            .handle()
            .infrastructure
            .ensure_fresh(trusted_now)
            .map_err(|_| ProductionRuntimeAdmissionError::WitnessStale {
                guard_id: GuardId::DurablePostgresql,
            })?;
        let remeasured = validate_durable_postgresql_runtime_handle(boundary, witness.handle())?;
        if witness.0.observed_value != remeasured {
            return Err(durable_postgresql_measurement_failed());
        }
        witness.recheck(boundary, trusted_now)
    }

    /// Repeat every SQL and exact-session observation through the retained,
    /// still-identical application pool. The synchronous recheck runs on both
    /// sides so a stale proof or changed projection cannot be spliced around
    /// the asynchronous database measurement.
    pub(super) async fn remeasure_durable_postgresql_guard_exact(
        boundary: &VerifiedProductionBoundary,
        witness: &VerifiedDurablePostgresqlRuntimeWitness,
        trusted_now: ConformanceTrustedTimeWindow,
    ) -> Result<(), ProductionRuntimeAdmissionError> {
        recheck_durable_postgresql_guard(boundary, witness, trusted_now)?;
        witness
            .handle()
            .local
            .remeasure_exact()
            .await
            .map_err(|_| durable_postgresql_measurement_failed())?;
        let verified_at = trusted_time_point(Utc::now());
        if verified_at.not_before < trusted_now.not_after {
            return Err(ProductionRuntimeAdmissionError::TrustedTimeRollback);
        }
        recheck_durable_postgresql_guard(boundary, witness, verified_at)
    }

    /// Exact signature-verifying permanent-closure runtime retained with the
    /// same PostgreSQL allocation that satisfied `DurablePostgresql` and the
    /// independently provisioned first-owner trust anchor used to authenticate
    /// its canonical certificate bytes.
    pub(super) struct VerifiedFirstOwnerPathClosedRuntimeHandle {
        runtime: crate::first_owner_runtime::VerifiedFirstOwnerClosureRuntime,
        profile: DeploymentSecurityProfile,
        authority_pins: StartupFirstOwnerAuthorityPins,
        authority: crate::first_owner_runtime::FirstOwnerAuthorityAnchor,
    }

    impl fmt::Debug for VerifiedFirstOwnerPathClosedRuntimeHandle {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("VerifiedFirstOwnerPathClosedRuntimeHandle")
                .field("runtime", &self.runtime)
                .field("profile", &"[RECEIPT-BOUND]")
                .field("authority", &"[INDEPENDENTLY-PINNED]")
                .finish_non_exhaustive()
        }
    }

    impl VerifiedFirstOwnerPathClosedRuntimeHandle {
        pub(super) fn retains_postgresql_runtime(
            &self,
            candidate: &crate::database::RetainedPostgresqlRuntime,
        ) -> bool {
            self.runtime.runtime().same_runtime(candidate) && self.runtime.same_runtime(candidate)
        }
    }

    pub(super) type VerifiedFirstOwnerPathClosedRuntimeWitness =
        VerifiedFirstOwnerPathClosedGuardWitness<VerifiedFirstOwnerPathClosedRuntimeHandle>;

    fn first_owner_path_closed_measurement_failed() -> ProductionRuntimeAdmissionError {
        ProductionRuntimeAdmissionError::GuardMeasurementFailed {
            guard_id: GuardId::FirstOwnerPathClosed,
        }
    }

    pub(super) fn first_owner_authority_from_pins(
        pins: &StartupFirstOwnerAuthorityPins,
    ) -> Result<
        crate::first_owner_runtime::FirstOwnerAuthorityAnchor,
        ProductionRuntimeAdmissionError,
    > {
        validate_namespaced_id(
            FIRST_OWNER_AUTHORITY_ID_ENV,
            &pins.authority_id,
            "first-owner-authority:",
        )
        .map_err(|_| first_owner_path_closed_measurement_failed())?;
        validate_namespaced_id(
            FIRST_OWNER_AUTHORITY_KEY_ID_ENV,
            &pins.key_id,
            "first-owner-authority-key:",
        )
        .map_err(|_| first_owner_path_closed_measurement_failed())?;
        let public_key = decode_first_owner_authority_public_key(pins)
            .map_err(|_| first_owner_path_closed_measurement_failed())?;
        crate::first_owner_runtime::FirstOwnerAuthorityAnchor::new(
            pins.authority_id.clone(),
            pins.key_id.clone(),
            pins.public_key_fingerprint.clone(),
            pins.minimum_authority_epoch,
            public_key,
        )
        .map_err(|_| first_owner_path_closed_measurement_failed())
    }

    fn validate_first_owner_path_closed_runtime_handle(
        boundary: &VerifiedProductionBoundary,
        profile: &DeploymentSecurityProfile,
        durable_postgresql: &VerifiedDurablePostgresqlRuntimeWitness,
        handle: &VerifiedFirstOwnerPathClosedRuntimeHandle,
    ) -> Result<RuntimeGuardExpectedValue, ProductionRuntimeAdmissionError> {
        if &handle.profile != profile
            || profile.deployment_id != boundary.deployed_workload.deployment_id()
        {
            return Err(first_owner_path_closed_measurement_failed());
        }
        let authority = first_owner_authority_from_pins(&handle.authority_pins)?;
        if authority != handle.authority {
            return Err(first_owner_path_closed_measurement_failed());
        }
        handle
            .runtime
            .verify_integrity()
            .map_err(|_| first_owner_path_closed_measurement_failed())?;
        if !handle
            .runtime
            .same_runtime(durable_postgresql.handle().runtime())
        {
            return Err(first_owner_path_closed_measurement_failed());
        }
        let challenge = exact_challenge(boundary, GuardId::FirstOwnerPathClosed)?;
        if handle.runtime.observed_value() != challenge.expected_value() {
            return Err(ProductionRuntimeAdmissionError::ExpectedValueMismatch {
                guard_id: GuardId::FirstOwnerPathClosed,
            });
        }
        Ok(handle.runtime.observed_value().clone())
    }

    pub(super) fn recheck_first_owner_path_closed_guard(
        boundary: &VerifiedProductionBoundary,
        profile: &DeploymentSecurityProfile,
        durable_postgresql: &VerifiedDurablePostgresqlRuntimeWitness,
        witness: &VerifiedFirstOwnerPathClosedRuntimeWitness,
        trusted_now: ConformanceTrustedTimeWindow,
    ) -> Result<(), ProductionRuntimeAdmissionError> {
        recheck_durable_postgresql_guard(boundary, durable_postgresql, trusted_now)?;
        let remeasured = validate_first_owner_path_closed_runtime_handle(
            boundary,
            profile,
            durable_postgresql,
            witness.handle(),
        )?;
        if witness.0.observed_value != remeasured {
            return Err(first_owner_path_closed_measurement_failed());
        }
        witness.recheck(boundary, trusted_now)
    }

    /// Authenticate and measure the closure record from the exact pool already
    /// sealed by DurablePostgresql. The observed certificate, atomic evidence,
    /// and assignment set must match both the receipt and independent anchor.
    pub(super) async fn verify_first_owner_path_closed_guard(
        boundary: &VerifiedProductionBoundary,
        profile: &DeploymentSecurityProfile,
        durable_postgresql: &VerifiedDurablePostgresqlRuntimeWitness,
        authority_pins: &StartupFirstOwnerAuthorityPins,
    ) -> Result<VerifiedFirstOwnerPathClosedRuntimeWitness, ProductionRuntimeAdmissionError> {
        let observed_at_not_before = Utc::now();
        let initial_time = trusted_time_point(observed_at_not_before);
        recheck_durable_postgresql_guard(boundary, durable_postgresql, initial_time)?;
        let challenge = exact_challenge(boundary, GuardId::FirstOwnerPathClosed)?;
        let expected_value = challenge.expected_value().clone();
        let requirement_digest = challenge.requirement_digest().to_owned();
        let challenge_binding_digest = challenge.challenge_binding_digest().to_owned();
        let retained_postgresql = Arc::new(durable_postgresql.handle().runtime().clone());
        let authority = first_owner_authority_from_pins(authority_pins)?;
        let runtime = crate::first_owner_runtime::verify_first_owner_path_closed(
            retained_postgresql,
            profile,
            &expected_value,
            authority.clone(),
        )
        .await
        .map_err(|_| first_owner_path_closed_measurement_failed())?;
        let observed_at_not_after = Utc::now();
        if observed_at_not_after < observed_at_not_before {
            return Err(ProductionRuntimeAdmissionError::TrustedTimeRollback);
        }
        let verification_time = trusted_time_point(observed_at_not_after);
        recheck_durable_postgresql_guard(boundary, durable_postgresql, verification_time)?;
        let handle = VerifiedFirstOwnerPathClosedRuntimeHandle {
            runtime,
            profile: profile.clone(),
            authority_pins: authority_pins.clone(),
            authority,
        };
        let observed_value = validate_first_owner_path_closed_runtime_handle(
            boundary,
            profile,
            durable_postgresql,
            &handle,
        )?;
        let valid_until = observed_at_not_before
            .checked_add_signed(chrono::TimeDelta::seconds(
                MAX_RUNTIME_GUARD_WITNESS_LIFETIME_SECONDS,
            ))
            .ok_or(ProductionRuntimeAdmissionError::InvalidObservationWindow {
                guard_id: GuardId::FirstOwnerPathClosed,
            })?;
        VerifiedFirstOwnerPathClosedGuardWitness::from_verified_observation(
            boundary,
            VerifiedRuntimeGuardObservation {
                guard_id: GuardId::FirstOwnerPathClosed,
                observed_value,
                requirement_digest,
                challenge_binding_digest,
                observed_at_not_before,
                observed_at_not_after,
                valid_until,
                handle,
            },
            verification_time,
        )
    }

    /// Repeat the signed live closure query through the same retained
    /// PostgreSQL channel. Synchronous witness and infrastructure checks fence
    /// both sides of the await so neither authority, runtime identity, nor
    /// trusted time can be substituted during remeasurement.
    pub(super) async fn remeasure_first_owner_path_closed_guard_exact(
        boundary: &VerifiedProductionBoundary,
        profile: &DeploymentSecurityProfile,
        durable_postgresql: &VerifiedDurablePostgresqlRuntimeWitness,
        witness: &VerifiedFirstOwnerPathClosedRuntimeWitness,
        trusted_now: ConformanceTrustedTimeWindow,
    ) -> Result<(), ProductionRuntimeAdmissionError> {
        recheck_first_owner_path_closed_guard(
            boundary,
            profile,
            durable_postgresql,
            witness,
            trusted_now,
        )?;
        let challenge = exact_challenge(boundary, GuardId::FirstOwnerPathClosed)?;
        witness
            .handle()
            .runtime
            .remeasure_exact(profile, challenge.expected_value())
            .await
            .map_err(|_| first_owner_path_closed_measurement_failed())?;
        let verified_at = trusted_time_point(Utc::now());
        if verified_at.not_before < trusted_now.not_after {
            return Err(ProductionRuntimeAdmissionError::TrustedTimeRollback);
        }
        recheck_first_owner_path_closed_guard(
            boundary,
            profile,
            durable_postgresql,
            witness,
            verified_at,
        )
    }

    pub(super) type VerifiedHttpsPublicUrlsRuntimeWitness =
        VerifiedHttpsPublicUrlsGuardWitness<VerifiedPublicIngressAttestation>;

    fn measured_public_ingress_value(
        attestation: &VerifiedPublicIngressAttestation,
    ) -> RuntimeGuardExpectedValue {
        RuntimeGuardExpectedValue::HttpsPublicUrls {
            public_origin_set_digest: attestation.public_origin_set_digest().to_owned(),
            ingress_binding_digest: attestation.ingress_binding_digest().to_owned(),
            attestation_profile_id: attestation.attestation_profile_id().to_owned(),
            attestation_profile_version: attestation.attestation_profile_version(),
            attestation_profile_digest: attestation.attestation_profile_digest().to_owned(),
        }
    }

    pub(super) async fn verify_https_public_urls_guard(
        boundary: &VerifiedProductionBoundary,
        pins: &StartupPublicIngressAttestationPins,
    ) -> Result<VerifiedHttpsPublicUrlsRuntimeWitness, ProductionRuntimeAdmissionError> {
        let measurement_failed = || ProductionRuntimeAdmissionError::GuardMeasurementFailed {
            guard_id: GuardId::HttpsPublicUrls,
        };
        let challenge = exact_challenge(boundary, GuardId::HttpsPublicUrls)?;
        let RuntimeGuardExpectedValue::HttpsPublicUrls {
            public_origin_set_digest,
            ingress_binding_digest,
            attestation_profile_id,
            attestation_profile_version,
            attestation_profile_digest,
        } = challenge.expected_value()
        else {
            return Err(ProductionRuntimeAdmissionError::GuardKindMismatch {
                expected: GuardId::HttpsPublicUrls,
                observed: challenge.expected_value().guard_id(),
            });
        };
        if pins.attestation_profile_id != *attestation_profile_id
            || pins.attestation_profile_version != *attestation_profile_version
            || pins.attestation_profile_digest != *attestation_profile_digest
        {
            return Err(measurement_failed());
        }
        let public_key =
            decode_public_ingress_authority_public_key(pins).map_err(|_| measurement_failed())?;
        let authority = PublicIngressAuthorityAnchor {
            authority_id: &pins.authority_id,
            key_id: &pins.key_id,
            public_key: &public_key,
            public_key_fingerprint: &pins.public_key_fingerprint,
            minimum_authority_epoch: pins.minimum_authority_epoch,
            attestation_profile_id: &pins.attestation_profile_id,
            attestation_profile_version: pins.attestation_profile_version,
            attestation_profile_digest: &pins.attestation_profile_digest,
        };

        let requested_at = Utc::now();
        boundary
            .ensure_fresh(trusted_time_point(requested_at))
            .map_err(|_| ProductionRuntimeAdmissionError::BoundaryStale)?;
        let mut request_nonce = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut request_nonce)
            .map_err(|_| measurement_failed())?;
        let request = build_public_ingress_attestation_request(
            ExpectedPublicIngress {
                deployment_id: boundary.deployed_workload.deployment_id(),
                trust_domain_id: boundary.deployed_workload.trust_domain_id(),
                workload_id: boundary.deployed_workload.workload_id(),
                source_revision: boundary.conformance.source_revision(),
                artifact_digest: boundary.deployed_workload.oci_subject_digest(),
                workload_instance_binding_digest: boundary
                    .deployed_workload
                    .workload_instance_binding_digest(),
                requirement_digest: challenge.requirement_digest(),
                challenge_binding_digest: challenge.challenge_binding_digest(),
                public_origin_set_digest,
                ingress_binding_digest,
            },
            authority,
            request_nonce,
            requested_at,
        )
        .map_err(|_| measurement_failed())?;
        let transport = UnixAuthorityTransport::new(
            pins.socket_path.clone(),
            AuthorityTransportDeadlines {
                connect: PUBLIC_INGRESS_TRANSPORT_PHASE_DEADLINE,
                write: PUBLIC_INGRESS_TRANSPORT_PHASE_DEADLINE,
                read: PUBLIC_INGRESS_TRANSPORT_PHASE_DEADLINE,
            },
            AuthorityTransportBounds {
                max_request_bytes: MAX_PUBLIC_INGRESS_REQUEST_BYTES,
                max_response_bytes: MAX_PUBLIC_INGRESS_RESPONSE_BYTES,
            },
            AuthorityTransportHardLimits {
                max_socket_path_bytes: MAX_AUTHORITY_SOCKET_PATH_BYTES,
                max_phase_deadline: MAX_PUBLIC_INGRESS_TRANSPORT_PHASE_DEADLINE,
                max_request_bytes: MAX_PUBLIC_INGRESS_REQUEST_BYTES,
                max_response_bytes: MAX_PUBLIC_INGRESS_RESPONSE_BYTES,
            },
        )
        .map_err(|_| measurement_failed())?;
        let raw_response = transport
            .exchange(request.as_bytes())
            .await
            .map_err(|_| measurement_failed())?;
        let verified_at = Utc::now();
        let attestation = verify_public_ingress_attestation(
            request,
            &raw_response,
            authority,
            trusted_time_point(verified_at),
        )
        .map_err(|_| measurement_failed())?;
        let observed_value = measured_public_ingress_value(&attestation);
        let observed_at_not_before = attestation.observed_at_not_before();
        let observed_at_not_after = attestation.observed_at_not_after();
        let valid_until = attestation.valid_until();
        VerifiedHttpsPublicUrlsGuardWitness::from_verified_observation(
            boundary,
            VerifiedRuntimeGuardObservation {
                guard_id: GuardId::HttpsPublicUrls,
                observed_value,
                requirement_digest: attestation.requirement_digest().to_owned(),
                challenge_binding_digest: attestation.challenge_binding_digest().to_owned(),
                observed_at_not_before,
                observed_at_not_after,
                valid_until,
                handle: attestation,
            },
            trusted_time_point(verified_at),
        )
    }

    #[cfg(test)]
    pub(super) fn seal_verified_https_public_urls_guard(
        boundary: &VerifiedProductionBoundary,
        attestation: VerifiedPublicIngressAttestation,
        trusted_now: ConformanceTrustedTimeWindow,
    ) -> Result<VerifiedHttpsPublicUrlsRuntimeWitness, ProductionRuntimeAdmissionError> {
        let observed_value = measured_public_ingress_value(&attestation);
        let observed_at_not_before = attestation.observed_at_not_before();
        let observed_at_not_after = attestation.observed_at_not_after();
        let valid_until = attestation.valid_until();
        VerifiedHttpsPublicUrlsGuardWitness::from_verified_observation(
            boundary,
            VerifiedRuntimeGuardObservation {
                guard_id: GuardId::HttpsPublicUrls,
                observed_value,
                requirement_digest: attestation.requirement_digest().to_owned(),
                challenge_binding_digest: attestation.challenge_binding_digest().to_owned(),
                observed_at_not_before,
                observed_at_not_after,
                valid_until,
                handle: attestation,
            },
            trusted_now,
        )
    }

    pub(super) fn recheck_https_public_urls_guard(
        boundary: &VerifiedProductionBoundary,
        witness: &VerifiedHttpsPublicUrlsRuntimeWitness,
        trusted_now: ConformanceTrustedTimeWindow,
    ) -> Result<(), ProductionRuntimeAdmissionError> {
        witness.handle().ensure_fresh(trusted_now).map_err(|_| {
            ProductionRuntimeAdmissionError::WitnessStale {
                guard_id: GuardId::HttpsPublicUrls,
            }
        })?;
        if witness.0.observed_value != measured_public_ingress_value(witness.handle()) {
            return Err(ProductionRuntimeAdmissionError::GuardMeasurementFailed {
                guard_id: GuardId::HttpsPublicUrls,
            });
        }
        witness.recheck(boundary, trusted_now)
    }

    pub(super) struct VerifiedSecureCookieRuntimeHandle {
        runtime: Arc<crate::cookie_runtime::ApiCookieRuntime>,
        policies: Arc<RetainedCookiePolicySet>,
    }

    impl VerifiedSecureCookieRuntimeHandle {
        pub(super) fn runtime(&self) -> &Arc<crate::cookie_runtime::ApiCookieRuntime> {
            &self.runtime
        }

        pub(super) fn policies(&self) -> &Arc<RetainedCookiePolicySet> {
            &self.policies
        }
    }

    pub(super) type VerifiedSecureCookieRuntimeWitness =
        VerifiedSecureCookiesGuardWitness<VerifiedSecureCookieRuntimeHandle>;

    /// Measure the immutable cookie authority owned by the active API runtime.
    /// Neither expected values, binding digests, nor observation times are
    /// accepted from the caller: all authority comes from the sealed boundary
    /// and all live facts come from the exact retained runtime allocation.
    pub(super) fn verify_secure_cookie_guard(
        boundary: &VerifiedProductionBoundary,
        runtime: &Arc<crate::cookie_runtime::ApiCookieRuntime>,
    ) -> Result<VerifiedSecureCookieRuntimeWitness, ProductionRuntimeAdmissionError> {
        verify_secure_cookie_guard_with_clock(boundary, runtime, Utc::now)
    }

    fn verify_secure_cookie_guard_with_clock(
        boundary: &VerifiedProductionBoundary,
        runtime: &Arc<crate::cookie_runtime::ApiCookieRuntime>,
        mut trusted_now: impl FnMut() -> DateTime<Utc>,
    ) -> Result<VerifiedSecureCookieRuntimeWitness, ProductionRuntimeAdmissionError> {
        let measurement_failed = || ProductionRuntimeAdmissionError::GuardMeasurementFailed {
            guard_id: GuardId::SecureCookies,
        };
        let observed_at_not_before = trusted_now();
        let policies = Arc::clone(runtime.secure_policy_set().ok_or_else(measurement_failed)?);
        policies
            .verify_integrity()
            .map_err(|_| measurement_failed())?;
        let observed_value = policies
            .measured_expected_value()
            .map_err(|_| measurement_failed())?;
        if runtime
            .measured_production_value()
            .map_err(|_| measurement_failed())?
            != observed_value
        {
            return Err(measurement_failed());
        }
        let observed_at_not_after = trusted_now();
        let valid_until = observed_at_not_before
            .checked_add_signed(chrono::TimeDelta::seconds(
                MAX_RUNTIME_GUARD_WITNESS_LIFETIME_SECONDS,
            ))
            .ok_or(ProductionRuntimeAdmissionError::InvalidObservationWindow {
                guard_id: GuardId::SecureCookies,
            })?;

        let challenge = exact_challenge(boundary, GuardId::SecureCookies)?;
        let requirement_digest = challenge.requirement_digest().to_owned();
        let challenge_binding_digest = challenge.challenge_binding_digest().to_owned();
        let verification_now = ConformanceTrustedTimeWindow {
            not_before: trusted_now(),
            not_after: trusted_now(),
        };
        VerifiedSecureCookiesGuardWitness::from_verified_observation(
            boundary,
            VerifiedRuntimeGuardObservation {
                guard_id: GuardId::SecureCookies,
                observed_value,
                requirement_digest,
                challenge_binding_digest,
                observed_at_not_before,
                observed_at_not_after,
                valid_until,
                handle: VerifiedSecureCookieRuntimeHandle {
                    runtime: Arc::clone(runtime),
                    policies,
                },
            },
            verification_now,
        )
    }

    pub(super) fn recheck_secure_cookie_guard(
        boundary: &VerifiedProductionBoundary,
        witness: &VerifiedSecureCookieRuntimeWitness,
        trusted_now: ConformanceTrustedTimeWindow,
    ) -> Result<(), ProductionRuntimeAdmissionError> {
        let handle = witness.handle();
        let retained_runtime_policy = handle.runtime.secure_policy_set().ok_or(
            ProductionRuntimeAdmissionError::GuardMeasurementFailed {
                guard_id: GuardId::SecureCookies,
            },
        )?;
        if !Arc::ptr_eq(retained_runtime_policy, &handle.policies) {
            return Err(ProductionRuntimeAdmissionError::GuardMeasurementFailed {
                guard_id: GuardId::SecureCookies,
            });
        }
        handle.policies.verify_integrity().map_err(|_| {
            ProductionRuntimeAdmissionError::GuardMeasurementFailed {
                guard_id: GuardId::SecureCookies,
            }
        })?;
        let remeasured = handle.policies.measured_expected_value().map_err(|_| {
            ProductionRuntimeAdmissionError::GuardMeasurementFailed {
                guard_id: GuardId::SecureCookies,
            }
        })?;
        if handle.runtime.measured_production_value().map_err(|_| {
            ProductionRuntimeAdmissionError::GuardMeasurementFailed {
                guard_id: GuardId::SecureCookies,
            }
        })? != remeasured
            || witness.0.observed_value != remeasured
        {
            return Err(ProductionRuntimeAdmissionError::GuardMeasurementFailed {
                guard_id: GuardId::SecureCookies,
            });
        }
        witness.recheck(boundary, trusted_now)
    }

    #[cfg(test)]
    pub(super) fn verify_secure_cookie_guard_with_test_clock(
        boundary: &VerifiedProductionBoundary,
        runtime: &Arc<crate::cookie_runtime::ApiCookieRuntime>,
        trusted_now: impl FnMut() -> DateTime<Utc>,
    ) -> Result<VerifiedSecureCookieRuntimeWitness, ProductionRuntimeAdmissionError> {
        verify_secure_cookie_guard_with_clock(boundary, runtime, trusted_now)
    }

    /// Exact process-lifetime authenticator composition retained after the
    /// NonDevelopmentAuthenticator guard seals. Every field is an allocation
    /// already owned by the immutable API runtime; no declaration-shaped
    /// substitute can be supplied independently.
    pub(super) struct VerifiedNonDevelopmentAuthenticatorRuntimeHandle {
        runtime: Arc<crate::authenticator_runtime::ApiAuthenticatorRuntime>,
        operational_observation: Arc<crate::authenticator_runtime::AuthenticatorRuntimeObservation>,
        authority: Arc<ResolvedEntraAuthenticatorAuthority>,
        binding_document: Arc<VerifiedAuthenticatorRuntimeBinding>,
        bearer_limits: Arc<ResolvedAuthenticatorBearerLimits>,
        browser_limits: Option<Arc<ResolvedAuthenticatorBrowserLimits>>,
        bearer_validator: Arc<crate::entra_auth::EntraTokenValidator>,
        bearer_observation: Arc<crate::entra_auth::EntraBearerRuntimeObservation>,
        runtime_binding:
            Arc<crate::authenticator_runtime::VerifiedEntraAuthenticatorRuntimeBinding>,
        entra_sso_dependencies: Arc<crate::entra_sso::EntraSsoDeps>,
        browser_origin:
            Option<Arc<crate::authenticator_runtime::VerifiedBrowserAuthenticatorOrigin>>,
        entra_sso_handler_dependencies:
            Option<Arc<crate::authenticator_runtime::VerifiedEntraSsoHandlerDeps>>,
    }

    impl fmt::Debug for VerifiedNonDevelopmentAuthenticatorRuntimeHandle {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("VerifiedNonDevelopmentAuthenticatorRuntimeHandle")
                .field("provider_id", &self.authority.provider_id())
                .field("runtime", &"[RETAINED]")
                .field("operational_observation", &"[RETAINED]")
                .field("authority", &"[RETAINED]")
                .field("binding_document", &"[RETAINED]")
                .field("limit_authorities", &"[RETAINED]")
                .field("bearer_validator", &"[RETAINED]")
                .field("runtime_binding", &"[RETAINED]")
                .field(
                    "browser_origin",
                    &self.browser_origin.as_ref().map(|_| "[RETAINED]"),
                )
                .field(
                    "entra_sso_handler_dependencies",
                    &self
                        .entra_sso_handler_dependencies
                        .as_ref()
                        .map(|_| "[RETAINED]"),
                )
                .finish_non_exhaustive()
        }
    }

    impl VerifiedNonDevelopmentAuthenticatorRuntimeHandle {
        fn capture(
            runtime: &Arc<crate::authenticator_runtime::ApiAuthenticatorRuntime>,
        ) -> Result<Self, ProductionRuntimeAdmissionError> {
            let measurement_failed = non_development_authenticator_measurement_failed;
            runtime
                .validate_production_posture()
                .map_err(|_| measurement_failed())?;
            let operational_observation = Arc::clone(runtime.operational_observation());
            let authority = runtime
                .entra_authenticator_authority()
                .ok_or_else(measurement_failed)?;
            let binding_document = Arc::clone(authority.verified_runtime_binding());
            let bearer_limits = Arc::clone(authority.bearer_limits());
            let browser_limits = authority.browser_limits().map(Arc::clone);
            let bearer_validator = runtime
                .entra_bearer_validator()
                .ok_or_else(measurement_failed)?;
            let bearer_observation = runtime
                .entra_bearer_observation()
                .ok_or_else(measurement_failed)?;
            let runtime_binding = runtime
                .verified_entra_runtime_binding()
                .ok_or_else(measurement_failed)?;
            let entra_sso_dependencies = runtime.entra_sso_dependencies();
            let browser_origin = runtime.browser_authenticator_origin();
            let entra_sso_handler_dependencies = runtime.entra_sso_handler_dependencies();
            let handle = Self {
                runtime: Arc::clone(runtime),
                operational_observation,
                authority,
                binding_document,
                bearer_limits,
                browser_limits,
                bearer_validator,
                bearer_observation,
                runtime_binding,
                entra_sso_dependencies,
                browser_origin,
                entra_sso_handler_dependencies,
            };
            validate_non_development_authenticator_runtime_handle(&handle)?;
            Ok(handle)
        }

        pub(super) fn retains_runtime(
            &self,
            runtime: &Arc<crate::authenticator_runtime::ApiAuthenticatorRuntime>,
        ) -> bool {
            Arc::ptr_eq(&self.runtime, runtime)
        }

        pub(super) fn matches_auth_mode(&self, auth_mode: &AuthMode) -> bool {
            self.runtime.auth_mode() == auth_mode && matches!(auth_mode, AuthMode::EntraId)
        }

        pub(super) fn matches_provider(&self, provider: &ActiveProviderConfiguration) -> bool {
            let ActiveProviderKindConfig::Oidc {
                configuration,
                verified_runtime_binding,
            } = &provider.kind_config
            else {
                return false;
            };
            let expected_provider = ExpectedProviderBinding {
                provider_id: provider.provider_id.clone(),
                configuration_version: provider.config_version,
                configuration_payload_digest: provider.payload_digest.clone(),
                lifecycle_record_version: provider.active_lifecycle_record_version,
                lifecycle_state: ProviderLifecycleState::Active,
                capability_descriptor_id: provider.capability_descriptor.descriptor_id.clone(),
                capability_descriptor_version: provider.capability_descriptor.descriptor_version,
                adapter_kind: provider.capability_descriptor.adapter_kind.clone(),
                adapter_version: provider.capability_descriptor.adapter_version.clone(),
            };
            provider.kind == "oidc"
                && provider.trust_domain_id == self.authority.trust_domain_id()
                && provider.capability_descriptor.implementation_applicable
                && provider.capability_descriptor.production_eligible
                && configuration.as_ref() == &self.authority.oidc_configuration
                && Arc::ptr_eq(verified_runtime_binding, &self.binding_document)
                && provider
                    .capability_descriptor
                    .advertised_capabilities
                    .as_slice()
                    == self.binding_document.document.capability_ids.as_slice()
                && self.runtime_binding.provider_binding() == &expected_provider
                && self.authority.provider_id() == provider.provider_id.as_str()
                && self.authority.provider_configuration_version() == provider.config_version
                && self.authority.provider_configuration_payload_digest()
                    == provider.payload_digest.as_str()
                && self.authority.provider_lifecycle_record_version()
                    == provider.active_lifecycle_record_version
        }
    }

    pub(super) type VerifiedNonDevelopmentAuthenticatorRuntimeWitness =
        VerifiedNonDevelopmentAuthenticatorGuardWitness<
            VerifiedNonDevelopmentAuthenticatorRuntimeHandle,
        >;

    fn non_development_authenticator_measurement_failed() -> ProductionRuntimeAdmissionError {
        ProductionRuntimeAdmissionError::GuardMeasurementFailed {
            guard_id: GuardId::NonDevelopmentAuthenticator,
        }
    }

    fn validate_non_development_authenticator_runtime_handle(
        handle: &VerifiedNonDevelopmentAuthenticatorRuntimeHandle,
    ) -> Result<RuntimeGuardExpectedValue, ProductionRuntimeAdmissionError> {
        let measurement_failed = non_development_authenticator_measurement_failed;
        handle
            .runtime
            .validate_production_posture()
            .map_err(|_| measurement_failed())?;
        handle
            .authority
            .verify_integrity()
            .map_err(|_| measurement_failed())?;
        handle
            .binding_document
            .verify_integrity()
            .map_err(|_| measurement_failed())?;
        handle
            .bearer_limits
            .verify_integrity()
            .map_err(|_| measurement_failed())?;
        if let Some(browser_limits) = &handle.browser_limits {
            browser_limits
                .verify_integrity()
                .map_err(|_| measurement_failed())?;
        }
        handle
            .runtime_binding
            .verify_integrity()
            .map_err(|_| measurement_failed())?;
        if !handle
            .runtime
            .retains_operational_observation(&handle.operational_observation)
            || !handle
                .runtime
                .retains_entra_authenticator_authority(&Some(Arc::clone(&handle.authority)))
            || !Arc::ptr_eq(
                &handle.binding_document,
                handle.authority.verified_runtime_binding(),
            )
            || !Arc::ptr_eq(&handle.bearer_limits, handle.authority.bearer_limits())
            || !handle
                .runtime
                .retains_authenticator_bearer_limits(&Some(Arc::clone(&handle.bearer_limits)))
            || !handle
                .runtime
                .retains_authenticator_browser_limits(&handle.browser_limits)
            || !handle
                .runtime
                .retains_entra_bearer_validator(&Some(Arc::clone(&handle.bearer_validator)))
            || !handle
                .runtime
                .retains_entra_bearer_observation(&Some(Arc::clone(&handle.bearer_observation)))
            || !handle.runtime.remeasures_entra_bearer_observation()
            || !handle
                .runtime
                .retains_verified_entra_runtime_binding(&Some(Arc::clone(&handle.runtime_binding)))
            || !handle.runtime_binding.retains_authority(&handle.authority)
            || !handle
                .runtime_binding
                .retains_bearer_validator(&handle.bearer_validator)
            || !handle
                .runtime
                .retains_entra_sso_dependencies(&handle.entra_sso_dependencies)
            || !handle
                .runtime_binding
                .retains_entra_sso_dependencies(&handle.entra_sso_dependencies)
            || handle.runtime.auth_mode() != &AuthMode::EntraId
        {
            return Err(measurement_failed());
        }
        let browser_declared = handle.authority.browser_path_id().is_some();
        if browser_declared != handle.browser_limits.is_some() {
            return Err(measurement_failed());
        }
        match (
            browser_declared,
            handle.browser_origin.as_ref(),
            handle.entra_sso_handler_dependencies.as_ref(),
        ) {
            (true, Some(origin), Some(handler))
                if origin.verify_integrity().is_ok()
                    && origin.retains_entra_runtime_binding(&handle.runtime_binding)
                    && origin.retains_entra_sso_dependencies(&handle.entra_sso_dependencies)
                    && handler.verify_integrity().is_ok()
                    && Arc::ptr_eq(handler.base(), &handle.entra_sso_dependencies)
                    && Arc::ptr_eq(handler.origin(), origin)
                    && handle
                        .runtime
                        .retains_browser_authenticator_origin(&handle.browser_origin)
                    && handle.runtime.retains_entra_sso_handler_dependencies(
                        &handle.entra_sso_handler_dependencies,
                    ) => {}
            (false, None, None)
                if handle.runtime.retains_browser_authenticator_origin(&None)
                    && handle.runtime.retains_entra_sso_handler_dependencies(&None) => {}
            _ => return Err(measurement_failed()),
        }

        let observed_value = handle
            .runtime
            .measured_authenticator_inventory_value()
            .ok_or_else(measurement_failed)?
            .clone();
        if handle.runtime.expected_authenticator_inventory_value() != Some(&observed_value)
            || handle
                .runtime_binding
                .measured_authenticator_inventory_value()
                != &observed_value
            || handle
                .runtime_binding
                .expected_authenticator_inventory_value()
                != &observed_value
            || handle.runtime.measured_authenticator_inventory_digest()
                != Some(
                    handle
                        .runtime_binding
                        .measured_authenticator_inventory_digest(),
                )
            || handle.runtime.expected_authenticator_inventory_digest()
                != Some(
                    handle
                        .runtime_binding
                        .expected_authenticator_inventory_digest(),
                )
        {
            return Err(measurement_failed());
        }
        let RuntimeGuardExpectedValue::NonDevelopmentAuthenticator {
            authenticator_inventory_digest,
            authenticators,
        } = &observed_value
        else {
            return Err(measurement_failed());
        };
        match authenticators.as_slice() {
            [authenticator]
                if &authenticator.provider == handle.runtime_binding.provider_binding()
                    && authenticator.authenticator_kind == ProductionAuthenticatorKind::Oidc
                    && authenticator.runtime_binding_digest.as_str()
                        == handle.runtime_binding.runtime_binding_digest()
                    && authenticator_inventory_digest.as_str()
                        == handle
                            .runtime_binding
                            .measured_authenticator_inventory_digest() => {}
            _ => return Err(measurement_failed()),
        }
        Ok(observed_value)
    }

    pub(super) fn measured_non_development_authenticator_value(
        runtime: &Arc<crate::authenticator_runtime::ApiAuthenticatorRuntime>,
    ) -> Result<RuntimeGuardExpectedValue, ProductionRuntimeAdmissionError> {
        let handle = VerifiedNonDevelopmentAuthenticatorRuntimeHandle::capture(runtime)?;
        validate_non_development_authenticator_runtime_handle(&handle)
    }

    #[cfg(test)]
    pub(super) fn capture_non_development_authenticator_runtime_handle(
        runtime: &Arc<crate::authenticator_runtime::ApiAuthenticatorRuntime>,
    ) -> Result<VerifiedNonDevelopmentAuthenticatorRuntimeHandle, ProductionRuntimeAdmissionError>
    {
        VerifiedNonDevelopmentAuthenticatorRuntimeHandle::capture(runtime)
    }

    pub(super) fn verify_non_development_authenticator_guard(
        boundary: &VerifiedProductionBoundary,
        runtime: &Arc<crate::authenticator_runtime::ApiAuthenticatorRuntime>,
    ) -> Result<VerifiedNonDevelopmentAuthenticatorRuntimeWitness, ProductionRuntimeAdmissionError>
    {
        verify_non_development_authenticator_guard_with_clock(boundary, runtime, Utc::now)
    }

    fn verify_non_development_authenticator_guard_with_clock(
        boundary: &VerifiedProductionBoundary,
        runtime: &Arc<crate::authenticator_runtime::ApiAuthenticatorRuntime>,
        mut trusted_now: impl FnMut() -> DateTime<Utc>,
    ) -> Result<VerifiedNonDevelopmentAuthenticatorRuntimeWitness, ProductionRuntimeAdmissionError>
    {
        let observed_at_not_before = trusted_now();
        boundary
            .ensure_fresh(trusted_time_point(observed_at_not_before))
            .map_err(|_| ProductionRuntimeAdmissionError::BoundaryStale)?;
        let handle = VerifiedNonDevelopmentAuthenticatorRuntimeHandle::capture(runtime)?;
        let observed_value = validate_non_development_authenticator_runtime_handle(&handle)?;
        let challenge = exact_challenge(boundary, GuardId::NonDevelopmentAuthenticator)?;
        if &observed_value != challenge.expected_value() {
            return Err(ProductionRuntimeAdmissionError::ExpectedValueMismatch {
                guard_id: GuardId::NonDevelopmentAuthenticator,
            });
        }
        let observed_at_not_after = trusted_now();
        let valid_until = observed_at_not_before
            .checked_add_signed(chrono::TimeDelta::seconds(
                MAX_RUNTIME_GUARD_WITNESS_LIFETIME_SECONDS,
            ))
            .ok_or(ProductionRuntimeAdmissionError::InvalidObservationWindow {
                guard_id: GuardId::NonDevelopmentAuthenticator,
            })?;
        let verification_now = ConformanceTrustedTimeWindow {
            not_before: trusted_now(),
            not_after: trusted_now(),
        };
        VerifiedNonDevelopmentAuthenticatorGuardWitness::from_verified_observation(
            boundary,
            VerifiedRuntimeGuardObservation {
                guard_id: GuardId::NonDevelopmentAuthenticator,
                observed_value,
                requirement_digest: challenge.requirement_digest().to_owned(),
                challenge_binding_digest: challenge.challenge_binding_digest().to_owned(),
                observed_at_not_before,
                observed_at_not_after,
                valid_until,
                handle,
            },
            verification_now,
        )
    }

    pub(super) fn recheck_non_development_authenticator_guard(
        boundary: &VerifiedProductionBoundary,
        witness: &VerifiedNonDevelopmentAuthenticatorRuntimeWitness,
        trusted_now: ConformanceTrustedTimeWindow,
    ) -> Result<(), ProductionRuntimeAdmissionError> {
        let remeasured = validate_non_development_authenticator_runtime_handle(witness.handle())?;
        if witness.0.observed_value != remeasured {
            return Err(non_development_authenticator_measurement_failed());
        }
        witness.recheck(boundary, trusted_now)
    }

    #[cfg(test)]
    pub(super) fn verify_non_development_authenticator_guard_with_test_clock(
        boundary: &VerifiedProductionBoundary,
        runtime: &Arc<crate::authenticator_runtime::ApiAuthenticatorRuntime>,
        trusted_now: impl FnMut() -> DateTime<Utc>,
    ) -> Result<VerifiedNonDevelopmentAuthenticatorRuntimeWitness, ProductionRuntimeAdmissionError>
    {
        verify_non_development_authenticator_guard_with_clock(boundary, runtime, trusted_now)
    }

    /// Exact process-lifetime secret-provider authority retained after the
    /// ApprovedSecretProvider live guard seals. Debug omits the operational
    /// leaves, authenticated binding, and lease identity.
    pub(super) struct VerifiedApprovedSecretProviderRuntimeHandle {
        runtime: Arc<crate::secret_provider_runtime::VaultKubernetesRuntime>,
        binding: Arc<VerifiedSecretProviderRuntimeBinding>,
        observation: Arc<crate::secret_provider_runtime::VaultRuntimeOperationalObservation>,
        lease: Arc<crate::secret_provider_runtime::VaultAuthenticatedLease>,
    }

    impl fmt::Debug for VerifiedApprovedSecretProviderRuntimeHandle {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("VerifiedApprovedSecretProviderRuntimeHandle")
                .field("provider_id", &self.binding.document.provider_id)
                .field(
                    "provider_configuration_version",
                    &self.binding.document.provider_configuration_version,
                )
                .field("runtime", &"[RETAINED]")
                .field("binding", &"[RETAINED]")
                .field("observation", &"[RETAINED]")
                .field("lease", &"[RETAINED]")
                .finish()
        }
    }

    impl VerifiedApprovedSecretProviderRuntimeHandle {
        pub(super) fn retains_runtime(
            &self,
            runtime: &Arc<crate::secret_provider_runtime::VaultKubernetesRuntime>,
        ) -> bool {
            Arc::ptr_eq(&self.runtime, runtime)
        }
    }

    pub(super) type VerifiedApprovedSecretProviderRuntimeWitness =
        VerifiedApprovedSecretProviderGuardWitness<VerifiedApprovedSecretProviderRuntimeHandle>;

    fn approved_secret_provider_measurement_failed() -> ProductionRuntimeAdmissionError {
        ProductionRuntimeAdmissionError::GuardMeasurementFailed {
            guard_id: GuardId::ApprovedSecretProvider,
        }
    }

    fn exact_secret_provider_row(
        provider: &ActiveProviderConfiguration,
        binding: &Arc<VerifiedSecretProviderRuntimeBinding>,
    ) -> Result<ExpectedProviderBinding, ProductionRuntimeAdmissionError> {
        let measurement_failed = approved_secret_provider_measurement_failed;
        let ActiveProviderKindConfig::SecretService {
            configuration,
            verified_runtime_binding: Some(retained_binding),
        } = &provider.kind_config
        else {
            return Err(measurement_failed());
        };
        let Some(reference) = configuration.runtime_binding_ref.as_ref() else {
            return Err(measurement_failed());
        };
        if provider.kind != "secret-service"
            || provider.active_lifecycle_record_version == 0
            || !Arc::ptr_eq(retained_binding, binding)
            || reference != &binding.reference
            || provider.provider_id != binding.document.provider_id
            || provider.config_version != binding.document.provider_configuration_version
            || provider.trust_domain_id != binding.document.trust_domain_id
            || provider.capability_descriptor.descriptor_id
                != binding.document.capability_descriptor_id
            || provider.capability_descriptor.descriptor_version
                != binding.document.capability_descriptor_version
            || provider.capability_descriptor.adapter_kind != binding.document.adapter_kind
            || provider.capability_descriptor.adapter_version != binding.document.adapter_version
            || validate_digest_pin(
                "active secret-provider configuration payload digest",
                &provider.payload_digest,
            )
            .is_err()
        {
            return Err(measurement_failed());
        }
        Ok(ExpectedProviderBinding {
            provider_id: provider.provider_id.clone(),
            configuration_version: provider.config_version,
            configuration_payload_digest: provider.payload_digest.clone(),
            lifecycle_record_version: provider.active_lifecycle_record_version,
            lifecycle_state: ProviderLifecycleState::Active,
            capability_descriptor_id: provider.capability_descriptor.descriptor_id.clone(),
            capability_descriptor_version: provider.capability_descriptor.descriptor_version,
            adapter_kind: provider.capability_descriptor.adapter_kind.clone(),
            adapter_version: provider.capability_descriptor.adapter_version.clone(),
        })
    }

    fn runtime_observation_matches_binding(
        binding: &VerifiedSecretProviderRuntimeBinding,
        observation: &crate::secret_provider_runtime::VaultRuntimeOperationalObservation,
    ) -> bool {
        let document = &binding.document;
        document.provider_id == observation.provider_id
            && document.provider_configuration_version == observation.provider_configuration_version
            && document.adapter_kind == observation.adapter_kind
            && document.adapter_version == observation.adapter_version
            && document.protocol_version == observation.protocol_version
            && document.backend_compatibility_profile.profile_id
                == observation.backend_compatibility_profile.profile_id
            && document.backend_compatibility_profile.profile_version
                == observation.backend_compatibility_profile.profile_version
            && document.backend_compatibility_profile.digest_contract
                == observation.backend_compatibility_profile.digest_contract
            && document.backend_compatibility_profile.binding_digest
                == observation.backend_compatibility_profile.binding_digest
            && document.transport.endpoint_base_url_binding_digest
                == observation.transport.endpoint_base_url_binding_digest
            && document.transport.ca_trust_binding_digest
                == observation.transport.ca_trust_binding_digest
            && document.transport.https_required == observation.transport.https_required
            && document.transport.redirects_allowed == observation.transport.redirects_allowed
            && document.transport.ambient_proxy_allowed
                == observation.transport.ambient_proxy_allowed
            && document.transport.built_in_roots_allowed
                == observation.transport.built_in_roots_allowed
            && document.transport.connect_timeout_millis
                == observation.transport.connect_timeout_millis
            && document.transport.request_timeout_millis
                == observation.transport.request_timeout_millis
            && document.transport.response_body_max_bytes
                == observation.transport.response_body_max_bytes
            && document.credential_source.kind == observation.credential_source.kind
            && document.credential_source.identity_binding_digest
                == observation.credential_source.identity_binding_digest
            && document.credential_source.audience_binding_digest
                == observation.credential_source.audience_binding_digest
            && document.credential_source.token_path_binding_digest
                == observation.credential_source.token_path_binding_digest
            && document
                .credential_source
                .provider_authentication_digest_contract
                == observation
                    .credential_source
                    .provider_authentication_digest_contract
            && document
                .credential_source
                .provider_authentication_binding_digest
                == observation
                    .credential_source
                    .provider_authentication_binding_digest
            && document.credential_source.static_bearer_allowed
                == observation.credential_source.static_bearer_allowed
            && document.credential_source.exported_bearer_allowed
                == observation.credential_source.exported_bearer_allowed
            && document.capability_bindings.len() == observation.capability_bindings.len()
            && document
                .capability_bindings
                .iter()
                .zip(&observation.capability_bindings)
                .all(|(expected, measured)| {
                    expected.capability_id == measured.capability_id
                        && expected.semantic_version == measured.semantic_version
                })
            && document.retained_consumer_ids == observation.retained_consumer_ids
            && document.ownership.single_runtime_owner == observation.ownership.single_runtime_owner
            && document.ownership.ambient_reconfiguration_allowed
                == observation.ownership.ambient_reconfiguration_allowed
    }

    /// Canonical R projection. D (the exact raw document digest) and P (the
    /// active configuration payload digest inside `provider`) are independent
    /// inputs; R can therefore never be replaced with either declaration.
    fn secret_provider_runtime_binding_digest(
        provider: &ExpectedProviderBinding,
        binding: &VerifiedSecretProviderRuntimeBinding,
        observation: &crate::secret_provider_runtime::VaultRuntimeOperationalObservation,
    ) -> Result<String, ProductionRuntimeAdmissionError> {
        let projection = serde_json::json!({
            "digest_contract": SECRET_PROVIDER_RUNTIME_BINDING_DIGEST_CONTRACT,
            "provider": provider,
            "binding_document_reference": &binding.reference,
            "observed_runtime": {
                "provider_id": &observation.provider_id,
                "provider_configuration_version": observation.provider_configuration_version,
                "adapter_kind": &observation.adapter_kind,
                "adapter_version": &observation.adapter_version,
                "protocol_version": &observation.protocol_version,
                "backend_compatibility_profile": {
                    "profile_id": &observation.backend_compatibility_profile.profile_id,
                    "profile_version": observation.backend_compatibility_profile.profile_version,
                    "digest_contract": &observation.backend_compatibility_profile.digest_contract,
                    "binding_digest": &observation.backend_compatibility_profile.binding_digest,
                },
                "transport": {
                    "endpoint_base_url_binding_digest": &observation.transport.endpoint_base_url_binding_digest,
                    "ca_trust_binding_digest": &observation.transport.ca_trust_binding_digest,
                    "https_required": observation.transport.https_required,
                    "redirects_allowed": observation.transport.redirects_allowed,
                    "ambient_proxy_allowed": observation.transport.ambient_proxy_allowed,
                    "built_in_roots_allowed": observation.transport.built_in_roots_allowed,
                    "connect_timeout_millis": observation.transport.connect_timeout_millis,
                    "request_timeout_millis": observation.transport.request_timeout_millis,
                    "response_body_max_bytes": observation.transport.response_body_max_bytes,
                },
                "credential_source": {
                    "kind": &observation.credential_source.kind,
                    "identity_binding_digest": &observation.credential_source.identity_binding_digest,
                    "audience_binding_digest": &observation.credential_source.audience_binding_digest,
                    "token_path_binding_digest": &observation.credential_source.token_path_binding_digest,
                    "provider_authentication_digest_contract": &observation.credential_source.provider_authentication_digest_contract,
                    "provider_authentication_binding_digest": &observation.credential_source.provider_authentication_binding_digest,
                    "static_bearer_allowed": observation.credential_source.static_bearer_allowed,
                    "exported_bearer_allowed": observation.credential_source.exported_bearer_allowed,
                },
                "capability_bindings": observation.capability_bindings.iter().map(|capability| {
                    serde_json::json!({
                        "capability_id": &capability.capability_id,
                        "semantic_version": &capability.semantic_version,
                    })
                }).collect::<Vec<_>>(),
                "retained_consumer_ids": &observation.retained_consumer_ids,
                "ownership": {
                    "single_runtime_owner": observation.ownership.single_runtime_owner,
                    "ambient_reconfiguration_allowed": observation.ownership.ambient_reconfiguration_allowed,
                },
            },
        });
        let canonical = canonical_json_bytes(&projection)
            .map_err(|_| approved_secret_provider_measurement_failed())?;
        let runtime_digest = raw_digest(&canonical);
        if runtime_digest == binding.reference.content_digest
            || runtime_digest == provider.configuration_payload_digest
        {
            return Err(approved_secret_provider_measurement_failed());
        }
        Ok(runtime_digest)
    }

    pub(super) fn measured_approved_secret_provider_value(
        provider: &ActiveProviderConfiguration,
        binding: &Arc<VerifiedSecretProviderRuntimeBinding>,
        observation: &crate::secret_provider_runtime::VaultRuntimeOperationalObservation,
    ) -> Result<RuntimeGuardExpectedValue, ProductionRuntimeAdmissionError> {
        binding
            .verify_integrity()
            .map_err(|_| approved_secret_provider_measurement_failed())?;
        if !runtime_observation_matches_binding(binding, observation) {
            return Err(approved_secret_provider_measurement_failed());
        }
        let required_capability_ids = observation
            .capability_bindings
            .iter()
            .map(|capability| capability.capability_id.clone())
            .collect::<Vec<_>>();
        if required_capability_ids.is_empty()
            || !required_capability_ids
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        {
            return Err(approved_secret_provider_measurement_failed());
        }
        if provider.capability_descriptor.advertised_capabilities != required_capability_ids {
            return Err(approved_secret_provider_measurement_failed());
        }
        let provider = exact_secret_provider_row(provider, binding)?;
        let runtime_binding_digest =
            secret_provider_runtime_binding_digest(&provider, binding, observation)?;
        let providers = vec![ExpectedSecretProviderBinding {
            provider,
            runtime_binding_digest,
        }];
        let provider_inventory_digest =
            secret_provider_inventory_digest(&providers, &required_capability_ids)
                .map_err(|_| approved_secret_provider_measurement_failed())?;
        Ok(RuntimeGuardExpectedValue::ApprovedSecretProvider {
            provider_inventory_digest,
            providers,
            required_capability_ids,
        })
    }

    fn validate_secret_provider_runtime_handle(
        provider: &ActiveProviderConfiguration,
        handle: &VerifiedApprovedSecretProviderRuntimeHandle,
    ) -> Result<RuntimeGuardExpectedValue, ProductionRuntimeAdmissionError> {
        if !handle.runtime.is_bound_to(&handle.binding)
            || !Arc::ptr_eq(
                handle.runtime.operational_observation(),
                &handle.observation,
            )
            || !handle.runtime.lease_is_current(&handle.lease)
        {
            return Err(approved_secret_provider_measurement_failed());
        }
        let readiness = handle.runtime.readiness_snapshot();
        if !readiness.is_ready()
            || readiness.generation != handle.lease.generation()
            || readiness.workload_identity_binding_digest.as_deref()
                != Some(
                    handle
                        .observation
                        .credential_source
                        .identity_binding_digest
                        .as_str(),
                )
            || handle.runtime.witness_valid_for(&handle.lease).is_err()
        {
            return Err(approved_secret_provider_measurement_failed());
        }
        measured_approved_secret_provider_value(provider, &handle.binding, &handle.observation)
    }

    pub(super) async fn verify_approved_secret_provider_guard(
        boundary: &VerifiedProductionBoundary,
        provider: &ActiveProviderConfiguration,
        binding: &Arc<VerifiedSecretProviderRuntimeBinding>,
        runtime: &Arc<crate::secret_provider_runtime::VaultKubernetesRuntime>,
    ) -> Result<VerifiedApprovedSecretProviderRuntimeWitness, ProductionRuntimeAdmissionError> {
        let measurement_failed = approved_secret_provider_measurement_failed;
        let observed_at_not_before = Utc::now();
        boundary
            .ensure_fresh(trusted_time_point(observed_at_not_before))
            .map_err(|_| ProductionRuntimeAdmissionError::BoundaryStale)?;
        if !runtime.is_bound_to(binding) {
            return Err(measurement_failed());
        }
        let observation = Arc::clone(runtime.operational_observation());
        let observed_value =
            measured_approved_secret_provider_value(provider, binding, &observation)?;
        let challenge = exact_challenge(boundary, GuardId::ApprovedSecretProvider)?;
        if &observed_value != challenge.expected_value() {
            return Err(ProductionRuntimeAdmissionError::ExpectedValueMismatch {
                guard_id: GuardId::ApprovedSecretProvider,
            });
        }

        // Only after the independently measured static runtime has matched the
        // receipt may a projected workload credential be sent to the provider.
        let lease = runtime
            .authenticate()
            .await
            .map_err(|_| measurement_failed())?;
        let witness_valid_for = runtime
            .witness_valid_for(&lease)
            .map_err(|_| measurement_failed())?
            .min(Duration::from_secs(
                MAX_RUNTIME_GUARD_WITNESS_LIFETIME_SECONDS as u64,
            ));
        if witness_valid_for.is_zero() {
            return Err(measurement_failed());
        }
        let observed_at_not_after = Utc::now();
        let valid_until = observed_at_not_after
            .checked_add_signed(chrono::TimeDelta::from_std(witness_valid_for).map_err(|_| {
                ProductionRuntimeAdmissionError::InvalidObservationWindow {
                    guard_id: GuardId::ApprovedSecretProvider,
                }
            })?)
            .ok_or(ProductionRuntimeAdmissionError::InvalidObservationWindow {
                guard_id: GuardId::ApprovedSecretProvider,
            })?;
        let handle = VerifiedApprovedSecretProviderRuntimeHandle {
            runtime: Arc::clone(runtime),
            binding: Arc::clone(binding),
            observation,
            lease,
        };
        if validate_secret_provider_runtime_handle(provider, &handle)? != observed_value {
            return Err(measurement_failed());
        }
        VerifiedApprovedSecretProviderGuardWitness::from_verified_observation(
            boundary,
            VerifiedRuntimeGuardObservation {
                guard_id: GuardId::ApprovedSecretProvider,
                observed_value,
                requirement_digest: challenge.requirement_digest().to_owned(),
                challenge_binding_digest: challenge.challenge_binding_digest().to_owned(),
                observed_at_not_before,
                observed_at_not_after,
                valid_until,
                handle,
            },
            trusted_time_point(Utc::now()),
        )
    }

    pub(super) fn recheck_approved_secret_provider_guard(
        boundary: &VerifiedProductionBoundary,
        provider: &ActiveProviderConfiguration,
        witness: &VerifiedApprovedSecretProviderRuntimeWitness,
        trusted_now: ConformanceTrustedTimeWindow,
    ) -> Result<(), ProductionRuntimeAdmissionError> {
        let remeasured = validate_secret_provider_runtime_handle(provider, witness.handle())?;
        if witness.0.observed_value != remeasured {
            return Err(approved_secret_provider_measurement_failed());
        }
        witness.recheck(boundary, trusted_now)
    }

    /// Exactly one nominal witness for every production guard. Named fields
    /// make omission, duplication, and cross-kind substitution compile-time
    /// errors instead of collection-shape checks.
    pub(super) struct VerifiedProductionRuntimeGuardWitnesses<
        DatabaseHandle,
        SecretProviderHandle,
        PublicIngressHandle,
        CookieHandle,
        AuthenticatorHandle,
        SigningHandle,
        DependencyHandle,
        FirstOwnerHandle,
    > {
        durable_postgresql: VerifiedDurablePostgresqlGuardWitness<DatabaseHandle>,
        approved_secret_provider: VerifiedApprovedSecretProviderGuardWitness<SecretProviderHandle>,
        https_public_urls: VerifiedHttpsPublicUrlsGuardWitness<PublicIngressHandle>,
        secure_cookies: VerifiedSecureCookiesGuardWitness<CookieHandle>,
        non_development_authenticator:
            VerifiedNonDevelopmentAuthenticatorGuardWitness<AuthenticatorHandle>,
        external_signing_key_material:
            VerifiedExternalSigningKeyMaterialGuardWitness<SigningHandle>,
        mock_dependencies_disabled: VerifiedMockDependenciesDisabledGuardWitness<DependencyHandle>,
        first_owner_path_closed: VerifiedFirstOwnerPathClosedGuardWitness<FirstOwnerHandle>,
    }

    impl<
            DatabaseHandle,
            SecretProviderHandle,
            PublicIngressHandle,
            CookieHandle,
            AuthenticatorHandle,
            SigningHandle,
            DependencyHandle,
            FirstOwnerHandle,
        > fmt::Debug
        for VerifiedProductionRuntimeGuardWitnesses<
            DatabaseHandle,
            SecretProviderHandle,
            PublicIngressHandle,
            CookieHandle,
            AuthenticatorHandle,
            SigningHandle,
            DependencyHandle,
            FirstOwnerHandle,
        >
    {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("VerifiedProductionRuntimeGuardWitnesses")
                .field("durable_postgresql", &self.durable_postgresql)
                .field("approved_secret_provider", &self.approved_secret_provider)
                .field("https_public_urls", &self.https_public_urls)
                .field("secure_cookies", &self.secure_cookies)
                .field(
                    "non_development_authenticator",
                    &self.non_development_authenticator,
                )
                .field(
                    "external_signing_key_material",
                    &self.external_signing_key_material,
                )
                .field(
                    "mock_dependencies_disabled",
                    &self.mock_dependencies_disabled,
                )
                .field("first_owner_path_closed", &self.first_owner_path_closed)
                .finish()
        }
    }

    impl<
            DatabaseHandle,
            SecretProviderHandle,
            PublicIngressHandle,
            CookieHandle,
            AuthenticatorHandle,
            SigningHandle,
            DependencyHandle,
            FirstOwnerHandle,
        >
        VerifiedProductionRuntimeGuardWitnesses<
            DatabaseHandle,
            SecretProviderHandle,
            PublicIngressHandle,
            CookieHandle,
            AuthenticatorHandle,
            SigningHandle,
            DependencyHandle,
            FirstOwnerHandle,
        >
    {
        #[allow(clippy::too_many_arguments)]
        pub(super) fn new(
            durable_postgresql: VerifiedDurablePostgresqlGuardWitness<DatabaseHandle>,
            approved_secret_provider: VerifiedApprovedSecretProviderGuardWitness<
                SecretProviderHandle,
            >,
            https_public_urls: VerifiedHttpsPublicUrlsGuardWitness<PublicIngressHandle>,
            secure_cookies: VerifiedSecureCookiesGuardWitness<CookieHandle>,
            non_development_authenticator: VerifiedNonDevelopmentAuthenticatorGuardWitness<
                AuthenticatorHandle,
            >,
            external_signing_key_material: VerifiedExternalSigningKeyMaterialGuardWitness<
                SigningHandle,
            >,
            mock_dependencies_disabled: VerifiedMockDependenciesDisabledGuardWitness<
                DependencyHandle,
            >,
            first_owner_path_closed: VerifiedFirstOwnerPathClosedGuardWitness<FirstOwnerHandle>,
        ) -> Self {
            Self {
                durable_postgresql,
                approved_secret_provider,
                https_public_urls,
                secure_cookies,
                non_development_authenticator,
                external_signing_key_material,
                mock_dependencies_disabled,
                first_owner_path_closed,
            }
        }

        fn recheck(
            &self,
            boundary: &VerifiedProductionBoundary,
            trusted_now: ConformanceTrustedTimeWindow,
        ) -> Result<(), ProductionRuntimeAdmissionError> {
            self.durable_postgresql.recheck(boundary, trusted_now)?;
            self.approved_secret_provider
                .recheck(boundary, trusted_now)?;
            self.https_public_urls.recheck(boundary, trusted_now)?;
            self.secure_cookies.recheck(boundary, trusted_now)?;
            self.non_development_authenticator
                .recheck(boundary, trusted_now)?;
            self.external_signing_key_material
                .recheck(boundary, trusted_now)?;
            self.mock_dependencies_disabled
                .recheck(boundary, trusted_now)?;
            self.first_owner_path_closed.recheck(boundary, trusted_now)
        }
    }

    /// Final non-cloneable serving authority. It owns the static production
    /// boundary and all eight live witnesses, which in turn retain the exact
    /// handles measured before admission.
    pub(super) struct VerifiedProductionRuntimeAdmission<
        DatabaseHandle,
        SecretProviderHandle,
        PublicIngressHandle,
        CookieHandle,
        AuthenticatorHandle,
        SigningHandle,
        DependencyHandle,
        FirstOwnerHandle,
    > {
        boundary: VerifiedProductionBoundary,
        witnesses: VerifiedProductionRuntimeGuardWitnesses<
            DatabaseHandle,
            SecretProviderHandle,
            PublicIngressHandle,
            CookieHandle,
            AuthenticatorHandle,
            SigningHandle,
            DependencyHandle,
            FirstOwnerHandle,
        >,
        last_freshness_fence_not_after: DateTime<Utc>,
    }

    impl<
            DatabaseHandle,
            SecretProviderHandle,
            PublicIngressHandle,
            CookieHandle,
            AuthenticatorHandle,
            SigningHandle,
            DependencyHandle,
            FirstOwnerHandle,
        > fmt::Debug
        for VerifiedProductionRuntimeAdmission<
            DatabaseHandle,
            SecretProviderHandle,
            PublicIngressHandle,
            CookieHandle,
            AuthenticatorHandle,
            SigningHandle,
            DependencyHandle,
            FirstOwnerHandle,
        >
    {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("VerifiedProductionRuntimeAdmission")
                .field("boundary", &self.boundary)
                .field("witnesses", &self.witnesses)
                .finish()
        }
    }

    impl<
            DatabaseHandle,
            SecretProviderHandle,
            PublicIngressHandle,
            CookieHandle,
            AuthenticatorHandle,
            SigningHandle,
            DependencyHandle,
            FirstOwnerHandle,
        >
        VerifiedProductionRuntimeAdmission<
            DatabaseHandle,
            SecretProviderHandle,
            PublicIngressHandle,
            CookieHandle,
            AuthenticatorHandle,
            SigningHandle,
            DependencyHandle,
            FirstOwnerHandle,
        >
    {
        pub(super) fn seal(
            boundary: VerifiedProductionBoundary,
            witnesses: VerifiedProductionRuntimeGuardWitnesses<
                DatabaseHandle,
                SecretProviderHandle,
                PublicIngressHandle,
                CookieHandle,
                AuthenticatorHandle,
                SigningHandle,
                DependencyHandle,
                FirstOwnerHandle,
            >,
            trusted_now: ConformanceTrustedTimeWindow,
        ) -> Result<Self, ProductionRuntimeAdmissionError> {
            validate_trusted_time(trusted_now)?;
            let challenge_count = boundary.runtime_guard_challenges().len();
            if challenge_count != 8 {
                return Err(ProductionRuntimeAdmissionError::CorruptChallengeCount {
                    observed: challenge_count,
                });
            }
            boundary
                .ensure_fresh(trusted_now)
                .map_err(|_| ProductionRuntimeAdmissionError::BoundaryStale)?;
            witnesses.recheck(&boundary, trusted_now)?;
            Ok(Self {
                boundary,
                witnesses,
                last_freshness_fence_not_after: trusted_now.not_after,
            })
        }

        pub(super) fn ensure_fresh(
            &mut self,
            trusted_now: ConformanceTrustedTimeWindow,
        ) -> Result<(), ProductionRuntimeAdmissionError> {
            validate_trusted_time(trusted_now)?;
            if trusted_now.not_before < self.last_freshness_fence_not_after {
                return Err(ProductionRuntimeAdmissionError::TrustedTimeRollback);
            }
            self.boundary
                .ensure_fresh(trusted_now)
                .map_err(|_| ProductionRuntimeAdmissionError::BoundaryStale)?;
            self.witnesses.recheck(&self.boundary, trusted_now)?;
            self.last_freshness_fence_not_after = trusted_now.not_after;
            Ok(())
        }

        pub(super) fn durable_postgresql_handle(&self) -> &DatabaseHandle {
            self.witnesses.durable_postgresql.handle()
        }

        pub(super) fn approved_secret_provider_handle(&self) -> &SecretProviderHandle {
            self.witnesses.approved_secret_provider.handle()
        }

        pub(super) fn public_ingress_handle(&self) -> &PublicIngressHandle {
            self.witnesses.https_public_urls.handle()
        }

        pub(super) fn secure_cookie_handle(&self) -> &CookieHandle {
            self.witnesses.secure_cookies.handle()
        }

        pub(super) fn authenticator_handle(&self) -> &AuthenticatorHandle {
            self.witnesses.non_development_authenticator.handle()
        }

        pub(super) fn external_signing_handle(&self) -> &SigningHandle {
            self.witnesses.external_signing_key_material.handle()
        }

        pub(super) fn dependency_handle(&self) -> &DependencyHandle {
            self.witnesses.mock_dependencies_disabled.handle()
        }

        pub(super) fn first_owner_handle(&self) -> &FirstOwnerHandle {
            self.witnesses.first_owner_path_closed.handle()
        }
    }

    impl<
            SecretProviderHandle,
            PublicIngressHandle,
            CookieHandle,
            AuthenticatorHandle,
            SigningHandle,
            DependencyHandle,
            FirstOwnerHandle,
        >
        VerifiedProductionRuntimeAdmission<
            VerifiedDurablePostgresqlRuntimeHandle,
            SecretProviderHandle,
            PublicIngressHandle,
            CookieHandle,
            AuthenticatorHandle,
            SigningHandle,
            DependencyHandle,
            FirstOwnerHandle,
        >
    {
        /// Derive database publication authority from the complete aggregate,
        /// never from the DurablePostgresql witness in isolation.
        pub(super) fn database_publication_token(&self) -> CompleteProductionRuntimeAdmissionToken {
            CompleteProductionRuntimeAdmissionToken {
                durable_postgresql_runtime: self.durable_postgresql_handle().runtime().clone(),
            }
        }
    }
}

#[derive(Debug)]
pub(crate) enum ConformanceState {
    NonProduction,
    Production(Box<VerifiedProductionBoundary>),
}

/// Non-cloneable prerequisite for the one-shot production migration process.
///
/// Serving admission still requires all eight live runtime witnesses. Database
/// schema creation necessarily precedes the database-backed witnesses, so the
/// process first consumes this narrower proof derived from the sealed
/// production boundary's exact DurablePostgresql requirement. It is not DDL
/// authority by itself: execution stays blocked until independently
/// authenticated target and durable-storage evidence is bound to the exact TLS
/// session. It carries no listener, router, application-pool, or serving
/// authority.
pub(crate) struct PendingProductionMigrationTarget {
    boundary: Box<VerifiedProductionBoundary>,
    role_contract: crate::database::MigrationRoleContract,
    receipt_bound_database_target: RuntimeGuardExpectedValue,
    // `None` exists only while the private structural verifier assembles the
    // database half of admission. The production constructor attaches the
    // verified proof before this value can leave the module; successful
    // session attestation fails closed if that invariant is ever violated.
    first_owner_install_certificate:
        Option<crate::first_owner_runtime::VerifiedFirstOwnerInstallCertificate>,
    expected_migration_inventory_digest: String,
    requirement_digest: String,
    challenge_binding_digest: String,
    pins: StartupPostgresqlInfrastructureAttestationPins,
    request_nonce: [u8; 32],
}

impl fmt::Debug for PendingProductionMigrationTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingProductionMigrationTarget")
            .field("requirement_digest", &self.requirement_digest)
            .field("challenge_binding_digest", &self.challenge_binding_digest)
            .field(
                "expected_migration_inventory_digest",
                &self.expected_migration_inventory_digest,
            )
            .field(
                "receipt_bound_database_target_guard",
                &self.receipt_bound_database_target.guard_id(),
            )
            .field(
                "first_owner_installation_binding",
                &self
                    .first_owner_install_certificate
                    .as_ref()
                    .map(|certificate| certificate.installation_binding().digest())
                    .unwrap_or("[ASSEMBLY-INCOMPLETE]"),
            )
            .field("request_tag", &"[DERIVED-FROM-TLS-CHANNEL]")
            .field("attestation_authority", &self.pins.authority_id)
            .field("role_contract", &"[RECEIPT-BOUND]")
            .finish()
    }
}

/// The sole production DDL capability. It can be minted only by consuming the
/// pending target and verifying one signed, nonce-bound response for the exact
/// already-open PostgreSQL session. Retaining the production boundary and the
/// opaque proof makes freshness rechecks mandatory immediately before DDL.
pub(crate) struct VerifiedProductionMigrationExecution {
    boundary: Box<VerifiedProductionBoundary>,
    role_contract: crate::database::MigrationRoleContract,
    expected_migration_inventory_digest: String,
    verified_infrastructure: VerifiedPostgresqlInfrastructureAttestation,
    first_owner_installation_binding: crate::first_owner_runtime::FirstOwnerInstallationBinding,
    first_owner_install_certificate:
        Option<crate::first_owner_runtime::VerifiedFirstOwnerInstallCertificate>,
}

/// Non-sensitive projection retained after a production migration commits.
///
/// This deliberately excludes the signed response, signature, public key,
/// database identity preimage, storage-binding preimages, session preimage,
/// network addresses, and distinguished names. The retained digests and
/// authority/profile counters are sufficient to correlate completion with the
/// independently verified attestation without turning durable inventory into
/// an alternate disclosure surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProductionMigrationCompletionEvidence {
    authority_id: String,
    authority_epoch: u64,
    authority_revision: u64,
    attestation_profile_id: String,
    attestation_profile_version: u64,
    attestation_profile_digest: String,
    measurement_sequence: u64,
    response_digest: String,
    session_binding_digest: String,
    database_identity_digest: String,
    storage_binding_digest: String,
}

impl ProductionMigrationCompletionEvidence {
    pub(crate) fn authority_id(&self) -> &str {
        &self.authority_id
    }

    pub(crate) fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    pub(crate) fn authority_revision(&self) -> u64 {
        self.authority_revision
    }

    pub(crate) fn attestation_profile_id(&self) -> &str {
        &self.attestation_profile_id
    }

    pub(crate) fn attestation_profile_version(&self) -> u64 {
        self.attestation_profile_version
    }

    pub(crate) fn attestation_profile_digest(&self) -> &str {
        &self.attestation_profile_digest
    }

    pub(crate) fn measurement_sequence(&self) -> u64 {
        self.measurement_sequence
    }

    pub(crate) fn response_digest(&self) -> &str {
        &self.response_digest
    }

    pub(crate) fn session_binding_digest(&self) -> &str {
        &self.session_binding_digest
    }

    pub(crate) fn database_identity_digest(&self) -> &str {
        &self.database_identity_digest
    }

    pub(crate) fn storage_binding_digest(&self) -> &str {
        &self.storage_binding_digest
    }
}

impl fmt::Debug for VerifiedProductionMigrationExecution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedProductionMigrationExecution")
            .field(
                "expected_migration_inventory_digest",
                &self.expected_migration_inventory_digest,
            )
            .field("role_contract", &"[RECEIPT-BOUND]")
            .field("verified_infrastructure", &self.verified_infrastructure)
            .field(
                "first_owner_installation_binding",
                &self.first_owner_installation_binding.digest(),
            )
            .finish()
    }
}

impl VerifiedProductionMigrationExecution {
    pub(crate) fn ensure_fresh(&self, now: DateTime<Utc>) -> Result<(), String> {
        ensure_production_migration_execution_before_expiry(now, self.valid_until())?;
        let trusted_now = trusted_time_point(now);
        self.boundary.ensure_fresh(trusted_now)?;
        self.verified_infrastructure
            .verify_integrity()
            .map_err(|error| {
                format!(
                    "verified PostgreSQL-infrastructure proof lost integrity before DDL: {error}"
                )
            })?;
        let challenge =
            runtime_admission::exact_challenge(self.boundary.as_ref(), GuardId::DurablePostgresql)
                .map_err(|error| {
                    format!(
                "verified PostgreSQL-infrastructure proof lost its exact runtime challenge: {error}"
            )
                })?;
        let RuntimeGuardExpectedValue::DurablePostgresql {
            database_provider,
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
        } = challenge.expected_value()
        else {
            return Err(
                "verified PostgreSQL-infrastructure proof no longer has a DurablePostgresql challenge"
                    .into(),
            );
        };
        if self.verified_infrastructure.deployment_id()
            != self.boundary.deployed_workload.deployment_id()
            || self.verified_infrastructure.trust_domain_id()
                != self.boundary.deployed_workload.trust_domain_id()
            || self.verified_infrastructure.workload_id()
                != self.boundary.deployed_workload.workload_id()
            || self.verified_infrastructure.source_revision()
                != self.boundary.conformance.source_revision()
            || self.verified_infrastructure.artifact_digest()
                != self.boundary.deployed_workload.oci_subject_digest()
            || self
                .verified_infrastructure
                .workload_instance_binding_digest()
                != self
                    .boundary
                    .deployed_workload
                    .workload_instance_binding_digest()
            || self.verified_infrastructure.requirement_digest() != challenge.requirement_digest()
            || self.verified_infrastructure.challenge_binding_digest()
                != challenge.challenge_binding_digest()
            || self.verified_infrastructure.database_provider() != *database_provider
            || self.verified_infrastructure.server_major_version() != *server_major_version
            || self.verified_infrastructure.attestation_profile_id()
                != attestation_profile_id.as_str()
            || self.verified_infrastructure.attestation_profile_version()
                != *attestation_profile_version
            || self.verified_infrastructure.attestation_profile_digest()
                != attestation_profile_digest.as_str()
            || self.verified_infrastructure.provider_route_binding_digest()
                != provider_route_binding_digest.as_str()
            || self.verified_infrastructure.database_identity_digest()
                != database_identity_digest.as_str()
            || self.verified_infrastructure.storage_binding_digest()
                != storage_binding_digest.as_str()
            || self.verified_infrastructure.migration_inventory_digest()
                != migration_inventory_digest.as_str()
            || self.verified_infrastructure.application_role() != application_role.as_str()
            || self.verified_infrastructure.migration_role() != migration_role.as_str()
            || self.verified_infrastructure.session_purpose() != PostgresqlSessionPurpose::Migration
        {
            return Err(
                "verified PostgreSQL-infrastructure proof differs from the retained production boundary"
                    .into(),
            );
        }
        self.verified_infrastructure
            .ensure_fresh(trusted_now)
            .map_err(|error| {
                format!("verified PostgreSQL-infrastructure proof is stale before DDL: {error}")
            })?;
        validate_first_owner_migration_binding(
            self.boundary.as_ref(),
            &self.first_owner_installation_binding,
        )?;
        if let Some(certificate) = self.first_owner_install_certificate.as_ref() {
            certificate.readback_expectation().map_err(|error| {
                format!(
                    "verified first-owner installation certificate lost integrity before DDL: {error}"
                )
            })?;
        }
        Ok(())
    }

    pub(crate) fn role_contract(&self) -> &crate::database::MigrationRoleContract {
        &self.role_contract
    }

    pub(crate) fn expected_migration_inventory_digest(&self) -> &str {
        &self.expected_migration_inventory_digest
    }

    /// Exclusive upper bound for the retained signed infrastructure proof.
    /// Callers may use it only to shorten an already-bounded migration run;
    /// `ensure_fresh` remains the sole DDL freshness decision.
    pub(crate) fn valid_until(&self) -> DateTime<Utc> {
        self.verified_infrastructure.valid_until()
    }

    /// Project the independently verified proof into the narrow durable
    /// evidence stored with a successfully committed migration inventory.
    pub(crate) fn completion_evidence(&self) -> ProductionMigrationCompletionEvidence {
        ProductionMigrationCompletionEvidence {
            authority_id: self.verified_infrastructure.authority_id().to_string(),
            authority_epoch: self.verified_infrastructure.authority_epoch(),
            authority_revision: self.verified_infrastructure.authority_revision(),
            attestation_profile_id: self
                .verified_infrastructure
                .attestation_profile_id()
                .to_string(),
            attestation_profile_version: self.verified_infrastructure.attestation_profile_version(),
            attestation_profile_digest: self
                .verified_infrastructure
                .attestation_profile_digest()
                .to_string(),
            measurement_sequence: self.verified_infrastructure.measurement_sequence(),
            response_digest: self.verified_infrastructure.response_digest().to_string(),
            session_binding_digest: self
                .verified_infrastructure
                .session_binding_digest()
                .to_string(),
            database_identity_digest: self
                .verified_infrastructure
                .database_identity_digest()
                .to_string(),
            storage_binding_digest: self
                .verified_infrastructure
                .storage_binding_digest()
                .to_string(),
        }
    }

    pub(crate) fn verified_infrastructure(&self) -> &VerifiedPostgresqlInfrastructureAttestation {
        &self.verified_infrastructure
    }

    pub(crate) fn first_owner_installation_binding(
        &self,
    ) -> &crate::first_owner_runtime::FirstOwnerInstallationBinding {
        &self.first_owner_installation_binding
    }

    /// Exclusive certificate-expiry fence for a fresh installation
    /// transaction. Lost-COMMIT reconciliation deliberately remains timeless.
    pub(crate) fn first_owner_installation_valid_until(&self) -> DateTime<Utc> {
        self.first_owner_installation_binding
            .installation_valid_until()
    }

    pub(crate) fn ensure_first_owner_installation_fresh(
        &self,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        if now >= self.first_owner_installation_valid_until() {
            Err(
                "first-owner installation capability expired before the atomic transaction committed"
                    .into(),
            )
        } else {
            validate_first_owner_migration_binding(
                self.boundary.as_ref(),
                &self.first_owner_installation_binding,
            )
        }
    }

    /// Build the read-only reconciliation witness without consuming the
    /// one-shot write authority. This is the only first-owner operation used
    /// on the lost-COMMIT branch.
    pub(crate) fn first_owner_readback_expectation(
        &self,
    ) -> Result<
        crate::first_owner_runtime::FirstOwnerInstallationReadbackExpectation,
        crate::first_owner_runtime::FirstOwnerRuntimeError,
    > {
        self.first_owner_install_certificate
            .as_ref()
            .ok_or(crate::first_owner_runtime::FirstOwnerRuntimeError::ReceiptBindingInvalid)?
            .readback_expectation()
    }

    /// Consume the certificate exactly once and mint the narrow SQL-writer
    /// authority at the selected migration boundary.
    pub(crate) fn take_first_owner_installation_authority(
        &mut self,
        trusted_now: ConformanceTrustedTimeWindow,
    ) -> Result<crate::first_owner_runtime::VerifiedFirstOwnerInstallationAuthority, String> {
        validate_first_owner_migration_binding(
            self.boundary.as_ref(),
            &self.first_owner_installation_binding,
        )?;
        self.first_owner_install_certificate
            .take()
            .ok_or_else(|| {
                "first-owner installation authority was requested more than once".to_string()
            })?
            .authorize_installation(trusted_now)
            .map_err(|error| format!("first-owner installation capability is not active: {error}"))
    }

    pub(crate) fn session_binding(&self) -> &PostgresqlSessionBinding {
        self.verified_infrastructure.session_binding()
    }
}

fn validate_first_owner_migration_binding(
    boundary: &VerifiedProductionBoundary,
    binding: &crate::first_owner_runtime::FirstOwnerInstallationBinding,
) -> Result<(), String> {
    let challenge = runtime_admission::exact_challenge(boundary, GuardId::FirstOwnerPathClosed)
        .map_err(|error| {
            format!("production migration lost its exact first-owner challenge: {error}")
        })?;
    let RuntimeGuardExpectedValue::FirstOwnerPathClosed {
        deployment_id,
        state_contract_version,
        authority_namespace_digest,
        closure_record_digest,
    } = challenge.expected_value()
    else {
        return Err(
            "production migration first-owner challenge changed to an unexpected guard kind".into(),
        );
    };
    if binding.deployment_id() != deployment_id
        || *state_contract_version
            != ryuki_core::security_profile::FIRST_OWNER_STATE_CONTRACT_VERSION
        || binding.authority_namespace_digest() != authority_namespace_digest
        || binding.closure_record_digest() != closure_record_digest
        || binding.requirement_digest() != challenge.requirement_digest()
        || binding.challenge_binding_digest() != challenge.challenge_binding_digest()
    {
        return Err(
            "verified first-owner installation binding differs from the retained production boundary"
                .into(),
        );
    }
    Ok(())
}

fn ensure_production_migration_execution_before_expiry(
    now: DateTime<Utc>,
    valid_until: DateTime<Utc>,
) -> Result<(), String> {
    if now >= valid_until {
        Err(
            "verified PostgreSQL-infrastructure proof cannot authorize DDL at or after its exclusive valid_until"
                .into(),
        )
    } else {
        Ok(())
    }
}

/// Apply-only admission state. Both variants are issued only after the
/// deployment security root is loaded. Non-production is executable with its
/// configured local role contract; production retains and rechecks the sealed
/// workload-bound prerequisite and remains non-executable until one exact
/// retained database session receives a valid independent target attestation.
pub(crate) enum VerifiedApplyOnlyMigrationAdmission {
    NonProduction {
        role_contract: crate::database::MigrationRoleContract,
        expected_migration_inventory_digest: String,
    },
    Production(Box<PendingProductionMigrationTarget>),
}

impl fmt::Debug for VerifiedApplyOnlyMigrationAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonProduction {
                expected_migration_inventory_digest,
                ..
            } => formatter
                .debug_struct("VerifiedApplyOnlyMigrationAdmission::NonProduction")
                .field(
                    "expected_migration_inventory_digest",
                    expected_migration_inventory_digest,
                )
                .field("role_contract", &"[CONFIGURED]")
                .finish(),
            Self::Production(admission) => admission.fmt(formatter),
        }
    }
}

impl VerifiedApplyOnlyMigrationAdmission {
    /// Consume the one-shot admission immediately before opening the isolated
    /// migration connection. Production yields only a pending target whose
    /// nonce-derived application name must be installed on that connection;
    /// it is not DDL authority.
    pub(crate) fn into_database_preflight(
        self,
        now: DateTime<Utc>,
    ) -> Result<MigrationDatabasePreflight, String> {
        match self {
            Self::NonProduction {
                role_contract,
                expected_migration_inventory_digest,
            } => Ok(MigrationDatabasePreflight::NonProduction {
                role_contract,
                expected_migration_inventory_digest,
            }),
            Self::Production(admission) => {
                admission.boundary.ensure_fresh(trusted_time_point(now))?;
                Ok(MigrationDatabasePreflight::Production(admission))
            }
        }
    }
}

pub(crate) enum MigrationDatabasePreflight {
    NonProduction {
        role_contract: crate::database::MigrationRoleContract,
        expected_migration_inventory_digest: String,
    },
    Production(Box<PendingProductionMigrationTarget>),
}

impl fmt::Debug for MigrationDatabasePreflight {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonProduction {
                expected_migration_inventory_digest,
                ..
            } => formatter
                .debug_struct("MigrationDatabasePreflight::NonProduction")
                .field(
                    "expected_migration_inventory_digest",
                    expected_migration_inventory_digest,
                )
                .field("role_contract", &"[CONFIGURED]")
                .finish(),
            Self::Production(pending) => pending.fmt(formatter),
        }
    }
}

impl PendingProductionMigrationTarget {
    /// Fresh context consumed by the TLS exporter. It cannot be turned into
    /// an application name until the exact direct TLS channel is measured.
    pub(crate) fn tls_exporter_context(&self) -> &[u8; 32] {
        &self.request_nonce
    }

    pub(crate) fn database_provider_and_route_digest(
        &self,
    ) -> Result<(ProductionDatabaseProvider, &str), String> {
        let RuntimeGuardExpectedValue::DurablePostgresql {
            database_provider,
            provider_route_binding_digest,
            ..
        } = &self.receipt_bound_database_target
        else {
            return Err(
                "production migration target no longer carries a DurablePostgresql expectation"
                    .into(),
            );
        };
        Ok((*database_provider, provider_route_binding_digest))
    }

    /// Derive the request tag from the one-shot nonce and the exact caller-
    /// observed exporter-bound TLS channel.
    pub(crate) fn request_tag_for_channel(
        &self,
        channel: &PostgresqlTlsChannelBinding,
    ) -> Result<String, String> {
        let (_, expected_route_digest) = self.database_provider_and_route_digest()?;
        if channel.provider_route_binding_digest != expected_route_digest {
            return Err(
                "observed PostgreSQL TLS channel differs from the receipt-bound provider route"
                    .into(),
            );
        }
        let channel_digest = postgresql_tls_channel_binding_digest(channel)
            .map_err(|error| format!("PostgreSQL TLS channel binding is invalid: {error}"))?;
        Ok(postgresql_attestation_request_tag(
            &self.request_nonce,
            &channel_digest,
        ))
    }

    /// Receipt-bound role names are exposed only for connection establishment
    /// and role attestation. DDL requires the later execution capability.
    pub(crate) fn migration_role_contract(&self) -> &crate::database::MigrationRoleContract {
        &self.role_contract
    }

    /// Bind one independently signed infrastructure measurement to the exact
    /// retained PostgreSQL session. The pending capability and nonce are
    /// consumed, preventing retry or proof reuse against a second connection.
    pub(crate) async fn attest_exact_session(
        self,
        session_binding: PostgresqlSessionBinding,
        requested_at: DateTime<Utc>,
    ) -> Result<VerifiedProductionMigrationExecution, String> {
        self.boundary
            .ensure_fresh(trusted_time_point(requested_at))?;
        {
            let challenge = runtime_admission::exact_challenge(
                self.boundary.as_ref(),
                GuardId::DurablePostgresql,
            )
            .map_err(|error| {
                format!(
                    "production migration target lost its exact DurablePostgresql challenge: {error}"
                )
            })?;
            if challenge.requirement_digest() != self.requirement_digest
                || challenge.challenge_binding_digest() != self.challenge_binding_digest
                || challenge.expected_value() != &self.receipt_bound_database_target
            {
                return Err(
                    "production migration target differs from its retained workload-bound database challenge"
                        .into(),
                );
            }
        }
        let request_tag = self.request_tag_for_channel(&session_binding.tls_channel_binding)?;
        if session_binding.application_name != request_tag {
            return Err(
                "PostgreSQL session application_name differs from the one-shot attestation request tag"
                    .into(),
            );
        }
        let first_owner_install_certificate = self
            .first_owner_install_certificate
            .as_ref()
            .ok_or_else(|| {
                "production migration target has no verified first-owner installation certificate"
                    .to_string()
            })?;
        validate_first_owner_migration_binding(
            self.boundary.as_ref(),
            first_owner_install_certificate.installation_binding(),
        )?;
        first_owner_install_certificate
            .readback_expectation()
            .map_err(|error| {
                format!(
                    "production migration first-owner certificate lost integrity before target attestation: {error}"
                )
            })?;
        let RuntimeGuardExpectedValue::DurablePostgresql {
            database_provider,
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
        } = &self.receipt_bound_database_target
        else {
            return Err(
                "production migration target no longer carries a DurablePostgresql expectation"
                    .into(),
            );
        };
        if self.pins.attestation_profile_id.as_str() != attestation_profile_id.as_str()
            || self.pins.attestation_profile_version != *attestation_profile_version
            || self.pins.attestation_profile_digest.as_str() != attestation_profile_digest.as_str()
        {
            return Err(
                "PostgreSQL-infrastructure authority profile pins differ from the receipt-bound runtime guard"
                    .into(),
            );
        }
        let public_key = decode_postgresql_infrastructure_authority_public_key(&self.pins)?;
        let authority = PostgresqlInfrastructureAuthorityAnchor {
            authority_id: &self.pins.authority_id,
            key_id: &self.pins.key_id,
            public_key: &public_key,
            public_key_fingerprint: &self.pins.public_key_fingerprint,
            minimum_authority_epoch: self.pins.minimum_authority_epoch,
            attestation_profile_id: &self.pins.attestation_profile_id,
            attestation_profile_version: self.pins.attestation_profile_version,
            attestation_profile_digest: &self.pins.attestation_profile_digest,
        };
        let request = build_postgresql_infrastructure_attestation_request(
            ExpectedPostgresqlInfrastructure {
                deployment_id: self.boundary.deployed_workload.deployment_id(),
                trust_domain_id: self.boundary.deployed_workload.trust_domain_id(),
                workload_id: self.boundary.deployed_workload.workload_id(),
                source_revision: self.boundary.conformance.source_revision(),
                artifact_digest: self.boundary.deployed_workload.oci_subject_digest(),
                workload_instance_binding_digest: self
                    .boundary
                    .deployed_workload
                    .workload_instance_binding_digest(),
                requirement_digest: &self.requirement_digest,
                challenge_binding_digest: &self.challenge_binding_digest,
                database_provider: *database_provider,
                server_major_version: *server_major_version,
                provider_route_binding_digest,
                database_identity_digest,
                storage_binding_digest,
                migration_inventory_digest,
                application_role,
                migration_role,
                session_purpose: PostgresqlSessionPurpose::Migration,
                session_binding: &session_binding,
            },
            authority,
            self.request_nonce,
            requested_at,
        )
        .map_err(|error| {
            format!("cannot build exact PostgreSQL-infrastructure attestation request: {error}")
        })?;
        if request.request_tag() != request_tag {
            return Err(
                "PostgreSQL-infrastructure request tag changed after exact session binding".into(),
            );
        }
        let transport = UnixAuthorityTransport::new(
            self.pins.socket_path.clone(),
            AuthorityTransportDeadlines {
                connect: POSTGRESQL_INFRASTRUCTURE_TRANSPORT_PHASE_DEADLINE,
                write: POSTGRESQL_INFRASTRUCTURE_TRANSPORT_PHASE_DEADLINE,
                read: POSTGRESQL_INFRASTRUCTURE_TRANSPORT_PHASE_DEADLINE,
            },
            AuthorityTransportBounds {
                max_request_bytes: MAX_POSTGRESQL_INFRASTRUCTURE_REQUEST_BYTES,
                max_response_bytes: MAX_POSTGRESQL_INFRASTRUCTURE_RESPONSE_BYTES,
            },
            AuthorityTransportHardLimits {
                max_socket_path_bytes: MAX_AUTHORITY_SOCKET_PATH_BYTES,
                max_phase_deadline: MAX_POSTGRESQL_INFRASTRUCTURE_TRANSPORT_PHASE_DEADLINE,
                max_request_bytes: MAX_POSTGRESQL_INFRASTRUCTURE_REQUEST_BYTES,
                max_response_bytes: MAX_POSTGRESQL_INFRASTRUCTURE_RESPONSE_BYTES,
            },
        )
        .map_err(|error| {
            format!("cannot configure bounded PostgreSQL-infrastructure transport: {error}")
        })?;
        let raw_response = transport
            .exchange(request.as_bytes())
            .await
            .map_err(|error| {
                format!("PostgreSQL-infrastructure attestation exchange failed: {error}")
            })?;
        let verified_at = Utc::now();
        self.boundary
            .ensure_fresh(trusted_time_point(verified_at))?;
        let verified_infrastructure = verify_postgresql_infrastructure_attestation(
            request,
            &raw_response,
            authority,
            trusted_time_point(verified_at),
        )
        .map_err(|error| {
            format!("PostgreSQL-infrastructure attestation verification failed: {error}")
        })?;
        if verified_infrastructure.session_binding() != &session_binding {
            return Err(
                "verified PostgreSQL-infrastructure response substituted the measured session"
                    .into(),
            );
        }
        let execution = VerifiedProductionMigrationExecution {
            boundary: self.boundary,
            role_contract: self.role_contract,
            expected_migration_inventory_digest: self.expected_migration_inventory_digest,
            verified_infrastructure,
            first_owner_installation_binding: self
                .first_owner_install_certificate
                .as_ref()
                .expect("verified above")
                .installation_binding()
                .clone(),
            first_owner_install_certificate: self.first_owner_install_certificate,
        };
        execution.ensure_fresh(verified_at)?;
        Ok(execution)
    }
}

fn verify_production_migration_admission(
    boundary: Box<VerifiedProductionBoundary>,
    mode: crate::database::MigrationStartupMode,
    pins: StartupPostgresqlInfrastructureAttestationPins,
    first_owner_install_certificate:
        crate::first_owner_runtime::VerifiedFirstOwnerInstallCertificate,
    now: DateTime<Utc>,
) -> Result<PendingProductionMigrationTarget, String> {
    let embedded_digest = crate::database::embedded_migration_inventory_digest()
        .map_err(|error| format!("cannot derive the embedded migration inventory: {error}"))?;
    let mut admission = verify_production_migration_admission_with_inventory_digest(
        pins,
        boundary,
        mode,
        now,
        &embedded_digest,
    )?;
    validate_first_owner_migration_binding(
        admission.boundary.as_ref(),
        first_owner_install_certificate.installation_binding(),
    )?;
    admission.first_owner_install_certificate = Some(first_owner_install_certificate);
    Ok(admission)
}

fn verify_production_migration_admission_with_inventory_digest(
    pins: StartupPostgresqlInfrastructureAttestationPins,
    boundary: Box<VerifiedProductionBoundary>,
    mode: crate::database::MigrationStartupMode,
    now: DateTime<Utc>,
    embedded_digest: &str,
) -> Result<PendingProductionMigrationTarget, String> {
    if mode != crate::database::MigrationStartupMode::ApplyOnly {
        return Err("production migration admission requires exact apply-only mode".into());
    }
    boundary.ensure_fresh(trusted_time_point(now))?;
    let challenge =
        runtime_admission::exact_challenge(boundary.as_ref(), GuardId::DurablePostgresql).map_err(
            |error| format!("production migration admission lost its database guard: {error}"),
        )?;
    let receipt_bound_database_target = challenge.expected_value().clone();
    let RuntimeGuardExpectedValue::DurablePostgresql {
        attestation_profile_id,
        attestation_profile_version,
        attestation_profile_digest,
        application_role,
        migration_role,
        migration_inventory_digest,
        ..
    } = &receipt_bound_database_target
    else {
        return Err(
            "production migration admission received a non-PostgreSQL database guard value".into(),
        );
    };
    if pins.attestation_profile_id.as_str() != attestation_profile_id.as_str()
        || pins.attestation_profile_version != *attestation_profile_version
        || pins.attestation_profile_digest.as_str() != attestation_profile_digest.as_str()
    {
        return Err(
            "PostgreSQL-infrastructure startup profile pins differ from the receipt-bound runtime guard"
                .into(),
        );
    }
    let role_contract = crate::database::MigrationRoleContract::from_receipt_bound_roles(
        migration_role,
        application_role,
    )?;
    if embedded_digest != migration_inventory_digest {
        return Err(
            "embedded migrations differ from the receipt-bound production inventory".into(),
        );
    }
    let expected_migration_inventory_digest = migration_inventory_digest.to_owned();
    let requirement_digest = challenge.requirement_digest().to_owned();
    let challenge_binding_digest = challenge.challenge_binding_digest().to_owned();
    let mut request_nonce = [0u8; 32];
    OsRng.try_fill_bytes(&mut request_nonce).map_err(|_| {
        "cannot generate the one-shot PostgreSQL-infrastructure attestation nonce".to_string()
    })?;
    if request_nonce.iter().all(|byte| *byte == 0) {
        return Err(
            "operating-system randomness produced an invalid PostgreSQL-infrastructure attestation nonce"
                .into(),
        );
    }
    Ok(PendingProductionMigrationTarget {
        boundary,
        role_contract,
        receipt_bound_database_target,
        first_owner_install_certificate: None,
        expected_migration_inventory_digest,
        requirement_digest,
        challenge_binding_digest,
        pins,
        request_nonce,
    })
}

/// Value-free scope authority for typed production secret resolution. Every
/// field comes from the sealed workload/profile identity; request handlers
/// cannot substitute scope from a stored SecretRef or caller input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProductionSecretResolutionAuthority {
    deployment_id: String,
    trust_domain_id: String,
    workload_id: String,
    authority_epoch: u64,
    tenant_id: Option<String>,
}

impl ProductionSecretResolutionAuthority {
    pub(crate) fn deployment_id(&self) -> &str {
        &self.deployment_id
    }

    pub(crate) fn trust_domain_id(&self) -> &str {
        &self.trust_domain_id
    }

    pub(crate) fn workload_id(&self) -> &str {
        &self.workload_id
    }

    pub(crate) fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    pub(crate) fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }
}

#[derive(Debug)]
pub(crate) struct SecurityContractContext {
    pub(crate) profile: DeploymentSecurityProfile,
    pub(crate) profile_digest: String,
    pub(crate) contract_root: PathBuf,
    pub(crate) profile_path: PathBuf,
    /// Production owns one indivisible proof aggregate. Non-production cannot
    /// retain detached production proof parts.
    pub(crate) conformance_state: ConformanceState,
    /// The secure-cookie production guard witness. It owns an Arc clone of the
    /// exact retained policy allocation shared with every API cookie consumer.
    /// The field remains `None` for non-production and until serving startup
    /// has loaded and validated the immutable application configuration.
    verified_secure_cookie_guard: Option<runtime_admission::VerifiedSecureCookieRuntimeWitness>,
    /// Independently signed public DNS/TLS/ingress observation for the exact
    /// workload instance sealed into the production boundary.
    verified_https_public_urls_guard:
        Option<runtime_admission::VerifiedHttpsPublicUrlsRuntimeWitness>,
    /// Live ApprovedSecretProvider witness retaining the exact authenticated
    /// runtime, binding Arc and bytes, measured operational allocation, and
    /// current provider lease that satisfied the receipt-bound D/P/R/I chain.
    verified_approved_secret_provider_guard:
        Option<runtime_admission::VerifiedApprovedSecretProviderRuntimeWitness>,
    /// Exact live Entra D/P/Q/R/I composition and every retained authority
    /// allocation that satisfied NonDevelopmentAuthenticator.
    verified_non_development_authenticator_guard:
        Option<runtime_admission::VerifiedNonDevelopmentAuthenticatorRuntimeWitness>,
    /// Live DurablePostgresql witness retaining the exact unpublished,
    /// channel-bound application pool and the same independently signed
    /// infrastructure proof used by its local receipt comparison.
    verified_durable_postgresql_guard:
        Option<runtime_admission::VerifiedDurablePostgresqlRuntimeWitness>,
    /// Independently authenticated permanent first-owner closure, atomic audit
    /// evidence, and five initial privileged-domain assignments measured
    /// through the exact retained DurablePostgresql runtime.
    verified_first_owner_path_closed_guard:
        Option<runtime_admission::VerifiedFirstOwnerPathClosedRuntimeWitness>,
    /// Exact active security-limit document selected by the deployment root.
    /// Runtime owners receive only opaque policies resolved from this retained
    /// authority and the verified provider D document.
    verified_security_limit_profile: Arc<VerifiedSecurityLimitProfile>,
    /// Active provider id -> immutable, content-addressed configuration.
    pub(crate) active_providers: BTreeMap<String, ActiveProviderConfiguration>,
    /// Lossless, non-authoritative projection retained for independent
    /// deployment/provider applicability derivation. Authority comes from the
    /// authenticated registry and later runtime proofs, never from this claim.
    pub(crate) provider_registry_applicability: ActiveProviderRegistryApplicabilityClaim,
    /// Semantically validated exact route/action/resource/resolver projection
    /// for the first permit-bearing repository seam.
    request_read_registry: RequestReadRegistryBinding,
}

#[derive(Debug, Clone)]
struct RequestReadRegistryBinding {
    registry_version: u64,
    maximum_authority_digest: String,
}

/// Exact, non-secret security-contract projection consumed by the
/// request-read credential/permit adapter. Every field comes from retained,
/// validated startup documents; it contains no runtime credential material.
#[derive(Debug, Clone)]
pub(crate) struct RequestReadSecurityNamespace {
    pub(crate) deployment_id: String,
    pub(crate) trust_domain_id: String,
    pub(crate) tenant_id: Option<String>,
    pub(crate) security_profile: SecurityProfile,
    pub(crate) profile_digest: String,
    pub(crate) policy_version: u64,
    pub(crate) action_registry_version: u64,
    pub(crate) action_registry_digest: String,
    pub(crate) maximum_authority_version: u64,
    pub(crate) maximum_authority_digest: String,
    pub(crate) provider_id: String,
    pub(crate) provider_configuration_version: u64,
    pub(crate) provider_lifecycle_version: u64,
    pub(crate) credential_source_provider: String,
}

#[derive(Debug)]
struct PreparedSecurityContract {
    profile: DeploymentSecurityProfile,
    profile_raw_bytes: Box<[u8]>,
    profile_digest: String,
    contract_root: PathBuf,
    profile_path: PathBuf,
    documents: BTreeMap<String, Value>,
    raw_document_bytes: BTreeMap<String, Vec<u8>>,
    reference_document_digests: BTreeMap<String, String>,
    verified_security_limit_profile: Arc<VerifiedSecurityLimitProfile>,
    active_providers: BTreeMap<String, ActiveProviderConfiguration>,
    provider_registry_applicability: ActiveProviderRegistryApplicabilityClaim,
    conformance_registry_lineage: Option<ValidatedConformanceRegistryLineage>,
    production_build_manifest: Option<PinnedProductionBuildManifest>,
}

/// Deliberately false until a live, one-use Kubernetes render-admission proof
/// is verified by the migration process itself. Keeping this as a runtime
/// fence preserves compilation and testability of the lower-level protocol
/// without making the offline manifest validator an execution authority.
#[inline(never)]
fn production_migration_runtime_render_admission_is_implemented() -> bool {
    false
}

impl SecurityContractContext {
    pub(crate) fn is_production(&self) -> bool {
        self.profile.security_profile.is_production()
    }

    /// Derive the one immutable namespace that every control-plane live grant
    /// must carry. Grant scope is deployment authority, not request input: it
    /// comes only from the startup-admitted security profile and refuses a
    /// federated/ambiguous topology until an explicit domain-selection
    /// authority exists.
    pub(crate) fn control_plane_grant_scope(
        &self,
    ) -> Result<ryuki_protocol::ControlPlaneGrantScope, String> {
        control_plane_grant_scope_from_profile(&self.profile)
    }

    fn select_entra_authenticator_provider(
        &self,
        ambiguity_context: &str,
    ) -> Result<&ActiveProviderConfiguration, String> {
        let candidates = self
            .active_providers
            .values()
            .filter(|provider| {
                provider.kind == "oidc"
                    && provider.capability_descriptor.adapter_kind == "auth.entra-id"
            })
            .collect::<Vec<_>>();
        match candidates.as_slice() {
            [provider] => Ok(*provider),
            [] => Err(
                "no active Entra OIDC provider has an exact authenticator runtime binding".into(),
            ),
            _ => Err(format!(
                "active Entra OIDC provider selection is ambiguous for {ambiguity_context}"
            )),
        }
    }

    /// Resolve the one active Entra authenticator authority as an indivisible
    /// D/P/Q/provider/limit bundle. This remains declaration authority; the
    /// runtime must independently measure its retained allocation before any
    /// production guard or session provenance can be sealed.
    pub(crate) fn resolved_entra_authenticator_authority(
        &self,
        browser_required: bool,
    ) -> Result<Arc<ResolvedEntraAuthenticatorAuthority>, String> {
        if self.profile.tenancy_mode != TenancyMode::SingleTenant {
            return Err(
                "Entra authenticator authority requires an exact tenant for multi-tenant profiles"
                    .into(),
            );
        }
        let provider = self.select_entra_authenticator_provider("authenticator authority")?;
        if !self
            .profile
            .trust_topology
            .trust_domain_ids
            .contains(&provider.trust_domain_id)
        {
            return Err(
                "active Entra provider trust domain is outside the deployment topology".into(),
            );
        }
        if let ConformanceState::Production(boundary) = &self.conformance_state {
            if self.profile.deployment_id != boundary.conformance.deployment_id()
                || provider.trust_domain_id != boundary.conformance.trust_domain_id()
            {
                return Err(
                    "active Entra authority differs from the sealed production identity".into(),
                );
            }
        } else if self.profile.security_profile.is_production() {
            return Err("production Entra authority has no sealed boundary".into());
        }
        let runtime_binding = Arc::clone(
            provider
                .verified_authenticator_runtime_binding()
                .ok_or_else(|| {
                    "active Entra OIDC provider has no exact authenticator runtime binding"
                        .to_string()
                })?,
        );
        let security_limit_profile = Arc::clone(&self.verified_security_limit_profile);
        let bearer_limits = ResolvedAuthenticatorBearerLimits::seal(
            Arc::clone(&security_limit_profile),
            Arc::clone(&runtime_binding),
            &provider.provider_id,
        )?;
        let has_browser_path = runtime_binding
            .document
            .credential_paths
            .iter()
            .any(|path| path.credential_profile.token_profile == "oidc-id-token");
        let browser_limits = if browser_required || has_browser_path {
            Some(ResolvedAuthenticatorBrowserLimits::seal(
                Arc::clone(&security_limit_profile),
                Arc::clone(&runtime_binding),
                &provider.provider_id,
            )?)
        } else {
            None
        };
        ResolvedEntraAuthenticatorAuthority::seal(
            &self.profile.deployment_id,
            None,
            security_limit_profile,
            provider,
            runtime_binding,
            bearer_limits,
            browser_limits,
        )
    }

    #[cfg(test)]
    pub(crate) fn verifies_security_limit_profile_integrity(&self) -> bool {
        self.verified_security_limit_profile
            .verify_integrity()
            .is_ok()
    }

    /// Resolve the single provider and namespace that admitted one
    /// request-read credential. Derived API tokens deliberately have no arm:
    /// their credential provider, audience, action grants, and lifecycle are
    /// not represented in the v1 provider registry and therefore fail closed.
    pub(crate) fn request_read_security_namespace(
        &self,
        auth_mode: &AuthMode,
        credential_provider: &str,
    ) -> Result<RequestReadSecurityNamespace, String> {
        let provider_matches_mode = match auth_mode {
            AuthMode::MockDryRun | AuthMode::StaticDryRun => {
                credential_provider == "development-fixture"
                    && self.profile.security_profile.admits_development_fixture()
            }
            // The canonical provider id is checked against the selected
            // registry configuration below. Transport/adapter aliases never
            // identify credential provenance.
            AuthMode::EntraId => true,
            AuthMode::Local => credential_provider == "local",
        };
        if !provider_matches_mode {
            return Err(format!(
                "credential provider {credential_provider} is not admitted by auth mode {}",
                auth_mode.as_str()
            ));
        }
        if self.profile.tenancy_mode != TenancyMode::SingleTenant {
            return Err(
                "request-read authority requires an exact tenant binding for multi-tenant profiles"
                    .into(),
            );
        }

        let selected = self.select_authentication_provider(auth_mode)?;
        if matches!(auth_mode, AuthMode::EntraId) && credential_provider != selected.provider_id {
            return Err(format!(
                "credential provider {credential_provider} does not match selected canonical provider {}",
                selected.provider_id
            ));
        }
        if selected.config_version == 0 || selected.active_lifecycle_record_version == 0 {
            return Err("request-read provider versions must be positive".into());
        }
        if self.profile.policy_version == 0
            || self.profile.action_resource_registry_ref.document_version == 0
            || self.request_read_registry.registry_version == 0
        {
            return Err("request-read authority versions must be positive".into());
        }
        validate_digest_pin("request-read deployment profile", &self.profile_digest)?;
        validate_digest_pin(
            "request-read action/resource registry",
            &self.profile.action_resource_registry_ref.content_digest,
        )?;
        validate_digest_pin(
            "request-read maximum authority",
            &self.request_read_registry.maximum_authority_digest,
        )?;
        if !self
            .profile
            .trust_topology
            .trust_domain_ids
            .contains(&selected.trust_domain_id)
        {
            return Err(
                "request-read provider trust domain is outside the deployment topology".into(),
            );
        }

        if let ConformanceState::Production(boundary) = &self.conformance_state {
            if self.profile.deployment_id != boundary.conformance.deployment_id()
                || selected.trust_domain_id != boundary.conformance.trust_domain_id()
            {
                return Err(
                    "request-read namespace differs from the sealed production boundary".into(),
                );
            }
        } else if self.profile.security_profile.is_production() {
            return Err("production request-read authority has no sealed boundary".into());
        }

        Ok(RequestReadSecurityNamespace {
            deployment_id: self.profile.deployment_id.clone(),
            trust_domain_id: selected.trust_domain_id.clone(),
            tenant_id: None,
            security_profile: self.profile.security_profile,
            profile_digest: self.profile_digest.clone(),
            policy_version: self.profile.policy_version,
            action_registry_version: self.request_read_registry.registry_version,
            action_registry_digest: self
                .profile
                .action_resource_registry_ref
                .content_digest
                .clone(),
            maximum_authority_version: self.request_read_registry.registry_version,
            maximum_authority_digest: self.request_read_registry.maximum_authority_digest.clone(),
            provider_id: selected.provider_id.clone(),
            provider_configuration_version: selected.config_version,
            provider_lifecycle_version: selected.active_lifecycle_record_version,
            credential_source_provider: credential_provider.to_string(),
        })
    }

    fn exact_production_secret_provider(
        &self,
    ) -> Result<
        (
            &ActiveProviderConfiguration,
            &Arc<VerifiedSecretProviderRuntimeBinding>,
        ),
        String,
    > {
        if !self.profile.security_profile.is_production() {
            return Err(
                "a production secret-provider runtime was requested outside production".into(),
            );
        }
        let ConformanceState::Production(boundary) = &self.conformance_state else {
            return Err("production startup has no sealed production-boundary proof".into());
        };
        let mut candidates = self
            .active_providers
            .values()
            .filter(|provider| provider.kind == "secret-service");
        let provider = candidates.next().ok_or_else(|| {
            "production startup has no active secret-service provider".to_string()
        })?;
        if candidates.next().is_some() {
            return Err(
                "production startup requires exactly one active secret-service provider".into(),
            );
        }
        let binding = provider
            .verified_secret_provider_runtime_binding()
            .ok_or_else(|| {
                "production secret-service provider has no exact verified runtime binding"
                    .to_string()
            })?;
        binding.verify_integrity()?;
        if binding.document.deployment_id != boundary.conformance.deployment_id()
            || binding.document.trust_domain_id != boundary.conformance.trust_domain_id()
            || binding.document.provider_id != provider.provider_id
            || binding.document.provider_configuration_version != provider.config_version
        {
            return Err(
                "production secret-service provider binding differs from the sealed production identity"
                    .into(),
            );
        }
        Ok((provider, binding))
    }

    /// Select the one exact production binding used to construct the runtime.
    /// Non-production never receives production secret-provider authority.
    pub(crate) fn verified_secret_provider_runtime_binding(
        &self,
    ) -> Result<Option<Arc<VerifiedSecretProviderRuntimeBinding>>, String> {
        if !self.profile.security_profile.is_production() {
            if self.verified_approved_secret_provider_guard.is_some() {
                return Err(
                    "non-production startup retained approved secret-provider authority".into(),
                );
            }
            return Ok(None);
        }
        let (_, binding) = self.exact_production_secret_provider()?;
        Ok(Some(Arc::clone(binding)))
    }

    pub(crate) fn production_secret_resolution_authority(
        &self,
    ) -> Result<ProductionSecretResolutionAuthority, String> {
        if self.profile.security_profile != SecurityProfile::Production {
            return Err("secret-resolution authority is production-only".into());
        }
        if self.profile.tenancy_mode != TenancyMode::SingleTenant {
            return Err(
                "the current production secret resolver requires single-tenant authority".into(),
            );
        }
        let ConformanceState::Production(boundary) = &self.conformance_state else {
            return Err("production startup has no sealed production-boundary proof".into());
        };
        if self.profile.deployment_id != boundary.deployed_workload.deployment_id()
            || boundary.deployed_workload.authority_epoch() == 0
        {
            return Err(
                "production secret-resolution scope differs from the sealed workload authority"
                    .into(),
            );
        }
        Ok(ProductionSecretResolutionAuthority {
            deployment_id: boundary.deployed_workload.deployment_id().to_owned(),
            trust_domain_id: boundary.deployed_workload.trust_domain_id().to_owned(),
            workload_id: boundary.deployed_workload.workload_id().to_owned(),
            authority_epoch: boundary.deployed_workload.authority_epoch(),
            tenant_id: None,
        })
    }

    pub(crate) fn validate_serving_checkpoint_freshness(
        &self,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        if !self.profile.security_profile.is_production() {
            if self.verified_durable_postgresql_guard.is_some()
                || self.verified_first_owner_path_closed_guard.is_some()
            {
                return Err(
                    "non-production serving startup retained DurablePostgresql or first-owner production authority"
                        .into(),
                );
            }
            return Ok(());
        }
        let ConformanceState::Production(boundary) = &self.conformance_state else {
            return Err(
                "production serving startup has no sealed production-boundary proof".into(),
            );
        };
        let trusted_now = trusted_time_point(now);
        boundary.ensure_fresh(trusted_now)?;
        let durable_postgresql_guard =
            self.verified_durable_postgresql_guard
                .as_ref()
                .ok_or_else(|| {
                    "production serving startup has no verified DurablePostgresql runtime guard"
                        .to_string()
                })?;
        runtime_admission::recheck_durable_postgresql_guard(
            boundary,
            durable_postgresql_guard,
            trusted_now,
        )
        .map_err(|error| {
            format!("DurablePostgresql runtime guard freshness recheck failed: {error}")
        })?;
        let first_owner_path_closed = self
            .verified_first_owner_path_closed_guard
            .as_ref()
            .ok_or_else(|| {
                "production serving startup has no verified first-owner-path-closed runtime guard"
                    .to_string()
            })?;
        runtime_admission::recheck_first_owner_path_closed_guard(
            boundary,
            &self.profile,
            durable_postgresql_guard,
            first_owner_path_closed,
            trusted_now,
        )
        .map_err(|error| {
            format!("first-owner-path-closed runtime guard freshness recheck failed: {error}")
        })?;
        if let Some(witness) = &self.verified_https_public_urls_guard {
            runtime_admission::recheck_https_public_urls_guard(boundary, witness, trusted_now)
                .map_err(|error| {
                    format!("https-public-urls runtime guard freshness recheck failed: {error}")
                })?;
        }
        if let Some(witness) = &self.verified_secure_cookie_guard {
            runtime_admission::recheck_secure_cookie_guard(boundary, witness, trusted_now)
                .map_err(|error| {
                    format!("secure-cookie runtime guard freshness recheck failed: {error}")
                })?;
        }
        if let Some(witness) = &self.verified_approved_secret_provider_guard {
            let (provider, _) = self.exact_production_secret_provider()?;
            runtime_admission::recheck_approved_secret_provider_guard(
                boundary,
                provider,
                witness,
                trusted_now,
            )
            .map_err(|error| {
                format!("approved-secret-provider runtime guard freshness recheck failed: {error}")
            })?;
        }
        if let Some(witness) = &self.verified_non_development_authenticator_guard {
            runtime_admission::recheck_non_development_authenticator_guard(
                boundary,
                witness,
                trusted_now,
            )
            .map_err(|error| {
                format!(
                    "non-development-authenticator runtime guard freshness recheck failed: {error}"
                )
            })?;
        }
        Ok(())
    }

    /// Derive the narrow one-shot migration authority before any database
    /// credential or connection is touched. Non-production continues to use
    /// its explicitly configured local migration contract. This capability is
    /// intentionally insufficient for serving or application-pool publication.
    pub(crate) fn into_apply_only_migration_admission(
        self,
        mode: crate::database::MigrationStartupMode,
        pins: &StartupSecurityPins,
        now: DateTime<Utc>,
    ) -> Result<VerifiedApplyOnlyMigrationAdmission, String> {
        if mode != crate::database::MigrationStartupMode::ApplyOnly {
            return Err("migration capability issuance requires exact apply-only mode".into());
        }
        if self.profile.security_profile != pins.security_profile
            || self.profile.deployment_id != pins.deployment_id
        {
            return Err(
                "migration admission startup pins differ from the loaded deployment identity"
                    .into(),
            );
        }
        match self.conformance_state {
            ConformanceState::NonProduction => {
                if pins.postgresql_infrastructure_attestation.is_some() {
                    return Err(
                        "non-production migration admission retained PostgreSQL-infrastructure production authority"
                            .into(),
                    );
                }
                let role_contract = crate::database::MigrationRoleContract::from_env()?;
                let expected_migration_inventory_digest =
                    crate::database::embedded_migration_inventory_digest().map_err(|error| {
                        format!("cannot derive the embedded migration inventory: {error}")
                    })?;
                Ok(VerifiedApplyOnlyMigrationAdmission::NonProduction {
                    role_contract,
                    expected_migration_inventory_digest,
                })
            }
            ConformanceState::Production(boundary) => {
                // The repository currently validates only an offline render
                // snapshot. It has no in-cluster admission/consume authority
                // and no runtime verifier that can bind ConfigMap materialized
                // values and receipt freshness to the executing Pod. Refuse
                // production before the caller reads the migration credential
                // or opens a database connection. Re-enable only by replacing
                // this containment fence with a non-cloneable, runtime-verified
                // render-admission capability carried into the DDL capability.
                if !production_migration_runtime_render_admission_is_implemented() {
                    return Err(
                        "production apply-only is disabled until live migration render admission, one-use attempt consumption, materialized-pin binding, and runtime receipt freshness are implemented"
                            .into(),
                    );
                }
                // The detached certificate is deliberately opened only after
                // live render admission. A disabled production path therefore
                // cannot consume or even read the one-shot deployment input.
                let first_owner_install_certificate =
                    load_first_owner_install_certificate_candidate(
                        pins,
                        &self.contract_root,
                        &self.profile,
                        boundary.as_ref(),
                    )?;
                let authority = pins
                    .postgresql_infrastructure_attestation
                    .as_ref()
                    .ok_or_else(|| {
                        "production migration admission has no independently pinned PostgreSQL-infrastructure authority"
                            .to_string()
                    })?
                    .clone();
                let admission = verify_production_migration_admission(
                    boundary,
                    mode,
                    authority,
                    first_owner_install_certificate,
                    now,
                )?;
                admission
                    .role_contract
                    .validate_optional_environment_consistency()?;
                Ok(VerifiedApplyOnlyMigrationAdmission::Production(Box::new(
                    admission,
                )))
            }
        }
    }

    /// Perform one nonce-bound exchange with the independently pinned public
    /// ingress authority and retain its exact non-cloneable proof. The caller
    /// supplies only the closed startup pin set; expected values, workload
    /// bindings, challenge digests, and time are derived internally.
    pub(crate) async fn verify_https_public_urls_runtime_guard(
        &mut self,
        pins: &StartupSecurityPins,
    ) -> Result<(), String> {
        if !self.profile.security_profile.is_production() {
            if self.verified_https_public_urls_guard.is_some()
                || pins.public_ingress_attestation.is_some()
            {
                return Err(
                    "non-production startup retained public-ingress production authority".into(),
                );
            }
            return Ok(());
        }
        let ConformanceState::Production(boundary) = &self.conformance_state else {
            return Err("production startup has no sealed production-boundary proof".into());
        };
        if self.verified_https_public_urls_guard.is_some() {
            return Err(
                "production https-public-urls runtime guard was verified more than once".into(),
            );
        }
        let authority = pins.public_ingress_attestation.as_ref().ok_or_else(|| {
            "production startup has no independently pinned public-ingress authority".to_string()
        })?;
        let witness = runtime_admission::verify_https_public_urls_guard(boundary, authority)
            .await
            .map_err(|error| {
                format!("https-public-urls runtime guard verification failed: {error}")
            })?;
        self.verified_https_public_urls_guard = Some(witness);
        Ok(())
    }

    /// Seal the live SecureCookies witness from the exact API cookie runtime.
    /// The verifier itself owns policy measurement, challenge binding, and
    /// trusted-time sampling; callers cannot supply any of those facts.
    pub(crate) fn verify_secure_cookie_runtime_guard(
        &mut self,
        runtime: &Arc<crate::cookie_runtime::ApiCookieRuntime>,
    ) -> Result<(), String> {
        if !self.profile.security_profile.is_production() {
            if self.verified_secure_cookie_guard.is_some() {
                return Err(
                    "non-production startup retained a production secure-cookie witness".into(),
                );
            }
            return Ok(());
        }
        let ConformanceState::Production(boundary) = &self.conformance_state else {
            return Err("production startup has no sealed production-boundary proof".into());
        };
        if self.verified_secure_cookie_guard.is_some() {
            return Err(
                "production secure-cookie runtime guard was verified more than once".into(),
            );
        }
        self.verified_secure_cookie_guard = Some(
            runtime_admission::verify_secure_cookie_guard(boundary, runtime).map_err(|error| {
                format!("secure-cookie runtime guard verification failed: {error}")
            })?,
        );
        Ok(())
    }

    /// Authenticate and seal the exact singleton secret-provider runtime only
    /// after its independently measured static leaves satisfy the receipt. The
    /// verifier retains the exact runtime, binding, observation, and lease.
    pub(crate) async fn verify_approved_secret_provider_runtime_guard(
        &mut self,
        runtime: &Arc<crate::secret_provider_runtime::VaultKubernetesRuntime>,
    ) -> Result<(), String> {
        if !self.profile.security_profile.is_production() {
            if self.verified_approved_secret_provider_guard.is_some() {
                return Err(
                    "non-production startup retained an approved secret-provider witness".into(),
                );
            }
            return Ok(());
        }
        if self.verified_approved_secret_provider_guard.is_some() {
            return Err(
                "production approved-secret-provider runtime guard was verified more than once"
                    .into(),
            );
        }
        let (provider, binding) = self.exact_production_secret_provider()?;
        let provider = provider.clone();
        let binding = Arc::clone(binding);
        let ConformanceState::Production(boundary) = &self.conformance_state else {
            return Err("production startup has no sealed production-boundary proof".into());
        };
        let witness = runtime_admission::verify_approved_secret_provider_guard(
            boundary, &provider, &binding, runtime,
        )
        .await
        .map_err(|error| {
            format!("approved-secret-provider runtime guard verification failed: {error}")
        })?;
        self.verified_approved_secret_provider_guard = Some(witness);
        Ok(())
    }

    pub(crate) fn retains_approved_secret_provider_runtime(
        &self,
        runtime: &Arc<crate::secret_provider_runtime::VaultKubernetesRuntime>,
    ) -> bool {
        self.verified_approved_secret_provider_guard
            .as_ref()
            .is_some_and(|witness| witness.handle().retains_runtime(runtime))
    }

    /// Seal NonDevelopmentAuthenticator from the exact immutable API runtime.
    /// Startup must call this once immediately after
    /// `ApiAuthenticatorRuntime::validate_production_posture` and before any
    /// handler-facing runtime Arc is published.
    pub(crate) fn verify_non_development_authenticator_runtime_guard(
        &mut self,
        runtime: &Arc<crate::authenticator_runtime::ApiAuthenticatorRuntime>,
    ) -> Result<(), String> {
        if !self.profile.security_profile.is_production() {
            if self.verified_non_development_authenticator_guard.is_some() {
                return Err(
                    "non-production startup retained a non-development-authenticator witness"
                        .into(),
                );
            }
            return Ok(());
        }
        if self.verified_non_development_authenticator_guard.is_some() {
            return Err(
                "production non-development-authenticator runtime guard was verified more than once"
                    .into(),
            );
        }
        let ConformanceState::Production(boundary) = &self.conformance_state else {
            return Err("production startup has no sealed production-boundary proof".into());
        };
        let witness =
            runtime_admission::verify_non_development_authenticator_guard(boundary, runtime)
                .map_err(|error| {
                    format!(
                        "non-development-authenticator runtime guard verification failed: {error}"
                    )
                })?;
        self.verified_non_development_authenticator_guard = Some(witness);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn retains_non_development_authenticator_runtime(
        &self,
        runtime: &Arc<crate::authenticator_runtime::ApiAuthenticatorRuntime>,
    ) -> bool {
        self.verified_non_development_authenticator_guard
            .as_ref()
            .is_some_and(|witness| witness.handle().retains_runtime(runtime))
    }

    /// Construct, independently attest, locally measure, and seal the exact
    /// production application database without publishing it. Every role,
    /// provider, route, profile, workload, and challenge value comes from the
    /// sealed boundary. The caller supplies only the already-admitted runtime
    /// configuration and the independently pinned authority set.
    pub(crate) async fn verify_durable_postgresql_runtime_guard(
        &mut self,
        pins: &StartupSecurityPins,
        config: &RyukiConfig,
    ) -> Result<crate::database::UnpublishedPostgresqlRuntime, String> {
        if !self.profile.security_profile.is_production() {
            if self.verified_durable_postgresql_guard.is_some()
                || pins.postgresql_infrastructure_attestation.is_some()
            {
                return Err(
                    "non-production startup retained DurablePostgresql production authority".into(),
                );
            }
            return Err("DurablePostgresql runtime verification is production-only".into());
        }
        if self.verified_durable_postgresql_guard.is_some() {
            return Err(
                "production DurablePostgresql runtime guard was verified more than once".into(),
            );
        }
        if self.profile.security_profile != pins.security_profile
            || self.profile.deployment_id != pins.deployment_id
        {
            return Err(
                "DurablePostgresql startup pins differ from the loaded deployment identity".into(),
            );
        }
        let authority_pins = pins
            .postgresql_infrastructure_attestation
            .as_ref()
            .ok_or_else(|| {
                "production startup has no independently pinned PostgreSQL-infrastructure authority"
                    .to_string()
            })?;
        let ConformanceState::Production(boundary) = &self.conformance_state else {
            return Err("production startup has no sealed production-boundary proof".into());
        };
        let challenge = runtime_admission::exact_challenge(boundary, GuardId::DurablePostgresql)
            .map_err(|error| format!("production startup lost its database guard: {error}"))?;
        let RuntimeGuardExpectedValue::DurablePostgresql {
            database_provider,
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
        } = challenge.expected_value()
        else {
            return Err("production startup database challenge is not DurablePostgresql".into());
        };
        if authority_pins.attestation_profile_id.as_str() != attestation_profile_id.as_str()
            || authority_pins.attestation_profile_version != *attestation_profile_version
            || authority_pins.attestation_profile_digest.as_str()
                != attestation_profile_digest.as_str()
        {
            return Err(
                "PostgreSQL-infrastructure startup profile pins differ from the receipt-bound runtime guard"
                    .into(),
            );
        }
        let roles = crate::database::ProductionDatabaseRoles::new(
            application_role.clone(),
            migration_role.clone(),
        )?;
        let settings = crate::database::ApplicationPoolSettings::new(
            config.server.pool_max_connections,
            config.server.pool_min_connections,
            config.server.pool_idle_timeout_secs,
            config.server.pool_acquire_timeout_secs,
            config.server.pool_max_lifetime_secs,
        )?;
        let mut request_nonce = [0u8; 32];
        OsRng.try_fill_bytes(&mut request_nonce).map_err(|_| {
            "cannot generate the one-shot PostgreSQL-infrastructure serving nonce".to_string()
        })?;
        if request_nonce.iter().all(|byte| *byte == 0) {
            return Err(
                "operating-system randomness produced an invalid PostgreSQL-infrastructure serving nonce"
                    .into(),
            );
        }
        boundary.ensure_fresh(trusted_time_point(Utc::now()))?;
        let unpublished = crate::database::construct_unpublished_channel_bound_production_database(
            &config.database_url,
            settings,
            roles,
            *database_provider,
            provider_route_binding_digest,
            &request_nonce,
        )
        .await
        .map_err(|error| {
            format!("cannot construct the unpublished production database runtime: {error}")
        })?;
        let session_binding = Arc::clone(unpublished.session_binding());
        let requested_at = Utc::now();
        boundary.ensure_fresh(trusted_time_point(requested_at))?;
        let public_key = decode_postgresql_infrastructure_authority_public_key(authority_pins)?;
        let authority = PostgresqlInfrastructureAuthorityAnchor {
            authority_id: &authority_pins.authority_id,
            key_id: &authority_pins.key_id,
            public_key: &public_key,
            public_key_fingerprint: &authority_pins.public_key_fingerprint,
            minimum_authority_epoch: authority_pins.minimum_authority_epoch,
            attestation_profile_id: &authority_pins.attestation_profile_id,
            attestation_profile_version: authority_pins.attestation_profile_version,
            attestation_profile_digest: &authority_pins.attestation_profile_digest,
        };
        let request = build_postgresql_infrastructure_attestation_request(
            ExpectedPostgresqlInfrastructure {
                deployment_id: boundary.deployed_workload.deployment_id(),
                trust_domain_id: boundary.deployed_workload.trust_domain_id(),
                workload_id: boundary.deployed_workload.workload_id(),
                source_revision: boundary.conformance.source_revision(),
                artifact_digest: boundary.deployed_workload.oci_subject_digest(),
                workload_instance_binding_digest: boundary
                    .deployed_workload
                    .workload_instance_binding_digest(),
                requirement_digest: challenge.requirement_digest(),
                challenge_binding_digest: challenge.challenge_binding_digest(),
                database_provider: *database_provider,
                server_major_version: *server_major_version,
                provider_route_binding_digest,
                database_identity_digest,
                storage_binding_digest,
                migration_inventory_digest,
                application_role,
                migration_role,
                session_purpose: PostgresqlSessionPurpose::ApplicationServing,
                session_binding: session_binding.as_ref(),
            },
            authority,
            request_nonce,
            requested_at,
        )
        .map_err(|error| {
            format!("cannot build exact PostgreSQL-infrastructure serving request: {error}")
        })?;
        if request.request_tag() != session_binding.application_name.as_str() {
            return Err(
                "PostgreSQL serving session application_name differs from the one-shot attestation request tag"
                    .into(),
            );
        }
        let transport = UnixAuthorityTransport::new(
            authority_pins.socket_path.clone(),
            AuthorityTransportDeadlines {
                connect: POSTGRESQL_INFRASTRUCTURE_TRANSPORT_PHASE_DEADLINE,
                write: POSTGRESQL_INFRASTRUCTURE_TRANSPORT_PHASE_DEADLINE,
                read: POSTGRESQL_INFRASTRUCTURE_TRANSPORT_PHASE_DEADLINE,
            },
            AuthorityTransportBounds {
                max_request_bytes: MAX_POSTGRESQL_INFRASTRUCTURE_REQUEST_BYTES,
                max_response_bytes: MAX_POSTGRESQL_INFRASTRUCTURE_RESPONSE_BYTES,
            },
            AuthorityTransportHardLimits {
                max_socket_path_bytes: MAX_AUTHORITY_SOCKET_PATH_BYTES,
                max_phase_deadline: MAX_POSTGRESQL_INFRASTRUCTURE_TRANSPORT_PHASE_DEADLINE,
                max_request_bytes: MAX_POSTGRESQL_INFRASTRUCTURE_REQUEST_BYTES,
                max_response_bytes: MAX_POSTGRESQL_INFRASTRUCTURE_RESPONSE_BYTES,
            },
        )
        .map_err(|error| {
            format!("cannot configure bounded PostgreSQL-infrastructure transport: {error}")
        })?;
        let raw_response = transport
            .exchange(request.as_bytes())
            .await
            .map_err(|error| {
                format!("PostgreSQL-infrastructure serving attestation exchange failed: {error}")
            })?;
        let proof_verified_at = Utc::now();
        boundary.ensure_fresh(trusted_time_point(proof_verified_at))?;
        let infrastructure = Arc::new(
            verify_postgresql_infrastructure_attestation(
                request,
                &raw_response,
                authority,
                trusted_time_point(proof_verified_at),
            )
            .map_err(|error| {
                format!("PostgreSQL-infrastructure serving proof verification failed: {error}")
            })?,
        );
        if infrastructure.session_purpose() != PostgresqlSessionPurpose::ApplicationServing
            || infrastructure.session_binding() != session_binding.as_ref()
        {
            return Err(
                "verified PostgreSQL-infrastructure proof substituted the application-serving session"
                    .into(),
            );
        }
        let infrastructure_evidence: Arc<
            dyn crate::database::VerifiedPostgresqlInfrastructureEvidence,
        > = infrastructure.clone();
        let local = crate::database::verify_local_durable_postgresql_runtime(
            &unpublished,
            infrastructure_evidence,
            challenge.expected_value(),
        )
        .map_err(|error| format!("local DurablePostgresql runtime verification failed: {error}"))?;
        let retained = unpublished.retained_handle();
        if !local.retains_runtime(&retained)
            || !local.retains_infrastructure_attestation(&infrastructure)
        {
            return Err(
                "DurablePostgresql verification did not retain the exact unpublished authority"
                    .into(),
            );
        }
        // Signature verification and the local digest/identity comparisons can
        // consume the proof's final validity instant. Resample immediately
        // before sealing so a proof that expired during synchronous work is
        // never installed as a live witness.
        let sealed_at = Utc::now();
        if sealed_at < proof_verified_at {
            return Err(
                "trusted time moved backwards while sealing DurablePostgresql authority".into(),
            );
        }
        let sealed_time = trusted_time_point(sealed_at);
        boundary.ensure_fresh(sealed_time)?;
        infrastructure.ensure_fresh(sealed_time).map_err(|error| {
            format!("PostgreSQL-infrastructure proof expired before sealing: {error}")
        })?;
        let witness = runtime_admission::seal_durable_postgresql_guard(
            boundary,
            local,
            infrastructure,
            sealed_time,
        )
        .map_err(|error| format!("DurablePostgresql runtime guard verification failed: {error}"))?;
        self.verified_durable_postgresql_guard = Some(witness);
        Ok(unpublished)
    }

    /// Authenticate and seal the permanent first-owner closure through the
    /// exact unpublished PostgreSQL runtime already retained by
    /// DurablePostgresql and the independently provisioned Ed25519 authority.
    pub(crate) async fn verify_first_owner_path_closed_runtime_guard(
        &mut self,
        pins: &StartupSecurityPins,
        unpublished: &crate::database::UnpublishedPostgresqlRuntime,
    ) -> Result<(), String> {
        if !self.profile.security_profile.is_production() {
            if self.verified_first_owner_path_closed_guard.is_some()
                || self.verified_durable_postgresql_guard.is_some()
                || pins.first_owner_authority.is_some()
            {
                return Err(
                    "non-production startup retained first-owner or DurablePostgresql production authority"
                        .into(),
                );
            }
            return Ok(());
        }
        if self.verified_first_owner_path_closed_guard.is_some() {
            return Err(
                "production first-owner-path-closed runtime guard was verified more than once"
                    .into(),
            );
        }
        if self.profile.security_profile != pins.security_profile
            || self.profile.deployment_id != pins.deployment_id
        {
            return Err(
                "first-owner startup pins differ from the loaded deployment identity".into(),
            );
        }
        if !unpublished.is_unpublished() {
            return Err(
                "first-owner closure verification requires the unpublished production database"
                    .into(),
            );
        }
        let authority_pins = pins.first_owner_authority.as_ref().ok_or_else(|| {
            "production startup has no independently pinned first-owner authority".to_string()
        })?;
        let other_authorities = [
            (
                "conformance trust-checkpoint",
                pins.conformance_trust_checkpoint_authority
                    .as_ref()
                    .ok_or_else(|| {
                        "production first-owner verification has no checkpoint authority pins"
                            .to_string()
                    })?
                    .public_key_fingerprint
                    .as_str(),
            ),
            (
                "deployed-workload attestation",
                pins.deployed_workload_attestation
                    .as_ref()
                    .ok_or_else(|| {
                        "production first-owner verification has no workload authority pins"
                            .to_string()
                    })?
                    .public_key_fingerprint
                    .as_str(),
            ),
            (
                "public-ingress attestation",
                pins.public_ingress_attestation
                    .as_ref()
                    .ok_or_else(|| {
                        "production first-owner verification has no ingress authority pins"
                            .to_string()
                    })?
                    .public_key_fingerprint
                    .as_str(),
            ),
            (
                "PostgreSQL-infrastructure attestation",
                pins.postgresql_infrastructure_attestation
                    .as_ref()
                    .ok_or_else(|| {
                        "production first-owner verification has no PostgreSQL authority pins"
                            .to_string()
                    })?
                    .public_key_fingerprint
                    .as_str(),
            ),
        ];
        for (label, public_key_fingerprint) in other_authorities {
            if authority_pins.public_key_fingerprint == public_key_fingerprint {
                return Err(format!(
                    "first-owner authority must use a cryptographically distinct key from the {label} authority"
                ));
            }
        }
        let witness = {
            let ConformanceState::Production(boundary) = &self.conformance_state else {
                return Err("production startup has no sealed production-boundary proof".into());
            };
            let durable_postgresql =
                self.verified_durable_postgresql_guard
                    .as_ref()
                    .ok_or_else(|| {
                        "production first-owner verification has no DurablePostgresql runtime guard"
                            .to_string()
                    })?;
            let candidate = unpublished.retained_handle();
            if !durable_postgresql
                .handle()
                .runtime()
                .same_runtime(&candidate)
            {
                return Err(
                    "first-owner closure verification received a PostgreSQL runtime other than the DurablePostgresql authority"
                        .into(),
                );
            }
            let witness = runtime_admission::verify_first_owner_path_closed_guard(
                boundary,
                &self.profile,
                durable_postgresql,
                authority_pins,
            )
            .await
            .map_err(|error| {
                format!("first-owner-path-closed runtime guard verification failed: {error}")
            })?;
            if !witness.handle().retains_postgresql_runtime(&candidate) {
                return Err(
                    "first-owner-path-closed witness did not retain the DurablePostgresql runtime"
                        .into(),
                );
            }
            witness
        };
        self.verified_first_owner_path_closed_guard = Some(witness);
        Ok(())
    }

    /// Repeat the exact channel-bound SQL/session observation at an
    /// asynchronous serving fence. This is intentionally separate from the
    /// value-free synchronous checkpoint recheck.
    pub(crate) async fn remeasure_durable_postgresql_runtime_guard(
        &self,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        if !self.profile.security_profile.is_production() {
            if self.verified_durable_postgresql_guard.is_some() {
                return Err(
                    "non-production startup retained DurablePostgresql production authority".into(),
                );
            }
            return Ok(());
        }
        let ConformanceState::Production(boundary) = &self.conformance_state else {
            return Err("production startup has no sealed production-boundary proof".into());
        };
        let witness = self
            .verified_durable_postgresql_guard
            .as_ref()
            .ok_or_else(|| {
                "production startup has no verified DurablePostgresql runtime guard".to_string()
            })?;
        runtime_admission::remeasure_durable_postgresql_guard_exact(
            boundary,
            witness,
            trusted_time_point(now),
        )
        .await
        .map_err(|error| format!("DurablePostgresql exact runtime remeasurement failed: {error}"))
    }

    /// Repeat the independently authenticated permanent-closure observation at
    /// an asynchronous fence through the same retained PostgreSQL channel.
    pub(crate) async fn remeasure_first_owner_path_closed_runtime_guard(
        &self,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        if !self.profile.security_profile.is_production() {
            if self.verified_first_owner_path_closed_guard.is_some()
                || self.verified_durable_postgresql_guard.is_some()
            {
                return Err(
                    "non-production startup retained first-owner or DurablePostgresql production authority"
                        .into(),
                );
            }
            return Ok(());
        }
        let ConformanceState::Production(boundary) = &self.conformance_state else {
            return Err("production startup has no sealed production-boundary proof".into());
        };
        let durable_postgresql =
            self.verified_durable_postgresql_guard
                .as_ref()
                .ok_or_else(|| {
                    "production startup has no verified DurablePostgresql runtime guard".to_string()
                })?;
        let first_owner_path_closed = self
            .verified_first_owner_path_closed_guard
            .as_ref()
            .ok_or_else(|| {
                "production startup has no verified first-owner-path-closed runtime guard"
                    .to_string()
            })?;
        runtime_admission::remeasure_first_owner_path_closed_guard_exact(
            boundary,
            &self.profile,
            durable_postgresql,
            first_owner_path_closed,
            trusted_time_point(now),
        )
        .await
        .map_err(|error| {
            format!("first-owner-path-closed exact runtime remeasurement failed: {error}")
        })
    }

    pub(crate) fn validate_runtime_bindings(
        &self,
        config: &RyukiConfig,
        legacy_auth_selector_present: bool,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        if !self.profile.security_profile.is_production()
            && (self.verified_durable_postgresql_guard.is_some()
                || self.verified_first_owner_path_closed_guard.is_some())
        {
            return Err(
                "non-production startup retained DurablePostgresql or first-owner production authority"
                    .into(),
            );
        }
        // Production authority always comes from the authenticated provider
        // registry. Reject the legacy selector before any guard-specific
        // branch can return early and accidentally leave two authority
        // sources configured for a future fully-admitted production startup.
        if self.profile.security_profile.is_production() && legacy_auth_selector_present {
            return Err(
                "RYUKI_AUTH_MODE and the provider registry cannot both select authority without migration_overlay"
                    .into(),
            );
        }
        if self.profile.security_profile.is_production() {
            let ConformanceState::Production(boundary) = &self.conformance_state else {
                return Err("production startup has no sealed production-boundary proof".into());
            };
            let secure_cookie_guard =
                self.verified_secure_cookie_guard.as_ref().ok_or_else(|| {
                    "production startup has no verified secure-cookie runtime guard".to_string()
                })?;
            let https_public_urls_guard = self
                .verified_https_public_urls_guard
                .as_ref()
                .ok_or_else(|| {
                    "production startup has no verified https-public-urls runtime guard".to_string()
                })?;
            let approved_secret_provider_guard = self
                .verified_approved_secret_provider_guard
                .as_ref()
                .ok_or_else(|| {
                    "production startup has no verified approved-secret-provider runtime guard"
                        .to_string()
                })?;
            let non_development_authenticator_guard = self
                .verified_non_development_authenticator_guard
                .as_ref()
                .ok_or_else(|| {
                    "production startup has no verified non-development-authenticator runtime guard"
                        .to_string()
                })?;
            let durable_postgresql_guard = self
                .verified_durable_postgresql_guard
                .as_ref()
                .ok_or_else(|| {
                    "production startup has no verified DurablePostgresql runtime guard".to_string()
                })?;
            let first_owner_path_closed_guard = self
                .verified_first_owner_path_closed_guard
                .as_ref()
                .ok_or_else(|| {
                    "production startup has no verified first-owner-path-closed runtime guard"
                        .to_string()
                })?;
            let (secret_provider, _) = self.exact_production_secret_provider()?;
            let trusted_now = trusted_time_point(now);
            runtime_admission::recheck_https_public_urls_guard(
                boundary,
                https_public_urls_guard,
                trusted_now,
            )
            .map_err(|error| {
                format!("https-public-urls runtime guard freshness recheck failed: {error}")
            })?;
            runtime_admission::recheck_secure_cookie_guard(
                boundary,
                secure_cookie_guard,
                trusted_now,
            )
            .map_err(|error| {
                format!("secure-cookie runtime guard freshness recheck failed: {error}")
            })?;
            runtime_admission::recheck_approved_secret_provider_guard(
                boundary,
                secret_provider,
                approved_secret_provider_guard,
                trusted_now,
            )
            .map_err(|error| {
                format!("approved-secret-provider runtime guard freshness recheck failed: {error}")
            })?;
            runtime_admission::recheck_non_development_authenticator_guard(
                boundary,
                non_development_authenticator_guard,
                trusted_now,
            )
            .map_err(|error| {
                format!(
                    "non-development-authenticator runtime guard freshness recheck failed: {error}"
                )
            })?;
            runtime_admission::recheck_durable_postgresql_guard(
                boundary,
                durable_postgresql_guard,
                trusted_now,
            )
            .map_err(|error| {
                format!("DurablePostgresql runtime guard freshness recheck failed: {error}")
            })?;
            runtime_admission::recheck_first_owner_path_closed_guard(
                boundary,
                &self.profile,
                durable_postgresql_guard,
                first_owner_path_closed_guard,
                trusted_now,
            )
            .map_err(|error| {
                format!("first-owner-path-closed runtime guard freshness recheck failed: {error}")
            })?;
            let selected = self.select_authentication_provider(&config.auth_mode)?;
            self.validate_selected_provider(selected, config)?;
            let provider_applicability = format!(
                "provider registry version {} with {} active provider applicability claims",
                self.provider_registry_applicability.registry_version,
                self.provider_registry_applicability.active_providers.len(),
            );
            // This is a code-owned topology check, not receipt discovery. The
            // current plan deliberately remains incomplete while mock-backed
            // routes, workers, and fallback stores are reachable; therefore it
            // cannot manufacture a nominal MockDependenciesDisabled witness.
            let dependency_plan_blocker =
                production_dependencies::current_production_dependency_admission_blocker();
            return Err(format!(
                "production semantic closure is verified and sealed to the pinned build and deployed workload (closure {}; {} receipt packages; {} evidence objects; workload {}; {}), and DurablePostgresql, the independently signed FirstOwnerPathClosed permanent closure, HttpsPublicUrls, the exact retained SecureCookies policy, the singleton ApprovedSecretProvider D/P/R/I composition, plus the NonDevelopmentAuthenticator D/P/Q/R/I composition have live workload-bound witnesses; startup remains blocked until the remaining {} runtime guards are verified: external-signing-key-material, mock-dependencies-disabled; {}",
                boundary.conformance.closure_digest(),
                boundary.conformance.package_count(),
                boundary.conformance.evidence_count(),
                boundary.deployed_workload.workload_id(),
                provider_applicability,
                REMAINING_PRODUCTION_RUNTIME_GUARDS.len(),
                dependency_plan_blocker,
            ));
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
            (
                AuthMode::EntraId,
                ActiveProviderKindConfig::Oidc {
                    configuration: oidc,
                    ..
                },
            ) => {
                if provider.kind != "oidc"
                    || provider.capability_descriptor.adapter_kind != "auth.entra-id"
                {
                    return Err(format!(
                        "selected provider {} does not exactly match the compiled entra-id authenticator selector",
                        provider.provider_id
                    ));
                }
                let _ = oidc.security_binding_summary()?;
                let witness = self
                    .verified_non_development_authenticator_guard
                    .as_ref()
                    .ok_or_else(|| {
                        format!(
                            "selected provider {} has no exact retained non-development-authenticator runtime witness",
                            provider.provider_id
                        )
                    })?;
                let handle = witness.handle();
                if !handle.matches_auth_mode(&config.auth_mode)
                    || !handle.matches_provider(provider)
                {
                    return Err(format!(
                        "selected provider {} differs from the exact provider and runtime retained by the non-development-authenticator witness",
                        provider.provider_id
                    ));
                }
                Ok(())
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

fn control_plane_grant_scope_from_profile(
    profile: &DeploymentSecurityProfile,
) -> Result<ryuki_protocol::ControlPlaneGrantScope, String> {
    let [trust_domain_id] = profile.trust_topology.trust_domain_ids.as_slice() else {
        return Err("control-plane grant scope requires exactly one admitted trust domain".into());
    };
    ryuki_protocol::ControlPlaneGrantScope::new(&profile.deployment_id, trust_domain_id)
        .map_err(|_| "control-plane grant scope in the admitted profile is invalid".into())
}

impl ActiveProviderConfiguration {
    fn matches_auth_mode(&self, auth_mode: &AuthMode) -> bool {
        match (auth_mode, &self.kind_config) {
            (
                AuthMode::MockDryRun | AuthMode::StaticDryRun,
                ActiveProviderKindConfig::DevelopmentFixture(_),
            )
            | (AuthMode::Local, ActiveProviderKindConfig::LocalWebauthn(_)) => true,
            (AuthMode::EntraId, ActiveProviderKindConfig::Oidc { .. }) => {
                self.kind == "oidc" && self.capability_descriptor.adapter_kind == "auth.entra-id"
            }
            _ => false,
        }
    }

    fn verified_authenticator_runtime_binding(
        &self,
    ) -> Option<&Arc<VerifiedAuthenticatorRuntimeBinding>> {
        let ActiveProviderKindConfig::Oidc {
            verified_runtime_binding,
            ..
        } = &self.kind_config
        else {
            return None;
        };
        Some(verified_runtime_binding)
    }

    fn verified_secret_provider_runtime_binding(
        &self,
    ) -> Option<&Arc<VerifiedSecretProviderRuntimeBinding>> {
        let ActiveProviderKindConfig::SecretService {
            verified_runtime_binding,
            ..
        } = &self.kind_config
        else {
            return None;
        };
        verified_runtime_binding.as_ref()
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

#[cfg(test)]
pub(crate) fn load_startup_security_contract(
    pins: &StartupSecurityPins,
    now: DateTime<Utc>,
) -> Result<SecurityContractContext, String> {
    let prepared = prepare_startup_security_contract(pins, now)?;
    if prepared.profile.security_profile.is_production() {
        return Err(
            "production serving startup requires asynchronous external conformance checkpoint reconciliation"
                .into(),
        );
    }
    finalize_startup_security_contract(prepared, None, None, || now)
}

/// Performs static production-boundary admission before database, application
/// configuration, signing-key, worker, router, or listener initialization.
/// This is not serving authority: main must next measure every live runtime
/// guard and retain the complete typed witness set. Non-production profiles
/// remain local-only. Production performs exactly one read/reconcile exchange
/// with the independently pinned authority and cannot bootstrap, accept, or
/// advance external state.
pub(crate) async fn load_startup_security_contract_for_serving(
    pins: &StartupSecurityPins,
) -> Result<SecurityContractContext, String> {
    let mut prepared = prepare_startup_security_contract(pins, Utc::now())?;
    let checkpoint = if prepared.profile.security_profile.is_production() {
        Some(reconcile_external_conformance_checkpoint(&mut prepared, pins).await?)
    } else {
        None
    };
    let deployed_workload = if prepared.profile.security_profile.is_production() {
        Some(
            reconcile_external_deployed_workload(
                &prepared,
                pins,
                checkpoint.as_ref().ok_or_else(|| {
                    "production startup lost its verified conformance checkpoint before workload attestation"
                        .to_string()
                })?,
            )
            .await?,
        )
    } else {
        None
    };
    finalize_startup_security_contract(prepared, checkpoint, deployed_workload, Utc::now)
}

fn prepare_startup_security_contract(
    pins: &StartupSecurityPins,
    now: DateTime<Utc>,
) -> Result<PreparedSecurityContract, String> {
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

    let production_build_manifest_candidate = if profile.security_profile.is_production() {
        let runtime_identity = current_runtime_build_identity()?;
        Some(load_production_build_manifest_candidate(
            pins,
            &store.root,
            &profile,
            &runtime_identity,
        )?)
    } else {
        None
    };

    let conformance_registry_lineage =
        load_pinned_conformance_trust_root_registry(&mut store, pins, &profile, now)?;

    let allow_repository_fixture_evidence = profile.security_profile.admits_development_fixture()
        && profile
            .enabled_features
            .iter()
            .any(|feature| feature == "repository-conformance")
        && profile
            .enabled_features
            .iter()
            .any(|feature| feature == "static-dry-run");
    let (
        documents,
        raw_document_bytes,
        reference_document_digests,
        provider_registry_version,
        active_providers,
        production_build_manifest,
    ) = {
        let mut verifier = ReferenceVerifier::new(&mut store, allow_repository_fixture_evidence);
        verifier.verify_value(&profile_value, 0)?;

        let provider_locator = &profile.provider_registry_ref.artifact_locator;
        let provider_registry = verifier
            .documents
            .get(provider_locator)
            .ok_or_else(|| "provider registry reference did not resolve to JSON".to_string())?;
        let provider_registry_version =
            required_u64(provider_registry, "registry_version", "provider registry")?;
        let active_providers = validate_provider_registry(
            provider_registry,
            &profile,
            now,
            &verifier.documents,
            &verifier.document_bytes,
            &verifier.visited,
        )?;

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

        let production_build_manifest = match production_build_manifest_candidate {
            Some(candidate) => {
                let control_trace_bytes = verifier
                    .document_bytes
                    .get(&profile.control_trace_ref.artifact_locator)
                    .ok_or_else(|| {
                        "production build manifest control-trace bytes did not resolve".to_string()
                    })?;
                Some(candidate.seal(control_trace_bytes)?)
            }
            None => None,
        };

        (
            verifier.documents,
            verifier.document_bytes,
            verifier.visited,
            provider_registry_version,
            active_providers,
            production_build_manifest,
        )
    };

    let provider_registry_applicability = build_provider_registry_applicability_claim(
        &profile,
        provider_registry_version,
        &active_providers,
    )?;
    if let Some(manifest) = production_build_manifest.as_ref() {
        validate_production_provider_build_bindings(
            &provider_registry_applicability,
            &manifest.document,
        )?;
    }
    let verified_security_limit_profile = Arc::new(verify_security_limit_profile(
        &profile.security_limit_profile_ref,
        &profile,
        now,
        &documents,
        &raw_document_bytes,
        &reference_document_digests,
    )?);

    Ok(PreparedSecurityContract {
        profile,
        profile_raw_bytes: profile_bytes.into_boxed_slice(),
        profile_digest: actual_profile_digest,
        contract_root: store.root,
        profile_path: pins.profile_path.clone(),
        documents,
        raw_document_bytes,
        reference_document_digests,
        verified_security_limit_profile,
        active_providers,
        provider_registry_applicability,
        conformance_registry_lineage,
        production_build_manifest,
    })
}

fn current_runtime_build_identity() -> Result<RuntimeBuildIdentity, String> {
    let source_revision = crate::build_identity::embedded_source_revision()
        .filter(|revision| !revision.is_empty())
        .ok_or_else(|| {
            "production build admission requires an embedded RYUKI_SOURCE_REVISION from the validated release build"
                .to_string()
        })?;
    let (executable_digest, executable_byte_length) = measure_current_executable()?;
    Ok(RuntimeBuildIdentity {
        source_revision: source_revision.into(),
        component: crate::build_identity::current_component(),
        executable_digest,
        executable_byte_length,
        shipped_adapters: crate::build_identity::compiled_shipped_adapters(),
        selector_dispositions: crate::build_identity::compiled_selector_dispositions(),
    })
}

fn measure_current_executable() -> Result<(String, u64), String> {
    let mut file = open_current_executable_image()?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("running executable metadata cannot be read: {error}"))?;
    if !metadata.is_file() {
        return Err("running executable image handle must reference a regular file".into());
    }
    if metadata.len() == 0 || metadata.len() > MAX_RUNTIME_EXECUTABLE_BYTES {
        return Err(format!(
            "running executable must be non-empty and no larger than {MAX_RUNTIME_EXECUTABLE_BYTES} bytes"
        ));
    }
    let mut digest = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("running executable read failed: {error}"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| "running executable byte accounting overflow".to_string())?;
        if total > MAX_RUNTIME_EXECUTABLE_BYTES {
            return Err(format!(
                "running executable exceeds {MAX_RUNTIME_EXECUTABLE_BYTES} bytes"
            ));
        }
        digest.update(&buffer[..read]);
    }
    if total != metadata.len() {
        return Err("running executable changed while being measured".into());
    }
    Ok((format!("sha256:{:x}", digest.finalize()), total))
}

#[cfg(target_os = "linux")]
fn open_current_executable_image() -> Result<fs::File, String> {
    // `/proc/self/exe` is a kernel-provided handle to the inode backing the
    // executing image. Opening it avoids re-resolving a replaceable deployment
    // pathname returned by `current_exe()`.
    fs::File::open("/proc/self/exe")
        .map_err(|error| format!("running executable image handle is unavailable: {error}"))
}

#[cfg(not(target_os = "linux"))]
fn open_current_executable_image() -> Result<fs::File, String> {
    Err(
        "production executable identity requires a platform executing-image handle; authoritative measurement is currently supported only on Linux"
            .into(),
    )
}

fn load_production_build_manifest_candidate(
    pins: &StartupSecurityPins,
    contract_root: &Path,
    profile: &DeploymentSecurityProfile,
    runtime: &RuntimeBuildIdentity,
) -> Result<ProductionBuildManifestCandidate, String> {
    let binding = pins.production_build_manifest.as_ref().ok_or_else(|| {
        "production startup has no independently pinned build-manifest binding".to_string()
    })?;
    if binding.path.starts_with(contract_root) {
        return Err(
            "production build manifest must be detached from the rollbackable security-contract root"
                .into(),
        );
    }
    let bytes = read_pinned_absolute_regular_file(
        "production build manifest",
        &binding.path,
        &binding.digest,
        MAX_PRODUCTION_BUILD_MANIFEST_BYTES,
    )?;
    let value = parse_json_strict(&bytes)
        .map_err(|error| format!("production build manifest JSON is invalid: {error}"))?;
    validate_against_schema(
        "production build manifest",
        PRODUCTION_BUILD_MANIFEST_SCHEMA,
        &value,
    )?;
    let document: ProductionBuildManifest = serde_json::from_value(value)
        .map_err(|error| format!("production build manifest is not losslessly typed: {error}"))?;
    let errors = document.validate_semantics();
    if !errors.is_empty() {
        return Err(format!(
            "production build manifest failed semantic validation: {}",
            errors.join("; ")
        ));
    }
    if document.component != runtime.component {
        return Err(
            "production build manifest component does not match the executing build target".into(),
        );
    }
    if document.source.revision != runtime.source_revision {
        return Err(
            "production build manifest source revision does not match the embedded release revision"
                .into(),
        );
    }
    if document.runtime_executable.content_digest != runtime.executable_digest
        || document.runtime_executable.byte_length != runtime.executable_byte_length
    {
        return Err(
            "production build manifest executable identity does not match the measured running executable"
                .into(),
        );
    }
    if document.shipped_adapters != runtime.shipped_adapters {
        return Err(
            "production build manifest shipped-adapter inventory does not match the compiled build surface"
                .into(),
        );
    }
    if document.selector_dispositions != runtime.selector_dispositions {
        return Err(
            "production build manifest selector inventory does not match the compiled build surface"
                .into(),
        );
    }
    if document.control_trace_ref != profile.control_trace_ref {
        return Err(
            "production build manifest does not bind the exact profile-selected ControlTrace"
                .into(),
        );
    }
    Ok(ProductionBuildManifestCandidate {
        source_path: binding.path.clone(),
        raw_digest: binding.digest.clone(),
        raw_bytes: bytes.into_boxed_slice(),
        document,
    })
}

/// Load and verify the detached one-shot first-owner installation input.
///
/// Callers must place this after the live render-admission fence. Merely
/// parsing startup environment cannot touch the path or mint installation
/// authority.
fn load_first_owner_install_certificate_candidate(
    pins: &StartupSecurityPins,
    contract_root: &Path,
    profile: &DeploymentSecurityProfile,
    boundary: &VerifiedProductionBoundary,
) -> Result<crate::first_owner_runtime::VerifiedFirstOwnerInstallCertificate, String> {
    let binding = pins
        .first_owner_closure_certificate
        .as_ref()
        .ok_or_else(|| {
            "production apply-only has no independently pinned first-owner closure certificate"
                .to_string()
        })?;
    if binding.path.starts_with(contract_root) {
        return Err(
            "first-owner closure certificate must be detached from the rollbackable security-contract root"
                .into(),
        );
    }
    let bytes = read_pinned_absolute_regular_file(
        "first-owner closure certificate",
        &binding.path,
        &binding.digest,
        u64::try_from(ryuki_core::security_profile::FIRST_OWNER_CLOSURE_CERTIFICATE_MAX_BYTES)
            .expect("first-owner certificate limit fits u64"),
    )?;
    let value = parse_json_strict(&bytes)
        .map_err(|error| format!("first-owner closure certificate JSON is invalid: {error}"))?;
    validate_against_schema(
        "first-owner closure certificate",
        FIRST_OWNER_CLOSURE_CERTIFICATE_SCHEMA,
        &value,
    )?;
    let challenge = runtime_admission::exact_challenge(boundary, GuardId::FirstOwnerPathClosed)
        .map_err(|error| {
            format!("production apply-only lost its exact first-owner closure challenge: {error}")
        })?;
    let authority_pins = pins.first_owner_authority.as_ref().ok_or_else(|| {
        "production apply-only has no independently pinned first-owner authority".to_string()
    })?;
    let authority = runtime_admission::first_owner_authority_from_pins(authority_pins)
        .map_err(|error| format!("first-owner authority pins are invalid: {error}"))?;
    crate::first_owner_runtime::verify_first_owner_install_certificate(
        bytes,
        &binding.digest,
        profile,
        challenge.expected_value(),
        challenge.requirement_digest(),
        challenge.challenge_binding_digest(),
        authority,
    )
    .map_err(|error| format!("first-owner closure certificate verification failed: {error}"))
}

impl ProductionBuildManifestCandidate {
    fn seal(self, control_trace_bytes: &[u8]) -> Result<PinnedProductionBuildManifest, String> {
        let measured_digest = raw_digest(control_trace_bytes);
        if measured_digest != self.document.control_trace_ref.content_digest {
            return Err(
                "production build manifest ControlTrace bytes do not match its content-addressed reference"
                    .into(),
            );
        }
        let control_trace = parse_json_strict(control_trace_bytes)
            .map_err(|error| format!("profile-selected ControlTrace JSON is invalid: {error}"))?;
        validate_against_schema(
            "profile-selected ControlTrace",
            CONTROL_TRACE_SCHEMA,
            &control_trace,
        )?;
        validate_manifest_trace_inventory(&self.document, &control_trace)?;
        Ok(PinnedProductionBuildManifest {
            source_path: self.source_path,
            raw_bytes: self.raw_bytes,
            raw_digest: self.raw_digest,
            document: self.document,
        })
    }
}

fn validate_manifest_trace_inventory(
    manifest: &ProductionBuildManifest,
    control_trace: &Value,
) -> Result<(), String> {
    validate_exact_implementation_applicability(control_trace, manifest).map_err(|error| {
        format!(
            "production build manifest implementation applicability failed independent derivation: {error}"
        )
    })
}

async fn reconcile_external_conformance_checkpoint(
    prepared: &mut PreparedSecurityContract,
    pins: &StartupSecurityPins,
) -> Result<VerifiedConformanceTrustCheckpoint, String> {
    reconcile_external_conformance_checkpoint_with_clock(prepared, pins, Utc::now).await
}

async fn reconcile_external_conformance_checkpoint_with_clock(
    prepared: &mut PreparedSecurityContract,
    pins: &StartupSecurityPins,
    mut trusted_now: impl FnMut() -> DateTime<Utc>,
) -> Result<VerifiedConformanceTrustCheckpoint, String> {
    let [trust_domain_id] = prepared.profile.trust_topology.trust_domain_ids.as_slice() else {
        return Err(
            "production conformance checkpoint reconciliation requires exactly one trust domain until per-document trust-domain partitioning is implemented"
                .into(),
        );
    };
    let authority_pins = pins
        .conformance_trust_checkpoint_authority
        .as_ref()
        .ok_or_else(|| {
            "production startup requires an independently pinned conformance checkpoint authority"
                .to_string()
        })?;
    let authority_public_key = decode_checkpoint_authority_public_key(authority_pins)?;
    let authority = ConformanceCheckpointAuthorityAnchor {
        authority_id: &authority_pins.authority_id,
        key_id: &authority_pins.key_id,
        public_key: &authority_public_key,
        public_key_fingerprint: &authority_pins.public_key_fingerprint,
        minimum_authority_epoch: authority_pins.minimum_authority_epoch,
    };
    let requested_document_digests = conformance_document_digests(
        &prepared.documents,
        &prepared.raw_document_bytes,
        &prepared.reference_document_digests,
    )?;
    let production_root = exact_profile_production_root(prepared)?;
    if requested_document_digests
        .binary_search(&production_root.content_digest)
        .is_err()
    {
        return Err(
            "production acceptance root is absent from the exact checkpoint document lookup".into(),
        );
    }
    let lineage = prepared
        .conformance_registry_lineage
        .take()
        .ok_or_else(|| {
            "production startup did not validate a conformance registry lineage".to_string()
        })?;

    let mut request_nonce = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut request_nonce)
        .map_err(|error| format!("failed to obtain a cryptographic checkpoint nonce: {error}"))?;
    let request = lineage
        .reconciliation_request(
            ConformanceTrustScope {
                deployment_id: &prepared.profile.deployment_id,
                trust_domain_id,
            },
            ConformanceProductionRootRef {
                document_id: &production_root.document_id,
                document_version: production_root.document_version,
                content_digest: &production_root.content_digest,
                artifact_locator: &production_root.artifact_locator,
            },
            authority,
            request_nonce,
            trusted_now(),
            &requested_document_digests,
        )
        .map_err(|error| format!("conformance checkpoint request is invalid: {error}"))?;
    let transport = UnixTrustCheckpointTransport::new(
        authority_pins.socket_path.clone(),
        CHECKPOINT_TRANSPORT_PHASE_DEADLINE,
        TrustCheckpointTransportBounds::production(),
    )
    .map_err(|error| format!("conformance checkpoint transport is invalid: {error}"))?;
    let raw_response = transport
        .read_reconcile(request.as_bytes())
        .await
        .map_err(|error| format!("conformance checkpoint reconciliation failed: {error}"))?;
    let trusted_now = trusted_now();
    lineage
        .verify_reconciliation_response(
            &request,
            &raw_response,
            authority,
            ConformanceTrustedTimeWindow {
                not_before: trusted_now,
                not_after: trusted_now,
            },
        )
        .map_err(|error| format!("conformance checkpoint response is untrusted: {error}"))
}

async fn reconcile_external_deployed_workload(
    prepared: &PreparedSecurityContract,
    pins: &StartupSecurityPins,
    checkpoint: &VerifiedConformanceTrustCheckpoint,
) -> Result<VerifiedDeployedWorkload, String> {
    let authority_pins = pins.deployed_workload_attestation.as_ref().ok_or_else(|| {
        "production startup requires an independently pinned deployed-workload attestation authority"
            .to_string()
    })?;
    if checkpoint.deployment_id() != pins.deployment_id
        || checkpoint.deployment_id() != prepared.profile.deployment_id
    {
        return Err(
            "verified conformance checkpoint deployment does not match the independent startup deployment pin"
                .into(),
        );
    }
    let build = prepared
        .production_build_manifest
        .as_ref()
        .ok_or_else(|| "production startup has no pinned build manifest".to_string())?;
    let authority_public_key = decode_deployed_workload_authority_public_key(authority_pins)?;
    let authority = DeployedWorkloadAuthorityAnchor {
        authority_id: &authority_pins.authority_id,
        key_id: &authority_pins.key_id,
        public_key: &authority_public_key,
        public_key_fingerprint: &authority_pins.public_key_fingerprint,
        minimum_authority_epoch: authority_pins.minimum_authority_epoch,
        measurement_profile_id: &authority_pins.measurement_profile_id,
        measurement_profile_version: authority_pins.measurement_profile_version,
        measurement_profile_digest: &authority_pins.measurement_profile_digest,
    };

    let requested_at = Utc::now();
    checkpoint
        .ensure_fresh(trusted_time_point(requested_at))
        .map_err(|error| {
            format!(
                "production conformance checkpoint expired before deployed-workload attestation: {error}"
            )
        })?;
    let mut request_nonce = [0u8; 32];
    OsRng.try_fill_bytes(&mut request_nonce).map_err(|error| {
        format!("failed to obtain a cryptographic deployed-workload nonce: {error}")
    })?;
    let request = build_deployed_workload_attestation_request(
        ExpectedDeployedWorkload {
            deployment_id: &pins.deployment_id,
            trust_domain_id: checkpoint.trust_domain_id(),
            workload_id: &authority_pins.workload_id,
            oci_subject: &build.document.oci_subject,
            runtime_executable: &build.document.runtime_executable,
        },
        authority,
        request_nonce,
        requested_at,
    )
    .map_err(|error| format!("deployed-workload attestation request is invalid: {error}"))?;

    let transport = UnixAuthorityTransport::new(
        authority_pins.socket_path.clone(),
        AuthorityTransportDeadlines {
            connect: DEPLOYED_WORKLOAD_TRANSPORT_PHASE_DEADLINE,
            write: DEPLOYED_WORKLOAD_TRANSPORT_PHASE_DEADLINE,
            read: DEPLOYED_WORKLOAD_TRANSPORT_PHASE_DEADLINE,
        },
        AuthorityTransportBounds {
            max_request_bytes: MAX_DEPLOYED_WORKLOAD_REQUEST_BYTES,
            max_response_bytes: MAX_DEPLOYED_WORKLOAD_RESPONSE_BYTES,
        },
        AuthorityTransportHardLimits {
            max_socket_path_bytes: MAX_AUTHORITY_SOCKET_PATH_BYTES,
            max_phase_deadline: MAX_DEPLOYED_WORKLOAD_TRANSPORT_PHASE_DEADLINE,
            max_request_bytes: MAX_DEPLOYED_WORKLOAD_REQUEST_BYTES,
            max_response_bytes: MAX_DEPLOYED_WORKLOAD_RESPONSE_BYTES,
        },
    )
    .map_err(|error| format!("deployed-workload attestation transport is invalid: {error}"))?;
    let raw_response = transport
        .exchange(request.as_bytes())
        .await
        .map_err(|error| {
            format!("deployed-workload attestation exchange failed without retry: {error}")
        })?;
    let verified_at = Utc::now();
    verify_deployed_workload_attestation(
        request,
        &raw_response,
        authority,
        trusted_time_point(verified_at),
    )
    .map_err(|error| format!("deployed-workload attestation response is untrusted: {error}"))
}

fn exact_profile_production_root(
    prepared: &PreparedSecurityContract,
) -> Result<VersionedContentReference, String> {
    let reference = prepared
        .profile
        .production_acceptance_receipt_ref
        .as_ref()
        .ok_or_else(|| {
            "production profile has no exact production_acceptance_receipt_ref".to_string()
        })?;
    if reference.artifact_kind != ArtifactKind::PackageExitReceipt {
        return Err("production acceptance root is not a package-exit receipt".into());
    }
    let raw_bytes = prepared
        .raw_document_bytes
        .get(&reference.artifact_locator)
        .ok_or_else(|| {
            "production acceptance root has no exact bytes from reference traversal".to_string()
        })?;
    let raw_bytes_digest = raw_digest(raw_bytes);
    let traversed_digest = prepared
        .reference_document_digests
        .get(&reference.artifact_locator)
        .ok_or_else(|| "production acceptance root has no verified traversal digest".to_string())?;
    if raw_bytes_digest != reference.content_digest || traversed_digest != &reference.content_digest
    {
        return Err(
            "production acceptance root bytes do not match the exact profile-selected digest"
                .into(),
        );
    }
    let document = prepared
        .documents
        .get(&reference.artifact_locator)
        .ok_or_else(|| "production acceptance root did not resolve to typed JSON".to_string())?;
    if document.get("contract_kind").and_then(Value::as_str) != Some("package-exit-receipt")
        || document.get("receipt_id").and_then(Value::as_str)
            != Some(reference.document_id.as_str())
        || document.get("document_version").and_then(Value::as_u64)
            != Some(reference.document_version)
        || document.get("package_id").and_then(Value::as_str) != Some("SB-9")
    {
        return Err(
            "production acceptance root reference does not identify the exact loaded SB-9 receipt"
                .into(),
        );
    }
    Ok(reference.clone())
}

fn decode_checkpoint_authority_public_key(
    pins: &StartupTrustCheckpointAuthorityPins,
) -> Result<[u8; ED25519_AUTHORITY_PUBLIC_KEY_BYTES], String> {
    let decoded = BASE64_STANDARD
        .decode(&pins.public_key_base64)
        .map_err(|_| {
            "configured checkpoint authority public key is not canonical base64".to_string()
        })?;
    if BASE64_STANDARD.encode(&decoded) != pins.public_key_base64
        || raw_digest(&decoded) != pins.public_key_fingerprint
    {
        return Err(
            "configured checkpoint authority public key does not match its canonical independent fingerprint pin"
                .into(),
        );
    }
    decoded
        .try_into()
        .map_err(|_| "configured checkpoint authority public key is not 32 bytes".to_string())
}

fn decode_deployed_workload_authority_public_key(
    pins: &StartupDeployedWorkloadAttestationPins,
) -> Result<[u8; ED25519_AUTHORITY_PUBLIC_KEY_BYTES], String> {
    let decoded = BASE64_STANDARD
        .decode(&pins.public_key_base64)
        .map_err(|_| {
            "configured deployed-workload authority public key is not canonical base64".to_string()
        })?;
    if BASE64_STANDARD.encode(&decoded) != pins.public_key_base64
        || raw_digest(&decoded) != pins.public_key_fingerprint
    {
        return Err(
            "configured deployed-workload authority public key does not match its canonical independent fingerprint pin"
                .into(),
        );
    }
    decoded.try_into().map_err(|_| {
        "configured deployed-workload authority public key is not 32 bytes".to_string()
    })
}

fn decode_public_ingress_authority_public_key(
    pins: &StartupPublicIngressAttestationPins,
) -> Result<[u8; ED25519_AUTHORITY_PUBLIC_KEY_BYTES], String> {
    let decoded = BASE64_STANDARD
        .decode(&pins.public_key_base64)
        .map_err(|_| {
            "configured public-ingress authority public key is not canonical base64".to_string()
        })?;
    if BASE64_STANDARD.encode(&decoded) != pins.public_key_base64
        || raw_digest(&decoded) != pins.public_key_fingerprint
    {
        return Err(
            "configured public-ingress authority public key does not match its canonical independent fingerprint pin"
                .into(),
        );
    }
    decoded
        .try_into()
        .map_err(|_| "configured public-ingress authority public key is not 32 bytes".to_string())
}

fn decode_postgresql_infrastructure_authority_public_key(
    pins: &StartupPostgresqlInfrastructureAttestationPins,
) -> Result<[u8; ED25519_AUTHORITY_PUBLIC_KEY_BYTES], String> {
    let decoded = BASE64_STANDARD
        .decode(&pins.public_key_base64)
        .map_err(|_| {
            "configured PostgreSQL-infrastructure authority public key is not canonical base64"
                .to_string()
        })?;
    if BASE64_STANDARD.encode(&decoded) != pins.public_key_base64
        || raw_digest(&decoded) != pins.public_key_fingerprint
    {
        return Err(
            "configured PostgreSQL-infrastructure authority public key does not match its canonical independent fingerprint pin"
                .into(),
        );
    }
    decoded.try_into().map_err(|_| {
        "configured PostgreSQL-infrastructure authority public key is not 32 bytes".to_string()
    })
}

fn decode_first_owner_authority_public_key(
    pins: &StartupFirstOwnerAuthorityPins,
) -> Result<[u8; ED25519_AUTHORITY_PUBLIC_KEY_BYTES], String> {
    let decoded = BASE64_STANDARD
        .decode(&pins.public_key_base64)
        .map_err(|_| {
            "configured first-owner authority public key is not canonical base64".to_string()
        })?;
    if BASE64_STANDARD.encode(&decoded) != pins.public_key_base64
        || raw_digest(&decoded) != pins.public_key_fingerprint
    {
        return Err(
            "configured first-owner authority public key does not match its canonical independent fingerprint pin"
                .into(),
        );
    }
    decoded
        .try_into()
        .map_err(|_| "configured first-owner authority public key is not 32 bytes".to_string())
}

fn conformance_document_digests(
    documents: &BTreeMap<String, Value>,
    raw_document_bytes: &BTreeMap<String, Vec<u8>>,
    reference_document_digests: &BTreeMap<String, String>,
) -> Result<Vec<String>, String> {
    let digests = documents
        .iter()
        .filter(|(_, document)| is_conformance_document(document))
        .map(|(locator, _)| {
            let exact_digest = raw_document_bytes
                .get(locator)
                .map(|bytes| raw_digest(bytes))
                .ok_or_else(|| {
                    format!(
                        "conformance document {locator} has no exact raw bytes from reference traversal"
                    )
                })?;
            let reference_digest = reference_document_digests.get(locator).ok_or_else(|| {
                format!(
                    "conformance document {locator} has no verified digest from reference traversal"
                )
            })?;
            if reference_digest != &exact_digest {
                return Err(format!(
                    "conformance document {locator} exact raw bytes do not match the verified reference digest"
                ));
            }
            Ok(reference_digest.clone())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if digests.len() > MAX_CHECKPOINT_DOCUMENT_DIGESTS {
        return Err(format!(
            "production checkpoint lookup requires {} unique conformance document digests, exceeding the bounded maximum of {MAX_CHECKPOINT_DOCUMENT_DIGESTS}",
            digests.len()
        ));
    }
    Ok(digests.into_iter().collect())
}

fn finalize_startup_security_contract(
    mut prepared: PreparedSecurityContract,
    verified_conformance_trust_checkpoint: Option<VerifiedConformanceTrustCheckpoint>,
    verified_deployed_workload: Option<VerifiedDeployedWorkload>,
    mut trusted_now: impl FnMut() -> DateTime<Utc>,
) -> Result<SecurityContractContext, String> {
    let mut verified_conformance_documents = verify_loaded_conformance_documents(
        &prepared.documents,
        &mut prepared.raw_document_bytes,
        &prepared.reference_document_digests,
        verified_conformance_trust_checkpoint.as_ref(),
        &prepared.profile,
        trusted_now(),
    )?;
    let verified_conformance_production_root = if prepared.profile.security_profile.is_production()
    {
        let checkpoint = verified_conformance_trust_checkpoint
            .as_ref()
            .ok_or_else(|| {
                "production serving startup has no externally reconciled conformance checkpoint proof"
                    .to_string()
            })?;
        checkpoint
            .ensure_fresh(trusted_time_point(trusted_now()))
            .map_err(|error| {
                format!(
                    "production conformance checkpoint expired during document verification: {error}"
                )
            })?;
        Some(verify_current_production_root_binding(
            checkpoint,
            &prepared.profile,
            &mut verified_conformance_documents,
        )?)
    } else {
        None
    };

    let conformance_state = if prepared.profile.security_profile.is_production() {
        let checkpoint = verified_conformance_trust_checkpoint.ok_or_else(|| {
            "production startup lost its verified conformance checkpoint before semantic closure"
                .to_string()
        })?;
        let production_root = verified_conformance_production_root.ok_or_else(|| {
            "production startup lost its verified current SB-9 root before semantic closure"
                .to_string()
        })?;
        let deployed_workload = verified_deployed_workload.ok_or_else(|| {
            "production startup lost its verified deployed-workload proof before semantic closure"
                .to_string()
        })?;
        let pinned_build = prepared.production_build_manifest.take().ok_or_else(|| {
            "production startup lost its pinned build manifest before semantic closure".to_string()
        })?;
        let control_trace_bytes = prepared
            .raw_document_bytes
            .remove(&prepared.profile.control_trace_ref.artifact_locator)
            .ok_or_else(|| {
                "production semantic closure has no exact ControlTrace bytes".to_string()
            })?;
        let control_trace =
            verify_control_trace_artifact(&prepared.profile.control_trace_ref, control_trace_bytes)
                .map_err(|error| format!("production ControlTrace proof is invalid: {error}"))?;
        let security_limit_profile = security_limit_applicability_claim(&prepared)?;
        let deployment_claims = ProductionDeploymentApplicabilityClaims {
            checkpoints: vec![DeploymentCheckpointApplicabilityClaim {
                trust_domain_id: checkpoint.trust_domain_id().to_owned(),
                authority_id: checkpoint.authority_id().to_owned(),
                authority_epoch: checkpoint.authority_epoch(),
                sequence: checkpoint.checkpoint_sequence(),
                trust_registry_digest: checkpoint.registry_digest().to_owned(),
                trust_registry_locator: checkpoint.registry_locator().to_owned(),
            }],
            provider_registry: prepared.provider_registry_applicability.clone(),
            security_limit_profile,
            deployed_artifact: deployed_workload.applicability_claim(),
        };
        let derived_context = derive_production_conformance_closure_context(
            &pinned_build.document,
            &prepared.profile,
            &deployment_claims,
            &prepared.profile_raw_bytes,
        )
        .map_err(|error| format!("production conformance closure context is invalid: {error}"))?;
        let verification_started_at = trusted_now();
        let conformance = verify_production_conformance_closure(
            checkpoint,
            production_root,
            verified_conformance_documents.into_values().collect(),
            control_trace,
            ProductionConformanceClosureInputs {
                manifest: &pinned_build.document,
                profile: &prepared.profile,
                deployment_claims: &deployment_claims,
                context: &derived_context,
            },
            trusted_time_point(verification_started_at),
        )
        .map_err(|error| format!("production semantic conformance closure failed: {error}"))?;
        let verification_finished_at = trusted_now();
        let final_semantic_time =
            semantic_verification_window(verification_started_at, verification_finished_at)?;
        ConformanceState::Production(Box::new(VerifiedProductionBoundary::seal(
            conformance,
            deployed_workload,
            pinned_build,
            std::mem::take(&mut prepared.profile_raw_bytes),
            prepared.profile_digest.clone(),
            final_semantic_time,
        )?))
    } else {
        if verified_conformance_trust_checkpoint.is_some()
            || verified_conformance_production_root.is_some()
            || verified_deployed_workload.is_some()
            || prepared.production_build_manifest.is_some()
            || !verified_conformance_documents.is_empty()
        {
            return Err(
                "non-production startup cannot retain detached production proof parts".into(),
            );
        }
        ConformanceState::NonProduction
    };

    validate_runtime_guard_challenge_set(&conformance_state)?;

    // Parse the route/action/resource projection only after the referenced
    // document set and (for production) its external checkpoint/semantic
    // closure have authenticated. This keeps semantic errors from masking a
    // stale or otherwise invalid production proof.
    let request_read_registry_document = prepared
        .documents
        .get(
            &prepared
                .profile
                .action_resource_registry_ref
                .artifact_locator,
        )
        .ok_or_else(|| {
            "request-read action/resource registry did not resolve to retained JSON".to_string()
        })?;
    let request_read_registry =
        request_read_registry_binding(request_read_registry_document, &prepared.profile)?;

    Ok(SecurityContractContext {
        profile: prepared.profile,
        profile_digest: prepared.profile_digest,
        contract_root: prepared.contract_root,
        profile_path: prepared.profile_path,
        conformance_state,
        verified_secure_cookie_guard: None,
        verified_https_public_urls_guard: None,
        verified_approved_secret_provider_guard: None,
        verified_non_development_authenticator_guard: None,
        verified_durable_postgresql_guard: None,
        verified_first_owner_path_closed_guard: None,
        verified_security_limit_profile: prepared.verified_security_limit_profile,
        active_providers: prepared.active_providers,
        provider_registry_applicability: prepared.provider_registry_applicability,
        request_read_registry,
    })
}

fn security_limit_applicability_claim(
    prepared: &PreparedSecurityContract,
) -> Result<SecurityLimitApplicabilityClaim, String> {
    prepared
        .verified_security_limit_profile
        .verify_integrity()?;
    let reference = &prepared.profile.security_limit_profile_ref;
    let document = prepared
        .documents
        .get(&reference.artifact_locator)
        .ok_or_else(|| "security-limit profile reference did not resolve to JSON".to_string())?;
    let raw_bytes = prepared
        .raw_document_bytes
        .get(&reference.artifact_locator)
        .ok_or_else(|| "security-limit profile has no exact raw bytes".to_string())?;
    let traversed_digest = prepared
        .reference_document_digests
        .get(&reference.artifact_locator)
        .ok_or_else(|| "security-limit profile has no verified traversal digest".to_string())?;
    let exact_document = parse_json_strict(raw_bytes)
        .map_err(|error| format!("security-limit profile JSON is invalid: {error}"))?;
    if raw_digest(raw_bytes) != reference.content_digest
        || traversed_digest != &reference.content_digest
        || &exact_document != document
        || document.get("contract_kind").and_then(Value::as_str) != Some("security-limit-profile")
        || document.get("document_id").and_then(Value::as_str)
            != Some(reference.document_id.as_str())
        || document.get("document_version").and_then(Value::as_u64)
            != Some(reference.document_version)
        || &prepared.verified_security_limit_profile.reference != reference
        || prepared.verified_security_limit_profile.raw_bytes.as_ref() != raw_bytes.as_slice()
        || &prepared.verified_security_limit_profile.document != document
    {
        return Err(
            "security-limit applicability claim differs from the exact profile-selected artifact"
                .into(),
        );
    }
    Ok(SecurityLimitApplicabilityClaim {
        document_id: reference.document_id.clone(),
        document_version: reference.document_version,
        content_digest: reference.content_digest.clone(),
        artifact_locator: reference.artifact_locator.clone(),
        profile_version: required_u64(document, "profile_version", "security-limit profile")?,
    })
}

fn verify_security_limit_profile(
    reference: &VersionedContentReference,
    profile: &DeploymentSecurityProfile,
    admitted_at: DateTime<Utc>,
    documents: &BTreeMap<String, Value>,
    raw_document_bytes: &BTreeMap<String, Vec<u8>>,
    reference_document_digests: &BTreeMap<String, String>,
) -> Result<VerifiedSecurityLimitProfile, String> {
    let document = documents
        .get(&reference.artifact_locator)
        .ok_or_else(|| "security-limit profile reference did not resolve to JSON".to_string())?;
    let raw_bytes = raw_document_bytes
        .get(&reference.artifact_locator)
        .ok_or_else(|| "security-limit profile has no exact raw bytes".to_string())?;
    let traversed_digest = reference_document_digests
        .get(&reference.artifact_locator)
        .ok_or_else(|| "security-limit profile has no verified traversal digest".to_string())?;
    if traversed_digest != &reference.content_digest {
        return Err(
            "security-limit profile traversal digest differs from the selected reference".into(),
        );
    }
    VerifiedSecurityLimitProfile::seal(
        reference.clone(),
        raw_bytes.clone(),
        document,
        SecurityLimitDeploymentSelection::from_profile(profile, admitted_at),
    )
}

fn verify_current_production_root_binding(
    checkpoint: &VerifiedConformanceTrustCheckpoint,
    profile: &DeploymentSecurityProfile,
    documents: &mut BTreeMap<String, VerifiedConformanceArtifact>,
) -> Result<VerifiedConformanceProductionRoot, String> {
    let reference = profile
        .production_acceptance_receipt_ref
        .as_ref()
        .ok_or_else(|| "production profile has no selected SB-9 receipt".to_string())?;
    let artifact = documents
        .remove(&reference.artifact_locator)
        .ok_or_else(|| {
            "profile-selected SB-9 receipt has no authenticated document proof".to_string()
        })?;
    let root = checkpoint
        .verify_current_production_root(artifact)
        .map_err(|error| format!("production root assertion is untrusted: {error}"))?;
    if root.document_id() != reference.document_id
        || root.document_version() != reference.document_version
        || root.content_digest() != reference.content_digest
        || root.artifact_locator() != reference.artifact_locator
    {
        return Err(
            "external current production root differs from the exact profile-selected SB-9 receipt"
                .into(),
        );
    }
    Ok(root)
}

fn trusted_time_point(now: DateTime<Utc>) -> ConformanceTrustedTimeWindow {
    ConformanceTrustedTimeWindow {
        not_before: now,
        not_after: now,
    }
}

fn semantic_verification_window(
    verification_started_at: DateTime<Utc>,
    verification_finished_at: DateTime<Utc>,
) -> Result<ConformanceTrustedTimeWindow, String> {
    if verification_finished_at < verification_started_at {
        return Err(
            "trusted time moved backwards during production semantic closure verification".into(),
        );
    }
    Ok(ConformanceTrustedTimeWindow {
        not_before: verification_started_at,
        not_after: verification_finished_at,
    })
}

fn validate_runtime_guard_challenge_set(
    conformance_state: &ConformanceState,
) -> Result<(), String> {
    let ConformanceState::Production(boundary) = conformance_state else {
        return Ok(());
    };
    let challenges = boundary.runtime_guard_challenges().collect::<Vec<_>>();
    if challenges.len() != 8 {
        return Err(
            "production semantic closure lost the exact eight runtime guard requirements".into(),
        );
    }
    let required_guard_ids = [
        GuardId::DurablePostgresql,
        GuardId::ApprovedSecretProvider,
        GuardId::HttpsPublicUrls,
        GuardId::SecureCookies,
        GuardId::NonDevelopmentAuthenticator,
        GuardId::ExternalSigningKeyMaterial,
        GuardId::MockDependenciesDisabled,
        GuardId::FirstOwnerPathClosed,
    ];
    if required_guard_ids.iter().any(|required| {
        challenges
            .iter()
            .filter(|challenge| challenge.guard_id() == *required)
            .count()
            != 1
    }) {
        return Err(
            "production semantic closure lost the unique complete runtime guard set".into(),
        );
    }
    if challenges.iter().any(|challenge| {
        challenge.guard_id() != challenge.expected_value().guard_id()
            || validate_digest_pin(
                "production runtime guard requirement digest",
                challenge.requirement_digest(),
            )
            .is_err()
            || validate_digest_pin(
                "production runtime guard challenge binding digest",
                challenge.challenge_binding_digest(),
            )
            .is_err()
            || challenge.requirement_digest() == challenge.challenge_binding_digest()
    }) {
        return Err(
            "production runtime guard challenges lost their typed semantic or workload binding"
                .into(),
        );
    }
    Ok(())
}

#[cfg(test)]
fn reject_incomplete_runtime_guard_admission(
    conformance_state: &ConformanceState,
) -> Result<(), String> {
    validate_runtime_guard_challenge_set(conformance_state)?;
    let ConformanceState::Production(boundary) = conformance_state else {
        return Ok(());
    };
    Err(format!(
        "production semantic closure {} is verified and sealed to the pinned build and deployed workload, but startup remains blocked until all eight receipt-bound live runtime guard witnesses are verified",
        boundary.conformance.closure_digest(),
    ))
}

fn load_pinned_conformance_trust_root_registry(
    store: &mut ArtifactStore,
    pins: &StartupSecurityPins,
    profile: &DeploymentSecurityProfile,
    now: DateTime<Utc>,
) -> Result<Option<ValidatedConformanceRegistryLineage>, String> {
    let reference = &profile.conformance_trust_root_registry_ref;
    let reference_path = Path::new(&reference.artifact_locator);
    if reference_path != pins.conformance_trust_root_registry_path.as_path() {
        return Err(
            "deployment profile trust-root registry path does not match the independent startup pin"
                .into(),
        );
    }
    if reference.content_digest != pins.conformance_trust_root_registry_digest {
        return Err(
            "deployment profile trust-root registry digest does not match the independent startup pin"
                .into(),
        );
    }

    let head_binding = ReferenceBinding {
        locator: reference.artifact_locator.clone(),
        digest: reference.content_digest.clone(),
        artifact_kind: Some("conformance-trust-root-registry".into()),
        document_id: Some(reference.document_id.clone()),
        document_version: Some(reference.document_version),
    };
    let lineage = load_conformance_trust_root_registry_lineage(store, head_binding)?;
    let head = lineage
        .last()
        .ok_or_else(|| "conformance trust-root registry lineage is empty".to_string())?;
    validate_conformance_trust_root_registry_lifecycle(&head.document, profile, now)?;

    let validated_lineage = if profile.security_profile.is_production() {
        let artifacts = lineage
            .iter()
            .map(|artifact| ConformanceRegistryArtifact {
                artifact_locator: &artifact.locator,
                raw_bytes: &artifact.raw_bytes,
            })
            .collect::<Vec<_>>();
        Some(
            ValidatedConformanceRegistryLineage::from_registry_chain(
                &artifacts,
                ConformanceTrustAnchor {
                    artifact_locator: &reference.artifact_locator,
                    document_id: &reference.document_id,
                    document_version: reference.document_version,
                    content_digest: &pins.conformance_trust_root_registry_digest,
                },
                now,
            )
            .map_err(|error| format!("conformance trust-root registry is not trusted: {error}"))?,
        )
    } else {
        None
    };
    Ok(validated_lineage)
}

#[derive(Debug)]
struct LoadedConformanceRegistryArtifact {
    locator: String,
    raw_bytes: Vec<u8>,
    document: Value,
}

fn load_conformance_trust_root_registry_lineage(
    store: &mut ArtifactStore,
    head: ReferenceBinding,
) -> Result<Vec<LoadedConformanceRegistryArtifact>, String> {
    let mut current = head;
    let mut newest_to_oldest = Vec::new();
    let mut locator_digests = BTreeMap::<String, String>::new();
    let mut identity_digests = BTreeMap::<(String, u64), String>::new();

    loop {
        if newest_to_oldest.len() >= MAX_REFERENCE_DEPTH {
            return Err(format!(
                "conformance trust-root registry lineage exceeds {MAX_REFERENCE_DEPTH} documents"
            ));
        }
        if current.artifact_kind.as_deref() != Some("conformance-trust-root-registry") {
            return Err(
                "conformance trust-root registry predecessor has the wrong artifact kind".into(),
            );
        }
        let document_id = current.document_id.as_deref().ok_or_else(|| {
            "conformance trust-root registry reference omits document_id".to_string()
        })?;
        let document_version = current.document_version.ok_or_else(|| {
            "conformance trust-root registry reference omits document_version".to_string()
        })?;
        if document_version == 0 {
            return Err(
                "conformance trust-root registry reference requires a positive document_version"
                    .into(),
            );
        }
        validate_digest_pin(
            "conformance trust-root registry reference digest",
            &current.digest,
        )?;
        let locator = PathBuf::from(&current.locator);
        validate_json_relative_path("conformance trust-root registry locator", &locator)?;

        if let Some(previous_digest) = locator_digests.get(&current.locator) {
            if previous_digest != &current.digest {
                return Err(format!(
                    "conformance trust-root registry locator {} is referenced with conflicting digests",
                    current.locator
                ));
            }
            return Err(format!(
                "conformance trust-root registry lineage contains a locator cycle at {}",
                current.locator
            ));
        }
        let identity = (document_id.to_owned(), document_version);
        if let Some(previous_digest) = identity_digests.get(&identity) {
            if previous_digest != &current.digest {
                return Err(format!(
                    "conformance trust-root registry {document_id}@{document_version} is referenced with conflicting digests"
                ));
            }
            return Err(format!(
                "conformance trust-root registry lineage repeats {document_id}@{document_version}"
            ));
        }
        locator_digests.insert(current.locator.clone(), current.digest.clone());
        identity_digests.insert(identity, current.digest.clone());

        let bytes = store.read(&locator, MAX_ARTIFACT_BYTES)?;
        let actual_digest = raw_digest(&bytes);
        if actual_digest != current.digest {
            return Err(format!(
                "conformance trust-root registry {} digest mismatch: expected {}, got {actual_digest}",
                current.locator, current.digest
            ));
        }
        let registry = parse_json_strict(&bytes).map_err(|error| {
            format!(
                "conformance trust-root registry {} JSON is invalid: {error}",
                current.locator
            )
        })?;
        validate_against_schema(
            "conformance trust-root registry",
            CONFORMANCE_TRUST_ROOT_REGISTRY_SCHEMA,
            &registry,
        )?;
        validate_reference_identity(&current, &registry)?;
        validate_typed_reference_document(&current, &registry)?;

        let predecessor_value = registry
            .get("predecessor_registry_ref")
            .ok_or_else(|| {
                format!(
                    "conformance trust-root registry {document_id}@{document_version} omits predecessor_registry_ref"
                )
            })?;
        let predecessor = if document_version == 1 {
            if !predecessor_value.is_null() {
                return Err(
                    "conformance trust-root registry version 1 must have a null predecessor_registry_ref"
                        .into(),
                );
            }
            None
        } else {
            if predecessor_value.is_null() {
                return Err(format!(
                    "conformance trust-root registry {document_id}@{document_version} has an incomplete lineage"
                ));
            }
            let predecessor: ConformanceRegistryPredecessorReference =
                serde_json::from_value(predecessor_value.clone()).map_err(|error| {
                    format!(
                        "conformance trust-root registry {document_id}@{document_version} has an invalid predecessor_registry_ref: {error}"
                    )
                })?;
            if predecessor.artifact_kind != "conformance-trust-root-registry" {
                return Err(format!(
                    "conformance trust-root registry {document_id}@{document_version} predecessor has the wrong artifact kind"
                ));
            }
            if predecessor.document_id != document_id {
                return Err(format!(
                    "conformance trust-root registry {document_id}@{document_version} predecessor changes document identity"
                ));
            }
            if predecessor.document_version != document_version - 1 {
                return Err(format!(
                    "conformance trust-root registry {document_id}@{document_version} predecessor must be version {}",
                    document_version - 1
                ));
            }
            Some(ReferenceBinding {
                locator: predecessor.artifact_locator,
                digest: predecessor.content_digest,
                artifact_kind: Some(predecessor.artifact_kind),
                document_id: Some(predecessor.document_id),
                document_version: Some(predecessor.document_version),
            })
        };
        newest_to_oldest.push(LoadedConformanceRegistryArtifact {
            locator: current.locator.clone(),
            raw_bytes: bytes,
            document: registry,
        });

        let Some(predecessor) = predecessor else {
            break;
        };
        current = predecessor;
    }

    newest_to_oldest.reverse();
    Ok(newest_to_oldest)
}

fn validate_conformance_trust_root_registry_lifecycle(
    registry: &Value,
    profile: &DeploymentSecurityProfile,
    now: DateTime<Utc>,
) -> Result<(), String> {
    let lifecycle = registry
        .get("lifecycle")
        .ok_or_else(|| "conformance trust-root registry omits lifecycle".to_string())?;
    let state = lifecycle
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| "conformance trust-root registry omits lifecycle.state".to_string())?;
    let effective_at = lifecycle
        .get("effective_at")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            "conformance trust-root registry omits lifecycle.effective_at".to_string()
        })?;
    let effective_at = DateTime::parse_from_rfc3339(effective_at)
        .map_err(|_| {
            "conformance trust-root registry lifecycle.effective_at is invalid".to_string()
        })?
        .with_timezone(&Utc);
    if effective_at > now {
        return Err("conformance trust-root registry lifecycle is future-dated".into());
    }

    let applicability = registry
        .get("applicability")
        .ok_or_else(|| "conformance trust-root registry omits applicability".to_string())?;
    if applicability
        .get("evaluation_scope")
        .and_then(Value::as_str)
        != Some("deployment")
    {
        return Err(
            "conformance trust-root registry applicability must be deployment-scoped".into(),
        );
    }
    for (field, expected) in [
        (
            "security_profiles",
            profile
                .applicability
                .security_profiles
                .iter()
                .map(|profile| profile.as_str().to_owned())
                .collect::<BTreeSet<_>>(),
        ),
        (
            "deployment_ids",
            profile
                .applicability
                .deployment_ids
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>(),
        ),
        (
            "trust_domain_ids",
            profile
                .trust_topology
                .trust_domain_ids
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>(),
        ),
    ] {
        let actual = json_string_set(applicability, field)?;
        if actual != expected {
            return Err(format!(
                "conformance trust-root registry applicability {field} does not exactly match the deployment profile"
            ));
        }
    }

    match state {
        "active" => Ok(()),
        "implementation_only"
            if profile.security_profile.admits_development_fixture()
                && profile
                    .enabled_features
                    .iter()
                    .any(|feature| feature == "repository-conformance")
                && profile
                    .enabled_features
                    .iter()
                    .any(|feature| feature == "static-dry-run") =>
        {
            Ok(())
        }
        "implementation_only" => Err(
            "implementation-only conformance trust-root registry requires the explicit test/development repository fixture"
                .into(),
        ),
        _ => Err(format!(
            "conformance trust-root registry lifecycle {state} cannot authenticate closure"
        )),
    }
}

fn verify_loaded_conformance_documents(
    documents: &BTreeMap<String, Value>,
    raw_document_bytes: &mut BTreeMap<String, Vec<u8>>,
    reference_document_digests: &BTreeMap<String, String>,
    trust_checkpoint: Option<&VerifiedConformanceTrustCheckpoint>,
    profile: &DeploymentSecurityProfile,
    trusted_now: DateTime<Utc>,
) -> Result<BTreeMap<String, VerifiedConformanceArtifact>, String> {
    let conformance_documents = documents
        .iter()
        .filter(|(_, document)| is_conformance_document(document))
        .collect::<Vec<_>>();
    if conformance_documents.is_empty() {
        return Ok(BTreeMap::new());
    }
    let trust_checkpoint = trust_checkpoint.ok_or_else(|| {
        "signed conformance documents require a fresh, independently authenticated external checkpoint lookup"
            .to_string()
    })?;
    let [trust_domain_id] = profile.trust_topology.trust_domain_ids.as_slice() else {
        return Err(
            "signed conformance documents require exactly one trust domain until per-document trust-domain binding is implemented"
                .into(),
        );
    };

    let control_trace = documents
        .get(&profile.control_trace_ref.artifact_locator)
        .ok_or_else(|| {
            "ControlTrace reference did not resolve before closure verification".to_string()
        })?;
    let mut trace_packages = BTreeMap::new();
    for trace in control_trace
        .get("traces")
        .and_then(Value::as_array)
        .ok_or_else(|| "ControlTrace omits traces".to_string())?
    {
        let trace_id = trace
            .get("trace_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "ControlTrace entry omits trace_id".to_string())?;
        let package_id = trace
            .get("owning_work_package")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("ControlTrace entry {trace_id} omits owning_work_package"))?;
        if trace_packages
            .insert(trace_id.to_owned(), package_id.to_owned())
            .is_some()
        {
            return Err(format!(
                "ControlTrace contains duplicate trace_id {trace_id}"
            ));
        }
    }

    let mut verified = BTreeMap::new();
    for (locator, document) in conformance_documents {
        let kind = document
            .get("contract_kind")
            .and_then(Value::as_str)
            .expect("filtered conformance document has a kind");
        let (package_id, tier_name) = match kind {
            "conformance-bundle" => {
                let trace_id = document
                    .get("trace_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("conformance bundle {locator} omits trace_id"))?;
                let package_id = trace_packages.get(trace_id).ok_or_else(|| {
                    format!("conformance bundle {locator} cites unknown trace_id {trace_id}")
                })?;
                let tier = document
                    .pointer("/provenance/evidence_tier/name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("conformance bundle {locator} omits evidence tier"))?;
                (package_id.as_str(), tier)
            }
            "package-exit-receipt" => {
                let package_id = document
                    .get("package_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("package receipt {locator} omits package_id"))?;
                let tier = document
                    .pointer("/evidence_tier/name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("package receipt {locator} omits evidence tier"))?;
                (package_id, tier)
            }
            _ => unreachable!("filtered conformance document kind"),
        };
        let evidence_tier = match tier_name {
            "repository_local" => EvidenceTier::RepositoryLocal,
            "operator_environment" => EvidenceTier::OperatorEnvironment,
            "externally_attested" => EvidenceTier::ExternallyAttested,
            _ => {
                return Err(format!(
                    "conformance document {locator} has unknown evidence tier"
                ));
            }
        };
        let raw_document = raw_document_bytes.remove(locator).ok_or_else(|| {
            format!(
                "conformance document {locator} has no exact raw bytes from reference traversal"
            )
        })?;
        let reference_digest = reference_document_digests.get(locator).ok_or_else(|| {
            format!(
                "conformance document {locator} has no verified digest from reference traversal"
            )
        })?;
        let artifact = trust_checkpoint
            .verify_artifact(
                ConformanceArtifactCandidate::new(
                    (*locator).clone(),
                    reference_digest.clone(),
                    raw_document,
                ),
                ConformanceVerificationContext {
                    deployment_id: &profile.deployment_id,
                    trust_domain_id,
                    package_id,
                    evidence_tier,
                },
                trusted_time_point(trusted_now),
            )
            .map_err(|error| format!("conformance document {locator} is untrusted: {error}"))?;
        if artifact.document() != document {
            return Err(format!(
                "conformance document {locator} is untrusted: sealed document does not match the validated traversal value"
            ));
        }
        verified.insert((*locator).clone(), artifact);
    }
    Ok(verified)
}

fn is_conformance_document(document: &Value) -> bool {
    matches!(
        document.get("contract_kind").and_then(Value::as_str),
        Some("conformance-bundle" | "package-exit-receipt")
    )
}

fn json_string_set(value: &Value, field: &str) -> Result<BTreeSet<String>, String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{field} must be an array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{field} must contain only strings"))
        })
        .collect()
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

fn optional_unicode(
    get: &mut impl FnMut(&str) -> Option<OsString>,
    name: &str,
) -> Result<Option<String>, String> {
    let Some(value) = get(name) else {
        return Ok(None);
    };
    let value = value
        .into_string()
        .map_err(|_| format!("{name} must contain valid UTF-8"))?;
    if value.is_empty() || value.trim() != value {
        return Err(format!(
            "{name} must be non-empty and contain no surrounding whitespace"
        ));
    }
    Ok(Some(value))
}

fn optional_trust_checkpoint_authority(
    get: &mut impl FnMut(&str) -> Option<OsString>,
) -> Result<Option<StartupTrustCheckpointAuthorityPins>, String> {
    let socket_path = optional_unicode(get, CONFORMANCE_TRUST_CHECKPOINT_SOCKET_ENV)?;
    let authority_id = optional_unicode(get, CONFORMANCE_TRUST_CHECKPOINT_AUTHORITY_ID_ENV)?;
    let key_id = optional_unicode(get, CONFORMANCE_TRUST_CHECKPOINT_KEY_ID_ENV)?;
    let public_key_base64 =
        optional_unicode(get, CONFORMANCE_TRUST_CHECKPOINT_PUBLIC_KEY_BASE64_ENV)?;
    let public_key_fingerprint =
        optional_unicode(get, CONFORMANCE_TRUST_CHECKPOINT_PUBLIC_KEY_FINGERPRINT_ENV)?;
    let minimum_authority_epoch =
        optional_unicode(get, CONFORMANCE_TRUST_CHECKPOINT_MIN_AUTHORITY_EPOCH_ENV)?;

    let any_present = socket_path.is_some()
        || authority_id.is_some()
        || key_id.is_some()
        || public_key_base64.is_some()
        || public_key_fingerprint.is_some()
        || minimum_authority_epoch.is_some();
    if !any_present {
        return Ok(None);
    }

    let socket_path = socket_path.ok_or_else(|| {
        format!(
            "{CONFORMANCE_TRUST_CHECKPOINT_SOCKET_ENV} is required when any conformance trust-checkpoint authority binding is configured"
        )
    })?;
    let authority_id = authority_id.ok_or_else(|| {
        format!(
            "{CONFORMANCE_TRUST_CHECKPOINT_AUTHORITY_ID_ENV} is required when any conformance trust-checkpoint authority binding is configured"
        )
    })?;
    let key_id = key_id.ok_or_else(|| {
        format!(
            "{CONFORMANCE_TRUST_CHECKPOINT_KEY_ID_ENV} is required when any conformance trust-checkpoint authority binding is configured"
        )
    })?;
    let public_key_base64 = public_key_base64.ok_or_else(|| {
        format!(
            "{CONFORMANCE_TRUST_CHECKPOINT_PUBLIC_KEY_BASE64_ENV} is required when any conformance trust-checkpoint authority binding is configured"
        )
    })?;
    let public_key_fingerprint = public_key_fingerprint.ok_or_else(|| {
        format!(
            "{CONFORMANCE_TRUST_CHECKPOINT_PUBLIC_KEY_FINGERPRINT_ENV} is required when any conformance trust-checkpoint authority binding is configured"
        )
    })?;
    let minimum_authority_epoch = minimum_authority_epoch.ok_or_else(|| {
        format!(
            "{CONFORMANCE_TRUST_CHECKPOINT_MIN_AUTHORITY_EPOCH_ENV} is required when any conformance trust-checkpoint authority binding is configured"
        )
    })?;

    validate_absolute_socket_path(CONFORMANCE_TRUST_CHECKPOINT_SOCKET_ENV, &socket_path)?;
    validate_namespaced_id(
        CONFORMANCE_TRUST_CHECKPOINT_AUTHORITY_ID_ENV,
        &authority_id,
        "conformance-trust-checkpoint-authority:",
    )?;
    validate_namespaced_id(
        CONFORMANCE_TRUST_CHECKPOINT_KEY_ID_ENV,
        &key_id,
        "conformance-trust-checkpoint-key:",
    )?;
    validate_digest_pin(
        CONFORMANCE_TRUST_CHECKPOINT_PUBLIC_KEY_FINGERPRINT_ENV,
        &public_key_fingerprint,
    )?;
    let public_key = BASE64_STANDARD
        .decode(&public_key_base64)
        .map_err(|_| {
            format!(
                "{CONFORMANCE_TRUST_CHECKPOINT_PUBLIC_KEY_BASE64_ENV} must be canonical base64 for a 32-byte Ed25519 public key"
            )
        })?;
    if public_key.len() != ED25519_AUTHORITY_PUBLIC_KEY_BYTES
        || BASE64_STANDARD.encode(&public_key) != public_key_base64
    {
        return Err(format!(
            "{CONFORMANCE_TRUST_CHECKPOINT_PUBLIC_KEY_BASE64_ENV} must be canonical base64 for a 32-byte Ed25519 public key"
        ));
    }
    if raw_digest(&public_key) != public_key_fingerprint {
        return Err(format!(
            "{CONFORMANCE_TRUST_CHECKPOINT_PUBLIC_KEY_FINGERPRINT_ENV} does not match the decoded authority public key"
        ));
    }
    let minimum_authority_epoch = parse_positive_exact_json_integer(
        CONFORMANCE_TRUST_CHECKPOINT_MIN_AUTHORITY_EPOCH_ENV,
        &minimum_authority_epoch,
    )?;

    Ok(Some(StartupTrustCheckpointAuthorityPins {
        socket_path: PathBuf::from(socket_path),
        authority_id,
        key_id,
        public_key_base64,
        public_key_fingerprint,
        minimum_authority_epoch,
    }))
}

fn optional_deployed_workload_attestation(
    get: &mut impl FnMut(&str) -> Option<OsString>,
) -> Result<Option<StartupDeployedWorkloadAttestationPins>, String> {
    let socket_path = optional_unicode(get, DEPLOYED_WORKLOAD_ATTESTATION_SOCKET_ENV)?;
    let authority_id = optional_unicode(get, DEPLOYED_WORKLOAD_ATTESTATION_AUTHORITY_ID_ENV)?;
    let key_id = optional_unicode(get, DEPLOYED_WORKLOAD_ATTESTATION_KEY_ID_ENV)?;
    let public_key_base64 =
        optional_unicode(get, DEPLOYED_WORKLOAD_ATTESTATION_PUBLIC_KEY_BASE64_ENV)?;
    let public_key_fingerprint = optional_unicode(
        get,
        DEPLOYED_WORKLOAD_ATTESTATION_PUBLIC_KEY_FINGERPRINT_ENV,
    )?;
    let minimum_authority_epoch =
        optional_unicode(get, DEPLOYED_WORKLOAD_ATTESTATION_MIN_AUTHORITY_EPOCH_ENV)?;
    let measurement_profile_id = optional_unicode(
        get,
        DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_ID_ENV,
    )?;
    let measurement_profile_version = optional_unicode(
        get,
        DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_VERSION_ENV,
    )?;
    let measurement_profile_digest = optional_unicode(
        get,
        DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_DIGEST_ENV,
    )?;
    let workload_id = optional_unicode(get, EXPECTED_WORKLOAD_ID_ENV)?;

    let any_present = [
        socket_path.as_ref(),
        authority_id.as_ref(),
        key_id.as_ref(),
        public_key_base64.as_ref(),
        public_key_fingerprint.as_ref(),
        minimum_authority_epoch.as_ref(),
        measurement_profile_id.as_ref(),
        measurement_profile_version.as_ref(),
        measurement_profile_digest.as_ref(),
        workload_id.as_ref(),
    ]
    .into_iter()
    .any(|value| value.is_some());
    if !any_present {
        return Ok(None);
    }

    let required = |value: Option<String>, name: &str| {
        value.ok_or_else(|| {
            format!(
                "{name} is required when any deployed-workload attestation binding is configured"
            )
        })
    };
    let socket_path = required(socket_path, DEPLOYED_WORKLOAD_ATTESTATION_SOCKET_ENV)?;
    let authority_id = required(authority_id, DEPLOYED_WORKLOAD_ATTESTATION_AUTHORITY_ID_ENV)?;
    let key_id = required(key_id, DEPLOYED_WORKLOAD_ATTESTATION_KEY_ID_ENV)?;
    let public_key_base64 = required(
        public_key_base64,
        DEPLOYED_WORKLOAD_ATTESTATION_PUBLIC_KEY_BASE64_ENV,
    )?;
    let public_key_fingerprint = required(
        public_key_fingerprint,
        DEPLOYED_WORKLOAD_ATTESTATION_PUBLIC_KEY_FINGERPRINT_ENV,
    )?;
    let minimum_authority_epoch = required(
        minimum_authority_epoch,
        DEPLOYED_WORKLOAD_ATTESTATION_MIN_AUTHORITY_EPOCH_ENV,
    )?;
    let measurement_profile_id = required(
        measurement_profile_id,
        DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_ID_ENV,
    )?;
    let measurement_profile_version = required(
        measurement_profile_version,
        DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_VERSION_ENV,
    )?;
    let measurement_profile_digest = required(
        measurement_profile_digest,
        DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_DIGEST_ENV,
    )?;
    let workload_id = required(workload_id, EXPECTED_WORKLOAD_ID_ENV)?;

    validate_absolute_socket_path(DEPLOYED_WORKLOAD_ATTESTATION_SOCKET_ENV, &socket_path)?;
    validate_namespaced_id(
        DEPLOYED_WORKLOAD_ATTESTATION_AUTHORITY_ID_ENV,
        &authority_id,
        "deployed-workload-attestation-authority:",
    )?;
    validate_namespaced_id(
        DEPLOYED_WORKLOAD_ATTESTATION_KEY_ID_ENV,
        &key_id,
        "deployed-workload-attestation-key:",
    )?;
    validate_namespaced_id(
        DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_ID_ENV,
        &measurement_profile_id,
        "deployed-workload-measurement-profile:",
    )?;
    validate_namespaced_id(EXPECTED_WORKLOAD_ID_ENV, &workload_id, "workload:")?;
    validate_digest_pin(
        DEPLOYED_WORKLOAD_ATTESTATION_PUBLIC_KEY_FINGERPRINT_ENV,
        &public_key_fingerprint,
    )?;
    validate_digest_pin(
        DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_DIGEST_ENV,
        &measurement_profile_digest,
    )?;
    let public_key = BASE64_STANDARD
        .decode(&public_key_base64)
        .map_err(|_| {
            format!(
                "{DEPLOYED_WORKLOAD_ATTESTATION_PUBLIC_KEY_BASE64_ENV} must be canonical base64 for a 32-byte Ed25519 public key"
            )
        })?;
    if public_key.len() != ED25519_AUTHORITY_PUBLIC_KEY_BYTES
        || BASE64_STANDARD.encode(&public_key) != public_key_base64
    {
        return Err(format!(
            "{DEPLOYED_WORKLOAD_ATTESTATION_PUBLIC_KEY_BASE64_ENV} must be canonical base64 for a 32-byte Ed25519 public key"
        ));
    }
    if raw_digest(&public_key) != public_key_fingerprint {
        return Err(format!(
            "{DEPLOYED_WORKLOAD_ATTESTATION_PUBLIC_KEY_FINGERPRINT_ENV} does not match the decoded authority public key"
        ));
    }
    let minimum_authority_epoch = parse_positive_exact_json_integer(
        DEPLOYED_WORKLOAD_ATTESTATION_MIN_AUTHORITY_EPOCH_ENV,
        &minimum_authority_epoch,
    )?;
    let measurement_profile_version = parse_positive_exact_json_integer(
        DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_VERSION_ENV,
        &measurement_profile_version,
    )?;

    Ok(Some(StartupDeployedWorkloadAttestationPins {
        socket_path: PathBuf::from(socket_path),
        authority_id,
        key_id,
        public_key_base64,
        public_key_fingerprint,
        minimum_authority_epoch,
        measurement_profile_id,
        measurement_profile_version,
        measurement_profile_digest,
        workload_id,
    }))
}

fn optional_public_ingress_attestation(
    get: &mut impl FnMut(&str) -> Option<OsString>,
) -> Result<Option<StartupPublicIngressAttestationPins>, String> {
    let socket_path = optional_unicode(get, PUBLIC_INGRESS_ATTESTATION_SOCKET_ENV)?;
    let authority_id = optional_unicode(get, PUBLIC_INGRESS_ATTESTATION_AUTHORITY_ID_ENV)?;
    let key_id = optional_unicode(get, PUBLIC_INGRESS_ATTESTATION_KEY_ID_ENV)?;
    let public_key_base64 =
        optional_unicode(get, PUBLIC_INGRESS_ATTESTATION_PUBLIC_KEY_BASE64_ENV)?;
    let public_key_fingerprint =
        optional_unicode(get, PUBLIC_INGRESS_ATTESTATION_PUBLIC_KEY_FINGERPRINT_ENV)?;
    let minimum_authority_epoch =
        optional_unicode(get, PUBLIC_INGRESS_ATTESTATION_MIN_AUTHORITY_EPOCH_ENV)?;
    let attestation_profile_id = optional_unicode(get, PUBLIC_INGRESS_ATTESTATION_PROFILE_ID_ENV)?;
    let attestation_profile_version =
        optional_unicode(get, PUBLIC_INGRESS_ATTESTATION_PROFILE_VERSION_ENV)?;
    let attestation_profile_digest =
        optional_unicode(get, PUBLIC_INGRESS_ATTESTATION_PROFILE_DIGEST_ENV)?;

    let any_present = [
        socket_path.as_ref(),
        authority_id.as_ref(),
        key_id.as_ref(),
        public_key_base64.as_ref(),
        public_key_fingerprint.as_ref(),
        minimum_authority_epoch.as_ref(),
        attestation_profile_id.as_ref(),
        attestation_profile_version.as_ref(),
        attestation_profile_digest.as_ref(),
    ]
    .into_iter()
    .any(|value| value.is_some());
    if !any_present {
        return Ok(None);
    }

    let required = |value: Option<String>, name: &str| {
        value.ok_or_else(|| {
            format!("{name} is required when any public-ingress attestation binding is configured")
        })
    };
    let socket_path = required(socket_path, PUBLIC_INGRESS_ATTESTATION_SOCKET_ENV)?;
    let authority_id = required(authority_id, PUBLIC_INGRESS_ATTESTATION_AUTHORITY_ID_ENV)?;
    let key_id = required(key_id, PUBLIC_INGRESS_ATTESTATION_KEY_ID_ENV)?;
    let public_key_base64 = required(
        public_key_base64,
        PUBLIC_INGRESS_ATTESTATION_PUBLIC_KEY_BASE64_ENV,
    )?;
    let public_key_fingerprint = required(
        public_key_fingerprint,
        PUBLIC_INGRESS_ATTESTATION_PUBLIC_KEY_FINGERPRINT_ENV,
    )?;
    let minimum_authority_epoch = required(
        minimum_authority_epoch,
        PUBLIC_INGRESS_ATTESTATION_MIN_AUTHORITY_EPOCH_ENV,
    )?;
    let attestation_profile_id = required(
        attestation_profile_id,
        PUBLIC_INGRESS_ATTESTATION_PROFILE_ID_ENV,
    )?;
    let attestation_profile_version = required(
        attestation_profile_version,
        PUBLIC_INGRESS_ATTESTATION_PROFILE_VERSION_ENV,
    )?;
    let attestation_profile_digest = required(
        attestation_profile_digest,
        PUBLIC_INGRESS_ATTESTATION_PROFILE_DIGEST_ENV,
    )?;

    validate_absolute_socket_path(PUBLIC_INGRESS_ATTESTATION_SOCKET_ENV, &socket_path)?;
    validate_namespaced_id(
        PUBLIC_INGRESS_ATTESTATION_AUTHORITY_ID_ENV,
        &authority_id,
        "public-ingress-attestation-authority:",
    )?;
    validate_namespaced_id(
        PUBLIC_INGRESS_ATTESTATION_KEY_ID_ENV,
        &key_id,
        "public-ingress-attestation-key:",
    )?;
    validate_namespaced_id(
        PUBLIC_INGRESS_ATTESTATION_PROFILE_ID_ENV,
        &attestation_profile_id,
        "ingress-attestation-profile:",
    )?;
    validate_digest_pin(
        PUBLIC_INGRESS_ATTESTATION_PUBLIC_KEY_FINGERPRINT_ENV,
        &public_key_fingerprint,
    )?;
    validate_digest_pin(
        PUBLIC_INGRESS_ATTESTATION_PROFILE_DIGEST_ENV,
        &attestation_profile_digest,
    )?;
    let public_key = BASE64_STANDARD.decode(&public_key_base64).map_err(|_| {
        format!(
            "{PUBLIC_INGRESS_ATTESTATION_PUBLIC_KEY_BASE64_ENV} must be canonical base64 for a 32-byte Ed25519 public key"
        )
    })?;
    if public_key.len() != ED25519_AUTHORITY_PUBLIC_KEY_BYTES
        || BASE64_STANDARD.encode(&public_key) != public_key_base64
    {
        return Err(format!(
            "{PUBLIC_INGRESS_ATTESTATION_PUBLIC_KEY_BASE64_ENV} must be canonical base64 for a 32-byte Ed25519 public key"
        ));
    }
    if raw_digest(&public_key) != public_key_fingerprint {
        return Err(format!(
            "{PUBLIC_INGRESS_ATTESTATION_PUBLIC_KEY_FINGERPRINT_ENV} does not match the decoded authority public key"
        ));
    }
    let minimum_authority_epoch = parse_positive_exact_json_integer(
        PUBLIC_INGRESS_ATTESTATION_MIN_AUTHORITY_EPOCH_ENV,
        &minimum_authority_epoch,
    )?;
    let attestation_profile_version = parse_positive_exact_json_integer(
        PUBLIC_INGRESS_ATTESTATION_PROFILE_VERSION_ENV,
        &attestation_profile_version,
    )?;

    Ok(Some(StartupPublicIngressAttestationPins {
        socket_path: PathBuf::from(socket_path),
        authority_id,
        key_id,
        public_key_base64,
        public_key_fingerprint,
        minimum_authority_epoch,
        attestation_profile_id,
        attestation_profile_version,
        attestation_profile_digest,
    }))
}

fn optional_postgresql_infrastructure_attestation(
    get: &mut impl FnMut(&str) -> Option<OsString>,
) -> Result<Option<StartupPostgresqlInfrastructureAttestationPins>, String> {
    let socket_path = optional_unicode(get, POSTGRESQL_INFRASTRUCTURE_ATTESTATION_SOCKET_ENV)?;
    let authority_id =
        optional_unicode(get, POSTGRESQL_INFRASTRUCTURE_ATTESTATION_AUTHORITY_ID_ENV)?;
    let key_id = optional_unicode(get, POSTGRESQL_INFRASTRUCTURE_ATTESTATION_KEY_ID_ENV)?;
    let public_key_base64 = optional_unicode(
        get,
        POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_BASE64_ENV,
    )?;
    let public_key_fingerprint = optional_unicode(
        get,
        POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_FINGERPRINT_ENV,
    )?;
    let minimum_authority_epoch = optional_unicode(
        get,
        POSTGRESQL_INFRASTRUCTURE_ATTESTATION_MIN_AUTHORITY_EPOCH_ENV,
    )?;
    let attestation_profile_id =
        optional_unicode(get, POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_ID_ENV)?;
    let attestation_profile_version = optional_unicode(
        get,
        POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_VERSION_ENV,
    )?;
    let attestation_profile_digest = optional_unicode(
        get,
        POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_DIGEST_ENV,
    )?;

    let any_present = [
        socket_path.as_ref(),
        authority_id.as_ref(),
        key_id.as_ref(),
        public_key_base64.as_ref(),
        public_key_fingerprint.as_ref(),
        minimum_authority_epoch.as_ref(),
        attestation_profile_id.as_ref(),
        attestation_profile_version.as_ref(),
        attestation_profile_digest.as_ref(),
    ]
    .into_iter()
    .any(|value| value.is_some());
    if !any_present {
        return Ok(None);
    }

    let required = |value: Option<String>, name: &str| {
        value.ok_or_else(|| {
            format!(
                "{name} is required when any PostgreSQL-infrastructure attestation binding is configured"
            )
        })
    };
    let socket_path = required(
        socket_path,
        POSTGRESQL_INFRASTRUCTURE_ATTESTATION_SOCKET_ENV,
    )?;
    let authority_id = required(
        authority_id,
        POSTGRESQL_INFRASTRUCTURE_ATTESTATION_AUTHORITY_ID_ENV,
    )?;
    let key_id = required(key_id, POSTGRESQL_INFRASTRUCTURE_ATTESTATION_KEY_ID_ENV)?;
    let public_key_base64 = required(
        public_key_base64,
        POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_BASE64_ENV,
    )?;
    let public_key_fingerprint = required(
        public_key_fingerprint,
        POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_FINGERPRINT_ENV,
    )?;
    let minimum_authority_epoch = required(
        minimum_authority_epoch,
        POSTGRESQL_INFRASTRUCTURE_ATTESTATION_MIN_AUTHORITY_EPOCH_ENV,
    )?;
    let attestation_profile_id = required(
        attestation_profile_id,
        POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_ID_ENV,
    )?;
    let attestation_profile_version = required(
        attestation_profile_version,
        POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_VERSION_ENV,
    )?;
    let attestation_profile_digest = required(
        attestation_profile_digest,
        POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_DIGEST_ENV,
    )?;

    validate_absolute_socket_path(
        POSTGRESQL_INFRASTRUCTURE_ATTESTATION_SOCKET_ENV,
        &socket_path,
    )?;
    validate_namespaced_id(
        POSTGRESQL_INFRASTRUCTURE_ATTESTATION_AUTHORITY_ID_ENV,
        &authority_id,
        "postgresql-infrastructure-attestation-authority:",
    )?;
    validate_namespaced_id(
        POSTGRESQL_INFRASTRUCTURE_ATTESTATION_KEY_ID_ENV,
        &key_id,
        "postgresql-infrastructure-attestation-key:",
    )?;
    validate_namespaced_id(
        POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_ID_ENV,
        &attestation_profile_id,
        "postgresql-infrastructure-attestation-profile:",
    )?;
    validate_digest_pin(
        POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_FINGERPRINT_ENV,
        &public_key_fingerprint,
    )?;
    validate_digest_pin(
        POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_DIGEST_ENV,
        &attestation_profile_digest,
    )?;
    let public_key = BASE64_STANDARD.decode(&public_key_base64).map_err(|_| {
        format!(
            "{POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_BASE64_ENV} must be canonical base64 for a 32-byte Ed25519 public key"
        )
    })?;
    if public_key.len() != ED25519_AUTHORITY_PUBLIC_KEY_BYTES
        || BASE64_STANDARD.encode(&public_key) != public_key_base64
    {
        return Err(format!(
            "{POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_BASE64_ENV} must be canonical base64 for a 32-byte Ed25519 public key"
        ));
    }
    if raw_digest(&public_key) != public_key_fingerprint {
        return Err(format!(
            "{POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_FINGERPRINT_ENV} does not match the decoded authority public key"
        ));
    }
    let key_bytes: [u8; ED25519_AUTHORITY_PUBLIC_KEY_BYTES] = public_key
        .as_slice()
        .try_into()
        .map_err(|_| {
            format!(
                "{POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_BASE64_ENV} must encode a valid Ed25519 public key"
            )
        })?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| {
        format!(
            "{POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_BASE64_ENV} must encode a valid Ed25519 public key"
        )
    })?;
    if verifying_key.is_weak() {
        return Err(format!(
            "{POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_BASE64_ENV} must not encode a weak Ed25519 public key"
        ));
    }
    let minimum_authority_epoch = parse_positive_exact_json_integer(
        POSTGRESQL_INFRASTRUCTURE_ATTESTATION_MIN_AUTHORITY_EPOCH_ENV,
        &minimum_authority_epoch,
    )?;
    let attestation_profile_version = parse_positive_exact_json_integer(
        POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_VERSION_ENV,
        &attestation_profile_version,
    )?;

    Ok(Some(StartupPostgresqlInfrastructureAttestationPins {
        socket_path: PathBuf::from(socket_path),
        authority_id,
        key_id,
        public_key_base64,
        public_key_fingerprint,
        minimum_authority_epoch,
        attestation_profile_id,
        attestation_profile_version,
        attestation_profile_digest,
    }))
}

fn optional_first_owner_authority(
    get: &mut impl FnMut(&str) -> Option<OsString>,
) -> Result<Option<StartupFirstOwnerAuthorityPins>, String> {
    let authority_id = optional_unicode(get, FIRST_OWNER_AUTHORITY_ID_ENV)?;
    let key_id = optional_unicode(get, FIRST_OWNER_AUTHORITY_KEY_ID_ENV)?;
    let public_key_base64 = optional_unicode(get, FIRST_OWNER_AUTHORITY_PUBLIC_KEY_BASE64_ENV)?;
    let public_key_fingerprint =
        optional_unicode(get, FIRST_OWNER_AUTHORITY_PUBLIC_KEY_FINGERPRINT_ENV)?;
    let minimum_authority_epoch = optional_unicode(get, FIRST_OWNER_AUTHORITY_MIN_EPOCH_ENV)?;

    let any_present = [
        authority_id.as_ref(),
        key_id.as_ref(),
        public_key_base64.as_ref(),
        public_key_fingerprint.as_ref(),
        minimum_authority_epoch.as_ref(),
    ]
    .into_iter()
    .any(|value| value.is_some());
    if !any_present {
        return Ok(None);
    }

    let required = |value: Option<String>, name: &str| {
        value.ok_or_else(|| {
            format!("{name} is required when any first-owner authority binding is configured")
        })
    };
    let authority_id = required(authority_id, FIRST_OWNER_AUTHORITY_ID_ENV)?;
    let key_id = required(key_id, FIRST_OWNER_AUTHORITY_KEY_ID_ENV)?;
    let public_key_base64 = required(
        public_key_base64,
        FIRST_OWNER_AUTHORITY_PUBLIC_KEY_BASE64_ENV,
    )?;
    let public_key_fingerprint = required(
        public_key_fingerprint,
        FIRST_OWNER_AUTHORITY_PUBLIC_KEY_FINGERPRINT_ENV,
    )?;
    let minimum_authority_epoch =
        required(minimum_authority_epoch, FIRST_OWNER_AUTHORITY_MIN_EPOCH_ENV)?;

    validate_namespaced_id(
        FIRST_OWNER_AUTHORITY_ID_ENV,
        &authority_id,
        "first-owner-authority:",
    )?;
    validate_namespaced_id(
        FIRST_OWNER_AUTHORITY_KEY_ID_ENV,
        &key_id,
        "first-owner-authority-key:",
    )?;
    validate_digest_pin(
        FIRST_OWNER_AUTHORITY_PUBLIC_KEY_FINGERPRINT_ENV,
        &public_key_fingerprint,
    )?;
    let public_key = BASE64_STANDARD.decode(&public_key_base64).map_err(|_| {
        format!(
            "{FIRST_OWNER_AUTHORITY_PUBLIC_KEY_BASE64_ENV} must be canonical base64 for a 32-byte Ed25519 public key"
        )
    })?;
    if public_key.len() != ED25519_AUTHORITY_PUBLIC_KEY_BYTES
        || BASE64_STANDARD.encode(&public_key) != public_key_base64
    {
        return Err(format!(
            "{FIRST_OWNER_AUTHORITY_PUBLIC_KEY_BASE64_ENV} must be canonical base64 for a 32-byte Ed25519 public key"
        ));
    }
    if raw_digest(&public_key) != public_key_fingerprint {
        return Err(format!(
            "{FIRST_OWNER_AUTHORITY_PUBLIC_KEY_FINGERPRINT_ENV} does not match the decoded authority public key"
        ));
    }
    let key_bytes: [u8; ED25519_AUTHORITY_PUBLIC_KEY_BYTES] = public_key
        .as_slice()
        .try_into()
        .map_err(|_| {
            format!(
                "{FIRST_OWNER_AUTHORITY_PUBLIC_KEY_BASE64_ENV} must encode a valid Ed25519 public key"
            )
        })?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| {
        format!(
            "{FIRST_OWNER_AUTHORITY_PUBLIC_KEY_BASE64_ENV} must encode a valid Ed25519 public key"
        )
    })?;
    if verifying_key.is_weak() {
        return Err(format!(
            "{FIRST_OWNER_AUTHORITY_PUBLIC_KEY_BASE64_ENV} must not encode a weak Ed25519 public key"
        ));
    }
    let minimum_authority_epoch = parse_positive_exact_json_integer(
        FIRST_OWNER_AUTHORITY_MIN_EPOCH_ENV,
        &minimum_authority_epoch,
    )?;

    Ok(Some(StartupFirstOwnerAuthorityPins {
        authority_id,
        key_id,
        public_key_base64,
        public_key_fingerprint,
        minimum_authority_epoch,
    }))
}

fn optional_first_owner_closure_certificate(
    get: &mut impl FnMut(&str) -> Option<OsString>,
) -> Result<Option<StartupFirstOwnerClosureCertificatePins>, String> {
    let path = optional_unicode(get, FIRST_OWNER_CLOSURE_CERTIFICATE_PATH_ENV)?;
    let digest = optional_unicode(get, FIRST_OWNER_CLOSURE_CERTIFICATE_DIGEST_ENV)?;
    if path.is_none() && digest.is_none() {
        return Ok(None);
    }
    let path = path.ok_or_else(|| {
        format!(
            "{FIRST_OWNER_CLOSURE_CERTIFICATE_PATH_ENV} is required when {FIRST_OWNER_CLOSURE_CERTIFICATE_DIGEST_ENV} is configured"
        )
    })?;
    let digest = digest.ok_or_else(|| {
        format!(
            "{FIRST_OWNER_CLOSURE_CERTIFICATE_DIGEST_ENV} is required when {FIRST_OWNER_CLOSURE_CERTIFICATE_PATH_ENV} is configured"
        )
    })?;
    validate_json_absolute_path(FIRST_OWNER_CLOSURE_CERTIFICATE_PATH_ENV, &path)?;
    validate_digest_pin(FIRST_OWNER_CLOSURE_CERTIFICATE_DIGEST_ENV, &digest)?;
    Ok(Some(StartupFirstOwnerClosureCertificatePins {
        path: PathBuf::from(path),
        digest,
    }))
}

fn optional_production_build_manifest(
    get: &mut impl FnMut(&str) -> Option<OsString>,
) -> Result<Option<StartupProductionBuildManifestPins>, String> {
    let path = optional_unicode(get, PRODUCTION_BUILD_MANIFEST_PATH_ENV)?;
    let digest = optional_unicode(get, PRODUCTION_BUILD_MANIFEST_DIGEST_ENV)?;
    if path.is_none() && digest.is_none() {
        return Ok(None);
    }
    let path = path.ok_or_else(|| {
        format!(
            "{PRODUCTION_BUILD_MANIFEST_PATH_ENV} is required when {PRODUCTION_BUILD_MANIFEST_DIGEST_ENV} is configured"
        )
    })?;
    let digest = digest.ok_or_else(|| {
        format!(
            "{PRODUCTION_BUILD_MANIFEST_DIGEST_ENV} is required when {PRODUCTION_BUILD_MANIFEST_PATH_ENV} is configured"
        )
    })?;
    validate_json_absolute_path(PRODUCTION_BUILD_MANIFEST_PATH_ENV, &path)?;
    validate_digest_pin(PRODUCTION_BUILD_MANIFEST_DIGEST_ENV, &digest)?;
    Ok(Some(StartupProductionBuildManifestPins {
        path: PathBuf::from(path),
        digest,
    }))
}

fn validate_absolute_socket_path(name: &str, raw: &str) -> Result<(), String> {
    let path = Path::new(raw);
    let components_are_lexically_normal = raw.strip_prefix('/').is_some_and(|suffix| {
        !suffix.is_empty()
            && !suffix
                .split('/')
                .any(|component| component.is_empty() || matches!(component, "." | ".."))
    });
    if raw.len() > MAX_AUTHORITY_SOCKET_PATH_BYTES
        || !path.is_absolute()
        || path.file_name().is_none()
        || raw.as_bytes().contains(&0)
        || raw.contains('\\')
        || !components_are_lexically_normal
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(format!(
            "{name} must be a normalized absolute Unix-domain socket path"
        ));
    }
    Ok(())
}

fn parse_positive_exact_json_integer(name: &str, raw: &str) -> Result<u64, String> {
    let value = raw.parse::<u64>().map_err(|_| {
        format!(
            "{name} must be a canonical positive base-10 integer no larger than {MAX_EXACT_JSON_INTEGER}"
        )
    })?;
    if value == 0 || value > MAX_EXACT_JSON_INTEGER || value.to_string() != raw {
        return Err(format!(
            "{name} must be a canonical positive base-10 integer no larger than {MAX_EXACT_JSON_INTEGER}"
        ));
    }
    Ok(value)
}

fn validate_json_absolute_path(name: &str, raw: &str) -> Result<(), String> {
    let path = Path::new(raw);
    let components_are_lexically_normal = raw.strip_prefix('/').is_some_and(|suffix| {
        !suffix.is_empty()
            && !suffix
                .split('/')
                .any(|component| component.is_empty() || matches!(component, "." | ".."))
    });
    if raw.len() > 4096
        || !path.is_absolute()
        || raw.contains('\\')
        || !components_are_lexically_normal
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(format!(
            "{name} must be a normalized absolute .json file path"
        ));
    }
    if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
        return Err(format!(
            "{name} must be a normalized absolute .json file path"
        ));
    }
    Ok(())
}

fn read_pinned_absolute_regular_file(
    label: &str,
    path: &Path,
    expected_digest: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, String> {
    let raw_path = path
        .to_str()
        .ok_or_else(|| format!("{label} path must contain valid UTF-8"))?;
    validate_json_absolute_path(label, raw_path)?;
    crate::pinned_file::read_stable_pinned_file(label, path, expected_digest, max_bytes)
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
    let raw = path
        .to_str()
        .ok_or_else(|| format!("{name} must contain valid UTF-8"))?;
    if raw.is_empty()
        || path.is_absolute()
        || raw.contains('\\')
        || raw
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("{name} must be a normalized relative path"));
    }
    Ok(())
}

fn validate_json_relative_path(name: &str, path: &Path) -> Result<(), String> {
    validate_relative_path(name, path)?;
    if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
        return Err(format!(
            "{name} must select a normalized relative .json path"
        ));
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

fn unique_registry_entry<'a>(
    document: &'a Value,
    collection: &str,
    key: &str,
    expected: &str,
) -> Result<&'a Value, String> {
    let entries = document
        .get(collection)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("action registry {collection} is not an array"))?;
    let mut matches = entries
        .iter()
        .filter(|entry| entry.get(key).and_then(Value::as_str) == Some(expected));
    let entry = matches
        .next()
        .ok_or_else(|| format!("action registry omits {key}={expected}"))?;
    if matches.next().is_some() {
        return Err(format!("action registry duplicates {key}={expected}"));
    }
    Ok(entry)
}

fn unique_route_mapping<'a>(
    document: &'a Value,
    method: &str,
    path_template: &str,
) -> Result<&'a Value, String> {
    let entries = document
        .get("route_mappings")
        .and_then(Value::as_array)
        .ok_or_else(|| "action registry route_mappings is not an array".to_string())?;
    let mut matches = entries.iter().filter(|entry| {
        entry.get("method").and_then(Value::as_str) == Some(method)
            && entry.get("path_template").and_then(Value::as_str) == Some(path_template)
    });
    let entry = matches.next().ok_or_else(|| {
        format!("action registry omits route mapping ({method}, {path_template})")
    })?;
    if matches.next().is_some() {
        return Err(format!(
            "action registry duplicates route mapping ({method}, {path_template})"
        ));
    }
    Ok(entry)
}

fn request_read_registry_binding(
    document: &Value,
    profile: &DeploymentSecurityProfile,
) -> Result<RequestReadRegistryBinding, String> {
    let registry_version = required_u64(document, "registry_version", "action registry")?;
    let profile_name = profile.security_profile.as_str();
    if !document
        .pointer("/applicability/security_profiles")
        .and_then(Value::as_array)
        .is_some_and(|profiles| profiles.iter().any(|value| value == profile_name))
    {
        return Err(format!(
            "request-read action registry does not apply to {profile_name}"
        ));
    }
    if profile.security_profile.is_production()
        && (document.pointer("/lifecycle/state") != Some(&Value::String("active".into()))
            || document.pointer("/applicability/evaluation_scope")
                != Some(&Value::String("deployment".into()))
            || document.pointer("/inventory_closure/coverage_status")
                != Some(&Value::String("complete".into()))
            || document.pointer("/inventory_closure/router_inventory_equal")
                != Some(&Value::Bool(true))
            || document.pointer("/inventory_closure/unknown_entries_rejected")
                != Some(&Value::Bool(true)))
    {
        return Err(
            "production request-read activation requires an active deployment registry with complete router closure"
                .into(),
        );
    }

    let actor_kinds = serde_json::json!(["verified-human", "service", "development-fixture"]);
    let read_action = unique_registry_entry(document, "actions", "action_id", "request.read")?;
    if read_action.get("resource_kind") != Some(&Value::String("request".into()))
        || read_action.get("permitted_actor_kinds") != Some(&actor_kinds)
        || read_action.get("authorization_semantics") != Some(&Value::String("instance".into()))
        || read_action.get("obligations") != Some(&serde_json::json!(["audit"]))
        || read_action.get("risk_class") != Some(&Value::String("ordinary".into()))
        || read_action.get("lifecycle") != Some(&Value::String("active".into()))
        || read_action.get("applicability_expression") != Some(&Value::String("always".into()))
    {
        return Err("request.read action semantics differ from the permit adapter".into());
    }
    let list_action = unique_registry_entry(document, "actions", "action_id", "request.list")?;
    if list_action.get("resource_kind") != Some(&Value::String("request".into()))
        || list_action.get("permitted_actor_kinds") != Some(&actor_kinds)
        || list_action.get("authorization_semantics") != Some(&Value::String("query".into()))
        || list_action.get("obligations") != Some(&serde_json::json!(["audit"]))
        || list_action.get("risk_class") != Some(&Value::String("ordinary".into()))
        || list_action.get("lifecycle") != Some(&Value::String("active".into()))
        || list_action.get("applicability_expression") != Some(&Value::String("always".into()))
    {
        return Err("request.list action semantics differ from the permit adapter".into());
    }

    let resource = unique_registry_entry(document, "resources", "resource_kind", "request")?;
    let required_fields = serde_json::json!([
        "resource_kind",
        "canonical_id",
        "deployment_id",
        "trust_domain_id",
        "tenant_id",
        "site_id",
        "environment_id",
        "owner_principal_id",
        "resource_version",
        "state_digest",
        "sensitivity",
        "lifecycle_state"
    ]);
    let scope_dimensions = serde_json::json!([
        "deployment_id",
        "trust_domain_id",
        "tenant_id",
        "site_id",
        "environment_id",
        "owner_principal_id"
    ]);
    if resource.get("canonical_id_pattern") != Some(&Value::String("^request:[a-z0-9-]+$".into()))
        || resource.get("resolver_id")
            != Some(&Value::String("resolver:request-instance-v1".into()))
        || resource.get("resolver_version") != Some(&Value::Number(1_u64.into()))
        || resource.get("scope_dimensions") != Some(&scope_dimensions)
        || resource.get("requires_security_version") != Some(&Value::Bool(true))
        || resource.get("aliases_allowed") != Some(&Value::Bool(false))
        || resource.get("sensitivity") != Some(&Value::String("confidential".into()))
        || resource.pointer("/canonical_resource_ref/schema_version")
            != Some(&Value::Number(1_u64.into()))
        || resource.pointer("/canonical_resource_ref/required_fields") != Some(&required_fields)
        || resource.pointer("/canonical_resource_ref/security_version_field")
            != Some(&Value::String("resource_version".into()))
        || resource.pointer("/canonical_resource_ref/canonicalization")
            != Some(&Value::String("resolve-before-policy".into()))
        || resource.get("lifecycle") != Some(&Value::String("active".into()))
        || resource.get("applicability_expression") != Some(&Value::String("always".into()))
    {
        return Err("request resource semantics differ from the permit adapter".into());
    }

    let read_resolver = unique_registry_entry(
        document,
        "resolvers",
        "resolver_id",
        "resolver:request-instance-v1",
    )?;
    if read_resolver.get("resolver_version") != Some(&Value::Number(1_u64.into()))
        || read_resolver.get("resource_kind") != Some(&Value::String("request".into()))
        || read_resolver.get("mode") != Some(&Value::String("instance".into()))
        || read_resolver.get("canonical_id_source") != Some(&Value::String("requests.id".into()))
        || read_resolver.get("security_version_source")
            != Some(&Value::String("requests.resource_version".into()))
        || read_resolver.get("state_digest_source")
            != Some(&Value::String("job_steps.(id,xmin)".into()))
        || read_resolver.get("permit_kind") != Some(&Value::String("AuthorizationPermit".into()))
        || read_resolver.get("fail_closed") != Some(&Value::Bool(true))
        || read_resolver.get("lifecycle") != Some(&Value::String("active".into()))
        || read_resolver.get("applicability_expression") != Some(&Value::String("always".into()))
    {
        return Err("request resolver semantics differ from the permit adapter".into());
    }
    let list_resolver = unique_registry_entry(
        document,
        "resolvers",
        "resolver_id",
        "resolver:request-query-v1",
    )?;
    if list_resolver.get("resolver_version") != Some(&Value::Number(1_u64.into()))
        || list_resolver.get("resource_kind") != Some(&Value::String("request".into()))
        || list_resolver.get("mode") != Some(&Value::String("collection".into()))
        || list_resolver.get("canonical_id_source")
            != Some(&Value::String("constant:request:collection".into()))
        || list_resolver.get("security_version_source")
            != Some(&Value::String("maximum-authority-binding.version".into()))
        || list_resolver.get("state_digest_source")
            != Some(&Value::String("maximum-authority-binding.digest".into()))
        || list_resolver.get("permit_kind") != Some(&Value::String("QueryPermit".into()))
        || list_resolver.get("fail_closed") != Some(&Value::Bool(true))
        || list_resolver.get("lifecycle") != Some(&Value::String("active".into()))
        || list_resolver.get("applicability_expression") != Some(&Value::String("always".into()))
    {
        return Err("request-list resolver semantics differ from the permit adapter".into());
    }

    let read_route = unique_route_mapping(document, "GET", "/api/requests/{id}")?;
    if read_route.get("mapping_id") != Some(&Value::String("route:request-read-v1".into()))
        || read_route.get("action_id") != Some(&Value::String("request.read".into()))
        || read_route.get("resource_kind") != Some(&Value::String("request".into()))
        || read_route.get("resolver_id")
            != Some(&Value::String("resolver:request-instance-v1".into()))
        || read_route.get("resolver_version") != Some(&Value::Number(1_u64.into()))
        || read_route.get("permit_kind") != Some(&Value::String("AuthorizationPermit".into()))
        || read_route.get("permitted_actor_kinds") != Some(&actor_kinds)
        || read_route.get("lifecycle") != Some(&Value::String("active".into()))
        || read_route.get("applicability_expression") != Some(&Value::String("always".into()))
        || read_route.get("source_file")
            != Some(&Value::String("sources/ryuki-api/src/contracts.rs".into()))
    {
        return Err("request-read route semantics differ from the permit adapter".into());
    }
    let list_route = unique_route_mapping(document, "GET", "/api/requests")?;
    if list_route.get("mapping_id") != Some(&Value::String("route:request-list-v1".into()))
        || list_route.get("action_id") != Some(&Value::String("request.list".into()))
        || list_route.get("resource_kind") != Some(&Value::String("request".into()))
        || list_route.get("resolver_id") != Some(&Value::String("resolver:request-query-v1".into()))
        || list_route.get("resolver_version") != Some(&Value::Number(1_u64.into()))
        || list_route.get("permit_kind") != Some(&Value::String("QueryPermit".into()))
        || list_route.get("permitted_actor_kinds") != Some(&actor_kinds)
        || list_route.get("lifecycle") != Some(&Value::String("active".into()))
        || list_route.get("applicability_expression") != Some(&Value::String("always".into()))
        || list_route.get("source_file")
            != Some(&Value::String("sources/ryuki-api/src/contracts.rs".into()))
    {
        return Err("request-list route semantics differ from the permit adapter".into());
    }

    let projection = serde_json::json!({
        "digest_contract": MAXIMUM_AUTHORITY_BINDING_DIGEST_CONTRACT,
        "registry_version": registry_version,
        "actions": [list_action, read_action],
        "resource": resource,
        "resolvers": [read_resolver, list_resolver],
        "routes": [list_route, read_route],
    });
    Ok(RequestReadRegistryBinding {
        registry_version,
        maximum_authority_digest: maximum_authority_binding_digest(&projection)?,
    })
}

fn maximum_authority_binding_digest(projection: &Value) -> Result<String, String> {
    maximum_authority_binding_digest_for_domain(
        MAXIMUM_AUTHORITY_BINDING_DIGEST_CONTRACT,
        projection,
    )
}

fn maximum_authority_binding_digest_for_domain(
    domain: &str,
    projection: &Value,
) -> Result<String, String> {
    let canonical = canonical_json_bytes(projection).map_err(|error| {
        format!("request-read maximum-authority projection is not canonicalizable: {error}")
    })?;
    let mut hasher = Sha256::new();
    for frame in [domain.as_bytes(), canonical.as_slice()] {
        hasher.update((frame.len() as u64).to_le_bytes());
        hasher.update(frame);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
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
    document_bytes: BTreeMap<String, Vec<u8>>,
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
            document_bytes: BTreeMap::new(),
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
        self.document_bytes.insert(reference.locator.clone(), bytes);
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
                    "source:ryuki-api-build-identity",
                    "sources/ryuki-api/src/build_identity.rs"
                )
                | (
                    "source:ryuki-api-contracts",
                    "sources/ryuki-api/src/contracts.rs"
                )
                | (
                    "source:ryuki-api-scheduler",
                    "sources/ryuki-api/src/scheduler.rs"
                )
                | ("source:ryuki-api-agents", "sources/ryuki-api/src/agents.rs")
                | (
                    "source:ryuki-api-request-authority",
                    "sources/ryuki-api/src/request_authority.rs"
                )
                | (
                    "source:ryuki-api-request-read-repository",
                    "sources/ryuki-api/src/repos/requests.rs"
                )
                | (
                    "source:ryuki-api-job-steps-repository",
                    "sources/ryuki-api/src/repos/job_steps.rs"
                )
                | (
                    "source:ryuki-api-degradation-repository",
                    "sources/ryuki-api/src/repos/degradation.rs"
                )
                | (
                    "source:ryuki-api-database-boundary",
                    "sources/ryuki-api/src/database.rs"
                )
                | (
                    "source:ryuki-api-postgresql-tls-channel",
                    "sources/ryuki-api/src/postgresql_tls_channel.rs"
                )
                | (
                    "source:ryuki-api-first-owner-runtime",
                    "sources/ryuki-api/src/first_owner_runtime.rs"
                )
                | (
                    "source:ryuki-api-production-dependencies",
                    "sources/ryuki-api/src/production_dependencies.rs"
                )
                | (
                    "source:ryuki-api-audit-repository",
                    "sources/ryuki-api/src/audit.rs"
                )
                | (
                    "source:ryuki-api-entra-auth",
                    "sources/ryuki-api/src/entra_auth.rs"
                )
                | (
                    "source:ryuki-api-identity-authority",
                    "sources/ryuki-api/src/identity_authority.rs"
                )
                | (
                    "source:ryuki-api-security-contract-loader",
                    "sources/ryuki-api/src/security_contracts.rs"
                )
                | (
                    "source:ryuki-core-postgresql-infrastructure",
                    "sources/ryuki-core/src/postgresql_infrastructure.rs"
                )
                | (
                    "source:ryuki-engine-authorization-kernel",
                    "sources/ryuki-engine/src/authorization.rs"
                )
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
        .or_else(|| object.get("reference_digest"))
        .or_else(|| object.get("bundle_digest"))
        .or_else(|| object.get("receipt_digest"))
        .or_else(|| object.get("ledger_digest"))?
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
            .or_else(|| object.get("receipt_id"))
            .or_else(|| object.get("bundle_id"))
            .or_else(|| object.get("ledger_id"))
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
            .or_else(|| document.get("bundle_id"))
            .or_else(|| document.get("ledger_id"))
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
        Some("conformance-trust-root-registry") => require_contract_document(
            reference,
            document,
            schema_uri,
            "conformance-trust-root-registry",
            "https://ryuki.io/schemas/security-contracts/v1/conformance-trust-root-registry.schema.json",
            CONFORMANCE_TRUST_ROOT_REGISTRY_SCHEMA,
        ),
        Some("control-trace") => require_contract_document(
            reference,
            document,
            schema_uri,
            "control-trace",
            "https://ryuki.io/schemas/security-contracts/v1/control-trace.schema.json",
            CONTROL_TRACE_SCHEMA,
        ),
        Some("conformance-bundle") => require_contract_document(
            reference,
            document,
            schema_uri,
            "conformance-bundle",
            "https://ryuki.io/schemas/security-contracts/v1/conformance-bundle.schema.json",
            CONFORMANCE_BUNDLE_SCHEMA,
        ),
        Some("provider-registry") => require_contract_document(
            reference,
            document,
            schema_uri,
            "provider-registry",
            "https://ryuki.io/schemas/security-contracts/v1/provider-registry.schema.json",
            PROVIDER_SCHEMA,
        ),
        Some("authenticator-runtime-binding") => require_contract_document(
            reference,
            document,
            schema_uri,
            "authenticator-runtime-binding",
            "https://ryuki.io/schemas/security-contracts/v1/authenticator-runtime-binding.schema.json",
            AUTHENTICATOR_RUNTIME_BINDING_SCHEMA,
        ),
        Some("secret-provider-runtime-binding") => require_contract_document(
            reference,
            document,
            schema_uri,
            "secret-provider-runtime-binding",
            "https://ryuki.io/schemas/security-contracts/v1/secret-provider-runtime-binding.schema.json",
            SECRET_PROVIDER_RUNTIME_BINDING_SCHEMA,
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
        Some("package-exit-receipt") => require_contract_document(
            reference,
            document,
            schema_uri,
            "package-exit-receipt",
            "https://ryuki.io/schemas/security-contracts/v1/package-exit-receipt.schema.json",
            PACKAGE_EXIT_RECEIPT_SCHEMA,
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
                "https://ryuki.io/schemas/security-contracts/v1/conformance-trust-root-registry.schema.json",
            ) => require_contract_document(
                reference,
                document,
                schema_uri,
                "conformance-trust-root-registry",
                "https://ryuki.io/schemas/security-contracts/v1/conformance-trust-root-registry.schema.json",
                CONFORMANCE_TRUST_ROOT_REGISTRY_SCHEMA,
            ),
            Some("https://ryuki.io/schemas/security-contracts/v1/control-trace.schema.json") => {
                require_contract_document(
                    reference,
                    document,
                    schema_uri,
                    "control-trace",
                    "https://ryuki.io/schemas/security-contracts/v1/control-trace.schema.json",
                    CONTROL_TRACE_SCHEMA,
                )
            }
            Some(
                "https://ryuki.io/schemas/security-contracts/v1/conformance-bundle.schema.json",
            ) => require_contract_document(
                reference,
                document,
                schema_uri,
                "conformance-bundle",
                "https://ryuki.io/schemas/security-contracts/v1/conformance-bundle.schema.json",
                CONFORMANCE_BUNDLE_SCHEMA,
            ),
            Some(
                "https://ryuki.io/schemas/security-contracts/v1/package-exit-receipt.schema.json",
            ) => require_contract_document(
                reference,
                document,
                schema_uri,
                "package-exit-receipt",
                "https://ryuki.io/schemas/security-contracts/v1/package-exit-receipt.schema.json",
                PACKAGE_EXIT_RECEIPT_SCHEMA,
            ),
            Some(
                "https://ryuki.io/schemas/security-contracts/v1/provider-registry.schema.json",
            ) => validate_against_schema("provider registry", PROVIDER_SCHEMA, document),
            Some(
                "https://ryuki.io/schemas/security-contracts/v1/authenticator-runtime-binding.schema.json",
            ) => require_contract_document(
                reference,
                document,
                schema_uri,
                "authenticator-runtime-binding",
                "https://ryuki.io/schemas/security-contracts/v1/authenticator-runtime-binding.schema.json",
                AUTHENTICATOR_RUNTIME_BINDING_SCHEMA,
            ),
            Some(
                "https://ryuki.io/schemas/security-contracts/v1/secret-provider-runtime-binding.schema.json",
            ) => require_contract_document(
                reference,
                document,
                schema_uri,
                "secret-provider-runtime-binding",
                "https://ryuki.io/schemas/security-contracts/v1/secret-provider-runtime-binding.schema.json",
                SECRET_PROVIDER_RUNTIME_BINDING_SCHEMA,
            ),
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
    document_bytes: &BTreeMap<String, Vec<u8>>,
    reference_document_digests: &BTreeMap<String, String>,
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
        let typed_configuration = parse_active_provider_configuration(
            configuration,
            profile,
            documents,
            document_bytes,
            reference_document_digests,
        )?;
        typed_configs.insert((provider_id.into(), version), typed_configuration);
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
                let previous_effective = lifecycle_effective_at(previous)?;
                let effective = lifecycle_effective_at(record)?;
                if effective < previous_effective {
                    return Err(format!(
                        "provider lifecycle {provider_id}@{config_version} effective_at chronology regresses from record {previous_version} to {version}"
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
        let (latest_record_version, latest) = history.last().expect("non-empty lifecycle history");
        if required_str(latest, "state", "provider lifecycle")? == "active" {
            let configuration = typed_configs
                .get(&(provider_id.clone(), config_version))
                .expect("lifecycle configuration checked above");
            let mut configuration = configuration.clone();
            configuration.active_lifecycle_record_version = *latest_record_version;
            let raw_configuration = configs
                .get(&(provider_id.clone(), config_version))
                .expect("active lifecycle configuration checked above");
            if !profile
                .trust_topology
                .trust_domain_ids
                .iter()
                .any(|candidate| candidate == &configuration.trust_domain_id)
            {
                return Err(format!(
                    "active provider {provider_id}@{config_version} uses an unbound trust domain"
                ));
            }
            if !string_set(raw_configuration.get("allowed_security_profiles"))
                .contains(profile.security_profile.as_str())
            {
                return Err(format!(
                    "active provider {provider_id}@{config_version} is not allowed in the selected profile"
                ));
            }
            if configuration.kind == "development-fixture"
                && profile.security_profile.is_production()
            {
                return Err("active development provider is never applicable to production".into());
            }
            if profile.security_profile.is_production()
                && configuration.kind == "secret-service"
                && configuration
                    .verified_secret_provider_runtime_binding()
                    .is_none()
            {
                return Err(format!(
                    "active production secret-service provider {provider_id}@{config_version} uses the legacy five-reference policy shape; a verified secret-provider runtime binding document is required"
                ));
            }
            if profile.security_profile.is_production()
                && matches!(configuration.kind.as_str(), "oidc" | "oidc-broker")
            {
                let binding = configuration
                    .verified_authenticator_runtime_binding()
                    .ok_or_else(|| {
                        format!(
                            "active production authenticator provider {provider_id}@{config_version} has no exact verified runtime-binding document"
                        )
                    })?;
                binding.verify_integrity().map_err(|error| {
                    format!(
                        "active production authenticator provider {provider_id}@{config_version} failed retained binding verification: {error}"
                    )
                })?;
            }
            if profile.security_profile.is_production()
                && !configuration.capability_descriptor.production_eligible
            {
                return Err(format!(
                    "active provider {provider_id}@{config_version} is not production eligible"
                ));
            }
            if active.insert(provider_id.clone(), configuration).is_some() {
                return Err(format!(
                    "provider {provider_id} has multiple active configuration versions"
                ));
            }
        }
    }
    if active.is_empty() {
        return Err("provider registry has no active provider authority".into());
    }
    let declared_provider_kinds = string_set(registry.pointer("/applicability/provider_kinds"));
    for provider in active.values() {
        if !declared_provider_kinds.contains(provider.kind.as_str()) {
            return Err(format!(
                "active provider {} kind {} is omitted from registry applicability",
                provider.provider_id, provider.kind
            ));
        }
    }
    let mut required_provider_ids = BTreeSet::new();
    for ((provider_id, _), configuration) in &configs {
        if string_set(configuration.get("required_for_profiles"))
            .contains(profile.security_profile.as_str())
        {
            required_provider_ids.insert(provider_id.clone());
        }
    }
    for provider_id in required_provider_ids {
        if !active.contains_key(&provider_id) {
            return Err(format!("required provider {provider_id} is not active"));
        }
    }
    Ok(active)
}

fn lifecycle_effective_at(record: &Value) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(required_str(record, "effective_at", "provider lifecycle")?)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| "provider lifecycle effective_at is invalid".to_string())
}

fn parse_active_provider_configuration(
    configuration: &Value,
    profile: &DeploymentSecurityProfile,
    documents: &BTreeMap<String, Value>,
    document_bytes: &BTreeMap<String, Vec<u8>>,
    reference_document_digests: &BTreeMap<String, String>,
) -> Result<ActiveProviderConfiguration, String> {
    let provider_id = required_str(configuration, "provider_id", "provider configuration")?;
    let config_version = required_u64(configuration, "config_version", "provider configuration")?;
    let payload_digest = required_str(configuration, "payload_digest", "provider configuration")?;
    let kind = required_str(configuration, "kind", "provider configuration")?;
    let trust_domain_id = required_str(configuration, "trust_domain_id", "provider configuration")?;
    let capability_descriptor = serde_json::from_value::<ProviderCapabilityDescriptorBinding>(
        configuration
            .get("capability_descriptor")
            .cloned()
            .ok_or_else(|| "provider configuration omits capability_descriptor".to_string())?,
    )
    .map_err(|error| format!("provider capability descriptor is not typed: {error}"))?;
    capability_descriptor.validate()?;
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
        "oidc" | "oidc-broker" => {
            let configuration =
                serde_json::from_value::<OidcKindConfig>(raw_kind_config.clone())
                    .map_err(|error| format!("OIDC kind_config is not typed: {error}"))?;
            let verified_runtime_binding = verify_authenticator_runtime_binding(
                &configuration.runtime_binding_ref,
                AuthenticatorBindingVerificationContext {
                    provider_id,
                    provider_configuration_version: config_version,
                    provider_payload_digest: payload_digest,
                    provider_kind: kind,
                    trust_domain_id,
                    capability_descriptor: &capability_descriptor,
                    oidc_configuration: &configuration,
                    raw_oidc_kind_config: &raw_kind_config,
                    deployment_profile: profile,
                },
                documents,
                document_bytes,
                reference_document_digests,
            )?;
            ActiveProviderKindConfig::Oidc {
                configuration: Box::new(configuration),
                verified_runtime_binding: Arc::new(verified_runtime_binding),
            }
        }
        "local-webauthn" => ActiveProviderKindConfig::LocalWebauthn(Box::new(
            serde_json::from_value(raw_kind_config)
                .map_err(|error| format!("local WebAuthn kind_config is not typed: {error}"))?,
        )),
        "secret-service" => {
            let configuration =
                serde_json::from_value::<CapabilityProviderKindConfig>(raw_kind_config)
                    .map_err(|error| format!("secret-service kind_config is not typed: {error}"))?;
            let verified_runtime_binding = configuration
                .runtime_binding_ref
                .as_ref()
                .map(|reference| {
                    verify_secret_provider_runtime_binding(
                        reference,
                        SecretProviderBindingVerificationContext {
                            provider_id,
                            provider_configuration_version: config_version,
                            trust_domain_id,
                            capability_descriptor: &capability_descriptor,
                            deployment_profile: profile,
                        },
                        documents,
                        document_bytes,
                        reference_document_digests,
                    )
                    .map(Arc::new)
                })
                .transpose()?;
            ActiveProviderKindConfig::SecretService {
                configuration: Box::new(configuration),
                verified_runtime_binding,
            }
        }
        "key-custody" | "certificate-authority" => ActiveProviderKindConfig::CapabilityProvider(
            Box::new(serde_json::from_value(raw_kind_config).map_err(|error| {
                format!("capability provider kind_config is not typed: {error}")
            })?),
        ),
        "oauth-service" | "api-token" | "workload" => {
            ActiveProviderKindConfig::NonAdapterProvider {
                configuration_kind: raw_kind_config
                    .get("configuration_kind")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "provider kind_config omits configuration_kind".to_string())?
                    .into(),
                content_addressed: raw_kind_config,
            }
        }
        _ => {
            return Err(format!(
                "provider kind {kind} has no closed typed kind_config projection"
            ));
        }
    };
    kind_config.validate_type(kind)?;
    kind_config.validate_adapter_binding(kind, &capability_descriptor.adapter_kind)?;

    Ok(ActiveProviderConfiguration {
        provider_id: provider_id.into(),
        config_version,
        payload_digest: payload_digest.into(),
        kind: kind.into(),
        trust_domain_id: trust_domain_id.into(),
        active_lifecycle_record_version: 0,
        capability_descriptor,
        credential_refs,
        kind_config,
    })
}

struct AuthenticatorBindingVerificationContext<'a> {
    provider_id: &'a str,
    provider_configuration_version: u64,
    provider_payload_digest: &'a str,
    provider_kind: &'a str,
    trust_domain_id: &'a str,
    capability_descriptor: &'a ProviderCapabilityDescriptorBinding,
    oidc_configuration: &'a OidcKindConfig,
    raw_oidc_kind_config: &'a Value,
    deployment_profile: &'a DeploymentSecurityProfile,
}

fn verify_authenticator_runtime_binding(
    reference: &ContentReferenceBinding,
    context: AuthenticatorBindingVerificationContext<'_>,
    documents: &BTreeMap<String, Value>,
    document_bytes: &BTreeMap<String, Vec<u8>>,
    reference_document_digests: &BTreeMap<String, String>,
) -> Result<VerifiedAuthenticatorRuntimeBinding, String> {
    reference.validate()?;
    validate_namespaced_id(
        "authenticator runtime-binding reference document id",
        &reference.document_id,
        "authenticator-runtime-binding:",
    )?;
    if Path::new(&reference.artifact_locator)
        .extension()
        .and_then(|extension| extension.to_str())
        != Some("json")
    {
        return Err(
            "authenticator runtime-binding reference locator must end in lowercase .json".into(),
        );
    }

    let locator = &reference.artifact_locator;
    let traversed_digest = reference_document_digests.get(locator).ok_or_else(|| {
        format!("authenticator runtime binding {locator} has no verified traversal digest")
    })?;
    let raw_bytes = document_bytes.get(locator).ok_or_else(|| {
        format!("authenticator runtime binding {locator} has no exact traversed bytes")
    })?;
    let traversed_document = documents.get(locator).ok_or_else(|| {
        format!("authenticator runtime binding {locator} did not resolve to typed JSON")
    })?;
    let exact_document = parse_json_strict(raw_bytes).map_err(|error| {
        format!("authenticator runtime binding {locator} JSON is invalid: {error}")
    })?;
    let exact_digest = raw_digest(raw_bytes);
    if traversed_digest != &reference.content_digest
        || exact_digest != reference.content_digest
        || &exact_document != traversed_document
    {
        return Err(format!(
            "authenticator runtime binding {locator} differs across its reference, exact bytes, and verified traversal"
        ));
    }
    validate_against_schema(
        "authenticator runtime binding",
        AUTHENTICATOR_RUNTIME_BINDING_SCHEMA,
        &exact_document,
    )?;
    let document = serde_json::from_value::<AuthenticatorRuntimeBindingDocument>(exact_document)
        .map_err(|error| {
            format!("authenticator runtime binding {locator} is not losslessly typed: {error}")
        })?;
    document.validate()?;
    let typed_oidc_kind_config =
        serde_json::to_value(context.oidc_configuration).map_err(|error| {
            format!("OIDC kind_config could not be losslessly reprojected: {error}")
        })?;
    if typed_oidc_kind_config != *context.raw_oidc_kind_config {
        return Err(format!(
            "authenticator runtime binding {locator} received divergent raw and typed OIDC kind_config authorities"
        ));
    }
    let provider_policy_binding_digest =
        authenticator_provider_policy_binding_digest(context.raw_oidc_kind_config).map_err(
            |error| {
                format!(
                    "authenticator runtime binding {locator} provider-policy digest could not be independently recomputed: {error}"
                )
            },
        )?;

    let descriptor = context.capability_descriptor;
    if context.oidc_configuration.runtime_binding_ref != *reference
        || document.document_id != reference.document_id
        || document.document_version != reference.document_version
        || document.provider_id != context.provider_id
        || document.provider_configuration_version != context.provider_configuration_version
        || document.deployment_id != context.deployment_profile.deployment_id
        || document.trust_domain_id != context.trust_domain_id
        || document.capability_descriptor_id != descriptor.descriptor_id
        || document.capability_descriptor_version != descriptor.descriptor_version
        || document.adapter_kind != descriptor.adapter_kind
        || document.adapter_version != descriptor.adapter_version
        || document.authenticator_kind != context.provider_kind
        || document.authenticator_kind != context.oidc_configuration.configuration_kind
    {
        return Err(format!(
            "authenticator runtime binding {locator} does not exactly match its reference, provider, deployment, trust-domain, descriptor, adapter, and authenticator-kind authority"
        ));
    }
    if context.oidc_configuration.validation_mode != "jwt-jwks"
        || context.oidc_configuration.accepted_algorithms.as_slice() != ["RS256"]
    {
        return Err(format!(
            "authenticator runtime binding {locator} requires the exact implemented jwt-jwks/RS256 OIDC provider policy"
        ));
    }
    if document.capability_ids != descriptor.advertised_capabilities {
        return Err(format!(
            "authenticator runtime binding {locator} capability inventory does not exactly match its provider descriptor"
        ));
    }
    if document.provider_policy.digest_contract
        != AUTHENTICATOR_PROVIDER_POLICY_BINDING_DIGEST_CONTRACT
        || document.provider_policy.binding_digest != provider_policy_binding_digest
    {
        return Err(format!(
            "authenticator runtime binding {locator} provider-policy digest does not match the independently recomputed OIDC kind_config"
        ));
    }
    validate_digest_pin(
        "OIDC provider configuration payload digest",
        context.provider_payload_digest,
    )?;
    if reference.content_digest == context.provider_payload_digest
        || reference.content_digest == provider_policy_binding_digest
        || context.provider_payload_digest == provider_policy_binding_digest
    {
        return Err(format!(
            "authenticator runtime binding {locator} violates D/P/Q digest separation"
        ));
    }

    Ok(VerifiedAuthenticatorRuntimeBinding {
        reference: reference.clone(),
        raw_bytes: raw_bytes.clone().into_boxed_slice(),
        document,
    })
}

struct SecretProviderBindingVerificationContext<'a> {
    provider_id: &'a str,
    provider_configuration_version: u64,
    trust_domain_id: &'a str,
    capability_descriptor: &'a ProviderCapabilityDescriptorBinding,
    deployment_profile: &'a DeploymentSecurityProfile,
}

fn verify_secret_provider_runtime_binding(
    reference: &ContentReferenceBinding,
    context: SecretProviderBindingVerificationContext<'_>,
    documents: &BTreeMap<String, Value>,
    document_bytes: &BTreeMap<String, Vec<u8>>,
    reference_document_digests: &BTreeMap<String, String>,
) -> Result<VerifiedSecretProviderRuntimeBinding, String> {
    reference.validate()?;
    let locator = &reference.artifact_locator;
    let traversed_digest = reference_document_digests.get(locator).ok_or_else(|| {
        format!("secret-provider runtime binding {locator} has no verified traversal digest")
    })?;
    let raw_bytes = document_bytes.get(locator).ok_or_else(|| {
        format!("secret-provider runtime binding {locator} has no exact traversed bytes")
    })?;
    let traversed_document = documents.get(locator).ok_or_else(|| {
        format!("secret-provider runtime binding {locator} did not resolve to typed JSON")
    })?;
    let exact_document = parse_json_strict(raw_bytes).map_err(|error| {
        format!("secret-provider runtime binding {locator} JSON is invalid: {error}")
    })?;
    let exact_digest = raw_digest(raw_bytes);
    if traversed_digest != &reference.content_digest
        || exact_digest != reference.content_digest
        || &exact_document != traversed_document
    {
        return Err(format!(
            "secret-provider runtime binding {locator} differs across its reference, exact bytes, and verified traversal"
        ));
    }
    validate_against_schema(
        "secret-provider runtime binding",
        SECRET_PROVIDER_RUNTIME_BINDING_SCHEMA,
        &exact_document,
    )?;
    let document = serde_json::from_value::<SecretProviderRuntimeBindingDocument>(exact_document)
        .map_err(|error| {
        format!("secret-provider runtime binding {locator} is not losslessly typed: {error}")
    })?;
    document.validate()?;

    let descriptor = context.capability_descriptor;
    if document.document_id != reference.document_id
        || document.document_version != reference.document_version
        || document.provider_id != context.provider_id
        || document.provider_configuration_version != context.provider_configuration_version
        || document.deployment_id != context.deployment_profile.deployment_id
        || document.trust_domain_id != context.trust_domain_id
        || document.capability_descriptor_id != descriptor.descriptor_id
        || document.capability_descriptor_version != descriptor.descriptor_version
        || document.adapter_kind != descriptor.adapter_kind
        || document.adapter_version != descriptor.adapter_version
    {
        return Err(format!(
            "secret-provider runtime binding {locator} does not exactly match its provider, deployment, trust-domain, descriptor, and adapter authority"
        ));
    }
    let capability_ids = document
        .capability_bindings
        .iter()
        .map(|binding| binding.capability_id.as_str())
        .collect::<Vec<_>>();
    if capability_ids
        != descriptor
            .advertised_capabilities
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    {
        return Err(format!(
            "secret-provider runtime binding {locator} capability inventory does not exactly match its provider descriptor"
        ));
    }

    Ok(VerifiedSecretProviderRuntimeBinding {
        reference: reference.clone(),
        raw_bytes: raw_bytes.clone().into_boxed_slice(),
        document,
    })
}

impl AuthenticatorRuntimeBindingDocument {
    fn validate(&self) -> Result<(), String> {
        const SCHEMA_URI: &str = "https://ryuki.io/schemas/security-contracts/v1/authenticator-runtime-binding.schema.json";
        if self.schema_uri != SCHEMA_URI
            || self.schema_version != "1.0.0"
            || self.contract_kind != "authenticator-runtime-binding"
            || !self.value_free
            || self.document_version == 0
            || self.provider_configuration_version == 0
            || self.capability_descriptor_version == 0
            || !matches!(self.authenticator_kind.as_str(), "oidc" | "oidc-broker")
        {
            return Err(
                "authenticator runtime binding has an invalid identity, version, contract kind, authenticator kind, or value-free marker"
                    .into(),
            );
        }
        for (label, value, prefix) in [
            (
                "authenticator runtime-binding document id",
                self.document_id.as_str(),
                "authenticator-runtime-binding:",
            ),
            (
                "authenticator runtime-binding provider id",
                self.provider_id.as_str(),
                "provider:",
            ),
            (
                "authenticator runtime-binding deployment id",
                self.deployment_id.as_str(),
                "deployment:",
            ),
            (
                "authenticator runtime-binding trust-domain id",
                self.trust_domain_id.as_str(),
                "trust-domain:",
            ),
        ] {
            validate_namespaced_id(label, value, prefix)?;
        }
        for (label, value) in [
            (
                "capability descriptor id",
                self.capability_descriptor_id.as_str(),
            ),
            ("adapter kind", self.adapter_kind.as_str()),
            ("adapter version", self.adapter_version.as_str()),
        ] {
            if value.is_empty() || value.trim() != value {
                return Err(format!(
                    "authenticator runtime binding {label} must be nonempty and canonical"
                ));
            }
        }
        if self.provider_policy.digest_contract
            != AUTHENTICATOR_PROVIDER_POLICY_BINDING_DIGEST_CONTRACT
        {
            return Err(
                "authenticator runtime binding provider-policy digest contract is invalid".into(),
            );
        }
        validate_digest_pin(
            "authenticator provider-policy binding digest",
            &self.provider_policy.binding_digest,
        )?;
        if self.capability_ids.is_empty()
            || !self.capability_ids.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(
                "authenticator runtime binding capabilities must be nonempty, strictly sorted, and unique"
                    .into(),
            );
        }
        if self.credential_paths.is_empty()
            || !self
                .credential_paths
                .windows(2)
                .all(|pair| pair[0].path_id < pair[1].path_id)
        {
            return Err(
                "authenticator runtime binding paths must be nonempty, strictly sorted, and unique"
                    .into(),
            );
        }

        let mut verifier_ids = BTreeSet::new();
        let mut profile_ids = BTreeSet::new();
        let mut cache_partition_digests = BTreeSet::new();
        let mut resolution_tuples = BTreeSet::new();
        let mut consumer_ids = BTreeSet::new();
        for path in &self.credential_paths {
            let verifier = &path.verifier;
            let profile = &path.credential_profile;
            validate_namespaced_id(
                "authenticator path id",
                &path.path_id,
                "authenticator-path:",
            )?;
            validate_namespaced_id(
                "authenticator verifier id",
                &verifier.verifier_id,
                "authenticator-verifier:",
            )?;
            validate_namespaced_id(
                "authenticator credential-profile id",
                &profile.profile_id,
                "credential-profile:",
            )?;
            if path.path_version == 0
                || verifier.verifier_version == 0
                || profile.profile_version == 0
                || !verifier_ids.insert(verifier.verifier_id.as_str())
                || !profile_ids.insert(profile.profile_id.as_str())
            {
                return Err(
                    "authenticator runtime binding path/verifier/profile identity is invalid or duplicated"
                        .into(),
                );
            }
            for (label, digest) in [
                (
                    "authenticator issuer binding digest",
                    verifier.issuer_binding_digest.as_str(),
                ),
                (
                    "authenticator audience-set binding digest",
                    verifier.audience_set_binding_digest.as_str(),
                ),
                (
                    "authenticator key-source binding digest",
                    verifier.key_source_binding_digest.as_str(),
                ),
                (
                    "authenticator cache-partition binding digest",
                    path.cache_partition.binding_digest.as_str(),
                ),
                (
                    "authenticator protocol binding digest",
                    path.protocol_binding.binding_digest.as_str(),
                ),
            ] {
                validate_digest_pin(label, digest)?;
            }
            if path.cache_partition.digest_contract != "ryuki-authenticator-cache-partition-v1"
                || path.protocol_binding.digest_contract
                    != "ryuki-authenticator-protocol-binding-v1"
                || !cache_partition_digests.insert(path.cache_partition.binding_digest.as_str())
            {
                return Err(
                    "authenticator runtime binding cache/protocol contract or cache partition is invalid"
                        .into(),
                );
            }
            if verifier.accepted_algorithm_ids.as_slice() != ["rs256"]
                || verifier.required_claim_ids.is_empty()
                || !verifier
                    .required_claim_ids
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
                || verifier
                    .required_claim_ids
                    .binary_search(&verifier.provider_subject_claim_id)
                    .is_err()
                || !authenticator_document_claim_flags_match(verifier)
                || verifier.key_source_kind != AuthenticatorKeySourceKind::JwtJwks
                || verifier.redirects_allowed
            {
                return Err("authenticator runtime binding verifier semantics are invalid".into());
            }
            match self.adapter_kind.as_str() {
                "auth.entra-id" if verifier.provider_subject_claim_id != "oid" => {
                    return Err(
                        "Entra authenticator runtime bindings must use the signed oid claim".into(),
                    );
                }
                "auth.entra-id" => {}
                _ if verifier.provider_subject_claim_id != "sub" => {
                    return Err(
                        "generic OIDC authenticator runtime bindings must use the signed sub claim"
                            .into(),
                    );
                }
                _ => {}
            }
            validate_namespaced_id(
                "authenticator clock-skew limit id",
                &verifier.clock_skew_limit_id,
                "limit:",
            )?;

            let claims_include = |required: &[&str]| {
                required.iter().all(|claim| {
                    verifier
                        .required_claim_ids
                        .binary_search_by(|candidate| candidate.as_str().cmp(claim))
                        .is_ok()
                })
            };
            let bearer_profile = profile.token_profile == "jwt-access-token"
                && profile.carrier == AuthenticatorCredentialCarrier::AuthorizationBearer
                && profile.proof_binding == AuthenticatorProofBinding::Bearer
                && profile.replay.credential_reuse
                    == AuthenticatorCredentialReuse::ReusableUntilExpiry
                && profile
                    .replay
                    .credential_lifetime_limit_id
                    .as_deref()
                    .is_some_and(|limit_id| {
                        validate_namespaced_id(
                            "authenticator credential-lifetime limit id",
                            limit_id,
                            "limit:",
                        )
                        .is_ok()
                    })
                && profile
                    .replay
                    .maximum_credential_lifetime_seconds
                    .is_some_and(|seconds| seconds > 0)
                && profile.replay.sender_constraint == AuthenticatorSenderConstraint::None
                && profile.replay.presentation_replay_defense
                    == AuthenticatorPresentationReplayDefense::None
                && profile.replay.nonce_binding == AuthenticatorNonceBinding::None
                && profile.replay.replay_store_binding_digest.is_none()
                && verifier.expiration_required
                && verifier.not_before_required
                && verifier.issued_at_required
                && !verifier.nonce_required
                && claims_include(&["aud", "exp", "iat", "iss", "nbf", "sub"]);
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
                && profile
                    .replay
                    .replay_store_binding_digest
                    .as_deref()
                    .is_some_and(|digest| {
                        validate_digest_pin("replay-store digest", digest).is_ok()
                    })
                && verifier.expiration_required
                && verifier.not_before_required
                && verifier.nonce_required
                && claims_include(&["aud", "exp", "iss", "nbf", "nonce", "sub"]);
            if !bearer_profile && !browser_profile {
                return Err(
                    "authenticator runtime binding credential profile is not an admitted closed OIDC path"
                        .into(),
                );
            }
            if !resolution_tuples.insert((
                verifier.issuer_binding_digest.as_str(),
                profile.token_profile.as_str(),
            )) {
                return Err(
                    "authenticator runtime binding repeats an issuer/token-profile resolution tuple"
                        .into(),
                );
            }
            if path.retained_consumer_ids.is_empty()
                || !path
                    .retained_consumer_ids
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
            {
                return Err(
                    "authenticator runtime binding retained consumers must be nonempty, strictly sorted, and unique"
                        .into(),
                );
            }
            for consumer in &path.retained_consumer_ids {
                validate_namespaced_id(
                    "authenticator retained consumer id",
                    consumer,
                    "runtime-consumer:",
                )?;
                if !consumer_ids.insert(consumer.as_str()) {
                    return Err(
                        "authenticator runtime binding retained consumers must be globally disjoint"
                            .into(),
                    );
                }
            }
        }
        if !self.ownership.single_runtime_owner || self.ownership.ambient_reconfiguration_allowed {
            return Err(
                "authenticator runtime binding requires one retained owner and forbids ambient reconfiguration"
                    .into(),
            );
        }
        Ok(())
    }
}

fn authenticator_document_claim_flags_match(
    verifier: &AuthenticatorVerifierRuntimeProjection,
) -> bool {
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

impl SecretProviderRuntimeBindingDocument {
    fn validate(&self) -> Result<(), String> {
        const SCHEMA_URI: &str = "https://ryuki.io/schemas/security-contracts/v1/secret-provider-runtime-binding.schema.json";
        if self.schema_uri != SCHEMA_URI
            || self.schema_version != "1.0.0"
            || self.contract_kind != "secret-provider-runtime-binding"
            || !self.value_free
            || self.document_version == 0
            || self.provider_configuration_version == 0
            || self.capability_descriptor_version == 0
        {
            return Err(
                "secret-provider runtime binding has an invalid identity, version, contract kind, or value-free marker"
                    .into(),
            );
        }
        validate_namespaced_id(
            "secret-provider runtime binding document id",
            &self.document_id,
            "secret-provider-runtime-binding:",
        )?;
        validate_namespaced_id(
            "secret-provider runtime binding provider id",
            &self.provider_id,
            "provider:",
        )?;
        for (label, value) in [
            ("deployment id", self.deployment_id.as_str()),
            ("trust domain id", self.trust_domain_id.as_str()),
            (
                "capability descriptor id",
                self.capability_descriptor_id.as_str(),
            ),
            ("adapter kind", self.adapter_kind.as_str()),
            ("adapter version", self.adapter_version.as_str()),
            ("protocol version", self.protocol_version.as_str()),
            (
                "backend compatibility profile id",
                self.backend_compatibility_profile.profile_id.as_str(),
            ),
        ] {
            if value.is_empty() || value.trim() != value {
                return Err(format!(
                    "secret-provider runtime binding {label} must be nonempty and canonical"
                ));
            }
        }
        if self.backend_compatibility_profile.profile_version == 0
            || self.backend_compatibility_profile.digest_contract
                != "ryuki-secret-provider-backend-compatibility-profile-v1"
            || self
                .credential_source
                .provider_authentication_digest_contract
                != "ryuki-secret-provider-authentication-binding-v1"
        {
            return Err(
                "secret-provider runtime binding backend/authentication digest contract or compatibility profile version is invalid"
                    .into(),
            );
        }
        for (label, digest) in [
            (
                "backend compatibility profile digest",
                self.backend_compatibility_profile.binding_digest.as_str(),
            ),
            (
                "endpoint base URL binding digest",
                self.transport.endpoint_base_url_binding_digest.as_str(),
            ),
            (
                "CA trust binding digest",
                self.transport.ca_trust_binding_digest.as_str(),
            ),
            (
                "workload identity binding digest",
                self.credential_source.identity_binding_digest.as_str(),
            ),
            (
                "workload audience binding digest",
                self.credential_source.audience_binding_digest.as_str(),
            ),
            (
                "workload token path binding digest",
                self.credential_source.token_path_binding_digest.as_str(),
            ),
            (
                "provider authentication binding digest",
                self.credential_source
                    .provider_authentication_binding_digest
                    .as_str(),
            ),
        ] {
            validate_digest_pin(label, digest)?;
        }
        if !self.transport.https_required
            || self.transport.redirects_allowed
            || self.transport.ambient_proxy_allowed
            || self.transport.built_in_roots_allowed
            || !(1..=3_000).contains(&self.transport.connect_timeout_millis)
            || !(1..=10_000).contains(&self.transport.request_timeout_millis)
            || !(1..=1_048_576).contains(&self.transport.response_body_max_bytes)
        {
            return Err(
                "secret-provider runtime binding transport violates the production hard bounds"
                    .into(),
            );
        }
        if self.credential_source.kind != "kubernetes-service-account-jwt"
            || self.credential_source.static_bearer_allowed
            || self.credential_source.exported_bearer_allowed
        {
            return Err(
                "secret-provider runtime binding requires non-exported Kubernetes workload authentication"
                    .into(),
            );
        }
        if self.capability_bindings.is_empty()
            || !self
                .capability_bindings
                .windows(2)
                .all(|pair| pair[0].capability_id < pair[1].capability_id)
        {
            return Err(
                "secret-provider runtime binding capabilities must be nonempty, strictly sorted, and unique"
                    .into(),
            );
        }
        for capability in &self.capability_bindings {
            if capability.capability_id.is_empty()
                || capability.semantic_version.is_empty()
                || capability.capability_id.trim() != capability.capability_id
                || capability.semantic_version.trim() != capability.semantic_version
            {
                return Err(
                    "secret-provider runtime binding capability identity/version is invalid".into(),
                );
            }
        }
        if self.retained_consumer_ids.is_empty()
            || !self
                .retained_consumer_ids
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            || self
                .retained_consumer_ids
                .iter()
                .any(|consumer| consumer.is_empty() || consumer.trim() != consumer)
        {
            return Err(
                "secret-provider runtime binding retained consumers must be nonempty, strictly sorted, and unique"
                    .into(),
            );
        }
        if !self.ownership.single_runtime_owner || self.ownership.ambient_reconfiguration_allowed {
            return Err(
                "secret-provider runtime binding requires one retained owner and forbids ambient reconfiguration"
                    .into(),
            );
        }
        Ok(())
    }
}

fn build_provider_registry_applicability_claim(
    profile: &DeploymentSecurityProfile,
    registry_version: u64,
    active_providers: &BTreeMap<String, ActiveProviderConfiguration>,
) -> Result<ActiveProviderRegistryApplicabilityClaim, String> {
    if registry_version == 0 {
        return Err(
            "provider registry applicability projection has a zero registry version".into(),
        );
    }
    let providers = active_providers
        .values()
        .map(|provider| {
            if provider.active_lifecycle_record_version == 0 {
                return Err(format!(
                    "active provider {} has no selected lifecycle record version",
                    provider.provider_id
                ));
            }
            Ok(ActiveProviderApplicabilityClaim {
                provider_id: provider.provider_id.clone(),
                provider_kind: provider.kind.clone(),
                configuration_version: provider.config_version,
                configuration_payload_digest: provider.payload_digest.clone(),
                lifecycle_record_version: provider.active_lifecycle_record_version,
                lifecycle_state: ProviderLifecycleState::Active,
                trust_domain_id: provider.trust_domain_id.clone(),
                descriptor_id: provider.capability_descriptor.descriptor_id.clone(),
                descriptor_version: provider.capability_descriptor.descriptor_version,
                adapter_kind: provider.capability_descriptor.adapter_kind.clone(),
                adapter_version: provider.capability_descriptor.adapter_version.clone(),
                advertised_capability_ids: provider
                    .capability_descriptor
                    .advertised_capabilities
                    .clone(),
                production_eligible: provider.capability_descriptor.production_eligible,
                mandatory_baseline_ref: ProviderMandatoryBaselineClaim {
                    document_id: provider
                        .capability_descriptor
                        .mandatory_baseline_ref
                        .document_id
                        .clone(),
                    document_version: provider
                        .capability_descriptor
                        .mandatory_baseline_ref
                        .document_version,
                    content_digest: provider
                        .capability_descriptor
                        .mandatory_baseline_ref
                        .content_digest
                        .clone(),
                    artifact_locator: provider
                        .capability_descriptor
                        .mandatory_baseline_ref
                        .artifact_locator
                        .clone(),
                },
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(ActiveProviderRegistryApplicabilityClaim {
        document_id: profile.provider_registry_ref.document_id.clone(),
        document_version: profile.provider_registry_ref.document_version,
        content_digest: profile.provider_registry_ref.content_digest.clone(),
        artifact_locator: profile.provider_registry_ref.artifact_locator.clone(),
        registry_version,
        active_providers: providers,
    })
}

fn validate_production_provider_build_bindings(
    registry: &ActiveProviderRegistryApplicabilityClaim,
    manifest: &ProductionBuildManifest,
) -> Result<(), String> {
    let shipped = manifest
        .shipped_adapters
        .iter()
        .map(|adapter| (adapter.adapter_kind.as_str(), adapter))
        .collect::<BTreeMap<_, _>>();
    if shipped.len() != manifest.shipped_adapters.len() {
        return Err("production build repeats a shipped adapter kind".into());
    }
    for provider in &registry.active_providers {
        let adapter = shipped
            .get(provider.adapter_kind.as_str())
            .ok_or_else(|| {
                format!(
                    "active provider {} references adapter {} that is not shipped in the measured build",
                    provider.provider_id, provider.adapter_kind
                )
            })?;
        if !provider.production_eligible || !adapter.production_eligible {
            return Err(format!(
                "active provider {} and measured adapter {} must both be production eligible",
                provider.provider_id, provider.adapter_kind
            ));
        }
        if provider.adapter_version != adapter.adapter_version {
            return Err(format!(
                "active provider {} adapter version does not match the measured build",
                provider.provider_id
            ));
        }
        if provider.advertised_capability_ids != adapter.capability_ids {
            return Err(format!(
                "active provider {} capability inventory does not exactly match measured adapter {}",
                provider.provider_id, provider.adapter_kind
            ));
        }
        let baseline = &provider.mandatory_baseline_ref;
        if baseline.document_id != adapter.mandatory_baseline.document_id
            || baseline.document_version != adapter.mandatory_baseline.document_version
            || baseline.content_digest != adapter.mandatory_baseline.content_digest
            || baseline.artifact_locator != adapter.mandatory_baseline.artifact_locator
        {
            return Err(format!(
                "active provider {} mandatory baseline reference does not match measured adapter {}",
                provider.provider_id, provider.adapter_kind
            ));
        }
    }
    Ok(())
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

impl ProviderCapabilityDescriptorBinding {
    fn validate(&self) -> Result<(), String> {
        if self.descriptor_id.is_empty()
            || self.descriptor_version == 0
            || self.adapter_kind.is_empty()
            || self.adapter_version.is_empty()
        {
            return Err(
                "typed provider capability descriptor omits identity, adapter, or version".into(),
            );
        }
        if !self.implementation_applicable {
            return Err(
                "typed provider capability descriptor must remain implementation-applicable".into(),
            );
        }
        if self.advertised_capabilities.is_empty()
            || self
                .advertised_capabilities
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(
                "typed provider advertised capabilities must be non-empty and strictly sorted"
                    .into(),
            );
        }
        self.mandatory_baseline_ref.validate()
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
            Self::Oidc {
                configuration: oidc,
                verified_runtime_binding,
            } if matches!(provider_kind, "oidc" | "oidc-broker")
                && oidc.configuration_kind == provider_kind
                && verified_runtime_binding.document.authenticator_kind == provider_kind =>
            {
                oidc.security_binding_summary().map(|_| ())
            }
            Self::LocalWebauthn(local)
                if provider_kind == "local-webauthn"
                    && local.configuration_kind == "local-webauthn" =>
            {
                local.security_binding_summary().map(|_| ())
            }
            Self::SecretService { configuration, .. }
                if provider_kind == "secret-service"
                    && configuration.configuration_kind == provider_kind =>
            {
                configuration
                    .security_binding_summary(provider_kind)
                    .map(|_| ())
            }
            Self::CapabilityProvider(capability)
                if matches!(provider_kind, "key-custody" | "certificate-authority")
                    && capability.configuration_kind == provider_kind =>
            {
                capability
                    .security_binding_summary(provider_kind)
                    .map(|_| ())
            }
            Self::NonAdapterProvider {
                configuration_kind,
                content_addressed,
            } if matches!(provider_kind, "oauth-service" | "api-token" | "workload")
                && configuration_kind == provider_kind
                && content_addressed.is_object() =>
            {
                Ok(())
            }
            _ => Err(format!(
                "provider kind {provider_kind} does not match its typed kind_config"
            )),
        }
    }

    fn validate_adapter_binding(
        &self,
        provider_kind: &str,
        descriptor_adapter_kind: &str,
    ) -> Result<(), String> {
        let capability = match self {
            Self::SecretService { configuration, .. } | Self::CapabilityProvider(configuration) => {
                configuration
            }
            _ => return Ok(()),
        };
        if capability.adapter_kind != descriptor_adapter_kind {
            return Err(format!(
                "provider kind {provider_kind} runtime adapter selector {} does not exactly match capability descriptor adapter {}",
                capability.adapter_kind, descriptor_adapter_kind
            ));
        }
        Ok(())
    }
}

impl CapabilityProviderKindConfig {
    fn security_binding_summary(&self, provider_kind: &str) -> Result<usize, String> {
        if self.adapter_kind.is_empty() {
            return Err(
                "capability provider kind_config omits its runtime adapter selector".into(),
            );
        }
        let legacy_references = [
            self.endpoint_policy_ref.as_ref(),
            self.authentication_ref.as_ref(),
            self.capability_policy_ref.as_ref(),
            self.rotation_policy_ref.as_ref(),
            self.revocation_policy_ref.as_ref(),
        ];
        let legacy_count = legacy_references
            .iter()
            .filter(|reference| reference.is_some())
            .count();
        match (
            provider_kind,
            self.runtime_binding_ref.as_ref(),
            legacy_count,
        ) {
            ("secret-service", Some(reference), 0) => {
                reference.validate()?;
                Ok(1)
            }
            ("secret-service", None, 5)
            | ("key-custody" | "certificate-authority", None, 5) => {
                for reference in legacy_references.into_iter().flatten() {
                    reference.validate()?;
                }
                Ok(5)
            }
            ("secret-service", Some(_), _) => Err(
                "secret-service kind_config cannot mix runtime_binding_ref with legacy policy references"
                    .into(),
            ),
            ("secret-service", None, _) => Err(
                "secret-service kind_config requires either runtime_binding_ref or all five legacy policy references"
                    .into(),
            ),
            ("key-custody" | "certificate-authority", Some(_), _) => Err(format!(
                "{provider_kind} kind_config cannot use a secret-provider runtime binding"
            )),
            ("key-custody" | "certificate-authority", None, _) => Err(format!(
                "{provider_kind} kind_config requires all five policy references"
            )),
            _ => Err(format!(
                "unsupported capability provider configuration kind {provider_kind}"
            )),
        }
    }
}

impl OidcKindConfig {
    fn security_binding_summary(&self) -> Result<usize, String> {
        for reference in [
            &self.runtime_binding_ref,
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
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
    use chrono::{TimeDelta, TimeZone};
    use ed25519_dalek::{Signer, SigningKey};
    use ryuki_core::conformance_applicability::{
        ApplicabilityInventoryBinding, APPLICABILITY_IDENTITY_CONTRACT,
        APPLICABILITY_INVENTORY_CONTRACT,
    };
    use ryuki_core::conformance_closure::tests::genuine_production_closure_fixture;
    use ryuki_core::conformance_trust::{
        canonical_json_bytes, conformance_signed_subject_digest, conformance_signing_bytes,
        CANONICALIZATION_PROFILE, CONFORMANCE_BUNDLE_DOMAIN, PACKAGE_EXIT_RECEIPT_DOMAIN,
        SIGNATURE_ALGORITHM, SIGNATURE_VERSION, TRUST_RECONCILIATION_PROTOCOL_VERSION,
        TRUST_RECONCILIATION_RESPONSE_DOMAIN,
    };
    use ryuki_core::deployed_workload::tests::{
        genuine_deployed_workload_fixture, genuine_deployed_workload_fixture_with_instance_binding,
        genuine_workload_instance_binding_digest,
    };
    use ryuki_core::production_applicability::derive_implementation_applicability;
    use ryuki_core::production_build::{
        BuildEndian, BuildSource, BuildTarget, MandatoryCapabilityBaseline, OciSubject,
        OciSubjectKind, RuntimeExecutable, SelectorDisposition, SelectorDomain,
        SourceRevisionAlgorithm, PRODUCTION_BUILD_MANIFEST_CONTRACT_KIND,
        PRODUCTION_BUILD_MANIFEST_SCHEMA_URI, PRODUCTION_BUILD_MANIFEST_SCHEMA_VERSION,
    };
    use ryuki_core::public_ingress::tests::{
        genuine_public_ingress_fixture, GenuinePublicIngressFixtureInput,
        GENUINE_PUBLIC_INGRESS_BINDING_DIGEST, GENUINE_PUBLIC_ORIGIN_SET_DIGEST,
    };
    use ryuki_core::security_profile::{ArtifactKind, MigrationOverlay, VersionedContentReference};
    use serde_json::json;
    #[cfg(unix)]
    use tempfile::Builder;
    use tempfile::TempDir;
    #[cfg(unix)]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[cfg(unix)]
    use tokio::net::UnixListener;

    use super::runtime_admission::*;
    use super::*;

    const DEPLOYMENT_ID: &str = "deployment:runtime-loader-test";
    const PROFILE_PATH: &str = "profiles/runtime-test.json";
    const TRUST_ROOT_REGISTRY_PATH: &str =
        "catalog/security-contracts/v1/conformance-trust-root-registry.runtime-test.json";
    const CONTROL_TRACE_PATH: &str =
        "catalog/security-contracts/v1/control-trace.runtime-test.json";
    const SECRET_PROVIDER_RUNTIME_BINDING_PATH: &str =
        "catalog/security-contracts/v1/secret-provider-runtime-binding.runtime-test.json";
    const AUTHENTICATOR_RUNTIME_BINDING_PATH: &str =
        "catalog/security-contracts/v1/authenticator-runtime-binding.runtime-test.json";

    fn maximum_authority_projection_fixture() -> Value {
        json!({
            "digest_contract": MAXIMUM_AUTHORITY_BINDING_DIGEST_CONTRACT,
            "registry_version": 7,
            "actions": [
                {
                    "action_id": "request.list",
                    "permitted_actor_kinds": ["service", "verified-human"]
                },
                {
                    "action_id": "request.read",
                    "permitted_actor_kinds": ["service", "verified-human"]
                }
            ],
            "resource": {
                "resource_kind": "request",
                "required_fields": ["canonical_id", "resource_version"]
            },
            "resolvers": [
                {
                    "resolver_id": "resolver:request-instance-v1",
                    "resolver_version": 1
                },
                {
                    "resolver_id": "resolver:request-query-v1",
                    "resolver_version": 1
                }
            ],
            "routes": [
                {
                    "method": "GET",
                    "path_template": "/api/requests"
                },
                {
                    "method": "GET",
                    "path_template": "/api/requests/{id}"
                }
            ]
        })
    }

    fn checked_in_request_registry_fixture() -> (Value, DeploymentSecurityProfile) {
        let registry = serde_json::from_str(include_str!(
            "../../../catalog/security-contracts/v1/action-resource-registry.implementation.json"
        ))
        .expect("checked-in action registry parses");
        let profile = serde_json::from_str(include_str!(
            "../../../catalog/security-contracts/v1/deployment-security-profile.implementation.json"
        ))
        .expect("checked-in deployment profile parses");
        (registry, profile)
    }

    #[test]
    fn request_registry_binding_accepts_only_the_exact_collection_contract() {
        let (registry, profile) = checked_in_request_registry_fixture();
        request_read_registry_binding(&registry, &profile)
            .expect("checked-in request registry must match the permit adapter");

        for (pointer, replacement) in [
            ("/actions/1/authorization_semantics", json!("instance")),
            (
                "/resources/0/scope_dimensions/5",
                json!("requester_principal_id"),
            ),
            (
                "/resources/0/canonical_resource_ref/schema_version",
                json!(2),
            ),
            (
                "/resolvers/1/canonical_id_source",
                json!("request-query.scope"),
            ),
            (
                "/resolvers/1/security_version_source",
                json!("principal.authority_version"),
            ),
            (
                "/resolvers/1/state_digest_source",
                json!("request-query.digest"),
            ),
            (
                "/route_mappings/1/permit_kind",
                json!("AuthorizationPermit"),
            ),
        ] {
            let mut changed = registry.clone();
            *changed.pointer_mut(pointer).expect("mutation pointer") = replacement;
            assert!(
                request_read_registry_binding(&changed, &profile).is_err(),
                "semantic drift at {pointer} must fail closed"
            );
        }
    }

    #[test]
    fn request_registry_binding_rejects_duplicate_selected_route_keys() {
        let (mut registry, profile) = checked_in_request_registry_fixture();
        let list_route = registry["route_mappings"]
            .as_array()
            .expect("route array")
            .iter()
            .find(|route| {
                route.get("method").and_then(Value::as_str) == Some("GET")
                    && route.get("path_template").and_then(Value::as_str) == Some("/api/requests")
            })
            .expect("request-list route")
            .clone();
        let mut duplicate = list_route;
        duplicate["mapping_id"] = json!("route:request-list-shadow-v1");
        registry["route_mappings"]
            .as_array_mut()
            .expect("route array")
            .push(duplicate);

        assert!(request_read_registry_binding(&registry, &profile)
            .unwrap_err()
            .contains("duplicates route mapping"));
    }

    #[test]
    fn maximum_authority_digest_is_invariant_to_json_object_key_order() {
        let first: Value = serde_json::from_str(
            r#"{"z":{"second":2,"first":1},"a":[{"right":true,"left":false}]}"#,
        )
        .unwrap();
        let reordered: Value = serde_json::from_str(
            r#"{"a":[{"left":false,"right":true}],"z":{"first":1,"second":2}}"#,
        )
        .unwrap();

        assert_eq!(
            maximum_authority_binding_digest(&first).unwrap(),
            maximum_authority_binding_digest(&reordered).unwrap()
        );
    }

    #[test]
    fn maximum_authority_digest_is_length_framed_and_domain_separated() {
        let projection = maximum_authority_projection_fixture();
        let digest = maximum_authority_binding_digest(&projection).unwrap();
        let alternate_domain = maximum_authority_binding_digest_for_domain(
            "ryuki-maximum-authority-binding-v2",
            &projection,
        )
        .unwrap();
        let unframed = raw_digest(&canonical_json_bytes(&projection).unwrap());

        assert_ne!(digest, alternate_domain);
        assert_ne!(digest, unframed);
    }

    #[test]
    fn maximum_authority_digest_binds_every_projection_component() {
        let projection = maximum_authority_projection_fixture();
        let expected = maximum_authority_binding_digest(&projection).unwrap();

        for (pointer, replacement) in [
            (
                "/digest_contract",
                json!("ryuki-maximum-authority-binding-v2"),
            ),
            ("/registry_version", json!(8)),
            ("/actions/0/action_id", json!("request.search")),
            (
                "/actions/1/permitted_actor_kinds/0",
                json!("development-fixture"),
            ),
            ("/resource/resource_kind", json!("audit-log")),
            ("/resource/required_fields/0", json!("alias")),
            (
                "/resolvers/0/resolver_id",
                json!("resolver:request-list-v1"),
            ),
            ("/resolvers/1/resolver_version", json!(2)),
            ("/routes/0/method", json!("POST")),
            ("/routes/1/path_template", json!("/api/requests")),
        ] {
            let mut mutated = projection.clone();
            *mutated
                .pointer_mut(pointer)
                .expect("fixture mutation pointer must resolve") = replacement;
            assert_ne!(
                expected,
                maximum_authority_binding_digest(&mutated).unwrap(),
                "mutation at {pointer} did not change the maximum-authority digest"
            );
        }
    }

    #[test]
    fn production_migration_execution_remains_contained_without_live_render_admission() {
        assert!(!production_migration_runtime_render_admission_is_implemented());
    }

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 16, 12, 0, 0).unwrap()
    }

    fn production_composition_time(seconds: i64, end_seconds: i64) -> ConformanceTrustedTimeWindow {
        let base = Utc.with_ymd_and_hms(2026, 7, 16, 12, 0, 0).unwrap();
        ConformanceTrustedTimeWindow {
            not_before: base + TimeDelta::seconds(seconds),
            not_after: base + TimeDelta::seconds(end_seconds),
        }
    }

    fn pinned_fixture_build(manifest: ProductionBuildManifest) -> PinnedProductionBuildManifest {
        let manifest_value = serde_json::to_value(&manifest).unwrap();
        let raw_bytes = canonical_json_bytes(&manifest_value).unwrap();
        PinnedProductionBuildManifest {
            source_path: PathBuf::from("fixtures/production-build-manifest.json"),
            raw_digest: raw_digest(&raw_bytes),
            raw_bytes: raw_bytes.into_boxed_slice(),
            document: manifest,
        }
    }

    fn genuine_production_boundary_parts(
        workload_deployment_id: Option<&str>,
        workload_valid_for_seconds: i64,
    ) -> (
        VerifiedConformanceClosure,
        VerifiedDeployedWorkload,
        PinnedProductionBuildManifest,
        Box<[u8]>,
        String,
    ) {
        let (conformance, profile_raw_bytes) = genuine_production_closure_fixture()
            .expect("the genuine signed closure fixture must verify");
        let manifest = conformance.production_build_manifest().clone();
        let workload_instance_binding_digest = genuine_workload_instance_binding_digest();
        let deployed_workload = genuine_deployed_workload_fixture_with_instance_binding(
            workload_deployment_id.unwrap_or(conformance.deployment_id()),
            conformance.trust_domain_id(),
            "workload:ryuki-api-fixture",
            &manifest.oci_subject,
            &manifest.runtime_executable,
            &workload_instance_binding_digest,
            workload_valid_for_seconds,
        )
        .expect("the genuine signed workload fixture must verify");
        let profile_raw_digest = raw_digest(&profile_raw_bytes);
        let pinned_build = pinned_fixture_build(manifest);
        (
            conformance,
            deployed_workload,
            pinned_build,
            profile_raw_bytes,
            profile_raw_digest,
        )
    }

    fn genuine_production_boundary(workload_valid_for_seconds: i64) -> VerifiedProductionBoundary {
        let (conformance, deployed_workload, pinned_build, profile_raw_bytes, profile_raw_digest) =
            genuine_production_boundary_parts(None, workload_valid_for_seconds);
        VerifiedProductionBoundary::seal(
            conformance,
            deployed_workload,
            pinned_build,
            profile_raw_bytes,
            profile_raw_digest,
            production_composition_time(5, 6),
        )
        .expect("one exact signed production identity must seal")
    }

    fn production_entra_authenticator_runtime_fixture(
        identity_suffix: &str,
    ) -> (
        RyukiConfig,
        Arc<crate::authenticator_runtime::ApiAuthenticatorRuntime>,
    ) {
        let mut config = RyukiConfig {
            auth_mode: AuthMode::EntraId,
            ..RyukiConfig::default()
        };
        config.entra_tenant_id = format!("tenant-{identity_suffix}");
        config.entra_client_id = format!("client-{identity_suffix}");
        config.entra_redirect_uri =
            format!("https://portal.example.test/{identity_suffix}/entra/callback");
        config.session.credential_hmac_key = "k".repeat(32);
        let cookie_runtime =
            crate::cookie_runtime::ApiCookieRuntime::from_admitted_config(&config, true)
                .expect("production Entra fixture cookie runtime");
        let authority = ResolvedEntraAuthenticatorAuthority::fixture(&config, 60, 3_600, true);
        let runtime = crate::authenticator_runtime::ApiAuthenticatorRuntime::from_admitted_config(
            &config,
            cookie_runtime,
            Some(authority),
            true,
        )
        .expect("production Entra fixture authenticator runtime");
        (config, runtime)
    }

    fn canonical_provider_for_runtime(
        runtime: &Arc<crate::authenticator_runtime::ApiAuthenticatorRuntime>,
    ) -> ActiveProviderConfiguration {
        let authority = runtime
            .entra_authenticator_authority()
            .expect("production Entra runtime authority");
        let document = &authority.runtime_binding.document;
        ActiveProviderConfiguration {
            provider_id: authority.provider_id.clone(),
            config_version: authority.provider_configuration_version,
            payload_digest: authority.provider_configuration_payload_digest.clone(),
            kind: "oidc".into(),
            trust_domain_id: authority.trust_domain_id.clone(),
            active_lifecycle_record_version: authority.provider_lifecycle_record_version,
            capability_descriptor: ProviderCapabilityDescriptorBinding {
                descriptor_id: document.capability_descriptor_id.clone(),
                descriptor_version: document.capability_descriptor_version,
                adapter_kind: document.adapter_kind.clone(),
                adapter_version: document.adapter_version.clone(),
                advertised_capabilities: document.capability_ids.clone(),
                mandatory_baseline_ref: authority.oidc_configuration.issuer_ref.clone(),
                implementation_applicable: true,
                production_eligible: true,
            },
            credential_refs: Vec::new(),
            kind_config: ActiveProviderKindConfig::Oidc {
                configuration: Box::new(authority.oidc_configuration.clone()),
                verified_runtime_binding: Arc::clone(&authority.runtime_binding),
            },
        }
    }

    fn postgresql_infrastructure_pins(
        boundary: &VerifiedProductionBoundary,
    ) -> StartupPostgresqlInfrastructureAttestationPins {
        let challenge =
            exact_challenge(boundary, GuardId::DurablePostgresql).expect("database challenge");
        let RuntimeGuardExpectedValue::DurablePostgresql {
            attestation_profile_id,
            attestation_profile_version,
            attestation_profile_digest,
            ..
        } = challenge.expected_value()
        else {
            panic!("database challenge changed kind");
        };
        let signing_key = SigningKey::from_bytes(&rand::random());
        let public_key = signing_key.verifying_key().to_bytes();
        StartupPostgresqlInfrastructureAttestationPins {
            socket_path: PathBuf::from("/run/ryuki/postgresql-infrastructure/authority.sock"),
            authority_id: "postgresql-infrastructure-attestation-authority:runtime-test".into(),
            key_id: "postgresql-infrastructure-attestation-key:runtime-test".into(),
            public_key_base64: BASE64_STANDARD.encode(public_key),
            public_key_fingerprint: raw_digest(&public_key),
            minimum_authority_epoch: 3,
            attestation_profile_id: attestation_profile_id.clone(),
            attestation_profile_version: *attestation_profile_version,
            attestation_profile_digest: attestation_profile_digest.clone(),
        }
    }

    fn postgresql_tls_channel_binding(
        provider_route_binding_digest: impl Into<String>,
    ) -> PostgresqlTlsChannelBinding {
        PostgresqlTlsChannelBinding {
            provider_route_binding_digest: provider_route_binding_digest.into(),
            server_name: "postgresql.database.svc".into(),
            peer_address: "127.0.0.1".into(),
            peer_port: 5432,
            trust_anchor_bundle_digest: raw_digest(b"postgresql exclusive CA bundle"),
            peer_leaf_certificate_digest: raw_digest(b"postgresql peer leaf certificate"),
            peer_certificate_chain_digest: raw_digest(b"postgresql peer certificate chain"),
            exporter_digest: raw_digest(b"postgresql TLS exporter"),
            tls_protocol: "tlsv1.3".into(),
            tls_cipher_suite: "tls_aes_256_gcm_sha384".into(),
            tls_cipher_bits: 256,
        }
    }

    fn postgresql_session_binding(
        application_name: impl Into<String>,
        tls_channel_binding: PostgresqlTlsChannelBinding,
    ) -> PostgresqlSessionBinding {
        PostgresqlSessionBinding {
            application_name: application_name.into(),
            database_name: "ryuki".into(),
            database_oid: 16_384,
            datid: 16_384,
            server_address: "127.0.0.1".into(),
            server_port: 5432,
            server_major_version: 18,
            primary: true,
            transaction_writable: true,
            default_transaction_writable: true,
            client_address: "127.0.0.1".into(),
            client_port: 43_210,
            backend_process_id: 4_321,
            backend_start: production_composition_time(7, 7).not_before,
            backend_type: "client backend".into(),
            session_login_role: "ryuki_migration_login".into(),
            session_user_oid: 20_001,
            current_role: "ryuki_migrator".into(),
            selected_role: "ryuki_migrator".into(),
            tls_enabled: true,
            tls_protocol: "tlsv1.3".into(),
            tls_cipher_suite: "tls_aes_256_gcm_sha384".into(),
            tls_cipher_bits: 256,
            client_distinguished_name: None,
            issuer_distinguished_name: None,
            tls_channel_binding,
        }
    }

    #[test]
    fn production_migration_admission_uses_receipt_bound_roles_only() {
        let boundary = genuine_production_boundary(240);
        let database_challenge =
            exact_challenge(&boundary, GuardId::DurablePostgresql).expect("database challenge");
        let expected_requirement_digest = database_challenge.requirement_digest().to_owned();
        let expected_challenge_binding_digest =
            database_challenge.challenge_binding_digest().to_owned();
        let expected_inventory_digest = match database_challenge.expected_value() {
            RuntimeGuardExpectedValue::DurablePostgresql {
                migration_inventory_digest,
                ..
            } => migration_inventory_digest.clone(),
            _ => panic!("database challenge changed kind"),
        };
        let admission = verify_production_migration_admission_with_inventory_digest(
            postgresql_infrastructure_pins(&boundary),
            Box::new(boundary),
            crate::database::MigrationStartupMode::ApplyOnly,
            production_composition_time(9, 9).not_before,
            &expected_inventory_digest,
        )
        .expect("the sealed database requirement must authorize only its migration roles");
        let debug = format!("{admission:?}");
        assert!(debug.contains("[RECEIPT-BOUND]"));
        assert!(!debug.contains("ryuki_migrator"));
        assert!(!debug.contains("ryuki_application"));
        assert!(admission
            .role_contract
            .matches_receipt_bound_roles("ryuki_migrator", "ryuki_application"));
        assert!(!admission
            .role_contract
            .matches_receipt_bound_roles("ryuki_application", "ryuki_migrator"));
        assert_eq!(admission.requirement_digest, expected_requirement_digest);
        assert_eq!(
            admission.challenge_binding_digest,
            expected_challenge_binding_digest
        );
    }

    #[test]
    fn production_migration_admission_rejects_attestation_profile_substitution() {
        let boundary = genuine_production_boundary(240);
        let expected_inventory_digest = match exact_challenge(&boundary, GuardId::DurablePostgresql)
            .expect("database challenge")
            .expected_value()
        {
            RuntimeGuardExpectedValue::DurablePostgresql {
                migration_inventory_digest,
                ..
            } => migration_inventory_digest.clone(),
            _ => panic!("database challenge changed kind"),
        };
        let mut pins = postgresql_infrastructure_pins(&boundary);
        pins.attestation_profile_id =
            "postgresql-infrastructure-attestation-profile:substituted".into();
        let error = verify_production_migration_admission_with_inventory_digest(
            pins,
            Box::new(boundary),
            crate::database::MigrationStartupMode::ApplyOnly,
            production_composition_time(9, 9).not_before,
            &expected_inventory_digest,
        )
        .unwrap_err();
        assert!(error.contains("profile pins differ"));
    }

    #[tokio::test]
    async fn production_migration_execution_rechecks_workload_challenge_binding() {
        let boundary = genuine_production_boundary(240);
        let expected_inventory_digest = match exact_challenge(&boundary, GuardId::DurablePostgresql)
            .expect("database challenge")
            .expected_value()
        {
            RuntimeGuardExpectedValue::DurablePostgresql {
                migration_inventory_digest,
                ..
            } => migration_inventory_digest.clone(),
            _ => panic!("database challenge changed kind"),
        };
        let mut admission = verify_production_migration_admission_with_inventory_digest(
            postgresql_infrastructure_pins(&boundary),
            Box::new(boundary),
            crate::database::MigrationStartupMode::ApplyOnly,
            production_composition_time(9, 9).not_before,
            &expected_inventory_digest,
        )
        .expect("the sealed database requirement must validate structurally");
        admission.challenge_binding_digest = raw_digest(b"substituted database challenge");
        let MigrationDatabasePreflight::Production(pending) =
            VerifiedApplyOnlyMigrationAdmission::Production(Box::new(admission))
                .into_database_preflight(production_composition_time(10, 10).not_before)
                .expect("the boundary itself remains fresh")
        else {
            panic!("production preflight changed kind");
        };
        let (_, route_digest) = pending
            .database_provider_and_route_digest()
            .expect("pending target retains its exact provider route");
        let channel = postgresql_tls_channel_binding(route_digest);
        let request_tag = pending
            .request_tag_for_channel(&channel)
            .expect("request tag is derived from the exact TLS channel");
        let error = pending
            .attest_exact_session(
                postgresql_session_binding(request_tag, channel),
                production_composition_time(11, 11).not_before,
            )
            .await
            .unwrap_err();
        assert!(error.contains("workload-bound database challenge"));
    }

    #[test]
    fn nonproduction_migration_preflight_remains_executable_without_attestation() {
        let role_contract = crate::database::MigrationRoleContract::from_receipt_bound_roles(
            "ryuki_migrator",
            "ryuki_application",
        )
        .expect("canonical role contract");
        let inventory_digest = raw_digest(b"nonproduction embedded inventory");
        let preflight = VerifiedApplyOnlyMigrationAdmission::NonProduction {
            role_contract,
            expected_migration_inventory_digest: inventory_digest.clone(),
        }
        .into_database_preflight(production_composition_time(9, 9).not_before)
        .expect("nonproduction preflight does not require production target authority");
        let MigrationDatabasePreflight::NonProduction {
            role_contract,
            expected_migration_inventory_digest,
        } = preflight
        else {
            panic!("nonproduction preflight changed kind");
        };
        assert!(role_contract.matches_receipt_bound_roles("ryuki_migrator", "ryuki_application"));
        assert_eq!(expected_migration_inventory_digest, inventory_digest);
    }

    #[test]
    fn production_migration_execution_cannot_authorize_ddl_at_or_after_valid_until() {
        let valid_until = production_composition_time(120, 120).not_before;
        ensure_production_migration_execution_before_expiry(
            valid_until - TimeDelta::nanoseconds(1),
            valid_until,
        )
        .expect("the exclusive fence remains open immediately before valid_until");
        for now in [valid_until, valid_until + TimeDelta::nanoseconds(1)] {
            let error =
                ensure_production_migration_execution_before_expiry(now, valid_until).unwrap_err();
            assert!(error.contains("cannot authorize DDL"));
            assert!(error.contains("at or after"));
        }
    }

    #[test]
    fn production_migration_preflight_withholds_ddl_authority_until_target_attestation() {
        let boundary = genuine_production_boundary(240);
        let expected_inventory_digest = match exact_challenge(&boundary, GuardId::DurablePostgresql)
            .expect("database challenge")
            .expected_value()
        {
            RuntimeGuardExpectedValue::DurablePostgresql {
                migration_inventory_digest,
                ..
            } => migration_inventory_digest.clone(),
            _ => panic!("database challenge changed kind"),
        };
        let admission = verify_production_migration_admission_with_inventory_digest(
            postgresql_infrastructure_pins(&boundary),
            Box::new(boundary),
            crate::database::MigrationStartupMode::ApplyOnly,
            production_composition_time(9, 9).not_before,
            &expected_inventory_digest,
        )
        .expect("the sealed database requirement must validate structurally");

        let preflight = VerifiedApplyOnlyMigrationAdmission::Production(Box::new(admission))
            .into_database_preflight(production_composition_time(10, 10).not_before)
            .expect("the pending target remains fresh before connection");
        let MigrationDatabasePreflight::Production(pending) = preflight else {
            panic!("production preflight changed kind");
        };
        let (_, route_digest) = pending
            .database_provider_and_route_digest()
            .expect("pending target retains its exact provider route");
        let channel = postgresql_tls_channel_binding(route_digest);
        let request_tag = pending
            .request_tag_for_channel(&channel)
            .expect("request tag is derived from the exact TLS channel");
        assert!(request_tag.starts_with("ryuki-pg-attest-"));
        assert!(request_tag.len() <= 63);
        assert!(pending
            .migration_role_contract()
            .matches_receipt_bound_roles("ryuki_migrator", "ryuki_application"));
    }

    #[tokio::test]
    async fn production_migration_rejects_session_tag_substitution_before_exchange() {
        let boundary = genuine_production_boundary(240);
        let expected_inventory_digest = match exact_challenge(&boundary, GuardId::DurablePostgresql)
            .expect("database challenge")
            .expected_value()
        {
            RuntimeGuardExpectedValue::DurablePostgresql {
                migration_inventory_digest,
                ..
            } => migration_inventory_digest.clone(),
            _ => panic!("database challenge changed kind"),
        };
        let admission = verify_production_migration_admission_with_inventory_digest(
            postgresql_infrastructure_pins(&boundary),
            Box::new(boundary),
            crate::database::MigrationStartupMode::ApplyOnly,
            production_composition_time(9, 9).not_before,
            &expected_inventory_digest,
        )
        .expect("the sealed database requirement must validate structurally");
        let MigrationDatabasePreflight::Production(pending) =
            VerifiedApplyOnlyMigrationAdmission::Production(Box::new(admission))
                .into_database_preflight(production_composition_time(10, 10).not_before)
                .expect("pending target remains fresh")
        else {
            panic!("production preflight changed kind");
        };
        let (_, route_digest) = pending
            .database_provider_and_route_digest()
            .expect("pending target retains its exact provider route");
        let channel = postgresql_tls_channel_binding(route_digest);
        let error = pending
            .attest_exact_session(
                postgresql_session_binding("ryuki-pg-attest-substituted", channel),
                production_composition_time(11, 11).not_before,
            )
            .await
            .unwrap_err();
        assert!(error.contains("application_name differs"));
    }

    #[test]
    fn production_migration_admission_rejects_expired_boundary() {
        let boundary = genuine_production_boundary(12);
        let expected_inventory_digest = match exact_challenge(&boundary, GuardId::DurablePostgresql)
            .expect("database challenge")
            .expected_value()
        {
            RuntimeGuardExpectedValue::DurablePostgresql {
                migration_inventory_digest,
                ..
            } => migration_inventory_digest.clone(),
            _ => panic!("database challenge changed kind"),
        };
        let error = verify_production_migration_admission_with_inventory_digest(
            postgresql_infrastructure_pins(&boundary),
            Box::new(boundary),
            crate::database::MigrationStartupMode::ApplyOnly,
            production_composition_time(13, 13).not_before,
            &expected_inventory_digest,
        )
        .unwrap_err();
        assert!(
            error.contains("no longer fresh"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn production_migration_admission_rejects_wrong_mode_and_image_inventory() {
        let boundary = genuine_production_boundary(240);
        let expected_inventory_digest = match exact_challenge(&boundary, GuardId::DurablePostgresql)
            .expect("database challenge")
            .expected_value()
        {
            RuntimeGuardExpectedValue::DurablePostgresql {
                migration_inventory_digest,
                ..
            } => migration_inventory_digest.clone(),
            _ => panic!("database challenge changed kind"),
        };
        let error = verify_production_migration_admission_with_inventory_digest(
            postgresql_infrastructure_pins(&boundary),
            Box::new(boundary),
            crate::database::MigrationStartupMode::VerifyOnly,
            production_composition_time(9, 9).not_before,
            &expected_inventory_digest,
        )
        .unwrap_err();
        assert!(error.contains("exact apply-only mode"));

        let boundary = genuine_production_boundary(240);
        let error = verify_production_migration_admission_with_inventory_digest(
            postgresql_infrastructure_pins(&boundary),
            Box::new(boundary),
            crate::database::MigrationStartupMode::ApplyOnly,
            production_composition_time(9, 9).not_before,
            &format!("sha256:{}", "f".repeat(64)),
        )
        .unwrap_err();
        assert!(error.contains("receipt-bound production inventory"));
    }

    fn genuine_public_ingress_attestation(
        boundary: &VerifiedProductionBoundary,
        profile_override: Option<(&str, u64, &str)>,
        valid_for_seconds: i64,
    ) -> VerifiedPublicIngressAttestation {
        let challenge = exact_challenge(boundary, GuardId::HttpsPublicUrls)
            .expect("the genuine boundary has one HTTPS public-URLs challenge");
        let RuntimeGuardExpectedValue::HttpsPublicUrls {
            attestation_profile_id,
            attestation_profile_version,
            attestation_profile_digest,
            ..
        } = challenge.expected_value()
        else {
            panic!("the genuine HTTPS public-URLs challenge changed kind");
        };
        let (attestation_profile_id, attestation_profile_version, attestation_profile_digest) =
            profile_override.unwrap_or((
                attestation_profile_id.as_str(),
                *attestation_profile_version,
                attestation_profile_digest.as_str(),
            ));
        genuine_public_ingress_fixture(GenuinePublicIngressFixtureInput {
            deployment_id: boundary.deployed_workload.deployment_id(),
            trust_domain_id: boundary.deployed_workload.trust_domain_id(),
            workload_id: boundary.deployed_workload.workload_id(),
            source_revision: boundary.conformance.source_revision(),
            artifact_digest: boundary.deployed_workload.oci_subject_digest(),
            workload_instance_binding_digest: boundary
                .deployed_workload
                .workload_instance_binding_digest(),
            requirement_digest: challenge.requirement_digest(),
            challenge_binding_digest: challenge.challenge_binding_digest(),
            attestation_profile_id,
            attestation_profile_version,
            attestation_profile_digest,
            valid_for_seconds,
        })
        .expect("the deterministic signed public-ingress fixture must verify")
    }

    #[test]
    fn genuine_https_public_urls_measurement_seals_the_nominal_guard() {
        let boundary = genuine_production_boundary(240);
        let attestation = genuine_public_ingress_attestation(&boundary, None, 180);
        assert_eq!(
            attestation.public_origin_set_digest(),
            GENUINE_PUBLIC_ORIGIN_SET_DIGEST
        );
        assert_eq!(
            attestation.ingress_binding_digest(),
            GENUINE_PUBLIC_INGRESS_BINDING_DIGEST
        );
        assert_eq!(
            attestation.ingress().routes[0].backend_binding_digest,
            boundary
                .deployed_workload
                .workload_instance_binding_digest()
        );

        let witness = seal_verified_https_public_urls_guard(
            &boundary,
            attestation,
            production_composition_time(9, 10),
        )
        .expect("the genuinely verified ingress witness must seal the nominal guard");
        recheck_https_public_urls_guard(&boundary, &witness, production_composition_time(11, 12))
            .expect("the genuinely verified ingress witness remains fresh");
        let debug = format!("{witness:?}");
        assert!(debug.contains("[RETAINED]"));
        assert!(!debug.contains("api.ryuki.example.test"));
    }

    #[test]
    fn genuine_https_public_urls_measurement_rejects_profile_substitution() {
        let boundary = genuine_production_boundary(240);
        let substituted_profile_digest = raw_digest(b"substituted ingress profile fixture");
        let attestation = genuine_public_ingress_attestation(
            &boundary,
            Some((
                "ingress-attestation-profile:substituted-fixture",
                1,
                &substituted_profile_digest,
            )),
            180,
        );
        let error = seal_verified_https_public_urls_guard(
            &boundary,
            attestation,
            production_composition_time(9, 10),
        )
        .unwrap_err();
        assert_eq!(
            error,
            ProductionRuntimeAdmissionError::ExpectedValueMismatch {
                guard_id: GuardId::HttpsPublicUrls,
            }
        );
    }

    #[test]
    fn genuine_https_public_urls_measurement_rejects_expired_evidence() {
        let boundary = genuine_production_boundary(240);
        let attestation = genuine_public_ingress_attestation(&boundary, None, 12);
        let error = seal_verified_https_public_urls_guard(
            &boundary,
            attestation,
            production_composition_time(11, 12),
        )
        .unwrap_err();
        assert_eq!(
            error,
            ProductionRuntimeAdmissionError::WitnessStale {
                guard_id: GuardId::HttpsPublicUrls,
            }
        );
    }

    struct TestRetainedRuntimeHandle {
        marker: &'static str,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for TestRetainedRuntimeHandle {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    type TestRuntimeGuardWitnesses = VerifiedProductionRuntimeGuardWitnesses<
        TestRetainedRuntimeHandle,
        TestRetainedRuntimeHandle,
        TestRetainedRuntimeHandle,
        TestRetainedRuntimeHandle,
        TestRetainedRuntimeHandle,
        TestRetainedRuntimeHandle,
        TestRetainedRuntimeHandle,
        TestRetainedRuntimeHandle,
    >;

    fn runtime_guard_binding(
        boundary: &VerifiedProductionBoundary,
        guard_id: GuardId,
    ) -> (RuntimeGuardExpectedValue, String, String) {
        let challenge = boundary
            .runtime_guard_challenges()
            .find(|challenge| challenge.guard_id() == guard_id)
            .expect("the genuine boundary has every guard exactly once");
        (
            challenge.expected_value().clone(),
            challenge.requirement_digest().to_owned(),
            challenge.challenge_binding_digest().to_owned(),
        )
    }

    fn test_runtime_guard_witnesses(
        boundary: &VerifiedProductionBoundary,
        drops: &Arc<AtomicUsize>,
    ) -> TestRuntimeGuardWitnesses {
        let observed_at_not_before = production_composition_time(7, 7).not_before;
        let observed_at_not_after = production_composition_time(8, 8).not_before;
        let valid_until = production_composition_time(180, 180).not_before;
        let trusted_now = production_composition_time(9, 10);
        macro_rules! witness {
            ($kind:ty, $guard_id:expr, $marker:expr) => {{
                let (observed_value, requirement_digest, challenge_binding_digest) =
                    runtime_guard_binding(boundary, $guard_id);
                <$kind>::seal_test_observation(
                    boundary,
                    observed_value,
                    requirement_digest,
                    challenge_binding_digest,
                    observed_at_not_before,
                    observed_at_not_after,
                    valid_until,
                    TestRetainedRuntimeHandle {
                        marker: $marker,
                        drops: Arc::clone(drops),
                    },
                    trusted_now,
                )
                .expect("the test-only exact observation must seal")
            }};
        }
        VerifiedProductionRuntimeGuardWitnesses::new(
            witness!(
                VerifiedDurablePostgresqlGuardWitness<TestRetainedRuntimeHandle>,
                GuardId::DurablePostgresql,
                "database-handle-secret-marker"
            ),
            witness!(
                VerifiedApprovedSecretProviderGuardWitness<TestRetainedRuntimeHandle>,
                GuardId::ApprovedSecretProvider,
                "secret-provider-handle-secret-marker"
            ),
            witness!(
                VerifiedHttpsPublicUrlsGuardWitness<TestRetainedRuntimeHandle>,
                GuardId::HttpsPublicUrls,
                "ingress-handle-secret-marker"
            ),
            witness!(
                VerifiedSecureCookiesGuardWitness<TestRetainedRuntimeHandle>,
                GuardId::SecureCookies,
                "cookie-handle-secret-marker"
            ),
            witness!(
                VerifiedNonDevelopmentAuthenticatorGuardWitness<TestRetainedRuntimeHandle>,
                GuardId::NonDevelopmentAuthenticator,
                "authenticator-handle-secret-marker"
            ),
            witness!(
                VerifiedExternalSigningKeyMaterialGuardWitness<TestRetainedRuntimeHandle>,
                GuardId::ExternalSigningKeyMaterial,
                "signing-handle-secret-marker"
            ),
            witness!(
                VerifiedMockDependenciesDisabledGuardWitness<TestRetainedRuntimeHandle>,
                GuardId::MockDependenciesDisabled,
                "dependency-handle-secret-marker"
            ),
            witness!(
                VerifiedFirstOwnerPathClosedGuardWitness<TestRetainedRuntimeHandle>,
                GuardId::FirstOwnerPathClosed,
                "first-owner-handle-secret-marker"
            ),
        )
    }

    #[test]
    fn runtime_admission_seals_exact_eight_and_retains_redacted_handles() {
        let boundary = genuine_production_boundary(240);
        assert_eq!(boundary.runtime_guard_challenges().len(), 8);
        let drops = Arc::new(AtomicUsize::new(0));
        let witnesses = test_runtime_guard_witnesses(&boundary, &drops);
        let mut admission = VerifiedProductionRuntimeAdmission::seal(
            boundary,
            witnesses,
            production_composition_time(11, 12),
        )
        .expect("the exact eight typed test witnesses must seal");
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert_eq!(
            admission.secure_cookie_handle().marker,
            "cookie-handle-secret-marker"
        );
        admission
            .ensure_fresh(production_composition_time(13, 14))
            .expect("the complete admission remains fresh");
        let rollback_error = admission
            .ensure_fresh(production_composition_time(12, 13))
            .unwrap_err();
        assert_eq!(
            rollback_error,
            ProductionRuntimeAdmissionError::TrustedTimeRollback
        );
        let debug = format!("{admission:?}");
        assert!(!debug.contains("secret-marker"));
        assert!(debug.contains("[RETAINED]"));
        drop(admission);
        assert_eq!(drops.load(Ordering::SeqCst), 8);
    }

    #[test]
    fn runtime_admission_rejects_cross_workload_witness_replay() {
        let (conformance, first_workload, pinned_build, profile_raw_bytes, profile_raw_digest) =
            genuine_production_boundary_parts(None, 240);
        let second_workload = genuine_deployed_workload_fixture(
            conformance.deployment_id(),
            conformance.trust_domain_id(),
            "workload:ryuki-api-fixture",
            &pinned_build.document.oci_subject,
            &pinned_build.document.runtime_executable,
            240,
        )
        .expect("the second genuine signed workload fixture must verify");
        assert_ne!(
            first_workload.workload_instance_binding_digest(),
            second_workload.workload_instance_binding_digest()
        );
        let second_challenge_digests = conformance
            .runtime_guard_requirements()
            .iter()
            .map(|requirement| {
                production_runtime_guard_challenge_digest(requirement, &second_workload)
                    .expect("the alternate genuine workload challenge must hash")
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let first_boundary = VerifiedProductionBoundary::seal(
            conformance,
            first_workload,
            pinned_build,
            profile_raw_bytes,
            profile_raw_digest,
            production_composition_time(5, 6),
        )
        .expect("the first genuine workload boundary must seal");
        let drops = Arc::new(AtomicUsize::new(0));
        let witnesses = test_runtime_guard_witnesses(&first_boundary, &drops);
        let mut second_boundary = first_boundary;
        second_boundary.deployed_workload = second_workload;
        second_boundary.runtime_guard_challenge_digests = second_challenge_digests;
        let error = VerifiedProductionRuntimeAdmission::seal(
            second_boundary,
            witnesses,
            production_composition_time(11, 12),
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                ProductionRuntimeAdmissionError::ChallengeBindingMismatch { .. }
            ),
            "unexpected replay rejection: {error:?}"
        );
        assert_eq!(drops.load(Ordering::SeqCst), 8);
    }

    #[test]
    fn runtime_guard_witness_rejects_value_binding_and_freshness_substitution() {
        let boundary = genuine_production_boundary(240);
        let (mut observed_value, requirement_digest, challenge_binding_digest) =
            runtime_guard_binding(&boundary, GuardId::DurablePostgresql);
        let RuntimeGuardExpectedValue::DurablePostgresql {
            server_major_version,
            ..
        } = &mut observed_value
        else {
            panic!("fixture guard kind changed");
        };
        *server_major_version = 17;
        let error = VerifiedDurablePostgresqlGuardWitness::seal_test_observation(
            &boundary,
            observed_value,
            requirement_digest,
            challenge_binding_digest,
            production_composition_time(7, 7).not_before,
            production_composition_time(8, 8).not_before,
            production_composition_time(180, 180).not_before,
            (),
            production_composition_time(9, 10),
        )
        .unwrap_err();
        assert_eq!(
            error,
            ProductionRuntimeAdmissionError::ExpectedValueMismatch {
                guard_id: GuardId::DurablePostgresql,
            }
        );

        let (observed_value, requirement_digest, challenge_binding_digest) =
            runtime_guard_binding(&boundary, GuardId::DurablePostgresql);
        let error = VerifiedDurablePostgresqlGuardWitness::seal_test_observation(
            &boundary,
            observed_value,
            requirement_digest,
            challenge_binding_digest,
            production_composition_time(7, 7).not_before,
            production_composition_time(8, 8).not_before,
            production_composition_time(10, 10).not_before,
            (),
            production_composition_time(9, 10),
        )
        .unwrap_err();
        assert_eq!(
            error,
            ProductionRuntimeAdmissionError::WitnessStale {
                guard_id: GuardId::DurablePostgresql,
            }
        );

        let (observed_value, requirement_digest, challenge_binding_digest) =
            runtime_guard_binding(&boundary, GuardId::DurablePostgresql);
        let error = VerifiedDurablePostgresqlGuardWitness::seal_test_observation(
            &boundary,
            observed_value,
            requirement_digest,
            challenge_binding_digest,
            production_composition_time(7, 7).not_before,
            production_composition_time(8, 8).not_before,
            production_composition_time(400, 400).not_before,
            (),
            production_composition_time(9, 10),
        )
        .unwrap_err();
        assert_eq!(
            error,
            ProductionRuntimeAdmissionError::InvalidObservationWindow {
                guard_id: GuardId::DurablePostgresql,
            }
        );

        let (observed_value, _, challenge_binding_digest) =
            runtime_guard_binding(&boundary, GuardId::DurablePostgresql);
        let error = VerifiedDurablePostgresqlGuardWitness::seal_test_observation(
            &boundary,
            observed_value,
            format!("sha256:{}", "f".repeat(64)),
            challenge_binding_digest,
            production_composition_time(7, 7).not_before,
            production_composition_time(8, 8).not_before,
            production_composition_time(180, 180).not_before,
            (),
            production_composition_time(9, 10),
        )
        .unwrap_err();
        assert_eq!(
            error,
            ProductionRuntimeAdmissionError::RequirementBindingMismatch {
                guard_id: GuardId::DurablePostgresql,
            }
        );
    }

    #[test]
    fn genuine_semantic_boundary_reaches_the_exact_live_guard_blocker() {
        let (conformance, deployed_workload, pinned_build, profile_raw_bytes, profile_raw_digest) =
            genuine_production_boundary_parts(None, 240);
        let boundary = VerifiedProductionBoundary::seal(
            conformance,
            deployed_workload,
            pinned_build,
            profile_raw_bytes,
            profile_raw_digest,
            production_composition_time(5, 6),
        )
        .expect("one exact signed production identity must seal");
        let state = ConformanceState::Production(Box::new(boundary));
        validate_runtime_guard_challenge_set(&state)
            .expect("finalization must preserve the exact typed eight-guard challenge set");
        let error = reject_incomplete_runtime_guard_admission(&state).unwrap_err();
        assert!(error.contains(
            "startup remains blocked until all eight receipt-bound live runtime guard witnesses are verified"
        ));
    }

    #[test]
    fn secure_cookie_live_witness_retains_the_exact_runtime_policy_arc() {
        let boundary = genuine_production_boundary(240);
        let config = RyukiConfig::default();
        let runtime = crate::cookie_runtime::ApiCookieRuntime::from_admitted_config(&config, true)
            .expect("production cookie runtime");
        let retained_policy = Arc::clone(
            runtime
                .secure_policy_set()
                .expect("production retains a secure policy"),
        );
        let mut samples = [
            production_composition_time(7, 7).not_before,
            production_composition_time(8, 8).not_before,
            production_composition_time(9, 9).not_before,
            production_composition_time(10, 10).not_before,
        ]
        .into_iter();
        let witness = verify_secure_cookie_guard_with_test_clock(&boundary, &runtime, || {
            samples.next().expect("secure-cookie verifier time sample")
        })
        .expect("the exact live cookie policy must satisfy its workload-bound challenge");

        assert!(Arc::ptr_eq(witness.handle().runtime(), &runtime));
        assert!(Arc::ptr_eq(witness.handle().policies(), &retained_policy));
        assert_eq!(
            retained_policy.measured_expected_value().unwrap(),
            runtime.measured_production_value().unwrap()
        );
        let debug = format!("{witness:?}");
        assert!(debug.contains("[RETAINED]"));
        assert!(!debug.contains("__Host-"));
    }

    #[test]
    fn secure_cookie_live_witness_rejects_policy_drift_and_nonproduction_modes() {
        let boundary = genuine_production_boundary(240);
        let verify = |runtime: &Arc<crate::cookie_runtime::ApiCookieRuntime>| {
            let mut samples = [
                production_composition_time(7, 7).not_before,
                production_composition_time(8, 8).not_before,
                production_composition_time(9, 9).not_before,
                production_composition_time(10, 10).not_before,
            ]
            .into_iter();
            verify_secure_cookie_guard_with_test_clock(&boundary, runtime, || {
                samples.next().expect("secure-cookie verifier time sample")
            })
        };

        let mut drifted = RyukiConfig::default();
        drifted.session.cookie_max_age_secs += 1;
        let drifted_runtime =
            crate::cookie_runtime::ApiCookieRuntime::from_admitted_config(&drifted, true)
                .expect("drifted production cookie runtime still constructs");
        assert_eq!(
            verify(&drifted_runtime).unwrap_err(),
            ProductionRuntimeAdmissionError::ExpectedValueMismatch {
                guard_id: GuardId::SecureCookies,
            }
        );

        let secure_nonproduction = crate::cookie_runtime::ApiCookieRuntime::from_admitted_config(
            &RyukiConfig::default(),
            false,
        )
        .expect("secure non-production cookie runtime");
        assert_eq!(
            verify(&secure_nonproduction).unwrap_err(),
            ProductionRuntimeAdmissionError::GuardMeasurementFailed {
                guard_id: GuardId::SecureCookies,
            }
        );

        let mut loopback = RyukiConfig::default();
        loopback.session.cookie_secure = false;
        loopback.server.bind_address = "127.0.0.1:8080".into();
        let loopback_runtime =
            crate::cookie_runtime::ApiCookieRuntime::from_admitted_config(&loopback, false)
                .expect("loopback development cookie runtime");
        assert_eq!(
            verify(&loopback_runtime).unwrap_err(),
            ProductionRuntimeAdmissionError::GuardMeasurementFailed {
                guard_id: GuardId::SecureCookies,
            }
        );
    }

    #[test]
    fn non_development_authenticator_measurement_retains_the_exact_runtime_graph() {
        let (_, runtime) = production_entra_authenticator_runtime_fixture("authenticator-guard");
        let measured = measured_non_development_authenticator_value(&runtime)
            .expect("the closed production Entra graph must be independently measurable");
        let RuntimeGuardExpectedValue::NonDevelopmentAuthenticator {
            authenticators,
            authenticator_inventory_digest,
        } = &measured
        else {
            panic!("live authenticator measurement changed kind");
        };
        assert_eq!(authenticators.len(), 1);
        assert_eq!(
            authenticators[0].authenticator_kind,
            ProductionAuthenticatorKind::Oidc
        );
        assert!(authenticator_inventory_digest.starts_with("sha256:"));

        let handle = capture_non_development_authenticator_runtime_handle(&runtime)
            .expect("the exact runtime graph must be retainable");
        assert!(handle.retains_runtime(&runtime));
        let (_, substituted_runtime) =
            production_entra_authenticator_runtime_fixture("authenticator-guard");
        assert_eq!(
            measured_non_development_authenticator_value(&substituted_runtime).unwrap(),
            measured,
            "an equal-valued independently constructed graph is useful only as a substitution test"
        );
        assert!(
            !handle.retains_runtime(&substituted_runtime),
            "equal values must not substitute for the retained runtime allocation"
        );

        let development_config = RyukiConfig::default();
        let development_cookie_runtime =
            crate::cookie_runtime::ApiCookieRuntime::from_admitted_config(
                &development_config,
                false,
            )
            .expect("development cookie runtime");
        let development_runtime =
            crate::authenticator_runtime::ApiAuthenticatorRuntime::from_admitted_config(
                &development_config,
                development_cookie_runtime,
                None,
                false,
            )
            .expect("development authenticator runtime");
        assert_eq!(
            measured_non_development_authenticator_value(&development_runtime).unwrap_err(),
            ProductionRuntimeAdmissionError::GuardMeasurementFailed {
                guard_id: GuardId::NonDevelopmentAuthenticator,
            }
        );
    }

    #[test]
    fn non_development_authenticator_witness_rejects_challenge_staleness_and_recheck_drift() {
        let boundary = genuine_production_boundary(240);
        let (_, runtime) = production_entra_authenticator_runtime_fixture("witness-guard");
        let mut samples = [
            production_composition_time(7, 7).not_before,
            production_composition_time(8, 8).not_before,
            production_composition_time(9, 9).not_before,
            production_composition_time(10, 10).not_before,
        ]
        .into_iter();
        assert_eq!(
            verify_non_development_authenticator_guard_with_test_clock(&boundary, &runtime, || {
                samples.next().expect("authenticator verifier time sample")
            },)
            .unwrap_err(),
            ProductionRuntimeAdmissionError::ExpectedValueMismatch {
                guard_id: GuardId::NonDevelopmentAuthenticator,
            },
            "the signed fixture names a different provider and must not admit this live graph"
        );

        let (expected_value, requirement_digest, challenge_binding_digest) =
            runtime_guard_binding(&boundary, GuardId::NonDevelopmentAuthenticator);
        let stale_handle = capture_non_development_authenticator_runtime_handle(&runtime).unwrap();
        assert_eq!(
            VerifiedNonDevelopmentAuthenticatorGuardWitness::seal_test_observation(
                &boundary,
                expected_value,
                requirement_digest,
                challenge_binding_digest,
                production_composition_time(7, 7).not_before,
                production_composition_time(8, 8).not_before,
                production_composition_time(10, 10).not_before,
                stale_handle,
                production_composition_time(9, 10),
            )
            .unwrap_err(),
            ProductionRuntimeAdmissionError::WitnessStale {
                guard_id: GuardId::NonDevelopmentAuthenticator,
            }
        );

        let (expected_value, requirement_digest, challenge_binding_digest) =
            runtime_guard_binding(&boundary, GuardId::NonDevelopmentAuthenticator);
        let handle = capture_non_development_authenticator_runtime_handle(&runtime).unwrap();
        let witness = VerifiedNonDevelopmentAuthenticatorGuardWitness::seal_test_observation(
            &boundary,
            expected_value,
            requirement_digest,
            challenge_binding_digest,
            production_composition_time(7, 7).not_before,
            production_composition_time(8, 8).not_before,
            production_composition_time(180, 180).not_before,
            handle,
            production_composition_time(9, 10),
        )
        .expect("nominal witness mechanics require an exact signed challenge");
        assert_eq!(
            recheck_non_development_authenticator_guard(
                &boundary,
                &witness,
                production_composition_time(10, 11),
            )
            .unwrap_err(),
            ProductionRuntimeAdmissionError::GuardMeasurementFailed {
                guard_id: GuardId::NonDevelopmentAuthenticator,
            },
            "recheck must independently remeasure instead of trusting the sealed observation"
        );
    }

    #[test]
    fn canonical_entra_provider_requires_and_matches_the_exact_runtime_witness() {
        let fixture = ActiveFixture::build();
        let mut context = fixture.load().expect("active test contract");
        let (config, runtime) = production_entra_authenticator_runtime_fixture("provider-guard");
        let provider = canonical_provider_for_runtime(&runtime);

        context
            .verify_non_development_authenticator_runtime_guard(&runtime)
            .expect("non-production verification is a no-op");
        assert!(!context.retains_non_development_authenticator_runtime(&runtime));
        assert!(context
            .validate_selected_provider(&provider, &config)
            .unwrap_err()
            .contains("has no exact retained non-development-authenticator runtime witness"));

        let boundary = genuine_production_boundary(240);
        let (expected_value, requirement_digest, challenge_binding_digest) =
            runtime_guard_binding(&boundary, GuardId::NonDevelopmentAuthenticator);
        let handle = capture_non_development_authenticator_runtime_handle(&runtime).unwrap();
        context.verified_non_development_authenticator_guard = Some(
            VerifiedNonDevelopmentAuthenticatorGuardWitness::seal_test_observation(
                &boundary,
                expected_value,
                requirement_digest,
                challenge_binding_digest,
                production_composition_time(7, 7).not_before,
                production_composition_time(8, 8).not_before,
                production_composition_time(180, 180).not_before,
                handle,
                production_composition_time(9, 10),
            )
            .expect("nominal exact-challenge witness"),
        );
        context
            .validate_selected_provider(&provider, &config)
            .expect("the exact witness-bound canonical provider must be accepted");

        let mut aliased_provider = provider.clone();
        aliased_provider.provider_id = "entra-id".into();
        assert!(context
            .validate_selected_provider(&aliased_provider, &config)
            .unwrap_err()
            .contains("differs from the exact provider and runtime retained"));
        assert_eq!(
            REMAINING_PRODUCTION_RUNTIME_GUARDS,
            [
                GuardId::ExternalSigningKeyMaterial,
                GuardId::MockDependenciesDisabled,
            ]
        );
    }

    #[test]
    fn runtime_guard_challenge_is_bound_to_the_exact_workload_instance_proof() {
        let (conformance, profile_raw_bytes) = genuine_production_closure_fixture()
            .expect("the genuine signed closure fixture must verify");
        let manifest = conformance.production_build_manifest().clone();
        let first_workload = genuine_deployed_workload_fixture(
            conformance.deployment_id(),
            conformance.trust_domain_id(),
            "workload:ryuki-api-fixture",
            &manifest.oci_subject,
            &manifest.runtime_executable,
            240,
        )
        .expect("the first genuine signed workload fixture must verify");
        let second_workload = genuine_deployed_workload_fixture(
            conformance.deployment_id(),
            conformance.trust_domain_id(),
            "workload:ryuki-api-fixture",
            &manifest.oci_subject,
            &manifest.runtime_executable,
            240,
        )
        .expect("the second genuine signed workload fixture must verify");
        assert_ne!(
            first_workload.workload_instance_binding_digest(),
            second_workload.workload_instance_binding_digest()
        );
        let first_requirement = &conformance.runtime_guard_requirements()[0];
        let expected_first =
            production_runtime_guard_challenge_digest(first_requirement, &first_workload).unwrap();
        assert_eq!(
            expected_first,
            production_runtime_guard_challenge_digest(first_requirement, &first_workload).unwrap()
        );
        assert_ne!(
            expected_first,
            production_runtime_guard_challenge_digest(first_requirement, &second_workload).unwrap()
        );

        let profile_raw_digest = raw_digest(&profile_raw_bytes);
        let boundary = VerifiedProductionBoundary::seal(
            conformance,
            first_workload,
            pinned_fixture_build(manifest),
            profile_raw_bytes,
            profile_raw_digest,
            production_composition_time(5, 6),
        )
        .expect("one exact signed production identity must seal");
        let challenges = boundary.runtime_guard_challenges().collect::<Vec<_>>();
        assert_eq!(challenges.len(), 8);
        assert_eq!(challenges[0].challenge_binding_digest(), expected_first);
        for challenge in challenges {
            assert_eq!(challenge.guard_id(), challenge.expected_value().guard_id());
            assert!(challenge.requirement_digest().starts_with("sha256:"));
            assert!(challenge.challenge_binding_digest().starts_with("sha256:"));
            assert_ne!(
                challenge.requirement_digest(),
                challenge.challenge_binding_digest()
            );
        }
    }

    #[test]
    fn production_boundary_rejects_a_genuine_cross_deployment_workload_proof() {
        let (conformance, deployed_workload, pinned_build, profile_raw_bytes, profile_raw_digest) =
            genuine_production_boundary_parts(Some("deployment:cross-wired-fixture"), 240);
        let error = VerifiedProductionBoundary::seal(
            conformance,
            deployed_workload,
            pinned_build,
            profile_raw_bytes,
            profile_raw_digest,
            production_composition_time(5, 6),
        )
        .unwrap_err();
        assert!(error.contains(
            "semantic closure, pinned build, and deployed-workload proof do not identify one exact production workload"
        ));
    }

    #[test]
    fn production_boundary_rejects_a_profile_raw_digest_substitution() {
        let (conformance, deployed_workload, pinned_build, profile_raw_bytes, _) =
            genuine_production_boundary_parts(None, 240);
        let error = VerifiedProductionBoundary::seal(
            conformance,
            deployed_workload,
            pinned_build,
            profile_raw_bytes,
            format!("sha256:{}", "f".repeat(64)),
            production_composition_time(5, 6),
        )
        .unwrap_err();
        assert!(error.contains(
            "production boundary profile bytes differ from the independent startup digest pin"
        ));
    }

    #[test]
    fn production_boundary_rejects_a_workload_that_expires_before_sealing() {
        let (conformance, deployed_workload, pinned_build, profile_raw_bytes, profile_raw_digest) =
            genuine_production_boundary_parts(None, 4);
        let error = VerifiedProductionBoundary::seal(
            conformance,
            deployed_workload,
            pinned_build,
            profile_raw_bytes,
            profile_raw_digest,
            production_composition_time(5, 6),
        )
        .unwrap_err();
        assert!(error.contains("production deployed-workload proof is stale"));
    }

    #[test]
    fn semantic_verification_window_rejects_a_backward_trusted_clock() {
        let started = Utc.with_ymd_and_hms(2026, 7, 17, 8, 0, 6).unwrap();
        let finished = Utc.with_ymd_and_hms(2026, 7, 17, 8, 0, 5).unwrap();
        let error = semantic_verification_window(started, finished).unwrap_err();
        assert_eq!(
            error,
            "trusted time moved backwards during production semantic closure verification"
        );
    }

    fn empty_provider_registry_applicability(
        profile: &DeploymentSecurityProfile,
    ) -> ActiveProviderRegistryApplicabilityClaim {
        ActiveProviderRegistryApplicabilityClaim {
            document_id: profile.provider_registry_ref.document_id.clone(),
            document_version: profile.provider_registry_ref.document_version,
            content_digest: profile.provider_registry_ref.content_digest.clone(),
            artifact_locator: profile.provider_registry_ref.artifact_locator.clone(),
            registry_version: 1,
            active_providers: Vec::new(),
        }
    }

    fn test_runtime_build_identity() -> RuntimeBuildIdentity {
        let adapter = ShippedAdapter {
            adapter_kind: "auth.test".into(),
            adapter_version: "0.1.0".into(),
            production_eligible: false,
            capability_ids: vec!["authenticate".into()],
            mandatory_baseline: MandatoryCapabilityBaseline {
                document_id: "baseline:test".into(),
                document_version: 1,
                content_digest: format!("sha256:{}", "d".repeat(64)),
                artifact_locator: "docs/architecture/test-baseline.md".into(),
                required_trace_ids: vec!["TRACE-SB-BOUND-01-AC-040".into()],
            },
        };
        RuntimeBuildIdentity {
            source_revision: "a".repeat(40),
            component: BuildComponent {
                component_id: "component:ryuki-api".into(),
                component_version: "0.1.0".into(),
                executable_name: "ryuki-api".into(),
                target: BuildTarget {
                    architecture: "x86_64".into(),
                    operating_system: "linux".into(),
                    family: "unix".into(),
                    pointer_width_bits: 64,
                    endian: BuildEndian::Little,
                },
            },
            executable_digest: format!("sha256:{}", "b".repeat(64)),
            executable_byte_length: 1234,
            shipped_adapters: vec![adapter],
            selector_dispositions: vec![BuildSelectorDisposition {
                selector_domain: SelectorDomain::AuthMode,
                selector: "test-auth".into(),
                disposition: SelectorDisposition::Implemented,
                adapter_kind: Some("auth.test".into()),
            }],
        }
    }

    fn test_production_build_manifest(
        runtime: &RuntimeBuildIdentity,
        profile: &DeploymentSecurityProfile,
        control_trace: &Value,
    ) -> ProductionBuildManifest {
        let mut manifest = ProductionBuildManifest {
            schema_uri: PRODUCTION_BUILD_MANIFEST_SCHEMA_URI.into(),
            schema_version: PRODUCTION_BUILD_MANIFEST_SCHEMA_VERSION.into(),
            contract_kind: PRODUCTION_BUILD_MANIFEST_CONTRACT_KIND.into(),
            document_id: "production-build-manifest:runtime-test".into(),
            document_version: 1,
            component: runtime.component.clone(),
            source: BuildSource {
                revision_algorithm: SourceRevisionAlgorithm::GitSha1,
                revision: runtime.source_revision.clone(),
            },
            runtime_executable: RuntimeExecutable {
                content_digest: runtime.executable_digest.clone(),
                byte_length: runtime.executable_byte_length,
            },
            oci_subject: OciSubject {
                subject_kind: OciSubjectKind::OciImageManifest,
                repository: "ghcr.io/example/ryuki-platform-api".into(),
                content_digest: format!("sha256:{}", "c".repeat(64)),
            },
            control_trace_ref: profile.control_trace_ref.clone(),
            shipped_adapters: runtime.shipped_adapters.clone(),
            selector_dispositions: runtime.selector_dispositions.clone(),
            implementation_applicability: ApplicabilityInventoryBinding {
                identity_contract: APPLICABILITY_IDENTITY_CONTRACT.into(),
                inventory_contract: APPLICABILITY_INVENTORY_CONTRACT.into(),
                instance_count: 1,
                content_digest: format!("sha256:{}", "f".repeat(64)),
            },
            implementation_applicability_instances: Vec::new(),
        };
        let derived = derive_implementation_applicability(control_trace, &manifest)
            .expect("derive test implementation applicability");
        manifest.implementation_applicability = derived.binding;
        manifest.implementation_applicability_instances = derived.instances;
        manifest
    }

    fn test_production_control_trace(fixture: &ActiveFixture) -> (Vec<u8>, Value) {
        let bytes = fs::read(fixture.root.join(CONTROL_TRACE_PATH)).unwrap();
        let value = parse_json_strict(&bytes).unwrap();
        (bytes, value)
    }

    fn production_trust_registry(key: &SigningKey, profile: &DeploymentSecurityProfile) -> Value {
        json!({
            "$schema": "https://ryuki.io/schemas/security-contracts/v1/conformance-trust-root-registry.schema.json",
            "schema_version": "1.0.0",
            "contract_kind": "conformance-trust-root-registry",
            "document_id": "conformance-trust-root-registry:runtime-test",
            "document_version": 1,
            "predecessor_registry_ref": null,
            "acceptance_status": "production_accepted",
            "production_accepted": true,
            "lifecycle": {"state": "active", "effective_at": "2026-07-15T00:00:00Z"},
            "applicability": {
                "evaluation_scope": "deployment",
                "security_profiles": ["production"],
                "deployment_ids": profile.applicability.deployment_ids,
                "trust_domain_ids": profile.trust_topology.trust_domain_ids
            },
            "trust_policy_version": 1,
            "canonicalization_profiles": [CANONICALIZATION_PROFILE],
            "signature_algorithms": [SIGNATURE_ALGORITHM],
            "keys": [{
                "key_id": "conformance-key:runtime-test",
                "signer_identity": "signer:runtime-test",
                "algorithm": SIGNATURE_ALGORITHM,
                "public_key_base64": BASE64_STANDARD.encode(key.verifying_key().to_bytes()),
                "public_key_fingerprint": raw_digest(&key.verifying_key().to_bytes()),
                "allowed_purposes": ["conformance_bundle", "package_exit_receipt"],
                "allowed_evidence_tiers": ["externally_attested"],
                "allowed_package_ids": ["SB-0", "SB-9"],
                "deployment_ids": profile.applicability.deployment_ids,
                "trust_domain_ids": profile.trust_topology.trust_domain_ids,
                "valid_from": "2026-07-15T00:00:00Z",
                "valid_until": "2026-07-17T00:00:00Z",
                "lifecycle": "active",
                "supersedes_key_id": null
            }],
            "key_tombstones": []
        })
    }

    fn signed_closure_document(
        kind: &str,
        key: &SigningKey,
        registry_version: u64,
        registry_digest: &str,
    ) -> Value {
        let (schema, id_field, id, purpose, domain) = match kind {
            "conformance-bundle" => (
                "https://ryuki.io/schemas/security-contracts/v1/conformance-bundle.schema.json",
                "bundle_id",
                "bundle:runtime-test",
                "conformance_bundle",
                CONFORMANCE_BUNDLE_DOMAIN,
            ),
            "package-exit-receipt" => (
                "https://ryuki.io/schemas/security-contracts/v1/package-exit-receipt.schema.json",
                "receipt_id",
                "package-exit-receipt:runtime-test",
                "package_exit_receipt",
                PACKAGE_EXIT_RECEIPT_DOMAIN,
            ),
            _ => panic!("unsupported signed closure kind"),
        };
        let mut document = json!({
            "$schema": schema,
            "schema_version": "1.0.0",
            "contract_kind": kind,
            "document_version": 1,
            "signer": {
                "signature_version": SIGNATURE_VERSION,
                "identity": "signer:runtime-test",
                "key_id": "conformance-key:runtime-test",
                "algorithm": SIGNATURE_ALGORITHM,
                "canonicalization": CANONICALIZATION_PROFILE,
                "purpose": purpose,
                "domain": domain,
                "trust_registry_id": "conformance-trust-root-registry:runtime-test",
                "trust_registry_version": registry_version,
                "trust_registry_digest": registry_digest,
                "signed_at": "2026-07-16T10:00:00Z",
                "signed_subject_digest": format!("sha256:{}", "a".repeat(64)),
                "signature_base64": BASE64_STANDARD.encode([0u8; 64])
            }
        });
        document[id_field] = json!(id);
        if kind == "conformance-bundle" {
            document["trace_id"] = json!("TRACE-RUNTIME-TEST");
            document["bindings"] = json!({"deployment_profile": {"deployment_id": DEPLOYMENT_ID}});
            document["provenance"] = json!({"evidence_tier": {"name": "externally_attested"}});
        } else {
            document["package_id"] = json!("SB-9");
            document["closure_context"] =
                json!({"deployment_profile": {"deployment_id": DEPLOYMENT_ID}});
            document["evidence_tier"] = json!({"name": "externally_attested"});
        }
        let subject_digest = conformance_signed_subject_digest(&document).unwrap();
        document["signer"]["signed_subject_digest"] = json!(subject_digest);
        let signature = key.sign(&conformance_signing_bytes(&document).unwrap());
        document["signer"]["signature_base64"] =
            json!(BASE64_STANDARD.encode(signature.to_bytes()));
        document
    }

    fn raw_document_bytes(documents: &BTreeMap<String, Value>) -> BTreeMap<String, Vec<u8>> {
        documents
            .iter()
            .filter(|(_, document)| is_conformance_document(document))
            .map(|(locator, document)| {
                (
                    locator.clone(),
                    serde_json::to_vec(document).expect("synthetic document bytes"),
                )
            })
            .collect()
    }

    fn reference_document_digests(
        document_bytes: &BTreeMap<String, Vec<u8>>,
    ) -> BTreeMap<String, String> {
        document_bytes
            .iter()
            .map(|(locator, bytes)| (locator.clone(), raw_digest(bytes)))
            .collect()
    }

    fn bind_production_root(
        profile: &mut DeploymentSecurityProfile,
        locator: &str,
        receipt: &Value,
    ) {
        let bytes = serde_json::to_vec(receipt).expect("synthetic production root bytes");
        profile.production_acceptance_receipt_ref = Some(VersionedContentReference {
            artifact_kind: ArtifactKind::PackageExitReceipt,
            document_id: receipt["receipt_id"]
                .as_str()
                .expect("synthetic receipt id")
                .to_owned(),
            document_version: receipt["document_version"]
                .as_u64()
                .expect("synthetic receipt version"),
            content_digest: raw_digest(&bytes),
            artifact_locator: locator.to_owned(),
        });
    }

    fn checkpoint_response(
        request_bytes: &[u8],
        request_digest: &str,
        checkpoint_key: &SigningKey,
        conformance_key: &SigningKey,
        documents: &BTreeMap<String, Value>,
        document_bytes: &BTreeMap<String, Vec<u8>>,
        registry_locator: &str,
    ) -> Vec<u8> {
        let request_value: Value =
            serde_json::from_slice(request_bytes).expect("canonical request JSON");
        let conformance_key_fingerprint = raw_digest(&conformance_key.verifying_key().to_bytes());
        let acceptance_records = documents
            .iter()
            .filter(|(_, document)| is_conformance_document(document))
            .enumerate()
            .map(|(index, (locator, document))| {
                let signer = &document["signer"];
                let signature = BASE64_STANDARD
                    .decode(signer["signature_base64"].as_str().unwrap())
                    .unwrap();
                let document_id = document
                    .get("bundle_id")
                    .or_else(|| document.get("receipt_id"))
                    .and_then(Value::as_str)
                    .unwrap();
                let authority_sequence = u64::try_from(index).unwrap() + 10;
                let work_package_id = document
                    .get("package_id")
                    .and_then(Value::as_str)
                    .unwrap_or("SB-0");
                json!({
                    "acceptance_record_id": format!("conformance-acceptance:runtime-{authority_sequence}"),
                    "document": {
                        "contract_kind": document["contract_kind"],
                        "document_id": document_id,
                        "document_version": document["document_version"],
                        "complete_document_digest": raw_digest(document_bytes.get(locator).unwrap()),
                        "signature_digest": raw_digest(&signature),
                        "signed_subject_digest": signer["signed_subject_digest"],
                    },
                    "signer": {
                        "key_id": signer["key_id"],
                        "public_key_fingerprint": conformance_key_fingerprint,
                    },
                    "registry": {
                        "registry_id": signer["trust_registry_id"],
                        "registry_version": signer["trust_registry_version"],
                        "registry_digest": signer["trust_registry_digest"],
                        "artifact_locator": registry_locator,
                        "head_sequence": 1,
                        "head_authority_revision": 3,
                    },
                    "deployment_id": DEPLOYMENT_ID,
                    "trust_domain_id": request_value["namespace"]["trust_domain_id"],
                    "work_package_id": work_package_id,
                    "purpose": signer["purpose"],
                    "evidence_tier": "externally_attested",
                    "authority_sequence": authority_sequence,
                    "authority_epoch": 7,
                    "accepted_at": {
                        "not_before": "2026-07-16T10:00:01Z",
                        "not_after": "2026-07-16T10:00:02Z",
                    },
                    "lifecycle": "accepted",
                })
            })
            .collect::<Vec<_>>();
        let production_root_acceptance_record_id = acceptance_records
            .iter()
            .find(|record| record["work_package_id"] == "SB-9")
            .and_then(|record| record["acceptance_record_id"].as_str())
            .expect("checkpoint fixture must contain an accepted SB-9 production root")
            .to_owned();
        let checkpoint_fingerprint = raw_digest(&checkpoint_key.verifying_key().to_bytes());
        let mut response = json!({
            "schema_version": TRUST_RECONCILIATION_PROTOCOL_VERSION,
            "contract_kind": "conformance-trust-reconciliation-response",
            "canonicalization": CANONICALIZATION_PROFILE,
            "signature_algorithm": SIGNATURE_ALGORITHM,
            "authority": {
                "authority_id": "conformance-trust-checkpoint-authority:runtime-test",
                "key_id": "conformance-trust-checkpoint-key:runtime-test",
                "public_key_fingerprint": checkpoint_fingerprint,
            },
            "request_nonce": request_value["request_nonce"],
            "request_digest": request_digest,
            "namespace": request_value["namespace"],
            "candidate_head": request_value["candidate_head"],
            "current_head": request_value["candidate_head"],
            "candidate_production_root": request_value["candidate_production_root"],
            "current_production_root": {
                "receipt_ref": request_value["candidate_production_root"],
                "acceptance_record_id": production_root_acceptance_record_id,
            },
            "validated_lineage_digest": request_value["validated_lineage_digest"],
            "state": "external_strongly_consistent",
            "outcome": "matched",
            "reconciliation": {
                "candidate_matches_current": true,
                "candidate_production_root_matches_current": true,
                "restored_state_reconciled": true,
                "no_auto_advance": true,
            },
            "checkpoint": {
                "sequence": 20,
                "authority_epoch": 7,
                "authority_revision": 3,
                "observed_at": {
                    "not_before": "2026-07-16T11:59:58Z",
                    "not_after": "2026-07-16T11:59:59Z",
                },
                "valid_until": "2026-07-16T12:04:00Z",
            },
            "acceptance_records": acceptance_records,
            "signature_base64": BASE64_STANDARD.encode([0u8; 64]),
        });
        let mut signed_subject = response.clone();
        signed_subject
            .as_object_mut()
            .unwrap()
            .remove("signature_base64");
        let canonical = canonical_json_bytes(&signed_subject).unwrap();
        let mut signing_bytes = Vec::new();
        for frame in [
            TRUST_RECONCILIATION_RESPONSE_DOMAIN.as_bytes(),
            canonical.as_slice(),
        ] {
            signing_bytes.extend_from_slice(&(frame.len() as u64).to_le_bytes());
            signing_bytes.extend_from_slice(frame);
        }
        response["signature_base64"] =
            json!(BASE64_STANDARD.encode(checkpoint_key.sign(&signing_bytes).to_bytes()));
        serde_json::to_vec(&response).unwrap()
    }

    fn verified_checkpoint_for_documents(
        lineage: ValidatedConformanceRegistryLineage,
        profile: &DeploymentSecurityProfile,
        conformance_key: &SigningKey,
        documents: &BTreeMap<String, Value>,
        document_bytes: &BTreeMap<String, Vec<u8>>,
        registry_locator: &str,
    ) -> VerifiedConformanceTrustCheckpoint {
        let checkpoint_key = SigningKey::from_bytes(&rand::random());
        let checkpoint_public_key = checkpoint_key.verifying_key().to_bytes();
        let checkpoint_fingerprint = raw_digest(&checkpoint_public_key);
        let authority = ConformanceCheckpointAuthorityAnchor {
            authority_id: "conformance-trust-checkpoint-authority:runtime-test",
            key_id: "conformance-trust-checkpoint-key:runtime-test",
            public_key: &checkpoint_public_key,
            public_key_fingerprint: &checkpoint_fingerprint,
            minimum_authority_epoch: 7,
        };
        let requested_document_digests = conformance_document_digests(
            documents,
            document_bytes,
            &reference_document_digests(document_bytes),
        )
        .unwrap();
        let request = lineage
            .reconciliation_request(
                ConformanceTrustScope {
                    deployment_id: &profile.deployment_id,
                    trust_domain_id: &profile.trust_topology.trust_domain_ids[0],
                },
                {
                    let root = profile
                        .production_acceptance_receipt_ref
                        .as_ref()
                        .expect("production fixture root");
                    ConformanceProductionRootRef {
                        document_id: &root.document_id,
                        document_version: root.document_version,
                        content_digest: &root.content_digest,
                        artifact_locator: &root.artifact_locator,
                    }
                },
                authority,
                [42u8; 32],
                fixed_now(),
                &requested_document_digests,
            )
            .unwrap();
        let response = checkpoint_response(
            request.as_bytes(),
            request.digest(),
            &checkpoint_key,
            conformance_key,
            documents,
            document_bytes,
            registry_locator,
        );
        lineage
            .verify_reconciliation_response(
                &request,
                &response,
                authority,
                ConformanceTrustedTimeWindow {
                    not_before: fixed_now(),
                    not_after: fixed_now(),
                },
            )
            .unwrap()
    }

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repository root")
    }

    fn clone_unsealed_test_prepared(
        prepared: &PreparedSecurityContract,
    ) -> PreparedSecurityContract {
        assert!(prepared.production_build_manifest.is_none());
        PreparedSecurityContract {
            profile: prepared.profile.clone(),
            profile_raw_bytes: prepared.profile_raw_bytes.clone(),
            profile_digest: prepared.profile_digest.clone(),
            contract_root: prepared.contract_root.clone(),
            profile_path: prepared.profile_path.clone(),
            documents: prepared.documents.clone(),
            raw_document_bytes: prepared.raw_document_bytes.clone(),
            reference_document_digests: prepared.reference_document_digests.clone(),
            verified_security_limit_profile: Arc::clone(&prepared.verified_security_limit_profile),
            active_providers: prepared.active_providers.clone(),
            provider_registry_applicability: prepared.provider_registry_applicability.clone(),
            conformance_registry_lineage: prepared.conformance_registry_lineage.clone(),
            production_build_manifest: None,
        }
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
                "sources/ryuki-api/src/build_identity.rs",
                "sources/ryuki-api/src/contracts.rs",
                "sources/ryuki-api/src/scheduler.rs",
                "sources/ryuki-api/src/agents.rs",
                "sources/ryuki-api/src/request_authority.rs",
                "sources/ryuki-api/src/repos/requests.rs",
                "sources/ryuki-api/src/repos/job_steps.rs",
                "sources/ryuki-api/src/repos/degradation.rs",
                "sources/ryuki-api/src/database.rs",
                "sources/ryuki-api/src/postgresql_tls_channel.rs",
                "sources/ryuki-api/src/first_owner_runtime.rs",
                "sources/ryuki-api/src/production_dependencies.rs",
                "sources/ryuki-api/src/audit.rs",
                "sources/ryuki-api/src/entra_auth.rs",
                "sources/ryuki-api/src/identity_authority.rs",
                "sources/ryuki-api/src/security_contracts.rs",
                "sources/ryuki-core/src/postgresql_infrastructure.rs",
                "sources/ryuki-engine/src/authorization.rs",
            ] {
                copy_relative(&repository, &root, relative);
            }

            copy_relative_as(
                &repository,
                &root,
                "catalog/security-contracts/v1/control-trace.implementation.json",
                CONTROL_TRACE_PATH,
            );
            let mut trust_root_registry: Value = serde_json::from_slice(
                &fs::read(repository.join(
                    "catalog/security-contracts/v1/conformance-trust-root-registry.implementation.json",
                ))
                .unwrap(),
            )
            .unwrap();
            trust_root_registry["applicability"]["deployment_ids"] = json!([DEPLOYMENT_ID]);
            let trust_root_registry_digest =
                write_json(&root, TRUST_ROOT_REGISTRY_PATH, &trust_root_registry);
            let control_trace_digest =
                raw_digest(&fs::read(root.join(CONTROL_TRACE_PATH)).unwrap());

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
                "authenticator-runtime-admission",
                "repository-conformance",
                "static-dry-run",
                "session-lookup-admission"
            ]);
            profile["applicability"]["enabled_feature_ids"] = profile["enabled_features"].clone();
            profile["conformance_trust_root_registry_ref"] = json!({
                "artifact_kind": "conformance-trust-root-registry",
                "document_id": "conformance-trust-root-registry:repository-implementation-v1",
                "document_version": 1,
                "content_digest": trust_root_registry_digest,
                "artifact_locator": TRUST_ROOT_REGISTRY_PATH
            });
            profile["control_trace_ref"]["content_digest"] = json!(control_trace_digest);
            profile["control_trace_ref"]["artifact_locator"] = json!(CONTROL_TRACE_PATH);
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
                conformance_trust_root_registry_path: PathBuf::from(TRUST_ROOT_REGISTRY_PATH),
                conformance_trust_root_registry_digest: trust_root_registry_digest,
                conformance_trust_checkpoint_authority: None,
                deployed_workload_attestation: None,
                public_ingress_attestation: None,
                postgresql_infrastructure_attestation: None,
                first_owner_authority: None,
                first_owner_closure_certificate: None,
                production_build_manifest: None,
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

        fn install_secret_provider_runtime_binding(&mut self) {
            let document = genuine_secret_provider_runtime_binding_document();
            let document_digest =
                write_json(&self.root, SECRET_PROVIDER_RUNTIME_BINDING_PATH, &document);
            let root = self.root.clone();
            self.rewrite_provider(|provider| {
                provider["applicability"]["provider_kinds"] = json!(["secret-service"]);
                let configuration = &mut provider["configurations"][0];
                configuration["kind"] = json!("secret-service");
                configuration["kind_config"] = json!({
                    "configuration_kind": "secret-service",
                    "adapter_kind": "fixture.repository-static-dry-run",
                    "runtime_binding_ref": {
                        "document_id": "secret-provider-runtime-binding:runtime-test",
                        "document_version": 1,
                        "content_digest": document_digest,
                        "artifact_locator": SECRET_PROVIDER_RUNTIME_BINDING_PATH
                    }
                });
                refresh_reference_digests(provider, &root);
                refresh_provider_payload_digests(provider);
            });
        }

        fn install_authenticator_runtime_binding(&mut self) {
            let provider_path = "catalog/security-contracts/v1/provider-registry.runtime-test.json";
            let provider: Value = serde_json::from_slice(
                &fs::read(self.root.join(provider_path)).expect("provider registry bytes"),
            )
            .expect("provider registry JSON");
            let content_reference = provider["configurations"][0]["capability_descriptor"]
                ["mandatory_baseline_ref"]
                .clone();
            let mut runtime_binding_ref = json!({
                "document_id": "authenticator-runtime-binding:runtime-test",
                "document_version": 1,
                "content_digest": raw_digest(b"temporary authenticator runtime binding"),
                "artifact_locator": AUTHENTICATOR_RUNTIME_BINDING_PATH
            });
            let mut kind_config = oidc_kind_config(runtime_binding_ref.clone(), &content_reference);
            let provider_policy_digest =
                authenticator_provider_policy_binding_digest(&kind_config).unwrap();
            let document = genuine_authenticator_runtime_binding_document_with_policy_digest(
                &provider_policy_digest,
            );
            runtime_binding_ref["content_digest"] = json!(write_json(
                &self.root,
                AUTHENTICATOR_RUNTIME_BINDING_PATH,
                &document,
            ));
            kind_config["runtime_binding_ref"] = runtime_binding_ref;

            let root = self.root.clone();
            self.rewrite_provider(|provider| {
                provider["applicability"]["provider_kinds"] = json!(["oidc"]);
                let configuration = &mut provider["configurations"][0];
                configuration["kind"] = json!("oidc");
                configuration["capability_descriptor"]["adapter_kind"] = json!("auth.entra-id");
                configuration["capability_descriptor"]["advertised_capabilities"] =
                    json!(["token-validation"]);
                configuration["kind_config"] = kind_config;
                refresh_reference_digests(provider, &root);
                refresh_provider_payload_digests(provider);
            });
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

        fn rewrite_trust_root_registry_raw(&mut self, bytes: &[u8]) {
            fs::write(self.root.join(TRUST_ROOT_REGISTRY_PATH), bytes).unwrap();
            let digest = raw_digest(bytes);
            self.pins.conformance_trust_root_registry_digest = digest.clone();
            self.rewrite_profile(|profile| {
                profile["conformance_trust_root_registry_ref"]["content_digest"] = json!(digest);
            });
        }

        fn rewrite_trust_root_registry(&mut self, mutate: impl FnOnce(&mut Value)) {
            let path = self.root.join(TRUST_ROOT_REGISTRY_PATH);
            let mut registry: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            mutate(&mut registry);
            let bytes = serde_json::to_vec_pretty(&registry).unwrap();
            self.rewrite_trust_root_registry_raw(&bytes);
        }

        fn install_trust_registry_lineage(
            &mut self,
            document_count: u64,
            mut mutate: impl FnMut(u64, &mut Value),
        ) -> Vec<(String, String)> {
            assert!(document_count > 0);
            let template: Value = serde_json::from_slice(
                &fs::read(self.root.join(TRUST_ROOT_REGISTRY_PATH)).unwrap(),
            )
            .unwrap();
            let mut written = Vec::new();
            let mut predecessor: Option<(String, String, String, u64)> = None;

            for version in 1..=document_count {
                let locator = if version == document_count {
                    TRUST_ROOT_REGISTRY_PATH.to_string()
                } else {
                    format!(
                        "catalog/security-contracts/v1/conformance-trust-root-registry.runtime-test-v{version}.json"
                    )
                };
                let mut registry = template.clone();
                registry["document_version"] = json!(version);
                registry["predecessor_registry_ref"] = match &predecessor {
                    Some((previous_locator, previous_digest, previous_id, previous_version)) => {
                        json!({
                            "artifact_kind": "conformance-trust-root-registry",
                            "document_id": previous_id,
                            "document_version": previous_version,
                            "content_digest": previous_digest,
                            "artifact_locator": previous_locator
                        })
                    }
                    None => Value::Null,
                };
                mutate(version, &mut registry);
                let document_id = registry["document_id"].as_str().unwrap().to_string();
                let document_version = registry["document_version"].as_u64().unwrap();
                let digest = write_json(&self.root, &locator, &registry);
                predecessor = Some((
                    locator.clone(),
                    digest.clone(),
                    document_id,
                    document_version,
                ));
                written.push((locator, digest));
            }

            let (head_locator, head_digest, head_id, head_version) =
                predecessor.expect("lineage has at least one registry");
            self.pins.conformance_trust_root_registry_path = PathBuf::from(&head_locator);
            self.pins.conformance_trust_root_registry_digest = head_digest.clone();
            self.rewrite_profile(|profile| {
                profile["conformance_trust_root_registry_ref"] = json!({
                    "artifact_kind": "conformance-trust-root-registry",
                    "document_id": head_id,
                    "document_version": head_version,
                    "content_digest": head_digest,
                    "artifact_locator": head_locator
                });
            });
            written
        }
    }

    #[test]
    fn control_plane_grant_scope_is_profile_authoritative_and_unambiguous() {
        let fixture = ActiveFixture::build();
        let context = fixture.load().expect("active fixture loads");
        let scope = context
            .control_plane_grant_scope()
            .expect("single-domain profile has a canonical grant scope");
        assert_eq!(scope.deployment_id(), DEPLOYMENT_ID);
        assert_eq!(scope.trust_domain_id(), "trust-domain:repository-fixture");

        let mut ambiguous = context.profile;
        ambiguous.trust_topology.trust_domain_ids =
            vec!["trust-domain:first".into(), "trust-domain:second".into()];
        assert!(control_plane_grant_scope_from_profile(&ambiguous).is_err());
        ambiguous.trust_topology.trust_domain_ids.clear();
        assert!(control_plane_grant_scope_from_profile(&ambiguous).is_err());
        ambiguous.trust_topology.trust_domain_ids = vec!["foreign-domain".into()];
        assert!(control_plane_grant_scope_from_profile(&ambiguous).is_err());
    }

    fn copy_relative(source_root: &Path, destination_root: &Path, relative: &str) {
        let destination = destination_root.join(relative);
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::copy(source_root.join(relative), destination).unwrap();
    }

    fn copy_relative_as(
        source_root: &Path,
        destination_root: &Path,
        source_relative: &str,
        destination_relative: &str,
    ) {
        let destination = destination_root.join(destination_relative);
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::copy(source_root.join(source_relative), destination).unwrap();
    }

    fn write_json(root: &Path, relative: &str, value: &Value) -> String {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let bytes = serde_json::to_vec_pretty(value).unwrap();
        fs::write(path, &bytes).unwrap();
        raw_digest(&bytes)
    }

    fn genuine_secret_provider_runtime_binding_document() -> Value {
        json!({
            "$schema": "https://ryuki.io/schemas/security-contracts/v1/secret-provider-runtime-binding.schema.json",
            "schema_version": "1.0.0",
            "contract_kind": "secret-provider-runtime-binding",
            "document_id": "secret-provider-runtime-binding:runtime-test",
            "document_version": 1,
            "value_free": true,
            "provider_id": "provider:repository-static-dry-run",
            "provider_configuration_version": 1,
            "deployment_id": DEPLOYMENT_ID,
            "trust_domain_id": "trust-domain:repository-fixture",
            "capability_descriptor_id": "capability-descriptor:repository-static-dry-run-v1",
            "capability_descriptor_version": 1,
            "adapter_kind": "fixture.repository-static-dry-run",
            "adapter_version": "1.0.0",
            "protocol_version": "1.0.0",
            "backend_compatibility_profile": {
                "profile_id": "backend-profile:vault-kv-v2",
                "profile_version": 1,
                "digest_contract": "ryuki-secret-provider-backend-compatibility-profile-v1",
                "binding_digest": raw_digest(b"runtime-test backend compatibility")
            },
            "transport": {
                "endpoint_base_url_binding_digest": raw_digest(b"runtime-test endpoint"),
                "ca_trust_binding_digest": raw_digest(b"runtime-test CA trust"),
                "https_required": true,
                "redirects_allowed": false,
                "ambient_proxy_allowed": false,
                "built_in_roots_allowed": false,
                "connect_timeout_millis": 3000,
                "request_timeout_millis": 10000,
                "response_body_max_bytes": 1048576
            },
            "credential_source": {
                "kind": "kubernetes-service-account-jwt",
                "identity_binding_digest": raw_digest(b"runtime-test workload identity"),
                "audience_binding_digest": raw_digest(b"runtime-test workload audience"),
                "token_path_binding_digest": raw_digest(b"runtime-test projected token path"),
                "provider_authentication_digest_contract": "ryuki-secret-provider-authentication-binding-v1",
                "provider_authentication_binding_digest": raw_digest(b"runtime-test provider authentication"),
                "static_bearer_allowed": false,
                "exported_bearer_allowed": false
            },
            "capability_bindings": [
                {
                    "capability_id": "dry-run-only",
                    "semantic_version": "1.0.0"
                },
                {
                    "capability_id": "static-human-fixture",
                    "semantic_version": "1.0.0"
                }
            ],
            "retained_consumer_ids": [
                "consumer:integration-tests",
                "consumer:secret-resolution"
            ],
            "ownership": {
                "single_runtime_owner": true,
                "ambient_reconfiguration_allowed": false
            }
        })
    }

    fn oidc_kind_config(runtime_binding_ref: Value, content_reference: &Value) -> Value {
        json!({
            "configuration_kind": "oidc",
            "runtime_binding_ref": runtime_binding_ref,
            "issuer_ref": content_reference,
            "endpoint_policy_ref": content_reference,
            "validation_mode": "jwt-jwks",
            "client_id_ref": content_reference,
            "client_authentication_method": "private_key_jwt",
            "accepted_audiences_ref": content_reference,
            "accepted_algorithms": ["RS256"],
            "redirect_policy_ref": content_reference,
            "claim_mapping_ref": content_reference,
            "assurance_mapping_ref": content_reference,
            "logout_mode": "back-channel",
            "lifecycle_mode": "scim-and-reconciliation",
            "revocation_mode": "event-and-introspection"
        })
    }

    fn genuine_authenticator_runtime_binding_document_with_policy_digest(
        provider_policy_binding_digest: &str,
    ) -> Value {
        json!({
            "$schema": "https://ryuki.io/schemas/security-contracts/v1/authenticator-runtime-binding.schema.json",
            "schema_version": "1.0.0",
            "contract_kind": "authenticator-runtime-binding",
            "document_id": "authenticator-runtime-binding:runtime-test",
            "document_version": 1,
            "value_free": true,
            "provider_id": "provider:repository-static-dry-run",
            "provider_configuration_version": 1,
            "deployment_id": DEPLOYMENT_ID,
            "trust_domain_id": "trust-domain:repository-fixture",
            "capability_descriptor_id": "capability-descriptor:repository-static-dry-run-v1",
            "capability_descriptor_version": 1,
            "adapter_kind": "auth.entra-id",
            "adapter_version": "1.0.0",
            "authenticator_kind": "oidc",
            "provider_policy": {
                "digest_contract": "ryuki-authenticator-provider-policy-binding-v1",
                "binding_digest": provider_policy_binding_digest
            },
            "capability_ids": ["token-validation"],
            "credential_paths": [{
                "path_id": "authenticator-path:runtime-test-bearer",
                "path_version": 1,
                "verifier": {
                    "verifier_id": "authenticator-verifier:runtime-test-bearer",
                    "verifier_version": 1,
                    "issuer_binding_digest": raw_digest(b"runtime-test issuer"),
                    "audience_set_binding_digest": raw_digest(b"runtime-test audiences"),
                    "accepted_algorithm_ids": ["rs256"],
                    "required_claim_ids": ["aud", "exp", "iat", "iss", "nbf", "oid", "sub"],
                    "provider_subject_claim_id": "oid",
                    "key_source_kind": "jwt-jwks",
                    "key_source_binding_digest": raw_digest(b"runtime-test key source"),
                    "expiration_required": true,
                    "not_before_required": true,
                    "issued_at_required": true,
                    "nonce_required": false,
                    "clock_skew_limit_id": "limit:authenticator.clock-skew",
                    "maximum_clock_skew_seconds": 60,
                    "redirects_allowed": false
                },
                "credential_profile": {
                    "profile_id": "credential-profile:runtime-test-bearer",
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
                "cache_partition": {
                    "digest_contract": "ryuki-authenticator-cache-partition-v1",
                    "binding_digest": raw_digest(b"runtime-test authenticator cache partition")
                },
                "protocol_binding": {
                    "digest_contract": "ryuki-authenticator-protocol-binding-v1",
                    "binding_digest": raw_digest(b"runtime-test bearer protocol")
                },
                "retained_consumer_ids": ["runtime-consumer:runtime-test-bearer"]
            }],
            "ownership": {
                "single_runtime_owner": true,
                "ambient_reconfiguration_allowed": false
            }
        })
    }

    fn genuine_authenticator_runtime_binding_document() -> Value {
        genuine_authenticator_runtime_binding_document_with_policy_digest(&raw_digest(
            b"runtime-test authenticator policy",
        ))
    }

    struct AuthenticatorBindingCase {
        profile: DeploymentSecurityProfile,
        capability_descriptor: ProviderCapabilityDescriptorBinding,
        oidc_configuration: OidcKindConfig,
        raw_oidc_kind_config: Value,
        provider_payload_digest: String,
        reference: ContentReferenceBinding,
        documents: BTreeMap<String, Value>,
        document_bytes: BTreeMap<String, Vec<u8>>,
        reference_document_digests: BTreeMap<String, String>,
    }

    impl AuthenticatorBindingCase {
        fn build() -> Self {
            let fixture = ActiveFixture::build();
            let profile = serde_json::from_slice(
                &fs::read(fixture.root.join(PROFILE_PATH)).expect("profile bytes"),
            )
            .expect("typed deployment profile");
            let registry: Value = serde_json::from_slice(
                &fs::read(
                    fixture
                        .root
                        .join("catalog/security-contracts/v1/provider-registry.runtime-test.json"),
                )
                .expect("provider registry bytes"),
            )
            .expect("provider registry JSON");
            let mut descriptor_value =
                registry["configurations"][0]["capability_descriptor"].clone();
            descriptor_value["adapter_kind"] = json!("auth.entra-id");
            descriptor_value["advertised_capabilities"] = json!(["token-validation"]);
            let capability_descriptor =
                serde_json::from_value(descriptor_value).expect("typed OIDC capability descriptor");
            let reference = ContentReferenceBinding {
                document_id: "authenticator-runtime-binding:runtime-test".into(),
                document_version: 1,
                content_digest: raw_digest(b"temporary authenticator runtime binding"),
                artifact_locator: AUTHENTICATOR_RUNTIME_BINDING_PATH.into(),
            };
            let reference_value = serde_json::to_value(&reference).unwrap();
            let kind_config_value = oidc_kind_config(
                reference_value,
                &registry["configurations"][0]["capability_descriptor"]["mandatory_baseline_ref"],
            );
            let provider_policy_binding_digest =
                authenticator_provider_policy_binding_digest(&kind_config_value).unwrap();
            let oidc_configuration = serde_json::from_value(kind_config_value.clone())
                .expect("typed OIDC provider configuration");
            let mut case = Self {
                profile,
                capability_descriptor,
                oidc_configuration,
                raw_oidc_kind_config: kind_config_value,
                provider_payload_digest: raw_digest(b"runtime-test OIDC provider payload"),
                reference,
                documents: BTreeMap::new(),
                document_bytes: BTreeMap::new(),
                reference_document_digests: BTreeMap::new(),
            };
            case.repin_document(
                genuine_authenticator_runtime_binding_document_with_policy_digest(
                    &provider_policy_binding_digest,
                ),
            );
            case
        }

        fn repin_document(&mut self, document: Value) {
            let bytes = serde_json::to_vec_pretty(&document).expect("runtime binding bytes");
            let digest = raw_digest(&bytes);
            self.reference.document_id = document["document_id"]
                .as_str()
                .expect("runtime binding document id")
                .into();
            self.reference.document_version = document["document_version"]
                .as_u64()
                .expect("runtime binding document version");
            self.reference.content_digest = digest.clone();
            self.oidc_configuration.runtime_binding_ref = self.reference.clone();
            self.raw_oidc_kind_config["runtime_binding_ref"] =
                serde_json::to_value(&self.reference).unwrap();
            self.documents
                .insert(AUTHENTICATOR_RUNTIME_BINDING_PATH.into(), document);
            self.document_bytes
                .insert(AUTHENTICATOR_RUNTIME_BINDING_PATH.into(), bytes);
            self.reference_document_digests
                .insert(AUTHENTICATOR_RUNTIME_BINDING_PATH.into(), digest);
        }

        fn document(&self) -> Value {
            self.documents[AUTHENTICATOR_RUNTIME_BINDING_PATH].clone()
        }

        fn verify(&self) -> Result<VerifiedAuthenticatorRuntimeBinding, String> {
            verify_authenticator_runtime_binding(
                &self.reference,
                AuthenticatorBindingVerificationContext {
                    provider_id: "provider:repository-static-dry-run",
                    provider_configuration_version: 1,
                    provider_payload_digest: &self.provider_payload_digest,
                    provider_kind: "oidc",
                    trust_domain_id: "trust-domain:repository-fixture",
                    capability_descriptor: &self.capability_descriptor,
                    oidc_configuration: &self.oidc_configuration,
                    raw_oidc_kind_config: &self.raw_oidc_kind_config,
                    deployment_profile: &self.profile,
                },
                &self.documents,
                &self.document_bytes,
                &self.reference_document_digests,
            )
        }
    }

    struct SecretProviderBindingCase {
        profile: DeploymentSecurityProfile,
        capability_descriptor: ProviderCapabilityDescriptorBinding,
        reference: ContentReferenceBinding,
        documents: BTreeMap<String, Value>,
        document_bytes: BTreeMap<String, Vec<u8>>,
        reference_document_digests: BTreeMap<String, String>,
    }

    impl SecretProviderBindingCase {
        fn build() -> Self {
            let fixture = ActiveFixture::build();
            let profile = serde_json::from_slice(
                &fs::read(fixture.root.join(PROFILE_PATH)).expect("profile bytes"),
            )
            .expect("typed deployment profile");
            let registry: Value = serde_json::from_slice(
                &fs::read(
                    fixture
                        .root
                        .join("catalog/security-contracts/v1/provider-registry.runtime-test.json"),
                )
                .expect("provider registry bytes"),
            )
            .expect("provider registry JSON");
            let capability_descriptor = serde_json::from_value(
                registry["configurations"][0]["capability_descriptor"].clone(),
            )
            .expect("typed provider capability descriptor");
            let mut case = Self {
                profile,
                capability_descriptor,
                reference: ContentReferenceBinding {
                    document_id: "secret-provider-runtime-binding:runtime-test".into(),
                    document_version: 1,
                    content_digest: raw_digest(b"temporary runtime binding digest"),
                    artifact_locator: SECRET_PROVIDER_RUNTIME_BINDING_PATH.into(),
                },
                documents: BTreeMap::new(),
                document_bytes: BTreeMap::new(),
                reference_document_digests: BTreeMap::new(),
            };
            case.repin_document(genuine_secret_provider_runtime_binding_document());
            case
        }

        fn repin_document(&mut self, document: Value) {
            let bytes = serde_json::to_vec_pretty(&document).expect("runtime binding bytes");
            let digest = raw_digest(&bytes);
            self.reference.document_id = document["document_id"]
                .as_str()
                .expect("runtime binding document id")
                .into();
            self.reference.document_version = document["document_version"]
                .as_u64()
                .expect("runtime binding document version");
            self.reference.content_digest = digest.clone();
            self.documents
                .insert(SECRET_PROVIDER_RUNTIME_BINDING_PATH.into(), document);
            self.document_bytes
                .insert(SECRET_PROVIDER_RUNTIME_BINDING_PATH.into(), bytes);
            self.reference_document_digests
                .insert(SECRET_PROVIDER_RUNTIME_BINDING_PATH.into(), digest);
        }

        fn document(&self) -> Value {
            self.documents[SECRET_PROVIDER_RUNTIME_BINDING_PATH].clone()
        }

        fn verify(&self) -> Result<VerifiedSecretProviderRuntimeBinding, String> {
            verify_secret_provider_runtime_binding(
                &self.reference,
                SecretProviderBindingVerificationContext {
                    provider_id: "provider:repository-static-dry-run",
                    provider_configuration_version: 1,
                    trust_domain_id: "trust-domain:repository-fixture",
                    capability_descriptor: &self.capability_descriptor,
                    deployment_profile: &self.profile,
                },
                &self.documents,
                &self.document_bytes,
                &self.reference_document_digests,
            )
        }
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
                CONFORMANCE_TRUST_ROOT_REGISTRY_PATH_ENV.into(),
                OsString::from(TRUST_ROOT_REGISTRY_PATH),
            ),
            (
                CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST_ENV.into(),
                OsString::from(&digest),
            ),
            (
                EXPECTED_DEPLOYMENT_ID_ENV.into(),
                OsString::from(DEPLOYMENT_ID),
            ),
            (SECURITY_PROFILE_ENV.into(), OsString::from("test")),
        ]);
        let pins = StartupSecurityPins::from_source(|name| values.get(name).cloned()).unwrap();
        assert_eq!(pins.security_profile, SecurityProfile::Test);
        assert!(pins.production_build_manifest.is_none());

        for missing in [
            SECURITY_CONTRACT_ROOT_ENV,
            SECURITY_PROFILE_PATH_ENV,
            SECURITY_PROFILE_DIGEST_ENV,
            CONFORMANCE_TRUST_ROOT_REGISTRY_PATH_ENV,
            CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST_ENV,
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
        let mut traversal = values.clone();
        traversal.insert(
            SECURITY_PROFILE_PATH_ENV.into(),
            OsString::from("../profile.json"),
        );
        assert!(StartupSecurityPins::from_source(|name| traversal.get(name).cloned()).is_err());

        let mut trust_root_traversal = values.clone();
        trust_root_traversal.insert(
            CONFORMANCE_TRUST_ROOT_REGISTRY_PATH_ENV.into(),
            OsString::from("../trust-root-registry.json"),
        );
        assert!(
            StartupSecurityPins::from_source(|name| trust_root_traversal.get(name).cloned())
                .unwrap_err()
                .contains("normalized relative path")
        );

        let mut non_json_trust_root = values.clone();
        non_json_trust_root.insert(
            CONFORMANCE_TRUST_ROOT_REGISTRY_PATH_ENV.into(),
            OsString::from("catalog/security-contracts/v1/trust-root.txt"),
        );
        assert!(
            StartupSecurityPins::from_source(|name| non_json_trust_root.get(name).cloned())
                .unwrap_err()
                .contains("relative .json path")
        );

        for noncanonical in [
            "catalog/./trust-root.json",
            "catalog//trust-root.json",
            "catalog\\trust-root.json",
        ] {
            let mut invalid = values.clone();
            invalid.insert(
                CONFORMANCE_TRUST_ROOT_REGISTRY_PATH_ENV.into(),
                OsString::from(noncanonical),
            );
            assert!(
                StartupSecurityPins::from_source(|name| invalid.get(name).cloned())
                    .unwrap_err()
                    .contains("normalized relative path")
            );
        }

        let checkpoint_key = SigningKey::from_bytes(&rand::random());
        let checkpoint_public_key =
            BASE64_STANDARD.encode(checkpoint_key.verifying_key().to_bytes());
        let checkpoint_fingerprint = raw_digest(&checkpoint_key.verifying_key().to_bytes());
        let mut complete_checkpoint = values.clone();
        for (name, value) in [
            (
                CONFORMANCE_TRUST_CHECKPOINT_SOCKET_ENV,
                "/run/ryuki/trust-checkpoint/authority.sock".to_string(),
            ),
            (
                CONFORMANCE_TRUST_CHECKPOINT_AUTHORITY_ID_ENV,
                "conformance-trust-checkpoint-authority:runtime-test".to_string(),
            ),
            (
                CONFORMANCE_TRUST_CHECKPOINT_KEY_ID_ENV,
                "conformance-trust-checkpoint-key:runtime-test".to_string(),
            ),
            (
                CONFORMANCE_TRUST_CHECKPOINT_PUBLIC_KEY_BASE64_ENV,
                checkpoint_public_key,
            ),
            (
                CONFORMANCE_TRUST_CHECKPOINT_PUBLIC_KEY_FINGERPRINT_ENV,
                checkpoint_fingerprint,
            ),
            (
                CONFORMANCE_TRUST_CHECKPOINT_MIN_AUTHORITY_EPOCH_ENV,
                "7".to_string(),
            ),
        ] {
            complete_checkpoint.insert(name.into(), OsString::from(value));
        }
        let checkpoint_pins =
            StartupSecurityPins::from_source(|name| complete_checkpoint.get(name).cloned())
                .unwrap()
                .conformance_trust_checkpoint_authority
                .expect("complete checkpoint binding");
        assert_eq!(
            checkpoint_pins.socket_path,
            PathBuf::from("/run/ryuki/trust-checkpoint/authority.sock")
        );
        assert_eq!(checkpoint_pins.minimum_authority_epoch, 7);

        let mut partial_checkpoint = values.clone();
        partial_checkpoint.insert(
            CONFORMANCE_TRUST_CHECKPOINT_SOCKET_ENV.into(),
            OsString::from("/run/ryuki/trust-checkpoint/authority.sock"),
        );
        assert!(
            StartupSecurityPins::from_source(|name| partial_checkpoint.get(name).cloned())
                .unwrap_err()
                .contains(CONFORMANCE_TRUST_CHECKPOINT_AUTHORITY_ID_ENV)
        );

        let mut production_without_checkpoint = values.clone();
        production_without_checkpoint
            .insert(SECURITY_PROFILE_ENV.into(), OsString::from("production"));
        assert!(StartupSecurityPins::from_source(|name| {
            production_without_checkpoint.get(name).cloned()
        })
        .unwrap_err()
        .contains("independently governed"));

        let mut production_without_build_manifest = complete_checkpoint.clone();
        production_without_build_manifest
            .insert(SECURITY_PROFILE_ENV.into(), OsString::from("production"));
        assert!(StartupSecurityPins::from_source(|name| {
            production_without_build_manifest.get(name).cloned()
        })
        .unwrap_err()
        .contains(PRODUCTION_BUILD_MANIFEST_PATH_ENV));

        let build_manifest_path = "/run/ryuki/build/production-build-manifest.json";
        let mut production_complete = production_without_build_manifest.clone();
        production_complete.insert(
            PRODUCTION_BUILD_MANIFEST_PATH_ENV.into(),
            OsString::from(build_manifest_path),
        );
        production_complete.insert(
            PRODUCTION_BUILD_MANIFEST_DIGEST_ENV.into(),
            OsString::from(&digest),
        );
        assert!(
            StartupSecurityPins::from_source(|name| production_complete.get(name).cloned())
                .unwrap_err()
                .contains(DEPLOYED_WORKLOAD_ATTESTATION_SOCKET_ENV)
        );

        let workload_key = SigningKey::from_bytes(&rand::random());
        let workload_public_key = BASE64_STANDARD.encode(workload_key.verifying_key().to_bytes());
        let workload_fingerprint = raw_digest(&workload_key.verifying_key().to_bytes());
        let workload_group = [
            (
                DEPLOYED_WORKLOAD_ATTESTATION_SOCKET_ENV,
                "/run/ryuki/workload-attestation/authority.sock".to_string(),
            ),
            (
                DEPLOYED_WORKLOAD_ATTESTATION_AUTHORITY_ID_ENV,
                "deployed-workload-attestation-authority:runtime-test".to_string(),
            ),
            (
                DEPLOYED_WORKLOAD_ATTESTATION_KEY_ID_ENV,
                "deployed-workload-attestation-key:runtime-test".to_string(),
            ),
            (
                DEPLOYED_WORKLOAD_ATTESTATION_PUBLIC_KEY_BASE64_ENV,
                workload_public_key,
            ),
            (
                DEPLOYED_WORKLOAD_ATTESTATION_PUBLIC_KEY_FINGERPRINT_ENV,
                workload_fingerprint,
            ),
            (
                DEPLOYED_WORKLOAD_ATTESTATION_MIN_AUTHORITY_EPOCH_ENV,
                "11".to_string(),
            ),
            (
                DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_ID_ENV,
                "deployed-workload-measurement-profile:runtime-test".to_string(),
            ),
            (
                DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_VERSION_ENV,
                "3".to_string(),
            ),
            (
                DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_DIGEST_ENV,
                digest.clone(),
            ),
            (EXPECTED_WORKLOAD_ID_ENV, "workload:ryuki-api".to_string()),
        ];
        for (name, value) in &workload_group {
            production_complete.insert((*name).into(), OsString::from(value));
        }
        assert!(
            StartupSecurityPins::from_source(|name| production_complete.get(name).cloned())
                .unwrap_err()
                .contains(PUBLIC_INGRESS_ATTESTATION_SOCKET_ENV)
        );

        let ingress_key = SigningKey::from_bytes(&rand::random());
        let ingress_public_key = BASE64_STANDARD.encode(ingress_key.verifying_key().to_bytes());
        let ingress_fingerprint = raw_digest(&ingress_key.verifying_key().to_bytes());
        let ingress_group = [
            (
                PUBLIC_INGRESS_ATTESTATION_SOCKET_ENV,
                "/run/ryuki/public-ingress/authority.sock".to_string(),
            ),
            (
                PUBLIC_INGRESS_ATTESTATION_AUTHORITY_ID_ENV,
                "public-ingress-attestation-authority:runtime-test".to_string(),
            ),
            (
                PUBLIC_INGRESS_ATTESTATION_KEY_ID_ENV,
                "public-ingress-attestation-key:runtime-test".to_string(),
            ),
            (
                PUBLIC_INGRESS_ATTESTATION_PUBLIC_KEY_BASE64_ENV,
                ingress_public_key,
            ),
            (
                PUBLIC_INGRESS_ATTESTATION_PUBLIC_KEY_FINGERPRINT_ENV,
                ingress_fingerprint,
            ),
            (
                PUBLIC_INGRESS_ATTESTATION_MIN_AUTHORITY_EPOCH_ENV,
                "13".to_string(),
            ),
            (
                PUBLIC_INGRESS_ATTESTATION_PROFILE_ID_ENV,
                "ingress-attestation-profile:runtime-test".to_string(),
            ),
            (
                PUBLIC_INGRESS_ATTESTATION_PROFILE_VERSION_ENV,
                "5".to_string(),
            ),
            (
                PUBLIC_INGRESS_ATTESTATION_PROFILE_DIGEST_ENV,
                digest.clone(),
            ),
        ];
        for (name, value) in &ingress_group {
            production_complete.insert((*name).into(), OsString::from(value));
        }
        assert!(
            StartupSecurityPins::from_source(|name| production_complete.get(name).cloned())
                .unwrap_err()
                .contains(POSTGRESQL_INFRASTRUCTURE_ATTESTATION_SOCKET_ENV)
        );

        let postgresql_key = SigningKey::from_bytes(&rand::random());
        let postgresql_public_key =
            BASE64_STANDARD.encode(postgresql_key.verifying_key().to_bytes());
        let postgresql_fingerprint = raw_digest(&postgresql_key.verifying_key().to_bytes());
        let postgresql_group = [
            (
                POSTGRESQL_INFRASTRUCTURE_ATTESTATION_SOCKET_ENV,
                "/run/ryuki/postgresql-infrastructure/authority.sock".to_string(),
            ),
            (
                POSTGRESQL_INFRASTRUCTURE_ATTESTATION_AUTHORITY_ID_ENV,
                "postgresql-infrastructure-attestation-authority:runtime-test".to_string(),
            ),
            (
                POSTGRESQL_INFRASTRUCTURE_ATTESTATION_KEY_ID_ENV,
                "postgresql-infrastructure-attestation-key:runtime-test".to_string(),
            ),
            (
                POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_BASE64_ENV,
                postgresql_public_key,
            ),
            (
                POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_FINGERPRINT_ENV,
                postgresql_fingerprint,
            ),
            (
                POSTGRESQL_INFRASTRUCTURE_ATTESTATION_MIN_AUTHORITY_EPOCH_ENV,
                "17".to_string(),
            ),
            (
                POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_ID_ENV,
                "postgresql-infrastructure-attestation-profile:runtime-test".to_string(),
            ),
            (
                POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_VERSION_ENV,
                "7".to_string(),
            ),
            (
                POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_DIGEST_ENV,
                digest.clone(),
            ),
        ];
        for (name, value) in &postgresql_group {
            production_complete.insert((*name).into(), OsString::from(value));
        }
        assert!(
            StartupSecurityPins::from_source(|name| production_complete.get(name).cloned())
                .unwrap_err()
                .contains(FIRST_OWNER_AUTHORITY_ID_ENV)
        );

        let first_owner_key = SigningKey::from_bytes(&rand::random());
        let first_owner_public_key =
            BASE64_STANDARD.encode(first_owner_key.verifying_key().to_bytes());
        let first_owner_fingerprint = raw_digest(&first_owner_key.verifying_key().to_bytes());
        let first_owner_group = [
            (
                FIRST_OWNER_AUTHORITY_ID_ENV,
                "first-owner-authority:runtime-test".to_string(),
            ),
            (
                FIRST_OWNER_AUTHORITY_KEY_ID_ENV,
                "first-owner-authority-key:runtime-test".to_string(),
            ),
            (
                FIRST_OWNER_AUTHORITY_PUBLIC_KEY_BASE64_ENV,
                first_owner_public_key,
            ),
            (
                FIRST_OWNER_AUTHORITY_PUBLIC_KEY_FINGERPRINT_ENV,
                first_owner_fingerprint,
            ),
            (FIRST_OWNER_AUTHORITY_MIN_EPOCH_ENV, "19".to_string()),
        ];
        for (name, value) in &first_owner_group {
            production_complete.insert((*name).into(), OsString::from(value));
        }
        let production_pins =
            StartupSecurityPins::from_source(|name| production_complete.get(name).cloned())
                .expect("production pins are complete");
        assert!(production_pins.first_owner_closure_certificate.is_none());

        let first_owner_certificate_path =
            "/run/ryuki/first-owner/first-owner-closure-certificate.json";
        let mut production_with_first_owner_certificate = production_complete.clone();
        production_with_first_owner_certificate.insert(
            FIRST_OWNER_CLOSURE_CERTIFICATE_PATH_ENV.into(),
            OsString::from(first_owner_certificate_path),
        );
        production_with_first_owner_certificate.insert(
            FIRST_OWNER_CLOSURE_CERTIFICATE_DIGEST_ENV.into(),
            OsString::from(&digest),
        );
        let production_certificate_pins = StartupSecurityPins::from_source(|name| {
            production_with_first_owner_certificate.get(name).cloned()
        })
        .expect("production first-owner certificate pins are complete");
        let certificate_pins = production_certificate_pins
            .first_owner_closure_certificate
            .as_ref()
            .expect("production first-owner certificate binding");
        assert_eq!(
            certificate_pins.path,
            PathBuf::from(first_owner_certificate_path)
        );
        assert_eq!(certificate_pins.digest, digest);
        production_certificate_pins
            .validate_first_owner_certificate_mode(crate::database::MigrationStartupMode::ApplyOnly)
            .expect("apply-only may retain the detached certificate pins");
        for forbidden_mode in [
            crate::database::MigrationStartupMode::LocalAuto,
            crate::database::MigrationStartupMode::VerifyOnly,
        ] {
            assert!(production_certificate_pins
                .validate_first_owner_certificate_mode(forbidden_mode)
                .unwrap_err()
                .contains("exact apply-only"));
        }

        for missing in [
            FIRST_OWNER_CLOSURE_CERTIFICATE_PATH_ENV,
            FIRST_OWNER_CLOSURE_CERTIFICATE_DIGEST_ENV,
        ] {
            let error = StartupSecurityPins::from_source(|name| {
                (name != missing)
                    .then(|| production_with_first_owner_certificate.get(name).cloned())
                    .flatten()
            })
            .unwrap_err();
            assert!(error.contains(missing));
        }

        for invalid_path in [
            "relative/first-owner-closure-certificate.json",
            "/run/ryuki/first-owner/../first-owner-closure-certificate.json",
            "/run/ryuki/first-owner/first-owner-closure-certificate.txt",
            "/run//ryuki/first-owner/first-owner-closure-certificate.json",
        ] {
            let mut invalid = production_with_first_owner_certificate.clone();
            invalid.insert(
                FIRST_OWNER_CLOSURE_CERTIFICATE_PATH_ENV.into(),
                OsString::from(invalid_path),
            );
            assert!(
                StartupSecurityPins::from_source(|name| invalid.get(name).cloned())
                    .unwrap_err()
                    .contains("normalized absolute .json")
            );
        }

        let mut invalid_digest = production_with_first_owner_certificate.clone();
        invalid_digest.insert(
            FIRST_OWNER_CLOSURE_CERTIFICATE_DIGEST_ENV.into(),
            OsString::from(format!("sha256:{}", "A".repeat(64))),
        );
        assert!(
            StartupSecurityPins::from_source(|name| invalid_digest.get(name).cloned())
                .unwrap_err()
                .contains(FIRST_OWNER_CLOSURE_CERTIFICATE_DIGEST_ENV)
        );

        let mut nonproduction_with_first_owner_certificate = values.clone();
        nonproduction_with_first_owner_certificate.insert(
            FIRST_OWNER_CLOSURE_CERTIFICATE_PATH_ENV.into(),
            OsString::from(first_owner_certificate_path),
        );
        nonproduction_with_first_owner_certificate.insert(
            FIRST_OWNER_CLOSURE_CERTIFICATE_DIGEST_ENV.into(),
            OsString::from(&digest),
        );
        assert!(StartupSecurityPins::from_source(|name| {
            nonproduction_with_first_owner_certificate
                .get(name)
                .cloned()
        })
        .unwrap_err()
        .contains("production apply-only"));
        for (label, socket_path, public_key) in [
            (
                "conformance trust-checkpoint",
                "/run/ryuki/trust-checkpoint/authority.sock",
                checkpoint_key.verifying_key().to_bytes(),
            ),
            (
                "deployed-workload attestation",
                "/run/ryuki/workload-attestation/authority.sock",
                workload_key.verifying_key().to_bytes(),
            ),
            (
                "public-ingress attestation",
                "/run/ryuki/public-ingress/authority.sock",
                ingress_key.verifying_key().to_bytes(),
            ),
        ] {
            let mut reused_socket = production_complete.clone();
            reused_socket.insert(
                POSTGRESQL_INFRASTRUCTURE_ATTESTATION_SOCKET_ENV.into(),
                OsString::from(socket_path),
            );
            let error = StartupSecurityPins::from_source(|name| reused_socket.get(name).cloned())
                .unwrap_err();
            assert!(error.contains("distinct Unix socket"), "{label}: {error}");

            let mut reused_key = production_complete.clone();
            reused_key.insert(
                POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_BASE64_ENV.into(),
                OsString::from(BASE64_STANDARD.encode(public_key)),
            );
            reused_key.insert(
                POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_FINGERPRINT_ENV.into(),
                OsString::from(raw_digest(&public_key)),
            );
            let error =
                StartupSecurityPins::from_source(|name| reused_key.get(name).cloned()).unwrap_err();
            assert!(
                error.contains("cryptographically distinct key"),
                "{label}: {error}"
            );
        }
        for (label, public_key) in [
            (
                "conformance trust-checkpoint",
                checkpoint_key.verifying_key().to_bytes(),
            ),
            (
                "deployed-workload attestation",
                workload_key.verifying_key().to_bytes(),
            ),
            (
                "public-ingress attestation",
                ingress_key.verifying_key().to_bytes(),
            ),
            (
                "PostgreSQL-infrastructure attestation",
                postgresql_key.verifying_key().to_bytes(),
            ),
        ] {
            let mut reused_key = production_complete.clone();
            reused_key.insert(
                FIRST_OWNER_AUTHORITY_PUBLIC_KEY_BASE64_ENV.into(),
                OsString::from(BASE64_STANDARD.encode(public_key)),
            );
            reused_key.insert(
                FIRST_OWNER_AUTHORITY_PUBLIC_KEY_FINGERPRINT_ENV.into(),
                OsString::from(raw_digest(&public_key)),
            );
            let error =
                StartupSecurityPins::from_source(|name| reused_key.get(name).cloned()).unwrap_err();
            assert!(
                error.contains("cryptographically distinct key"),
                "{label}: {error}"
            );
        }
        let workload_pins = production_pins
            .deployed_workload_attestation
            .as_ref()
            .expect("production workload attestation binding");
        assert_eq!(workload_pins.minimum_authority_epoch, 11);
        assert_eq!(workload_pins.measurement_profile_version, 3);
        assert_eq!(workload_pins.workload_id, "workload:ryuki-api");
        let ingress_pins = production_pins
            .public_ingress_attestation
            .as_ref()
            .expect("production public-ingress attestation binding");
        assert_eq!(ingress_pins.minimum_authority_epoch, 13);
        assert_eq!(ingress_pins.attestation_profile_version, 5);
        let postgresql_pins = production_pins
            .postgresql_infrastructure_attestation
            .as_ref()
            .expect("production PostgreSQL-infrastructure attestation binding");
        assert_eq!(postgresql_pins.minimum_authority_epoch, 17);
        assert_eq!(postgresql_pins.attestation_profile_version, 7);
        let first_owner_pins = production_pins
            .first_owner_authority
            .as_ref()
            .expect("production first-owner authority binding");
        assert_eq!(first_owner_pins.minimum_authority_epoch, 19);
        assert_eq!(
            first_owner_pins.authority_id,
            "first-owner-authority:runtime-test"
        );
        let build_pins = production_pins
            .production_build_manifest
            .expect("production build manifest binding");
        assert_eq!(build_pins.path, PathBuf::from(build_manifest_path));
        assert_eq!(build_pins.digest, digest);

        let mut nonproduction_with_build_manifest = values.clone();
        nonproduction_with_build_manifest.insert(
            PRODUCTION_BUILD_MANIFEST_PATH_ENV.into(),
            OsString::from(build_manifest_path),
        );
        nonproduction_with_build_manifest.insert(
            PRODUCTION_BUILD_MANIFEST_DIGEST_ENV.into(),
            OsString::from(&digest),
        );
        assert!(StartupSecurityPins::from_source(|name| {
            nonproduction_with_build_manifest.get(name).cloned()
        })
        .unwrap_err()
        .contains("production-only"));

        let mut nonproduction_with_workload = values.clone();
        for (name, value) in &workload_group {
            nonproduction_with_workload.insert((*name).into(), OsString::from(value));
        }
        assert!(StartupSecurityPins::from_source(|name| {
            nonproduction_with_workload.get(name).cloned()
        })
        .unwrap_err()
        .contains("production-only"));

        let mut nonproduction_with_ingress = values.clone();
        for (name, value) in &ingress_group {
            nonproduction_with_ingress.insert((*name).into(), OsString::from(value));
        }
        assert!(StartupSecurityPins::from_source(|name| {
            nonproduction_with_ingress.get(name).cloned()
        })
        .unwrap_err()
        .contains("production-only"));

        let mut nonproduction_with_postgresql = values.clone();
        for (name, value) in &postgresql_group {
            nonproduction_with_postgresql.insert((*name).into(), OsString::from(value));
        }
        assert!(StartupSecurityPins::from_source(|name| {
            nonproduction_with_postgresql.get(name).cloned()
        })
        .unwrap_err()
        .contains("production-only"));

        let mut nonproduction_with_first_owner = values.clone();
        for (name, value) in &first_owner_group {
            nonproduction_with_first_owner.insert((*name).into(), OsString::from(value));
        }
        assert!(StartupSecurityPins::from_source(|name| {
            nonproduction_with_first_owner.get(name).cloned()
        })
        .unwrap_err()
        .contains("production-only"));

        for (missing, _) in &workload_group {
            assert!(StartupSecurityPins::from_source(|name| {
                (name != *missing)
                    .then(|| production_complete.get(name).cloned())
                    .flatten()
            })
            .unwrap_err()
            .contains(*missing));
        }

        for (missing, _) in &ingress_group {
            assert!(StartupSecurityPins::from_source(|name| {
                (name != *missing)
                    .then(|| production_complete.get(name).cloned())
                    .flatten()
            })
            .unwrap_err()
            .contains(*missing));
        }

        for (missing, _) in &postgresql_group {
            assert!(StartupSecurityPins::from_source(|name| {
                (name != *missing)
                    .then(|| production_complete.get(name).cloned())
                    .flatten()
            })
            .unwrap_err()
            .contains(*missing));
        }

        for (missing, _) in &first_owner_group {
            assert!(StartupSecurityPins::from_source(|name| {
                (name != *missing)
                    .then(|| production_complete.get(name).cloned())
                    .flatten()
            })
            .unwrap_err()
            .contains(*missing));
        }

        for missing in [
            PRODUCTION_BUILD_MANIFEST_PATH_ENV,
            PRODUCTION_BUILD_MANIFEST_DIGEST_ENV,
        ] {
            assert!(StartupSecurityPins::from_source(|name| {
                (name != missing)
                    .then(|| production_complete.get(name).cloned())
                    .flatten()
            })
            .unwrap_err()
            .contains(missing));
        }
        for invalid_path in [
            "relative/production-build-manifest.json",
            "/run/ryuki/build/../production-build-manifest.json",
            "/run/ryuki/build/production-build-manifest.txt",
            "/run//ryuki/build/production-build-manifest.json",
        ] {
            let mut invalid = production_complete.clone();
            invalid.insert(
                PRODUCTION_BUILD_MANIFEST_PATH_ENV.into(),
                OsString::from(invalid_path),
            );
            assert!(
                StartupSecurityPins::from_source(|name| invalid.get(name).cloned())
                    .unwrap_err()
                    .contains("normalized absolute .json")
            );
        }
        for invalid_counter in ["0", "03", "9007199254740992"] {
            let mut invalid = production_complete.clone();
            invalid.insert(
                DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_VERSION_ENV.into(),
                OsString::from(invalid_counter),
            );
            assert!(
                StartupSecurityPins::from_source(|name| invalid.get(name).cloned())
                    .unwrap_err()
                    .contains("canonical positive")
            );
        }
        for invalid_counter in ["0", "03", "9007199254740992"] {
            let mut invalid = production_complete.clone();
            invalid.insert(
                FIRST_OWNER_AUTHORITY_MIN_EPOCH_ENV.into(),
                OsString::from(invalid_counter),
            );
            assert!(
                StartupSecurityPins::from_source(|name| invalid.get(name).cloned())
                    .unwrap_err()
                    .contains("canonical positive")
            );
        }
        for (name, value) in [
            (FIRST_OWNER_AUTHORITY_ID_ENV, "authority:wrong-prefix"),
            (FIRST_OWNER_AUTHORITY_KEY_ID_ENV, "key:wrong-prefix"),
        ] {
            let mut invalid = production_complete.clone();
            invalid.insert(name.into(), OsString::from(value));
            assert!(
                StartupSecurityPins::from_source(|name| invalid.get(name).cloned())
                    .unwrap_err()
                    .contains(name)
            );
        }
        for invalid_socket in [
            "run/ryuki/workload-attestation.sock".to_string(),
            "/run//ryuki/workload-attestation.sock".to_string(),
            format!("/run/{}.sock", "a".repeat(MAX_AUTHORITY_SOCKET_PATH_BYTES)),
        ] {
            let mut invalid = production_complete.clone();
            invalid.insert(
                DEPLOYED_WORKLOAD_ATTESTATION_SOCKET_ENV.into(),
                OsString::from(invalid_socket),
            );
            assert!(
                StartupSecurityPins::from_source(|name| invalid.get(name).cloned())
                    .unwrap_err()
                    .contains("normalized absolute")
            );
        }
        let mut mismatched_workload_key = production_complete.clone();
        mismatched_workload_key.insert(
            DEPLOYED_WORKLOAD_ATTESTATION_PUBLIC_KEY_FINGERPRINT_ENV.into(),
            OsString::from(format!("sha256:{}", "b".repeat(64))),
        );
        assert!(
            StartupSecurityPins::from_source(|name| mismatched_workload_key.get(name).cloned())
                .unwrap_err()
                .contains("does not match")
        );
        let weak_postgresql_key = [0u8; ED25519_AUTHORITY_PUBLIC_KEY_BYTES];
        let mut invalid_postgresql_key = production_complete.clone();
        invalid_postgresql_key.insert(
            POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_BASE64_ENV.into(),
            OsString::from(BASE64_STANDARD.encode(weak_postgresql_key)),
        );
        invalid_postgresql_key.insert(
            POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_FINGERPRINT_ENV.into(),
            OsString::from(raw_digest(&weak_postgresql_key)),
        );
        assert!(
            StartupSecurityPins::from_source(|name| invalid_postgresql_key.get(name).cloned())
                .unwrap_err()
                .contains("Ed25519 public key")
        );
        let weak_first_owner_key = [0u8; ED25519_AUTHORITY_PUBLIC_KEY_BYTES];
        let mut invalid_first_owner_key = production_complete.clone();
        invalid_first_owner_key.insert(
            FIRST_OWNER_AUTHORITY_PUBLIC_KEY_BASE64_ENV.into(),
            OsString::from(BASE64_STANDARD.encode(weak_first_owner_key)),
        );
        invalid_first_owner_key.insert(
            FIRST_OWNER_AUTHORITY_PUBLIC_KEY_FINGERPRINT_ENV.into(),
            OsString::from(raw_digest(&weak_first_owner_key)),
        );
        assert!(
            StartupSecurityPins::from_source(|name| invalid_first_owner_key.get(name).cloned())
                .unwrap_err()
                .contains("weak Ed25519 public key")
        );
        let mut mismatched_first_owner_key = production_complete.clone();
        mismatched_first_owner_key.insert(
            FIRST_OWNER_AUTHORITY_PUBLIC_KEY_FINGERPRINT_ENV.into(),
            OsString::from(format!("sha256:{}", "b".repeat(64))),
        );
        assert!(
            StartupSecurityPins::from_source(|name| mismatched_first_owner_key.get(name).cloned())
                .unwrap_err()
                .contains("does not match")
        );
        let mut zero_build_digest = production_complete;
        zero_build_digest.insert(
            PRODUCTION_BUILD_MANIFEST_DIGEST_ENV.into(),
            OsString::from(format!("sha256:{}", "0".repeat(64))),
        );
        assert!(
            StartupSecurityPins::from_source(|name| zero_build_digest.get(name).cloned())
                .unwrap_err()
                .contains("nonzero")
        );

        let mut relative_socket = complete_checkpoint.clone();
        relative_socket.insert(
            CONFORMANCE_TRUST_CHECKPOINT_SOCKET_ENV.into(),
            OsString::from("run/ryuki/trust-checkpoint.sock"),
        );
        assert!(
            StartupSecurityPins::from_source(|name| relative_socket.get(name).cloned())
                .unwrap_err()
                .contains("normalized absolute")
        );

        let mut mismatched_checkpoint_key = complete_checkpoint;
        mismatched_checkpoint_key.insert(
            CONFORMANCE_TRUST_CHECKPOINT_PUBLIC_KEY_FINGERPRINT_ENV.into(),
            OsString::from(format!("sha256:{}", "b".repeat(64))),
        );
        assert!(StartupSecurityPins::from_source(|name| {
            mismatched_checkpoint_key.get(name).cloned()
        })
        .unwrap_err()
        .contains("does not match"));

        let mut malformed_trust_root_digest = values;
        malformed_trust_root_digest.insert(
            CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST_ENV.into(),
            OsString::from(format!("sha256:{}", "0".repeat(64))),
        );
        assert!(StartupSecurityPins::from_source(|name| {
            malformed_trust_root_digest.get(name).cloned()
        })
        .unwrap_err()
        .contains("nonzero"));
    }

    #[cfg(unix)]
    #[test]
    fn detached_build_manifest_read_is_exact_bounded_and_regular() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("temporary build-manifest root");
        let root = fs::canonicalize(temp.path()).expect("canonical temporary root");
        let path = root.join("production-build-manifest.json");
        let bytes = br#"{"contract_kind":"production-build-manifest"}"#;
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let digest = raw_digest(bytes);

        assert_eq!(
            read_pinned_absolute_regular_file(
                "production build manifest",
                &path,
                &digest,
                MAX_PRODUCTION_BUILD_MANIFEST_BYTES,
            )
            .unwrap(),
            bytes
        );
        assert!(read_pinned_absolute_regular_file(
            "production build manifest",
            &path,
            &format!("sha256:{}", "b".repeat(64)),
            MAX_PRODUCTION_BUILD_MANIFEST_BYTES,
        )
        .unwrap_err()
        .contains("digest mismatch"));
        assert!(read_pinned_absolute_regular_file(
            "production build manifest",
            &path,
            &digest,
            (bytes.len() - 1) as u64,
        )
        .unwrap_err()
        .contains("no larger"));

        let directory = root.join("directory.json");
        fs::create_dir(&directory).unwrap();
        assert!(read_pinned_absolute_regular_file(
            "production build manifest",
            &directory,
            &digest,
            MAX_PRODUCTION_BUILD_MANIFEST_BYTES,
        )
        .unwrap_err()
        .contains("regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn detached_build_manifest_read_rejects_symlink_components() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("temporary build-manifest root");
        let root = fs::canonicalize(temp.path()).expect("canonical temporary root");
        let real = root.join("real");
        fs::create_dir(&real).unwrap();
        let manifest = real.join("production-build-manifest.json");
        let bytes = b"{}";
        fs::write(&manifest, bytes).unwrap();
        let link = root.join("linked");
        symlink(&real, &link).unwrap();

        assert!(read_pinned_absolute_regular_file(
            "production build manifest",
            &link.join("production-build-manifest.json"),
            &raw_digest(bytes),
            MAX_PRODUCTION_BUILD_MANIFEST_BYTES,
        )
        .unwrap_err()
        .contains("symlink"));
    }

    #[test]
    fn detached_build_manifest_is_bound_to_runtime_surface_and_exact_trace_set() {
        let fixture = ActiveFixture::build();
        let profile: DeploymentSecurityProfile = serde_json::from_slice(
            &fs::read(fixture.root.join(PROFILE_PATH)).expect("profile bytes"),
        )
        .unwrap();
        let runtime = test_runtime_build_identity();
        let (control_trace_bytes, control_trace) = test_production_control_trace(&fixture);
        let manifest = test_production_build_manifest(&runtime, &profile, &control_trace);
        let detached = TempDir::new().expect("detached build-manifest root");
        let detached_root = fs::canonicalize(detached.path()).unwrap();
        let path = detached_root.join("production-build-manifest.json");
        let bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        fs::write(&path, &bytes).unwrap();
        let mut pins = fixture.pins.clone();
        pins.production_build_manifest = Some(StartupProductionBuildManifestPins {
            path: path.clone(),
            digest: raw_digest(&bytes),
        });

        let candidate =
            load_production_build_manifest_candidate(&pins, &fixture.root, &profile, &runtime)
                .expect("exact detached manifest must bind the runtime build surface");
        fs::write(&path, b"{}").unwrap();
        let proof = candidate
            .seal(&control_trace_bytes)
            .expect("sealing consumes the already loaded bytes without rereading the path");
        let debug = format!("{proof:?}");
        assert!(debug.contains("production-build-manifest:runtime-test"));
        assert!(debug.contains(&raw_digest(&bytes)));

        assert!(
            load_production_build_manifest_candidate(&pins, &fixture.root, &profile, &runtime,)
                .unwrap_err()
                .contains("digest mismatch")
        );
    }

    #[test]
    fn provider_applicability_must_exactly_match_the_measured_build() {
        let fixture = ActiveFixture::build();
        let profile: DeploymentSecurityProfile = serde_json::from_slice(
            &fs::read(fixture.root.join(PROFILE_PATH)).expect("profile bytes"),
        )
        .unwrap();
        let runtime = test_runtime_build_identity();
        let (_, control_trace) = test_production_control_trace(&fixture);
        let mut manifest = test_production_build_manifest(&runtime, &profile, &control_trace);
        manifest.shipped_adapters[0].production_eligible = true;
        let adapter = &manifest.shipped_adapters[0];
        let mut registry = empty_provider_registry_applicability(&profile);
        registry
            .active_providers
            .push(ActiveProviderApplicabilityClaim {
                provider_id: "provider:test".into(),
                provider_kind: "oidc".into(),
                configuration_version: 1,
                configuration_payload_digest: format!("sha256:{}", "8".repeat(64)),
                lifecycle_record_version: 3,
                lifecycle_state: ProviderLifecycleState::Active,
                trust_domain_id: profile.trust_topology.trust_domain_ids[0].clone(),
                descriptor_id: "capability-descriptor:test".into(),
                descriptor_version: 1,
                adapter_kind: adapter.adapter_kind.clone(),
                adapter_version: adapter.adapter_version.clone(),
                advertised_capability_ids: adapter.capability_ids.clone(),
                production_eligible: true,
                mandatory_baseline_ref: ProviderMandatoryBaselineClaim {
                    document_id: adapter.mandatory_baseline.document_id.clone(),
                    document_version: adapter.mandatory_baseline.document_version,
                    content_digest: adapter.mandatory_baseline.content_digest.clone(),
                    artifact_locator: adapter.mandatory_baseline.artifact_locator.clone(),
                },
            });
        validate_production_provider_build_bindings(&registry, &manifest)
            .expect("exact provider/build binding must pass");

        registry.active_providers[0]
            .advertised_capability_ids
            .push("unmeasured-capability".into());
        assert!(
            validate_production_provider_build_bindings(&registry, &manifest)
                .unwrap_err()
                .contains("does not exactly match")
        );
    }

    #[test]
    fn detached_build_manifest_rejects_identity_swaps_before_checkpoint_io() {
        let fixture = ActiveFixture::build();
        let mut profile: DeploymentSecurityProfile = serde_json::from_slice(
            &fs::read(fixture.root.join(PROFILE_PATH)).expect("profile bytes"),
        )
        .unwrap();
        let runtime = test_runtime_build_identity();
        let (_, control_trace) = test_production_control_trace(&fixture);
        let detached = TempDir::new().expect("detached build-manifest root");
        let detached_root = fs::canonicalize(detached.path()).unwrap();
        let path = detached_root.join("production-build-manifest.json");

        let mut manifest = test_production_build_manifest(&runtime, &profile, &control_trace);
        manifest.source.revision = "f".repeat(40);
        let bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        fs::write(&path, &bytes).unwrap();
        let mut pins = fixture.pins.clone();
        pins.production_build_manifest = Some(StartupProductionBuildManifestPins {
            path: path.clone(),
            digest: raw_digest(&bytes),
        });
        assert!(
            load_production_build_manifest_candidate(&pins, &fixture.root, &profile, &runtime,)
                .unwrap_err()
                .contains("embedded release revision")
        );

        let mut manifest = test_production_build_manifest(&runtime, &profile, &control_trace);
        manifest.shipped_adapters[0].adapter_version = "0.2.0".into();
        let derived = derive_implementation_applicability(&control_trace, &manifest).unwrap();
        manifest.implementation_applicability = derived.binding;
        manifest.implementation_applicability_instances = derived.instances;
        let bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        fs::write(&path, &bytes).unwrap();
        pins.production_build_manifest.as_mut().unwrap().digest = raw_digest(&bytes);
        assert!(
            load_production_build_manifest_candidate(&pins, &fixture.root, &profile, &runtime,)
                .unwrap_err()
                .contains("compiled build surface")
        );

        let manifest = test_production_build_manifest(&runtime, &profile, &control_trace);
        let bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        fs::write(&path, &bytes).unwrap();
        pins.production_build_manifest.as_mut().unwrap().digest = raw_digest(&bytes);
        let candidate =
            load_production_build_manifest_candidate(&pins, &fixture.root, &profile, &runtime)
                .unwrap();
        let mut changed_trace = control_trace.clone();
        let mut extra = changed_trace["traces"][0].clone();
        extra["trace_id"] = json!("TRACE-SB-OTHER-01-AC-001");
        changed_trace["traces"].as_array_mut().unwrap().push(extra);
        let changed_trace_bytes = serde_json::to_vec_pretty(&changed_trace).unwrap();
        assert!(candidate
            .seal(&changed_trace_bytes)
            .unwrap_err()
            .contains("content-addressed reference"));

        profile.control_trace_ref.content_digest = raw_digest(&changed_trace_bytes);
        let mut stale_manifest = manifest;
        stale_manifest.control_trace_ref = profile.control_trace_ref.clone();
        let stale_inventory =
            derive_implementation_applicability(&control_trace, &stale_manifest).unwrap();
        stale_manifest.implementation_applicability = stale_inventory.binding;
        stale_manifest.implementation_applicability_instances = stale_inventory.instances;
        let bytes = serde_json::to_vec_pretty(&stale_manifest).unwrap();
        fs::write(&path, &bytes).unwrap();
        pins.production_build_manifest.as_mut().unwrap().digest = raw_digest(&bytes);
        let candidate =
            load_production_build_manifest_candidate(&pins, &fixture.root, &profile, &runtime)
                .unwrap();
        assert!(candidate
            .seal(&changed_trace_bytes)
            .unwrap_err()
            .contains("not the exact independently derived inventory"));
    }

    #[test]
    fn build_manifest_cannot_reside_under_the_security_contract_root() {
        let fixture = ActiveFixture::build();
        let profile: DeploymentSecurityProfile = serde_json::from_slice(
            &fs::read(fixture.root.join(PROFILE_PATH)).expect("profile bytes"),
        )
        .unwrap();
        let runtime = test_runtime_build_identity();
        let (_, control_trace) = test_production_control_trace(&fixture);
        let manifest = test_production_build_manifest(&runtime, &profile, &control_trace);
        let path = fixture.root.join("production-build-manifest.json");
        let bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        fs::write(&path, &bytes).unwrap();
        let mut pins = fixture.pins.clone();
        pins.production_build_manifest = Some(StartupProductionBuildManifestPins {
            path,
            digest: raw_digest(&bytes),
        });

        assert!(
            load_production_build_manifest_candidate(&pins, &fixture.root, &profile, &runtime,)
                .unwrap_err()
                .contains("detached from the rollbackable security-contract root")
        );
    }

    #[test]
    fn active_test_contract_loads_and_binds_credential_free_loopback() {
        let fixture = ActiveFixture::build();
        let context = fixture.load().expect("active test contract must load");
        assert_eq!(context.active_providers.len(), 1);
        assert_eq!(context.provider_registry_applicability.registry_version, 1);
        let provider_claim = &context.provider_registry_applicability.active_providers[0];
        assert_eq!(
            provider_claim.adapter_kind,
            "fixture.repository-static-dry-run"
        );
        assert_eq!(provider_claim.adapter_version, "1.0.0");
        assert_eq!(provider_claim.lifecycle_record_version, 3);
        assert_eq!(
            provider_claim.advertised_capability_ids,
            ["dry-run-only", "static-human-fixture"]
        );
        assert!(matches!(
            &context.conformance_state,
            ConformanceState::NonProduction
        ));
        assert!(context.verifies_security_limit_profile_integrity());
        assert!(context
            .validate_serving_checkpoint_freshness(fixed_now())
            .is_ok());
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

    #[tokio::test]
    async fn nonproduction_refuses_durable_postgresql_authority_before_database_construction() {
        let fixture = ActiveFixture::build();
        let mut context = fixture.load().expect("active test contract must load");
        let config = RyukiConfig::default();

        let error = context
            .verify_durable_postgresql_runtime_guard(&fixture.pins, &config)
            .await
            .unwrap_err();
        assert!(error.contains("production-only"));
        context
            .validate_serving_checkpoint_freshness(fixed_now())
            .expect("non-production without retained authority remains valid");

        let signing_key = SigningKey::from_bytes(&rand::random());
        let public_key = signing_key.verifying_key().to_bytes();
        let mut authority_pins = fixture.pins.clone();
        authority_pins.postgresql_infrastructure_attestation =
            Some(StartupPostgresqlInfrastructureAttestationPins {
                socket_path: PathBuf::from("/run/ryuki/postgresql-infrastructure/authority.sock"),
                authority_id: "postgresql-infrastructure-attestation-authority:nonproduction-test"
                    .into(),
                key_id: "postgresql-infrastructure-attestation-key:nonproduction-test".into(),
                public_key_base64: BASE64_STANDARD.encode(public_key),
                public_key_fingerprint: raw_digest(&public_key),
                minimum_authority_epoch: 1,
                attestation_profile_id:
                    "postgresql-infrastructure-attestation-profile:nonproduction-test".into(),
                attestation_profile_version: 1,
                attestation_profile_digest: raw_digest(b"nonproduction PostgreSQL profile"),
            });
        let error = context
            .verify_durable_postgresql_runtime_guard(&authority_pins, &config)
            .await
            .unwrap_err();
        assert!(error.contains("retained DurablePostgresql production authority"));
    }

    #[test]
    fn first_owner_path_closed_has_a_concrete_guard_and_two_guards_remain() {
        assert_eq!(
            REMAINING_PRODUCTION_RUNTIME_GUARDS,
            [
                GuardId::ExternalSigningKeyMaterial,
                GuardId::MockDependenciesDisabled,
            ]
        );
        let _verify_database_api = SecurityContractContext::verify_durable_postgresql_runtime_guard;
        let _remeasure_database_api =
            SecurityContractContext::remeasure_durable_postgresql_runtime_guard;
        let _verify_first_owner_api =
            SecurityContractContext::verify_first_owner_path_closed_runtime_guard;
        let _remeasure_first_owner_api =
            SecurityContractContext::remeasure_first_owner_path_closed_runtime_guard;
    }

    #[test]
    fn security_limit_claim_is_bound_to_exact_profile_selected_bytes() {
        let fixture = ActiveFixture::build();
        let mut prepared = prepare_startup_security_contract(&fixture.pins, fixed_now()).unwrap();
        let reference = prepared.profile.security_limit_profile_ref.clone();
        let claim = security_limit_applicability_claim(&prepared).unwrap();
        assert_eq!(claim.document_id, reference.document_id);
        assert_eq!(claim.document_version, reference.document_version);
        assert_eq!(claim.content_digest, reference.content_digest);
        assert_eq!(claim.artifact_locator, reference.artifact_locator);
        assert_eq!(claim.profile_version, 3);

        prepared
            .raw_document_bytes
            .get_mut(&reference.artifact_locator)
            .unwrap()
            .push(b' ');
        assert!(security_limit_applicability_claim(&prepared)
            .unwrap_err()
            .contains("exact profile-selected artifact"));

        prepared
            .raw_document_bytes
            .get_mut(&reference.artifact_locator)
            .unwrap()
            .pop();
        prepared
            .documents
            .get_mut(&reference.artifact_locator)
            .unwrap()["profile_version"] = json!(4);
        assert!(security_limit_applicability_claim(&prepared)
            .unwrap_err()
            .contains("exact profile-selected artifact"));
    }

    fn fixture_entra_policy_reference(
        document_id: &str,
        artifact_locator: &str,
        digest_character: char,
    ) -> ContentReferenceBinding {
        ContentReferenceBinding {
            document_id: document_id.into(),
            document_version: 1,
            content_digest: format!("sha256:{}", digest_character.to_string().repeat(64)),
            artifact_locator: artifact_locator.into(),
        }
    }

    fn fixture_entra_authority_components() -> (
        Arc<VerifiedSecurityLimitProfile>,
        ActiveProviderConfiguration,
        Arc<VerifiedAuthenticatorRuntimeBinding>,
        Arc<ResolvedAuthenticatorBearerLimits>,
        Arc<ResolvedAuthenticatorBrowserLimits>,
    ) {
        let initial_binding = fixture_authenticator_runtime_binding(60, 3_600);
        let oidc_configuration = OidcKindConfig {
            configuration_kind: "oidc".into(),
            runtime_binding_ref: initial_binding.reference.clone(),
            issuer_ref: fixture_entra_policy_reference(
                "issuer:fixture-entra",
                "catalog/security-contracts/v1/issuer.fixture.json",
                'a',
            ),
            endpoint_policy_ref: fixture_entra_policy_reference(
                "endpoint-policy:fixture-entra",
                "catalog/security-contracts/v1/endpoint-policy.fixture.json",
                'b',
            ),
            validation_mode: "jwt-jwks".into(),
            client_id_ref: fixture_entra_policy_reference(
                "client-id:fixture-entra",
                "catalog/security-contracts/v1/client-id.fixture.json",
                'c',
            ),
            client_authentication_method: "none".into(),
            accepted_audiences_ref: fixture_entra_policy_reference(
                "accepted-audiences:fixture-entra",
                "catalog/security-contracts/v1/accepted-audiences.fixture.json",
                'd',
            ),
            accepted_algorithms: vec!["RS256".into()],
            redirect_policy_ref: fixture_entra_policy_reference(
                "redirect-policy:fixture-entra",
                "catalog/security-contracts/v1/redirect-policy.fixture.json",
                'e',
            ),
            claim_mapping_ref: fixture_entra_policy_reference(
                "claim-mapping:fixture-entra",
                "catalog/security-contracts/v1/claim-mapping.fixture.json",
                '9',
            ),
            assurance_mapping_ref: fixture_entra_policy_reference(
                "assurance-mapping:fixture-entra",
                "catalog/security-contracts/v1/assurance-mapping.fixture.json",
                '8',
            ),
            logout_mode: "provider-session".into(),
            lifecycle_mode: "provider-registry".into(),
            revocation_mode: "provider-registry".into(),
        };
        let q = authenticator_provider_policy_binding_digest(
            &serde_json::to_value(&oidc_configuration).unwrap(),
        )
        .unwrap();
        let mut binding_document: Value =
            serde_json::from_slice(&initial_binding.raw_bytes).unwrap();
        binding_document["capability_ids"] = json!(["browser-sso", "token-validation"]);
        binding_document["provider_policy"]["binding_digest"] = json!(q);
        let runtime_binding = Arc::new(fixture_verified_authenticator_runtime_binding(
            binding_document,
        ));
        let mut oidc_configuration = oidc_configuration;
        oidc_configuration.runtime_binding_ref = runtime_binding.reference.clone();
        let provider = ActiveProviderConfiguration {
            provider_id: "provider:fixture-entra".into(),
            config_version: 1,
            payload_digest: format!("sha256:{}", "ab".repeat(32)),
            kind: "oidc".into(),
            trust_domain_id: "trust-domain:fixture-authenticator".into(),
            active_lifecycle_record_version: 3,
            capability_descriptor: ProviderCapabilityDescriptorBinding {
                descriptor_id: "capability-descriptor:fixture-entra".into(),
                descriptor_version: 1,
                adapter_kind: "auth.entra-id".into(),
                adapter_version: "1.0.0".into(),
                advertised_capabilities: vec!["browser-sso".into(), "token-validation".into()],
                mandatory_baseline_ref: fixture_entra_policy_reference(
                    "mandatory-baseline:fixture-entra",
                    "catalog/security-contracts/v1/mandatory-baseline.fixture.json",
                    '7',
                ),
                implementation_applicable: true,
                production_eligible: true,
            },
            credential_refs: Vec::new(),
            kind_config: ActiveProviderKindConfig::Oidc {
                configuration: Box::new(oidc_configuration),
                verified_runtime_binding: Arc::clone(&runtime_binding),
            },
        };
        let security_limit_profile = Arc::new(fixture_security_limit_profile(60, 3_600));
        let bearer_limits = ResolvedAuthenticatorBearerLimits::seal(
            Arc::clone(&security_limit_profile),
            Arc::clone(&runtime_binding),
            &provider.provider_id,
        )
        .unwrap();
        let browser_limits = ResolvedAuthenticatorBrowserLimits::seal(
            Arc::clone(&security_limit_profile),
            Arc::clone(&runtime_binding),
            &provider.provider_id,
        )
        .unwrap();
        (
            security_limit_profile,
            provider,
            runtime_binding,
            bearer_limits,
            browser_limits,
        )
    }

    #[test]
    fn resolved_entra_authority_retains_one_exact_d_and_limit_profile_allocation() {
        let (profile, provider, binding, bearer, browser) = fixture_entra_authority_components();
        let authority = ResolvedEntraAuthenticatorAuthority::seal(
            "deployment:fixture-authenticator",
            None,
            Arc::clone(&profile),
            &provider,
            Arc::clone(&binding),
            Arc::clone(&bearer),
            Some(Arc::clone(&browser)),
        )
        .unwrap();

        assert!(Arc::ptr_eq(&authority.security_limit_profile, &profile));
        assert!(Arc::ptr_eq(authority.verified_runtime_binding(), &binding));
        assert!(Arc::ptr_eq(authority.bearer_limits(), &bearer));
        assert!(Arc::ptr_eq(authority.browser_limits().unwrap(), &browser));
        assert_eq!(
            authority.deployment_id(),
            "deployment:fixture-authenticator"
        );
        assert_eq!(
            authority.trust_domain_id(),
            "trust-domain:fixture-authenticator"
        );
        assert_eq!(authority.tenant_id(), None);
        assert_eq!(authority.provider_id(), "provider:fixture-entra");
        assert_eq!(authority.provider_configuration_version(), 1);
        assert_eq!(authority.provider_lifecycle_record_version(), 3);
        assert_eq!(
            authority.provider_lifecycle_state(),
            ProviderLifecycleState::Active
        );
        assert_eq!(authority.bearer_path_id(), "authenticator-path:api-bearer");
        assert_eq!(authority.bearer_path_version(), 1);
        assert_eq!(
            authority.browser_path_id(),
            Some("authenticator-path:browser-sso")
        );
        assert_eq!(authority.browser_path_version(), Some(1));
        let declared = authority.declared_runtime_binding_projection();
        assert_eq!(declared.provider.provider_id, "provider:fixture-entra");
        assert_eq!(
            declared.binding_document_reference.content_digest,
            binding.reference.content_digest
        );
        assert_eq!(
            declared.provider_policy_binding_digest,
            authority.provider_policy_binding_digest()
        );
        assert_eq!(declared.capability_ids, ["browser-sso", "token-validation"]);
        assert_eq!(declared.credential_paths.len(), 2);
        assert!(declared.credential_paths.iter().all(|path| {
            !path.cache_partition_binding_digest.is_empty()
                && !path.protocol_binding_digest.is_empty()
                && !path.retained_consumer_ids.is_empty()
        }));
        assert!(declared.ownership.single_runtime_owner);
        assert!(!declared.ownership.ambient_reconfiguration_allowed);
        let declared_expectation_digest = authenticator_runtime_binding_digest(declared).unwrap();
        assert_ne!(
            declared_expectation_digest,
            authority.binding_document_reference().content_digest
        );
        assert_ne!(
            declared_expectation_digest,
            authority.provider_configuration_payload_digest()
        );
        assert_ne!(
            declared_expectation_digest,
            authority.provider_policy_binding_digest()
        );
        assert!(authority.verify_integrity().is_ok());
    }

    #[test]
    fn resolved_entra_authority_rejects_equal_looking_substitute_allocations() {
        let (profile, provider, binding, bearer, browser) = fixture_entra_authority_components();
        let duplicate_profile = Arc::new(fixture_security_limit_profile(60, 3_600));
        let duplicate_binding = Arc::new(fixture_verified_authenticator_runtime_binding(
            serde_json::from_slice(&binding.raw_bytes).unwrap(),
        ));
        assert_eq!(
            duplicate_profile.reference, profile.reference,
            "fixture must be value-equal before pointer substitution is attempted"
        );
        assert_eq!(
            duplicate_binding.reference, binding.reference,
            "fixture D must be value-equal before pointer substitution is attempted"
        );
        let mut substituted_provider = provider.clone();
        let ActiveProviderKindConfig::Oidc {
            verified_runtime_binding,
            ..
        } = &mut substituted_provider.kind_config
        else {
            panic!("fixture must retain OIDC authority")
        };
        *verified_runtime_binding = Arc::clone(&duplicate_binding);
        let provider_error = ResolvedEntraAuthenticatorAuthority::seal(
            "deployment:fixture-authenticator",
            None,
            Arc::clone(&profile),
            &substituted_provider,
            Arc::clone(&binding),
            Arc::clone(&bearer),
            Some(browser),
        )
        .unwrap_err();
        assert!(provider_error.contains("different D allocations"));

        let substituted_browser = ResolvedAuthenticatorBrowserLimits::seal(
            duplicate_profile,
            duplicate_binding,
            &provider.provider_id,
        )
        .unwrap();

        let error = ResolvedEntraAuthenticatorAuthority::seal(
            "deployment:fixture-authenticator",
            None,
            profile,
            &provider,
            binding,
            bearer,
            Some(substituted_browser),
        )
        .unwrap_err();
        assert!(error.contains("exact D/profile allocations"));
    }

    #[test]
    fn request_read_entra_provenance_requires_the_selected_canonical_provider_id() {
        let fixture = ActiveFixture::build();
        let mut context = fixture.load().expect("active test contract");
        let (_, mut provider, _, _, _) = fixture_entra_authority_components();
        provider.trust_domain_id = context
            .profile
            .trust_topology
            .trust_domain_ids
            .first()
            .expect("fixture trust domain")
            .clone();
        let canonical_provider_id = provider.provider_id.clone();
        context.active_providers.clear();
        context
            .active_providers
            .insert(canonical_provider_id.clone(), provider);

        for alias in ["entra-id", "oidc"] {
            let error = context
                .request_read_security_namespace(&AuthMode::EntraId, alias)
                .expect_err("adapter aliases must not identify credential provenance");
            assert!(error.contains("does not match selected canonical provider"));
        }

        let namespace = context
            .request_read_security_namespace(&AuthMode::EntraId, &canonical_provider_id)
            .expect("the exact selected provider id must identify credential provenance");
        assert_eq!(namespace.provider_id, canonical_provider_id);
        assert_eq!(namespace.credential_source_provider, namespace.provider_id);
    }

    #[test]
    fn resolved_entra_authority_rejects_d_p_q_aliasing() {
        let (profile, mut provider, binding, bearer, browser) =
            fixture_entra_authority_components();
        let aliased_q = {
            let ActiveProviderKindConfig::Oidc { configuration, .. } = &provider.kind_config else {
                panic!("fixture must retain OIDC policy authority")
            };
            authenticator_provider_policy_binding_digest(
                &serde_json::to_value(configuration.as_ref()).unwrap(),
            )
            .unwrap()
        };
        provider.payload_digest = aliased_q;

        let error = ResolvedEntraAuthenticatorAuthority::seal(
            "deployment:fixture-authenticator",
            None,
            profile,
            &provider,
            binding,
            bearer,
            Some(browser),
        )
        .unwrap_err();
        assert!(error.contains("D/P/Q digest separation"));
    }

    fn resolve_fixture_bearer_limits(
        document: Value,
        d_clock_skew_seconds: u64,
        d_maximum_lifetime_seconds: u64,
    ) -> Result<Arc<ResolvedAuthenticatorBearerLimits>, String> {
        let profile = Arc::new(fixture_verified_security_limit_profile(document));
        let binding = Arc::new(fixture_authenticator_runtime_binding(
            d_clock_skew_seconds,
            d_maximum_lifetime_seconds,
        ));
        ResolvedAuthenticatorBearerLimits::seal(profile, binding, "provider:fixture-entra")
    }

    fn resolve_fixture_browser_limits(
        binding_document: Value,
        profile_clock_skew_seconds: u64,
    ) -> Result<Arc<ResolvedAuthenticatorBrowserLimits>, String> {
        resolve_fixture_browser_limits_with_profile(
            fixture_security_limit_profile(profile_clock_skew_seconds, 3_600)
                .document
                .clone(),
            binding_document,
        )
    }

    fn resolve_fixture_browser_limits_with_profile(
        profile_document: Value,
        binding_document: Value,
    ) -> Result<Arc<ResolvedAuthenticatorBrowserLimits>, String> {
        ResolvedAuthenticatorBrowserLimits::seal(
            Arc::new(fixture_verified_security_limit_profile(profile_document)),
            Arc::new(fixture_verified_authenticator_runtime_binding(
                binding_document,
            )),
            "provider:fixture-entra",
        )
    }

    fn canonical_authenticator_limit_document() -> Value {
        fixture_security_limit_profile(60, 3_600).document.clone()
    }

    fn authenticator_limit_index(document: &Value, limit_id: &str) -> usize {
        document["limits"]
            .as_array()
            .expect("test security-limit rows")
            .iter()
            .position(|limit| limit["limit_id"] == limit_id)
            .expect("test authenticator limit id")
    }

    #[test]
    fn authenticator_bearer_limits_resolve_exact_profile_and_d_values() {
        let resolved = ResolvedAuthenticatorBearerLimits::fixture(60, 3_600);
        assert_eq!(
            resolved.clock_skew_limit_id(),
            AUTHENTICATOR_CLOCK_SKEW_LIMIT_ID
        );
        assert_eq!(resolved.maximum_clock_skew_seconds(), 60);
        assert_eq!(
            resolved.credential_lifetime_limit_id(),
            AUTHENTICATOR_OIDC_ACCESS_TOKEN_LIFETIME_LIMIT_ID
        );
        assert_eq!(resolved.maximum_credential_lifetime_seconds(), 3_600);
        assert_eq!(resolved.provider_id(), "provider:fixture-entra");
        assert_eq!(resolved.path_id(), "authenticator-path:api-bearer");
        assert!(resolved
            .security_limit_profile_content_digest()
            .starts_with("sha256:"));
        assert!(resolved.remeasures_exact_values());
    }

    #[test]
    fn authenticator_browser_limits_resolve_exact_profile_and_session_values() {
        let resolved = ResolvedAuthenticatorBrowserLimits::fixture(60);
        assert_eq!(
            resolved.clock_skew_limit_id(),
            AUTHENTICATOR_CLOCK_SKEW_LIMIT_ID
        );
        assert_eq!(resolved.maximum_clock_skew_seconds(), 60);
        assert_eq!(
            resolved.state_lifetime_limit_id(),
            AUTHENTICATOR_BROWSER_STATE_LIFETIME_LIMIT_ID
        );
        assert_eq!(
            resolved.maximum_state_lifetime_seconds(),
            AUTHENTICATOR_BROWSER_STATE_MAXIMUM_TTL_SECONDS
        );
        assert_eq!(
            resolved.session_maximum_age_limit_id(),
            AUTHENTICATOR_BROWSER_SESSION_MAXIMUM_AGE_LIMIT_ID
        );
        assert_eq!(
            resolved.maximum_session_age_seconds(),
            ryuki_core::config::MAX_SESSION_COOKIE_AGE_SECS
        );
        assert_eq!(
            resolved.federated_authority_staleness_limit_id(),
            AUTHENTICATOR_FEDERATED_AUTHORITY_STALENESS_LIMIT_ID
        );
        assert_eq!(
            resolved.maximum_federated_authority_staleness_seconds(),
            900
        );
        assert_eq!(resolved.provider_id(), "provider:fixture-entra");
        assert_eq!(resolved.path_id(), "authenticator-path:browser-sso");
        assert!(resolved.remeasures_exact_values());
    }

    #[test]
    fn authenticator_browser_limit_resolution_is_lazy_and_exact() {
        let binding = fixture_authenticator_runtime_binding(60, 3_600);
        let mut bearer_only: Value = serde_json::from_slice(&binding.raw_bytes).unwrap();
        bearer_only["credential_paths"]
            .as_array_mut()
            .unwrap()
            .retain(|path| path["credential_profile"]["token_profile"] != "oidc-id-token");
        assert!(resolve_fixture_browser_limits(bearer_only, 60)
            .unwrap_err()
            .contains("omits its browser ID-token"));

        let mut wrong_id: Value = serde_json::from_slice(&binding.raw_bytes).unwrap();
        let browser = wrong_id["credential_paths"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|path| path["credential_profile"]["token_profile"] == "oidc-id-token")
            .unwrap();
        browser["verifier"]["clock_skew_limit_id"] = json!("limit:wrong-browser-clock-skew");
        assert!(resolve_fixture_browser_limits(wrong_id, 60)
            .unwrap_err()
            .contains("canonical clock-skew"));

        let mismatched_binding = fixture_authenticator_runtime_binding(61, 3_600);
        let mismatched: Value = serde_json::from_slice(&mismatched_binding.raw_bytes).unwrap();
        assert!(resolve_fixture_browser_limits(mismatched, 60)
            .unwrap_err()
            .contains("D clock-skew maximum differs"));
    }

    #[test]
    fn authenticator_browser_limit_resolution_rejects_missing_and_duplicate_rows() {
        let binding = fixture_authenticator_runtime_binding(60, 3_600);
        let binding_document: Value = serde_json::from_slice(&binding.raw_bytes).unwrap();
        for limit_id in [
            AUTHENTICATOR_BROWSER_STATE_LIFETIME_LIMIT_ID,
            AUTHENTICATOR_BROWSER_SESSION_MAXIMUM_AGE_LIMIT_ID,
            AUTHENTICATOR_FEDERATED_AUTHORITY_STALENESS_LIMIT_ID,
        ] {
            let mut missing = canonical_authenticator_limit_document();
            missing["limits"]
                .as_array_mut()
                .unwrap()
                .retain(|limit| limit["limit_id"] != limit_id);
            assert!(
                resolve_fixture_browser_limits_with_profile(missing, binding_document.clone(),)
                    .unwrap_err()
                    .contains("omits required authenticator limit"),
                "missing browser limit {limit_id} must fail closed"
            );

            let mut duplicate = canonical_authenticator_limit_document();
            let index = authenticator_limit_index(&duplicate, limit_id);
            let repeated = duplicate["limits"][index].clone();
            duplicate["limits"].as_array_mut().unwrap().push(repeated);
            assert!(
                resolve_fixture_browser_limits_with_profile(duplicate, binding_document.clone(),)
                    .unwrap_err()
                    .contains("duplicates authenticator limit"),
                "duplicate browser limit {limit_id} must fail closed"
            );
        }
    }

    #[test]
    fn authenticator_browser_limit_resolution_enforces_exact_and_cross_limit_bounds() {
        let binding = fixture_authenticator_runtime_binding(60, 3_600);
        let binding_document: Value = serde_json::from_slice(&binding.raw_bytes).unwrap();

        let mut wrong_state_lifetime = canonical_authenticator_limit_document();
        let state_index = authenticator_limit_index(
            &wrong_state_lifetime,
            AUTHENTICATOR_BROWSER_STATE_LIFETIME_LIMIT_ID,
        );
        wrong_state_lifetime["limits"][state_index]["selected_value"] = json!(599);
        wrong_state_lifetime["limits"][state_index]["published_default"] = json!(599);
        wrong_state_lifetime["limits"][state_index]["hard_bounds"]["minimum"] = json!(1);
        wrong_state_lifetime["limits"][state_index]["hard_bounds"]["maximum"] = json!(1_200);
        assert!(resolve_fixture_browser_limits_with_profile(
            wrong_state_lifetime,
            binding_document.clone(),
        )
        .unwrap_err()
        .contains("must resolve exactly to 600 seconds"));

        let mut zero_session_age = canonical_authenticator_limit_document();
        let session_index = authenticator_limit_index(
            &zero_session_age,
            AUTHENTICATOR_BROWSER_SESSION_MAXIMUM_AGE_LIMIT_ID,
        );
        zero_session_age["limits"][session_index]["selected_value"] = json!(0);
        zero_session_age["limits"][session_index]["published_default"] = json!(0);
        zero_session_age["limits"][session_index]["hard_bounds"]["minimum"] = json!(0);
        assert!(resolve_fixture_browser_limits_with_profile(
            zero_session_age,
            binding_document.clone(),
        )
        .unwrap_err()
        .contains("must be positive"));

        let mut oversized_session_age = canonical_authenticator_limit_document();
        let session_index = authenticator_limit_index(
            &oversized_session_age,
            AUTHENTICATOR_BROWSER_SESSION_MAXIMUM_AGE_LIMIT_ID,
        );
        oversized_session_age["limits"][session_index]["selected_value"] = json!(86_401);
        oversized_session_age["limits"][session_index]["published_default"] = json!(86_401);
        oversized_session_age["limits"][session_index]["hard_bounds"]["maximum"] = json!(90_000);
        assert!(resolve_fixture_browser_limits_with_profile(
            oversized_session_age,
            binding_document.clone(),
        )
        .unwrap_err()
        .contains("exceeds the 86400 second runtime cap"));

        let mut staleness_out_of_bounds = canonical_authenticator_limit_document();
        let staleness_index = authenticator_limit_index(
            &staleness_out_of_bounds,
            AUTHENTICATOR_FEDERATED_AUTHORITY_STALENESS_LIMIT_ID,
        );
        staleness_out_of_bounds["limits"][staleness_index]["hard_bounds"]["maximum"] = json!(899);
        assert!(resolve_fixture_browser_limits_with_profile(
            staleness_out_of_bounds,
            binding_document.clone(),
        )
        .unwrap_err()
        .contains("outside its exact hard bounds"));

        let mut staleness_exceeds_session = canonical_authenticator_limit_document();
        let session_index = authenticator_limit_index(
            &staleness_exceeds_session,
            AUTHENTICATOR_BROWSER_SESSION_MAXIMUM_AGE_LIMIT_ID,
        );
        staleness_exceeds_session["limits"][session_index]["selected_value"] = json!(600);
        staleness_exceeds_session["limits"][session_index]["published_default"] = json!(600);
        assert!(resolve_fixture_browser_limits_with_profile(
            staleness_exceeds_session,
            binding_document,
        )
        .unwrap_err()
        .contains("staleness exceeds the browser session maximum age"));
    }

    #[test]
    fn authenticator_browser_limit_resolution_applies_scoped_tightening_overrides() {
        let matching_override = |override_id: &str, selected_value: u64| {
            json!({
                "override_id": override_id,
                "selected_value": selected_value,
                "scope_dimensions": [
                    {"dimension": "deployment_id", "value": "deployment:fixture-authenticator"},
                    {"dimension": "provider_id", "value": "provider:fixture-entra"},
                    {"dimension": "trust_domain_id", "value": "trust-domain:fixture-authenticator"}
                ],
                "tightens_only": true,
                "reason": "Test exact browser limit override."
            })
        };
        let mut document = canonical_authenticator_limit_document();
        let session_index = authenticator_limit_index(
            &document,
            AUTHENTICATOR_BROWSER_SESSION_MAXIMUM_AGE_LIMIT_ID,
        );
        document["limits"][session_index]["overrides"] = Value::Array(vec![matching_override(
            "override:fixture-entra-browser-session-age",
            1_800,
        )]);
        let staleness_index = authenticator_limit_index(
            &document,
            AUTHENTICATOR_FEDERATED_AUTHORITY_STALENESS_LIMIT_ID,
        );
        document["limits"][staleness_index]["overrides"] = Value::Array(vec![matching_override(
            "override:fixture-entra-federated-staleness",
            600,
        )]);
        let binding = fixture_authenticator_runtime_binding(60, 3_600);
        let binding_document: Value = serde_json::from_slice(&binding.raw_bytes).unwrap();
        let resolved = resolve_fixture_browser_limits_with_profile(document, binding_document)
            .expect("exact scoped browser overrides must resolve");
        assert_eq!(resolved.maximum_session_age_seconds(), 1_800);
        assert_eq!(
            resolved.maximum_federated_authority_staleness_seconds(),
            600
        );
        assert!(resolved.remeasures_exact_values());

        let mut invalid = canonical_authenticator_limit_document();
        let session_index =
            authenticator_limit_index(&invalid, AUTHENTICATOR_BROWSER_SESSION_MAXIMUM_AGE_LIMIT_ID);
        invalid["limits"][session_index]["overrides"] = Value::Array(vec![matching_override(
            "override:fixture-entra-browser-session-too-short",
            600,
        )]);
        let binding = fixture_authenticator_runtime_binding(60, 3_600);
        let binding_document: Value = serde_json::from_slice(&binding.raw_bytes).unwrap();
        assert!(
            resolve_fixture_browser_limits_with_profile(invalid, binding_document)
                .unwrap_err()
                .contains("staleness exceeds the browser session maximum age")
        );
    }

    #[test]
    fn authenticator_browser_limit_integrity_rejects_resolved_value_substitution() {
        let mut substituted_state = ResolvedAuthenticatorBrowserLimits::fixture(60);
        let resolved = Arc::get_mut(&mut substituted_state).expect("unique test allocation");
        resolved.values.state_lifetime = resolved.values.session_maximum_age.clone();
        assert!(resolved
            .verify_integrity()
            .unwrap_err()
            .contains("exact D/profile remeasurement"));

        let mut substituted_session = ResolvedAuthenticatorBrowserLimits::fixture(60);
        let resolved = Arc::get_mut(&mut substituted_session).expect("unique test allocation");
        resolved.values.session_maximum_age = resolved.values.state_lifetime.clone();
        assert!(resolved
            .verify_integrity()
            .unwrap_err()
            .contains("exact D/profile remeasurement"));

        let mut substituted_staleness = ResolvedAuthenticatorBrowserLimits::fixture(60);
        let resolved = Arc::get_mut(&mut substituted_staleness).expect("unique test allocation");
        resolved.values.federated_authority_staleness = resolved.values.session_maximum_age.clone();
        assert!(resolved
            .verify_integrity()
            .unwrap_err()
            .contains("exact D/profile remeasurement"));
    }

    #[test]
    fn authenticator_bearer_limit_resolution_rejects_missing_and_duplicate_rows() {
        let mut missing = canonical_authenticator_limit_document();
        missing["limits"]
            .as_array_mut()
            .unwrap()
            .retain(|limit| limit["limit_id"] != AUTHENTICATOR_CLOCK_SKEW_LIMIT_ID);
        assert!(resolve_fixture_bearer_limits(missing, 60, 3_600)
            .unwrap_err()
            .contains("omits required authenticator limit"));

        let mut duplicate = canonical_authenticator_limit_document();
        let clock_index = authenticator_limit_index(&duplicate, AUTHENTICATOR_CLOCK_SKEW_LIMIT_ID);
        let repeated = duplicate["limits"][clock_index].clone();
        duplicate["limits"].as_array_mut().unwrap().push(repeated);
        assert!(resolve_fixture_bearer_limits(duplicate, 60, 3_600)
            .unwrap_err()
            .contains("duplicates authenticator limit"));
    }

    #[test]
    fn authenticator_bearer_limit_resolution_rejects_fractional_and_wrong_ttl_shapes() {
        let mut fractional = canonical_authenticator_limit_document();
        let clock_index = authenticator_limit_index(&fractional, AUTHENTICATOR_CLOCK_SKEW_LIMIT_ID);
        fractional["limits"][clock_index]["selected_value"] = json!(60.5);
        assert!(resolve_fixture_bearer_limits(fractional, 60, 3_600)
            .unwrap_err()
            .contains("exact nonnegative integer"));

        let mut wrong_unit = canonical_authenticator_limit_document();
        let clock_index = authenticator_limit_index(&wrong_unit, AUTHENTICATOR_CLOCK_SKEW_LIMIT_ID);
        wrong_unit["limits"][clock_index]["unit"] = json!("items");
        assert!(resolve_fixture_bearer_limits(wrong_unit, 60, 3_600)
            .unwrap_err()
            .contains("category ttl and unit seconds"));

        let mut wrong_category = canonical_authenticator_limit_document();
        let clock_index =
            authenticator_limit_index(&wrong_category, AUTHENTICATOR_CLOCK_SKEW_LIMIT_ID);
        wrong_category["limits"][clock_index]["category"] = json!("rate");
        assert!(resolve_fixture_bearer_limits(wrong_category, 60, 3_600)
            .unwrap_err()
            .contains("category ttl and unit seconds"));
    }

    #[test]
    fn authenticator_limit_resolution_rejects_invalid_published_defaults() {
        let mut fractional = canonical_authenticator_limit_document();
        let clock_index = authenticator_limit_index(&fractional, AUTHENTICATOR_CLOCK_SKEW_LIMIT_ID);
        fractional["limits"][clock_index]["published_default"] = json!(60.5);
        assert!(resolve_fixture_bearer_limits(fractional, 60, 3_600)
            .unwrap_err()
            .contains("published default must be an exact nonnegative integer"));

        let mut outside_bounds = canonical_authenticator_limit_document();
        let clock_index =
            authenticator_limit_index(&outside_bounds, AUTHENTICATOR_CLOCK_SKEW_LIMIT_ID);
        outside_bounds["limits"][clock_index]["published_default"] = json!(301);
        assert!(resolve_fixture_bearer_limits(outside_bounds, 60, 3_600)
            .unwrap_err()
            .contains("published default 301 is outside its exact hard bounds"));
    }

    #[test]
    fn authenticator_bearer_limit_resolution_rejects_bounds_and_inactive_rows() {
        let mut out_of_bounds = canonical_authenticator_limit_document();
        let clock_index =
            authenticator_limit_index(&out_of_bounds, AUTHENTICATOR_CLOCK_SKEW_LIMIT_ID);
        out_of_bounds["limits"][clock_index]["hard_bounds"]["maximum"] = json!(59);
        assert!(resolve_fixture_bearer_limits(out_of_bounds, 60, 3_600)
            .unwrap_err()
            .contains("outside its exact hard bounds"));

        let mut inactive = canonical_authenticator_limit_document();
        let lifetime_index =
            authenticator_limit_index(&inactive, AUTHENTICATOR_OIDC_ACCESS_TOKEN_LIFETIME_LIMIT_ID);
        inactive["limits"][lifetime_index]["lifecycle"] = json!("retired");
        assert!(resolve_fixture_bearer_limits(inactive, 60, 3_600)
            .unwrap_err()
            .contains("must be active and fully enforced"));
    }

    #[test]
    fn authenticator_bearer_limit_resolution_applies_one_tightening_override() {
        let mut document = canonical_authenticator_limit_document();
        let clock_index = authenticator_limit_index(&document, AUTHENTICATOR_CLOCK_SKEW_LIMIT_ID);
        document["limits"][clock_index]["overrides"] = json!([{
            "override_id": "override:fixture-entra-clock-skew",
            "selected_value": 30,
            "scope_dimensions": [
                {"dimension": "deployment_id", "value": "deployment:fixture-authenticator"},
                {"dimension": "provider_id", "value": "provider:fixture-entra"},
                {"dimension": "trust_domain_id", "value": "trust-domain:fixture-authenticator"}
            ],
            "tightens_only": true,
            "reason": "Test a scoped tighter maximum."
        }]);
        let resolved = resolve_fixture_bearer_limits(document, 30, 3_600)
            .expect("one exact matching override must tighten the runtime maximum");
        assert_eq!(resolved.maximum_clock_skew_seconds(), 30);
        assert!(resolved.remeasures_exact_values());
    }

    #[test]
    fn authenticator_bearer_limit_resolution_rejects_ambiguous_or_widening_overrides() {
        let matching_override = |override_id: &str, selected_value: u64| {
            json!({
                "override_id": override_id,
                "selected_value": selected_value,
                "scope_dimensions": [
                    {"dimension": "deployment_id", "value": "deployment:fixture-authenticator"},
                    {"dimension": "provider_id", "value": "provider:fixture-entra"},
                    {"dimension": "trust_domain_id", "value": "trust-domain:fixture-authenticator"}
                ],
                "tightens_only": true,
                "reason": "Test override."
            })
        };

        let mut ambiguous = canonical_authenticator_limit_document();
        let clock_index = authenticator_limit_index(&ambiguous, AUTHENTICATOR_CLOCK_SKEW_LIMIT_ID);
        ambiguous["limits"][clock_index]["overrides"] = Value::Array(vec![
            matching_override("override:fixture-entra-clock-skew-a", 30),
            matching_override("override:fixture-entra-clock-skew-b", 20),
        ]);
        assert!(resolve_fixture_bearer_limits(ambiguous, 30, 3_600)
            .unwrap_err()
            .contains("ambiguous applicable overrides"));

        let mut widening = canonical_authenticator_limit_document();
        let clock_index = authenticator_limit_index(&widening, AUTHENTICATOR_CLOCK_SKEW_LIMIT_ID);
        widening["limits"][clock_index]["overrides"] = Value::Array(vec![matching_override(
            "override:fixture-entra-clock-skew-wider",
            61,
        )]);
        assert!(resolve_fixture_bearer_limits(widening, 61, 3_600)
            .unwrap_err()
            .contains("does not strictly tighten"));

        let mut equal = canonical_authenticator_limit_document();
        let clock_index = authenticator_limit_index(&equal, AUTHENTICATOR_CLOCK_SKEW_LIMIT_ID);
        equal["limits"][clock_index]["overrides"] = Value::Array(vec![matching_override(
            "override:fixture-entra-clock-skew-equal",
            60,
        )]);
        assert!(resolve_fixture_bearer_limits(equal, 60, 3_600)
            .unwrap_err()
            .contains("does not strictly tighten"));
    }

    #[test]
    fn authenticator_bearer_limit_resolution_rejects_d_value_mismatch() {
        let document = canonical_authenticator_limit_document();
        assert!(resolve_fixture_bearer_limits(document.clone(), 61, 3_600)
            .unwrap_err()
            .contains("D clock-skew maximum differs"));
        assert!(resolve_fixture_bearer_limits(document, 60, 3_601)
            .unwrap_err()
            .contains("D credential-lifetime maximum differs"));
    }

    #[test]
    fn verified_security_limit_profile_detects_exact_byte_and_typed_document_drift() {
        let mut exact = fixture_security_limit_profile(60, 3_600);
        assert!(exact.verify_integrity().is_ok());
        exact.raw_bytes[0] = b'[';
        assert!(exact
            .verify_integrity()
            .unwrap_err()
            .contains("exact digest"));

        let mut typed = fixture_security_limit_profile(60, 3_600);
        typed.document["profile_version"] = json!(999);
        assert!(typed
            .verify_integrity()
            .unwrap_err()
            .contains("sealed typed document"));
    }

    #[test]
    fn nonproduction_verified_profile_preserves_implementation_scope_admission() {
        let document: Value = serde_json::from_str(include_str!(
            "../../../catalog/security-contracts/v1/security-limit-profile.implementation.json"
        ))
        .unwrap();
        let verified = fixture_verified_security_limit_profile(document);
        assert!(verified.verify_integrity().is_ok());
    }

    #[tokio::test]
    async fn nonproduction_serving_loader_never_contacts_a_checkpoint_authority() {
        let fixture = ActiveFixture::build();
        assert!(fixture
            .pins
            .conformance_trust_checkpoint_authority
            .is_none());
        let context = load_startup_security_contract_for_serving(&fixture.pins)
            .await
            .expect("test startup remains a bounded local admission");
        assert!(matches!(
            &context.conformance_state,
            ConformanceState::NonProduction
        ));
    }

    #[test]
    fn checkpoint_lookup_digests_are_exact_sorted_unique_and_bounded() {
        let first = json!({
            "contract_kind": "conformance-bundle",
            "bundle_id": "bundle:first"
        });
        let second = json!({
            "contract_kind": "package-exit-receipt",
            "receipt_id": "package-exit-receipt:second"
        });
        let documents = BTreeMap::from([
            ("z.json".into(), first.clone()),
            ("a.json".into(), second.clone()),
        ]);
        let bytes = BTreeMap::from([
            ("z.json".into(), serde_json::to_vec_pretty(&first).unwrap()),
            ("a.json".into(), serde_json::to_vec(&second).unwrap()),
        ]);
        let reference_digests = reference_document_digests(&bytes);
        let digests = conformance_document_digests(&documents, &bytes, &reference_digests).unwrap();
        let mut expected = bytes
            .values()
            .map(|bytes| raw_digest(bytes))
            .collect::<Vec<_>>();
        expected.sort();
        expected.dedup();
        assert_eq!(digests, expected);

        let mut mismatched_reference_digests = reference_digests.clone();
        mismatched_reference_digests.insert("z.json".into(), format!("sha256:{}", "b".repeat(64)));
        assert!(
            conformance_document_digests(&documents, &bytes, &mismatched_reference_digests,)
                .unwrap_err()
                .contains("do not match the verified reference digest")
        );

        let mut missing = bytes.clone();
        missing.remove("z.json");
        assert!(
            conformance_document_digests(&documents, &missing, &reference_digests)
                .unwrap_err()
                .contains("exact raw bytes")
        );

        let oversized_documents = (0..=MAX_CHECKPOINT_DOCUMENT_DIGESTS)
            .map(|index| {
                (
                    format!("document-{index}.json"),
                    json!({
                        "contract_kind": "conformance-bundle",
                        "bundle_id": format!("bundle:{index}")
                    }),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let oversized_bytes = oversized_documents
            .iter()
            .map(|(locator, document)| (locator.clone(), serde_json::to_vec(document).unwrap()))
            .collect::<BTreeMap<_, _>>();
        assert!(conformance_document_digests(
            &oversized_documents,
            &oversized_bytes,
            &reference_document_digests(&oversized_bytes),
        )
        .unwrap_err()
        .contains(&format!(
            "bounded maximum of {MAX_CHECKPOINT_DOCUMENT_DIGESTS}"
        )));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn production_reconciliation_wires_random_request_transport_and_core_proof() {
        let conformance_key = SigningKey::from_bytes(&rand::random());
        let checkpoint_key = SigningKey::from_bytes(&rand::random());
        let checkpoint_public_key = checkpoint_key.verifying_key().to_bytes();
        let checkpoint_fingerprint = raw_digest(&checkpoint_public_key);
        let mut fixture = ActiveFixture::build();
        let mut profile_value: Value = serde_json::from_slice(
            &fs::read(fixture.root.join(PROFILE_PATH)).expect("profile bytes"),
        )
        .unwrap();
        profile_value["security_profile"] = json!("production");
        profile_value["applicability"]["security_profiles"] = json!(["production"]);
        profile_value["conformance_trust_root_registry_ref"]["document_id"] =
            json!("conformance-trust-root-registry:runtime-test");
        profile_value["conformance_trust_root_registry_ref"]["document_version"] = json!(1);
        let provisional_profile: DeploymentSecurityProfile =
            serde_json::from_value(profile_value.clone()).unwrap();
        let registry = production_trust_registry(&conformance_key, &provisional_profile);
        let registry_bytes = serde_json::to_vec_pretty(&registry).unwrap();
        let registry_digest = raw_digest(&registry_bytes);
        profile_value["conformance_trust_root_registry_ref"]["content_digest"] =
            json!(registry_digest);
        let mut profile: DeploymentSecurityProfile = serde_json::from_value(profile_value).unwrap();
        fixture.rewrite_trust_root_registry_raw(&registry_bytes);

        let mut artifact_store = ArtifactStore::open(&fixture.root).unwrap();
        let lineage = load_pinned_conformance_trust_root_registry(
            &mut artifact_store,
            &fixture.pins,
            &profile,
            fixed_now(),
        )
        .unwrap()
        .expect("production lineage");
        let finalization_lineage = lineage.clone();
        let bundle = signed_closure_document(
            "conformance-bundle",
            &conformance_key,
            1,
            &fixture.pins.conformance_trust_root_registry_digest,
        );
        let production_root = signed_closure_document(
            "package-exit-receipt",
            &conformance_key,
            1,
            &fixture.pins.conformance_trust_root_registry_digest,
        );
        let production_root_locator = "receipts/runtime-sb9-root.json";
        bind_production_root(&mut profile, production_root_locator, &production_root);
        let documents = BTreeMap::from([
            (
                profile.control_trace_ref.artifact_locator.clone(),
                json!({
                    "traces": [{
                        "trace_id": "TRACE-RUNTIME-TEST",
                        "owning_work_package": "SB-0"
                    }]
                }),
            ),
            ("evidence/runtime-bundle.json".into(), bundle),
            (production_root_locator.into(), production_root),
        ]);
        let document_bytes = raw_document_bytes(&documents);
        let reference_digests = reference_document_digests(&document_bytes);
        let requested_digests =
            conformance_document_digests(&documents, &document_bytes, &reference_digests).unwrap();

        let socket_directory = Builder::new()
            .prefix("ryuki-api-ckpt-")
            .tempdir_in("/tmp")
            .unwrap();
        let socket_path = socket_directory.path().join("authority.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        let mut pins = fixture.pins.clone();
        pins.security_profile = SecurityProfile::Production;
        pins.conformance_trust_checkpoint_authority = Some(StartupTrustCheckpointAuthorityPins {
            socket_path: socket_path.clone(),
            authority_id: "conformance-trust-checkpoint-authority:runtime-test".into(),
            key_id: "conformance-trust-checkpoint-key:runtime-test".into(),
            public_key_base64: BASE64_STANDARD.encode(checkpoint_public_key),
            public_key_fingerprint: checkpoint_fingerprint,
            minimum_authority_epoch: 7,
        });
        let profile_document = serde_json::to_value(&profile).unwrap();
        let profile_raw_bytes = serde_json::to_vec_pretty(&profile_document).unwrap();
        let profile_digest = raw_digest(&profile_raw_bytes);
        let mut prepared = PreparedSecurityContract {
            profile: profile.clone(),
            profile_raw_bytes: profile_raw_bytes.clone().into_boxed_slice(),
            profile_digest: profile_digest.clone(),
            contract_root: fixture.root.clone(),
            profile_path: fixture.pins.profile_path.clone(),
            documents: documents.clone(),
            raw_document_bytes: document_bytes.clone(),
            reference_document_digests: reference_digests.clone(),
            verified_security_limit_profile: Arc::new(fixture_security_limit_profile(60, 3_600)),
            active_providers: BTreeMap::new(),
            provider_registry_applicability: empty_provider_registry_applicability(&profile),
            conformance_registry_lineage: Some(lineage),
            production_build_manifest: None,
        };
        let mut missing_socket_prepared = clone_unsealed_test_prepared(&prepared);

        let server_documents = documents.clone();
        let server_document_bytes = document_bytes.clone();
        let server_checkpoint_key = checkpoint_key.clone();
        let server_conformance_key = conformance_key.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = [0u8; 4];
            stream.read_exact(&mut header).await.unwrap();
            let mut request = vec![0u8; u32::from_be_bytes(header) as usize];
            stream.read_exact(&mut request).await.unwrap();
            let request_value: Value = serde_json::from_slice(&request).unwrap();
            assert_eq!(request_value["operation"].as_str(), Some("read_reconcile"));
            assert_eq!(
                request_value["requested_document_digests"],
                json!(requested_digests)
            );
            let zero_nonce = BASE64_STANDARD.encode([0u8; 32]);
            assert_ne!(
                request_value["request_nonce"].as_str(),
                Some(zero_nonce.as_str())
            );
            let response = checkpoint_response(
                &request,
                &raw_digest(&request),
                &server_checkpoint_key,
                &server_conformance_key,
                &server_documents,
                &server_document_bytes,
                TRUST_ROOT_REGISTRY_PATH,
            );
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&response).await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let checkpoint =
            reconcile_external_conformance_checkpoint_with_clock(&mut prepared, &pins, fixed_now)
                .await
                .expect("signed read/reconcile response must produce an opaque proof");
        server.await.unwrap();
        assert_eq!(
            checkpoint.authority_id(),
            "conformance-trust-checkpoint-authority:runtime-test"
        );
        assert_eq!(checkpoint.authority_epoch(), 7);
        assert_eq!(checkpoint.checkpoint_sequence(), 20);
        let mut verification_bytes = document_bytes.clone();
        let mut verified = verify_loaded_conformance_documents(
            &documents,
            &mut verification_bytes,
            &reference_digests,
            Some(&checkpoint),
            &profile,
            fixed_now(),
        )
        .expect("the returned proof must authenticate the exact requested bytes");
        assert_eq!(verified.len(), 2);
        let verified_root =
            verify_current_production_root_binding(&checkpoint, &profile, &mut verified)
                .expect("the external checkpoint must bind the exact profile-selected SB-9 root");
        assert_eq!(
            verified_root.document_id(),
            "package-exit-receipt:runtime-test"
        );
        assert_eq!(verified.len(), 1);
        assert!(checkpoint
            .ensure_fresh(trusted_time_point(
                Utc.with_ymd_and_hms(2026, 7, 16, 12, 4, 1).unwrap(),
            ))
            .unwrap_err()
            .to_string()
            .contains("stale"));

        let expiring_checkpoint = verified_checkpoint_for_documents(
            finalization_lineage,
            &profile,
            &conformance_key,
            &documents,
            &document_bytes,
            TRUST_ROOT_REGISTRY_PATH,
        );
        let expiring_prepared = PreparedSecurityContract {
            profile: profile.clone(),
            profile_raw_bytes: profile_raw_bytes.into_boxed_slice(),
            profile_digest,
            contract_root: fixture.root.clone(),
            profile_path: fixture.pins.profile_path.clone(),
            documents: documents.clone(),
            raw_document_bytes: document_bytes.clone(),
            reference_document_digests: reference_digests,
            verified_security_limit_profile: Arc::new(fixture_security_limit_profile(60, 3_600)),
            active_providers: BTreeMap::new(),
            provider_registry_applicability: empty_provider_registry_applicability(&profile),
            conformance_registry_lineage: None,
            production_build_manifest: None,
        };
        let mut time_sample = 0usize;
        let error = finalize_startup_security_contract(
            expiring_prepared,
            Some(expiring_checkpoint),
            None,
            || {
                time_sample += 1;
                if time_sample == 1 {
                    fixed_now()
                } else {
                    Utc.with_ymd_and_hms(2026, 7, 16, 12, 4, 1).unwrap()
                }
            },
        )
        .expect_err("a checkpoint expiring during document verification must fail closed");
        assert!(error.contains("expired during document verification"));

        let mut missing_socket_pins = pins;
        missing_socket_pins
            .conformance_trust_checkpoint_authority
            .as_mut()
            .unwrap()
            .socket_path = socket_directory.path().join("missing.sock");
        let error = reconcile_external_conformance_checkpoint_with_clock(
            &mut missing_socket_prepared,
            &missing_socket_pins,
            fixed_now,
        )
        .await
        .expect_err("serving startup must fail closed when the authority is unavailable");
        assert!(error.contains("reconciliation failed"));
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
    fn independently_pinned_trust_root_registry_is_strict_and_content_addressed() {
        let missing = ActiveFixture::build();
        fs::remove_file(missing.root.join(TRUST_ROOT_REGISTRY_PATH)).unwrap();
        assert!(missing
            .load()
            .unwrap_err()
            .contains("artifact catalog/security-contracts/v1/conformance-trust-root-registry.runtime-test.json is unavailable"));

        let mut malformed = ActiveFixture::build();
        malformed.rewrite_trust_root_registry_raw(b"{\"not\":\"closed\"");
        assert!(malformed.load().unwrap_err().contains("JSON is invalid"));

        let tampered = ActiveFixture::build();
        fs::OpenOptions::new()
            .append(true)
            .open(tampered.root.join(TRUST_ROOT_REGISTRY_PATH))
            .unwrap()
            .write_all(b"\n")
            .unwrap();
        assert!(tampered.load().unwrap_err().contains("digest mismatch"));
    }

    #[test]
    fn complete_two_version_trust_registry_lineage_loads_for_test_profile() {
        let mut fixture = ActiveFixture::build();
        fixture.install_trust_registry_lineage(2, |_, _| {});
        assert!(fixture.load().is_ok());
    }

    #[test]
    fn trust_registry_lineage_requires_an_exact_predecessor_binding() {
        let mut missing = ActiveFixture::build();
        missing.install_trust_registry_lineage(2, |version, registry| {
            if version == 2 {
                registry
                    .as_object_mut()
                    .unwrap()
                    .remove("predecessor_registry_ref");
            }
        });
        assert!(missing.load().is_err());

        let mut null = ActiveFixture::build();
        null.install_trust_registry_lineage(2, |version, registry| {
            if version == 2 {
                registry["predecessor_registry_ref"] = Value::Null;
            }
        });
        assert!(null.load().is_err());

        let mut wrong_kind = ActiveFixture::build();
        wrong_kind.install_trust_registry_lineage(2, |version, registry| {
            if version == 2 {
                registry["predecessor_registry_ref"]["artifact_kind"] = json!("provider-registry");
            }
        });
        assert!(wrong_kind.load().is_err());

        let mut wrong_id = ActiveFixture::build();
        wrong_id.install_trust_registry_lineage(2, |version, registry| {
            if version == 2 {
                registry["predecessor_registry_ref"]["document_id"] =
                    json!("conformance-trust-root-registry:other-runtime-test");
            }
        });
        assert!(wrong_id
            .load()
            .unwrap_err()
            .contains("changes document identity"));

        let mut wrong_version = ActiveFixture::build();
        wrong_version.install_trust_registry_lineage(2, |version, registry| {
            if version == 2 {
                registry["predecessor_registry_ref"]["document_version"] = json!(2);
            }
        });
        assert!(wrong_version
            .load()
            .unwrap_err()
            .contains("predecessor must be version 1"));

        let mut wrong_digest = ActiveFixture::build();
        wrong_digest.install_trust_registry_lineage(2, |version, registry| {
            if version == 2 {
                registry["predecessor_registry_ref"]["content_digest"] =
                    json!(format!("sha256:{}", "b".repeat(64)));
            }
        });
        assert!(wrong_digest.load().unwrap_err().contains("digest mismatch"));

        let mut wrong_locator = ActiveFixture::build();
        wrong_locator.install_trust_registry_lineage(2, |version, registry| {
            if version == 2 {
                registry["predecessor_registry_ref"]["artifact_locator"] =
                    json!("catalog/security-contracts/v1/missing-registry.json");
            }
        });
        assert!(wrong_locator.load().unwrap_err().contains("is unavailable"));
    }

    #[test]
    fn trust_registry_lineage_rejects_locator_conflicts_and_raw_predecessor_tampering() {
        let mut conflict = ActiveFixture::build();
        conflict.install_trust_registry_lineage(2, |version, registry| {
            if version == 2 {
                registry["predecessor_registry_ref"]["artifact_locator"] =
                    json!(TRUST_ROOT_REGISTRY_PATH);
            }
        });
        assert!(conflict.load().unwrap_err().contains("conflicting digests"));

        let mut tampered = ActiveFixture::build();
        let written = tampered.install_trust_registry_lineage(2, |_, _| {});
        fs::OpenOptions::new()
            .append(true)
            .open(tampered.root.join(&written[0].0))
            .unwrap()
            .write_all(b"\n")
            .unwrap();
        assert!(tampered.load().unwrap_err().contains("digest mismatch"));
    }

    #[test]
    fn trust_registry_lineage_strictly_parses_every_predecessor() {
        let mut fixture = ActiveFixture::build();
        let written = fixture.install_trust_registry_lineage(2, |_, _| {});
        let predecessor_path = fixture.root.join(&written[0].0);
        let raw = fs::read_to_string(&predecessor_path).unwrap();
        let duplicate = raw.replacen(
            "\"schema_version\": \"1.0.0\",",
            "\"schema_version\": \"1.0.0\",\n  \"schema_version\": \"1.0.0\",",
            1,
        );
        fs::write(&predecessor_path, duplicate.as_bytes()).unwrap();
        let predecessor_digest = raw_digest(duplicate.as_bytes());
        fixture.rewrite_trust_root_registry(|registry| {
            registry["predecessor_registry_ref"]["content_digest"] = json!(predecessor_digest);
        });
        assert!(fixture
            .load()
            .unwrap_err()
            .contains("duplicate JSON object key"));
    }

    #[test]
    fn trust_registry_lineage_is_bounded_to_the_reference_depth_limit() {
        let mut fixture = ActiveFixture::build();
        fixture.install_trust_registry_lineage((MAX_REFERENCE_DEPTH + 1) as u64, |_, _| {});
        assert!(fixture
            .load()
            .unwrap_err()
            .contains(&format!("lineage exceeds {MAX_REFERENCE_DEPTH} documents")));
    }

    #[test]
    fn profile_trust_root_reference_must_exactly_match_independent_pins() {
        let mut path_mismatch = ActiveFixture::build();
        path_mismatch.rewrite_profile(|profile| {
            profile["conformance_trust_root_registry_ref"]["artifact_locator"] =
                json!("catalog/security-contracts/v1/other-trust-root-registry.json");
        });
        assert!(path_mismatch
            .load()
            .unwrap_err()
            .contains("path does not match the independent startup pin"));

        let mut digest_mismatch = ActiveFixture::build();
        digest_mismatch.rewrite_profile(|profile| {
            profile["conformance_trust_root_registry_ref"]["content_digest"] =
                json!(format!("sha256:{}", "b".repeat(64)));
        });
        assert!(digest_mismatch
            .load()
            .unwrap_err()
            .contains("digest does not match the independent startup pin"));

        let mut identity_mismatch = ActiveFixture::build();
        identity_mismatch.rewrite_profile(|profile| {
            profile["conformance_trust_root_registry_ref"]["document_id"] =
                json!("conformance-trust-root-registry:wrong-registry");
        });
        assert!(identity_mismatch
            .load()
            .unwrap_err()
            .contains("document identity mismatch"));
    }

    #[test]
    fn implementation_trust_root_registry_is_fixture_only() {
        let mut fixture = ActiveFixture::build();
        fixture.rewrite_profile(|profile| {
            profile["enabled_features"] = json!(["static-dry-run"]);
            profile["applicability"]["enabled_feature_ids"] = profile["enabled_features"].clone();
        });
        assert!(fixture
            .load()
            .unwrap_err()
            .contains("implementation-only conformance trust-root registry requires"));
    }

    #[test]
    fn trust_root_registry_applicability_must_exactly_match_profile() {
        let mut fixture = ActiveFixture::build();
        fixture.rewrite_trust_root_registry(|registry| {
            registry["applicability"]["deployment_ids"] = json!(["deployment:other"]);
        });
        assert!(fixture
            .load()
            .unwrap_err()
            .contains("applicability deployment_ids does not exactly match"));

        let mut fixture = ActiveFixture::build();
        fixture.rewrite_trust_root_registry(|registry| {
            registry["applicability"]["trust_domain_ids"] = json!(["trust-domain:other"]);
        });
        assert!(fixture
            .load()
            .unwrap_err()
            .contains("applicability trust_domain_ids does not exactly match"));
    }

    #[test]
    fn production_signature_stage_authenticates_before_its_final_defense_in_depth_block() {
        // Exercise the cryptographic stage in isolation. Full production startup
        // remains intentionally unreachable earlier in reference traversal until
        // topology, egress, and retention artifacts have embedded trusted schemas.
        let key = SigningKey::from_bytes(&rand::random());
        let mut fixture = ActiveFixture::build();
        let mut profile_value: Value = serde_json::from_slice(
            &fs::read(fixture.root.join(PROFILE_PATH)).expect("profile bytes"),
        )
        .unwrap();
        profile_value["security_profile"] = json!("production");
        profile_value["applicability"]["security_profiles"] = json!(["production"]);
        profile_value["conformance_trust_root_registry_ref"]["document_id"] =
            json!("conformance-trust-root-registry:runtime-test");
        profile_value["conformance_trust_root_registry_ref"]["document_version"] = json!(1);
        let provisional_profile: DeploymentSecurityProfile =
            serde_json::from_value(profile_value.clone()).unwrap();
        let registry = production_trust_registry(&key, &provisional_profile);
        let registry_bytes = serde_json::to_vec_pretty(&registry).unwrap();
        let registry_digest = raw_digest(&registry_bytes);
        profile_value["conformance_trust_root_registry_ref"]["content_digest"] =
            json!(registry_digest);
        let mut profile: DeploymentSecurityProfile = serde_json::from_value(profile_value).unwrap();
        fixture.rewrite_trust_root_registry_raw(&registry_bytes);

        let mut artifact_store = ArtifactStore::open(&fixture.root).unwrap();
        let lineage = load_pinned_conformance_trust_root_registry(
            &mut artifact_store,
            &fixture.pins,
            &profile,
            fixed_now(),
        )
        .expect("production trust registry must load")
        .expect("production registry must create a validated lineage");

        let bundle = signed_closure_document(
            "conformance-bundle",
            &key,
            1,
            &fixture.pins.conformance_trust_root_registry_digest,
        );
        let receipt = signed_closure_document(
            "package-exit-receipt",
            &key,
            1,
            &fixture.pins.conformance_trust_root_registry_digest,
        );
        let production_root_locator = "receipts/runtime-sb9.json";
        bind_production_root(&mut profile, production_root_locator, &receipt);
        let documents = BTreeMap::from([
            (
                profile.control_trace_ref.artifact_locator.clone(),
                json!({
                    "traces": [{
                        "trace_id": "TRACE-RUNTIME-TEST",
                        "owning_work_package": "SB-0"
                    }]
                }),
            ),
            ("evidence/runtime-bundle.json".into(), bundle),
            (production_root_locator.into(), receipt),
        ]);
        let document_bytes = raw_document_bytes(&documents);
        let reference_digests = reference_document_digests(&document_bytes);
        let checkpoint = verified_checkpoint_for_documents(
            lineage,
            &profile,
            &key,
            &documents,
            &document_bytes,
            TRUST_ROOT_REGISTRY_PATH,
        );
        let mut verification_bytes = document_bytes.clone();
        let mut verified = verify_loaded_conformance_documents(
            &documents,
            &mut verification_bytes,
            &reference_digests,
            Some(&checkpoint),
            &profile,
            fixed_now(),
        )
        .expect("valid signatures must authenticate");
        assert_eq!(verified.len(), 2);
        let expected_trust_domain = profile.trust_topology.trust_domain_ids[0].as_str();
        assert!(verified.values().all(|proof| {
            proof.deployment_id() == DEPLOYMENT_ID
                && proof.trust_domain_id() == expected_trust_domain
                && matches!(proof.package_id(), "SB-0" | "SB-9")
                && proof.evidence_tier() == EvidenceTier::ExternallyAttested
        }));
        verify_current_production_root_binding(&checkpoint, &profile, &mut verified)
            .expect("the accepted SB-9 receipt must match the external current root");
        assert_eq!(
            verified.len(),
            1,
            "the SB-9 artifact is owned by the root proof"
        );
        let wrong_locator_root = checkpoint
            .verify_artifact(
                ConformanceArtifactCandidate::new(
                    "receipts/wrong-sb9.json".into(),
                    reference_digests[production_root_locator].clone(),
                    document_bytes[production_root_locator].clone(),
                ),
                ConformanceVerificationContext {
                    deployment_id: &profile.deployment_id,
                    trust_domain_id: expected_trust_domain,
                    package_id: "SB-9",
                    evidence_tier: EvidenceTier::ExternallyAttested,
                },
                trusted_time_point(fixed_now()),
            )
            .expect("the signed receipt remains accepted independently of its source locator");
        assert!(checkpoint
            .verify_current_production_root(wrong_locator_root)
            .unwrap_err()
            .to_string()
            .contains("exact current SB-9"));
        let mut swapped_bytes = document_bytes.clone();
        let bundle_bytes = swapped_bytes
            .remove("evidence/runtime-bundle.json")
            .expect("bundle bytes");
        let receipt_bytes = swapped_bytes
            .remove(production_root_locator)
            .expect("receipt bytes");
        swapped_bytes.insert("evidence/runtime-bundle.json".into(), receipt_bytes);
        swapped_bytes.insert(production_root_locator.into(), bundle_bytes);
        let swapped_error = verify_loaded_conformance_documents(
            &documents,
            &mut swapped_bytes,
            &reference_digests,
            Some(&checkpoint),
            &profile,
            fixed_now(),
        )
        .expect_err("raw bytes cannot be paired with another artifact's traversal digest");
        assert!(swapped_error.contains("raw bytes do not match"));

        let mut tampered = documents.clone();
        tampered.get_mut("evidence/runtime-bundle.json").unwrap()["signer"]["signature_base64"] =
            BASE64_STANDARD.encode([0u8; 64]).into();
        let mut tampered_bytes = raw_document_bytes(&tampered);
        let tampered_digests = reference_document_digests(&tampered_bytes);
        let error = verify_loaded_conformance_documents(
            &tampered,
            &mut tampered_bytes,
            &tampered_digests,
            Some(&checkpoint),
            &profile,
            fixed_now(),
        )
        .expect_err("tampered signature must fail before the production block");
        assert!(error.contains("untrusted"));
        assert!(!error.contains("production startup is blocked"));

        for (pointer, replacement) in [
            (
                "/signer/trust_registry_digest",
                json!(format!("sha256:{}", "b".repeat(64))),
            ),
            (
                "/bindings/deployment_profile/deployment_id",
                json!("deployment:other"),
            ),
            (
                "/provenance/evidence_tier/name",
                json!("operator_environment"),
            ),
        ] {
            let mut scoped_tamper = documents.clone();
            *scoped_tamper
                .get_mut("evidence/runtime-bundle.json")
                .unwrap()
                .pointer_mut(pointer)
                .unwrap() = replacement;
            let mut scoped_tamper_bytes = raw_document_bytes(&scoped_tamper);
            let scoped_tamper_digests = reference_document_digests(&scoped_tamper_bytes);
            assert!(verify_loaded_conformance_documents(
                &scoped_tamper,
                &mut scoped_tamper_bytes,
                &scoped_tamper_digests,
                Some(&checkpoint),
                &profile,
                fixed_now(),
            )
            .is_err());
        }

        let mut package_tamper = documents.clone();
        package_tamper.get_mut(production_root_locator).unwrap()["package_id"] = json!("SB-8");
        let mut package_tamper_bytes = raw_document_bytes(&package_tamper);
        let package_tamper_digests = reference_document_digests(&package_tamper_bytes);
        assert!(verify_loaded_conformance_documents(
            &package_tamper,
            &mut package_tamper_bytes,
            &package_tamper_digests,
            Some(&checkpoint),
            &profile,
            fixed_now(),
        )
        .is_err());

        let mut wrong_domain_profile = profile.clone();
        wrong_domain_profile.trust_topology.trust_domain_ids = vec!["trust-domain:other".into()];
        let mut wrong_domain_bytes = document_bytes.clone();
        assert!(verify_loaded_conformance_documents(
            &documents,
            &mut wrong_domain_bytes,
            &reference_digests,
            Some(&checkpoint),
            &wrong_domain_profile,
            fixed_now(),
        )
        .is_err());
    }

    #[test]
    fn production_signature_stage_selects_the_exact_two_version_lineage_head() {
        let key = SigningKey::from_bytes(&rand::random());
        let mut fixture = ActiveFixture::build();
        let mut profile_value: Value = serde_json::from_slice(
            &fs::read(fixture.root.join(PROFILE_PATH)).expect("profile bytes"),
        )
        .unwrap();
        profile_value["security_profile"] = json!("production");
        profile_value["applicability"]["security_profiles"] = json!(["production"]);
        profile_value["conformance_trust_root_registry_ref"]["document_id"] =
            json!("conformance-trust-root-registry:runtime-test");
        profile_value["conformance_trust_root_registry_ref"]["document_version"] = json!(2);
        let provisional_profile: DeploymentSecurityProfile =
            serde_json::from_value(profile_value.clone()).unwrap();

        let predecessor_locator =
            "catalog/security-contracts/v1/conformance-trust-root-registry.runtime-test-v1.json";
        let mut predecessor = production_trust_registry(&key, &provisional_profile);
        predecessor["lifecycle"]["effective_at"] = json!("2026-07-14T00:00:00Z");
        predecessor["keys"][0]["valid_from"] = json!("2026-07-14T00:00:00Z");
        let predecessor_digest = write_json(&fixture.root, predecessor_locator, &predecessor);

        let mut head = predecessor;
        head["document_version"] = json!(2);
        head["lifecycle"]["effective_at"] = json!("2026-07-15T00:00:00Z");
        head["predecessor_registry_ref"] = json!({
            "artifact_kind": "conformance-trust-root-registry",
            "document_id": "conformance-trust-root-registry:runtime-test",
            "document_version": 1,
            "content_digest": predecessor_digest,
            "artifact_locator": predecessor_locator
        });
        let head_bytes = serde_json::to_vec_pretty(&head).unwrap();
        let head_digest = raw_digest(&head_bytes);
        profile_value["conformance_trust_root_registry_ref"]["content_digest"] = json!(head_digest);
        let mut profile: DeploymentSecurityProfile = serde_json::from_value(profile_value).unwrap();
        fixture.rewrite_trust_root_registry_raw(&head_bytes);

        let mut artifact_store = ArtifactStore::open(&fixture.root).unwrap();
        let lineage = load_pinned_conformance_trust_root_registry(
            &mut artifact_store,
            &fixture.pins,
            &profile,
            fixed_now(),
        )
        .expect("complete production registry lineage must load")
        .expect("production lineage must construct a validated lineage");

        let bundle = signed_closure_document(
            "conformance-bundle",
            &key,
            2,
            &fixture.pins.conformance_trust_root_registry_digest,
        );
        let production_root = signed_closure_document(
            "package-exit-receipt",
            &key,
            2,
            &fixture.pins.conformance_trust_root_registry_digest,
        );
        let production_root_locator = "receipts/runtime-v2-sb9.json";
        bind_production_root(&mut profile, production_root_locator, &production_root);
        let documents = BTreeMap::from([
            (
                profile.control_trace_ref.artifact_locator.clone(),
                json!({
                    "traces": [{
                        "trace_id": "TRACE-RUNTIME-TEST",
                        "owning_work_package": "SB-0"
                    }]
                }),
            ),
            ("evidence/runtime-v2-bundle.json".into(), bundle),
            (production_root_locator.into(), production_root),
        ]);
        let document_bytes = raw_document_bytes(&documents);
        let reference_digests = reference_document_digests(&document_bytes);
        let checkpoint = verified_checkpoint_for_documents(
            lineage,
            &profile,
            &key,
            &documents,
            &document_bytes,
            TRUST_ROOT_REGISTRY_PATH,
        );
        let mut verification_bytes = document_bytes.clone();
        let mut verified = verify_loaded_conformance_documents(
            &documents,
            &mut verification_bytes,
            &reference_digests,
            Some(&checkpoint),
            &profile,
            fixed_now(),
        )
        .expect("the current lineage head must authenticate its exact signed document");
        assert_eq!(verified.len(), 2);
        verify_current_production_root_binding(&checkpoint, &profile, &mut verified)
            .expect("the v2 lineage checkpoint must bind its exact current SB-9 root");
        assert_eq!(verified.len(), 1);
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

    #[test]
    fn finalized_startup_retains_the_exact_verified_authenticator_binding_arc() {
        let mut fixture = ActiveFixture::build();
        fixture.install_authenticator_runtime_binding();

        let prepared = prepare_startup_security_contract(&fixture.pins, fixed_now())
            .expect("the authenticator binding must survive full reference traversal");
        let provider = &prepared.active_providers["provider:repository-static-dry-run"];
        let prepared_binding = Arc::clone(
            provider
                .verified_authenticator_runtime_binding()
                .expect("pre-finalization OIDC provider must retain exact D"),
        );
        assert_eq!(provider.kind, "oidc");
        assert_eq!(provider.capability_descriptor.adapter_kind, "auth.entra-id");
        prepared_binding
            .verify_integrity()
            .expect("retained exact D bytes must re-hash and reparse");

        let context = finalize_startup_security_contract(prepared, None, None, fixed_now)
            .expect("non-production finalization must preserve the authenticator projection");
        let retained_binding = context.active_providers["provider:repository-static-dry-run"]
            .verified_authenticator_runtime_binding()
            .expect("final context must retain exact authenticator D");
        assert!(Arc::ptr_eq(&prepared_binding, retained_binding));
        assert_eq!(
            retained_binding.reference.artifact_locator,
            AUTHENTICATOR_RUNTIME_BINDING_PATH
        );
        assert_eq!(
            retained_binding.document.provider_policy.digest_contract,
            AUTHENTICATOR_PROVIDER_POLICY_BINDING_DIGEST_CONTRACT
        );
        assert_ne!(
            retained_binding.reference.content_digest,
            context.active_providers["provider:repository-static-dry-run"].payload_digest
        );
    }

    #[test]
    fn authenticator_binding_requires_exact_reference_traversal_and_raw_bytes() {
        let valid = AuthenticatorBindingCase::build();
        valid.verify().expect("exact D/P/Q binding must verify");

        let mut raw_substitution = AuthenticatorBindingCase::build();
        raw_substitution
            .document_bytes
            .get_mut(AUTHENTICATOR_RUNTIME_BINDING_PATH)
            .unwrap()
            .push(b' ');
        assert!(raw_substitution
            .verify()
            .unwrap_err()
            .contains("differs across its reference, exact bytes, and verified traversal"));

        let mut traversal_substitution = AuthenticatorBindingCase::build();
        traversal_substitution.reference_document_digests.insert(
            AUTHENTICATOR_RUNTIME_BINDING_PATH.into(),
            raw_digest(b"substituted authenticator traversal digest"),
        );
        assert!(traversal_substitution
            .verify()
            .unwrap_err()
            .contains("differs across its reference, exact bytes, and verified traversal"));

        let mut parsed_substitution = AuthenticatorBindingCase::build();
        parsed_substitution
            .documents
            .get_mut(AUTHENTICATOR_RUNTIME_BINDING_PATH)
            .unwrap()["adapter_version"] = json!("2.0.0");
        assert!(parsed_substitution
            .verify()
            .unwrap_err()
            .contains("differs across its reference, exact bytes, and verified traversal"));

        let mut retained = valid.verify().unwrap();
        retained.raw_bytes[0] ^= 1;
        assert!(retained
            .verify_integrity()
            .unwrap_err()
            .contains("exact digest"));
    }

    #[test]
    fn authenticator_binding_rejects_authority_capability_and_policy_substitution() {
        for (pointer, substituted) in [
            ("/provider_id", json!("provider:substituted-runtime")),
            ("/provider_configuration_version", json!(2)),
            ("/deployment_id", json!("deployment:substituted-runtime")),
            (
                "/trust_domain_id",
                json!("trust-domain:substituted-runtime"),
            ),
            (
                "/capability_descriptor_id",
                json!("capability-descriptor:substituted-runtime-v1"),
            ),
            ("/capability_descriptor_version", json!(2)),
            ("/adapter_version", json!("2.0.0")),
            ("/authenticator_kind", json!("oidc-broker")),
        ] {
            let mut case = AuthenticatorBindingCase::build();
            let mut document = case.document();
            *document.pointer_mut(pointer).unwrap() = substituted;
            case.repin_document(document);
            let error = case
                .verify()
                .expect_err("authority substitution must fail closed");
            assert!(
                error.contains("does not exactly match"),
                "{pointer}: {error}"
            );
        }

        let mut adapter_substitution = AuthenticatorBindingCase::build();
        let mut document = adapter_substitution.document();
        document["adapter_kind"] = json!("auth.generic-oidc");
        document["credential_paths"][0]["verifier"]["provider_subject_claim_id"] = json!("sub");
        adapter_substitution.repin_document(document);
        assert!(adapter_substitution
            .verify()
            .unwrap_err()
            .contains("does not exactly match"));

        let mut capability_substitution = AuthenticatorBindingCase::build();
        let mut document = capability_substitution.document();
        document["capability_ids"] = json!(["browser-sso"]);
        capability_substitution.repin_document(document);
        assert!(capability_substitution
            .verify()
            .unwrap_err()
            .contains("capability inventory does not exactly match"));

        let mut document_q_substitution = AuthenticatorBindingCase::build();
        let mut document = document_q_substitution.document();
        document["provider_policy"]["binding_digest"] =
            json!(raw_digest(b"caller-supplied provider policy"));
        document_q_substitution.repin_document(document);
        assert!(document_q_substitution
            .verify()
            .unwrap_err()
            .contains("independently recomputed OIDC kind_config"));

        let mut provider_policy_drift = AuthenticatorBindingCase::build();
        provider_policy_drift
            .oidc_configuration
            .client_authentication_method = "mtls".into();
        provider_policy_drift.raw_oidc_kind_config["client_authentication_method"] = json!("mtls");
        assert!(provider_policy_drift
            .verify()
            .unwrap_err()
            .contains("independently recomputed OIDC kind_config"));

        let mut digest_domain_confusion = AuthenticatorBindingCase::build();
        digest_domain_confusion.provider_payload_digest =
            digest_domain_confusion.reference.content_digest.clone();
        assert!(digest_domain_confusion
            .verify()
            .unwrap_err()
            .contains("D/P/Q digest separation"));
    }

    #[test]
    fn authenticator_binding_rejects_reference_schema_and_implemented_policy_confusion() {
        let mut reference_identity = AuthenticatorBindingCase::build();
        reference_identity.reference.document_id =
            "authenticator-runtime-binding:substituted-runtime".into();
        assert!(reference_identity
            .verify()
            .unwrap_err()
            .contains("does not exactly match"));

        let mut non_json = AuthenticatorBindingCase::build();
        non_json.reference.artifact_locator =
            "catalog/security-contracts/v1/authenticator-runtime-binding.runtime-test.JSON".into();
        non_json.oidc_configuration.runtime_binding_ref = non_json.reference.clone();
        non_json.raw_oidc_kind_config["runtime_binding_ref"] =
            serde_json::to_value(&non_json.reference).unwrap();
        assert!(non_json.verify().unwrap_err().contains("lowercase .json"));

        for (pointer, substituted) in [
            (
                "/$schema",
                json!(
                    "https://ryuki.io/schemas/security-contracts/v1/action-resource-registry.schema.json"
                ),
            ),
            ("/contract_kind", json!("action-resource-registry")),
        ] {
            let mut case = AuthenticatorBindingCase::build();
            let mut document = case.document();
            *document.pointer_mut(pointer).unwrap() = substituted;
            case.repin_document(document);
            assert!(case.verify().is_err(), "{pointer} relabel was accepted");
        }

        for (validation_mode, algorithms) in [
            ("authenticated-introspection", vec!["RS256".to_string()]),
            ("jwt-jwks", vec!["PS256".to_string()]),
        ] {
            let mut case = AuthenticatorBindingCase::build();
            case.oidc_configuration.validation_mode = validation_mode.into();
            case.oidc_configuration.accepted_algorithms = algorithms.clone();
            case.raw_oidc_kind_config["validation_mode"] = json!(validation_mode);
            case.raw_oidc_kind_config["accepted_algorithms"] = json!(algorithms);
            assert!(case
                .verify()
                .unwrap_err()
                .contains("exact implemented jwt-jwks/RS256"));
        }
    }

    #[test]
    fn provider_schema_requires_a_nonzero_json_authenticator_runtime_reference() {
        let mut fixture = ActiveFixture::build();
        fixture.install_authenticator_runtime_binding();
        let provider_path = "catalog/security-contracts/v1/provider-registry.runtime-test.json";
        let provider: Value =
            serde_json::from_slice(&fs::read(fixture.root.join(provider_path)).unwrap()).unwrap();
        validate_against_schema("OIDC provider fixture", PROVIDER_SCHEMA, &provider)
            .expect("the exact authenticator reference must satisfy the provider schema");

        let mut omitted = provider.clone();
        omitted["configurations"][0]["kind_config"]
            .as_object_mut()
            .unwrap()
            .remove("runtime_binding_ref");
        assert!(
            validate_against_schema("OIDC provider fixture", PROVIDER_SCHEMA, &omitted)
                .unwrap_err()
                .contains("runtime_binding_ref")
        );

        let mut zero_digest = provider.clone();
        zero_digest["configurations"][0]["kind_config"]["runtime_binding_ref"]["content_digest"] =
            json!(format!("sha256:{}", "0".repeat(64)));
        assert!(
            validate_against_schema("OIDC provider fixture", PROVIDER_SCHEMA, &zero_digest)
                .is_err()
        );

        let mut uppercase_extension = provider;
        uppercase_extension["configurations"][0]["kind_config"]["runtime_binding_ref"]
            ["artifact_locator"] =
            json!("catalog/security-contracts/v1/authenticator-runtime-binding.runtime-test.JSON");
        assert!(validate_against_schema(
            "OIDC provider fixture",
            PROVIDER_SCHEMA,
            &uppercase_extension
        )
        .is_err());
    }

    #[test]
    fn finalized_startup_retains_the_exact_verified_secret_provider_binding_arc() {
        let mut fixture = ActiveFixture::build();
        fixture.install_secret_provider_runtime_binding();

        let prepared = prepare_startup_security_contract(&fixture.pins, fixed_now())
            .expect("the runtime binding must survive full reference traversal");
        let prepared_binding = Arc::clone(
            prepared.active_providers["provider:repository-static-dry-run"]
                .verified_secret_provider_runtime_binding()
                .expect("pre-finalization provider must retain the verified binding"),
        );
        let context = finalize_startup_security_contract(prepared, None, None, fixed_now)
            .expect("non-production finalization must preserve the verified projection");
        let retained_binding = context.active_providers["provider:repository-static-dry-run"]
            .verified_secret_provider_runtime_binding()
            .expect("final context must retain the verified binding");

        assert!(Arc::ptr_eq(&prepared_binding, retained_binding));
        assert_eq!(
            retained_binding.reference.artifact_locator,
            SECRET_PROVIDER_RUNTIME_BINDING_PATH
        );
        assert_eq!(
            retained_binding.document.document_id,
            "secret-provider-runtime-binding:runtime-test"
        );
        assert_eq!(
            retained_binding.document.provider_id,
            "provider:repository-static-dry-run"
        );
        assert_eq!(
            retained_binding.document.capability_bindings.len(),
            context.active_providers["provider:repository-static-dry-run"]
                .capability_descriptor
                .advertised_capabilities
                .len()
        );
        retained_binding
            .verify_integrity()
            .expect("the retained exact raw bytes must re-hash and reparse");
    }

    fn operational_observation_from_binding(
        binding: &VerifiedSecretProviderRuntimeBinding,
    ) -> crate::secret_provider_runtime::VaultRuntimeOperationalObservation {
        let document = &binding.document;
        crate::secret_provider_runtime::VaultRuntimeOperationalObservation {
            provider_id: document.provider_id.clone(),
            provider_configuration_version: document.provider_configuration_version,
            adapter_kind: document.adapter_kind.clone(),
            adapter_version: document.adapter_version.clone(),
            protocol_version: document.protocol_version.clone(),
            backend_compatibility_profile:
                crate::secret_provider_runtime::VaultBackendCompatibilityObservation {
                    profile_id: document.backend_compatibility_profile.profile_id.clone(),
                    profile_version: document.backend_compatibility_profile.profile_version,
                    digest_contract: document
                        .backend_compatibility_profile
                        .digest_contract
                        .clone(),
                    binding_digest: document
                        .backend_compatibility_profile
                        .binding_digest
                        .clone(),
                },
            transport: crate::secret_provider_runtime::VaultTransportObservation {
                endpoint_base_url_binding_digest: document
                    .transport
                    .endpoint_base_url_binding_digest
                    .clone(),
                ca_trust_binding_digest: document.transport.ca_trust_binding_digest.clone(),
                https_required: document.transport.https_required,
                redirects_allowed: document.transport.redirects_allowed,
                ambient_proxy_allowed: document.transport.ambient_proxy_allowed,
                built_in_roots_allowed: document.transport.built_in_roots_allowed,
                connect_timeout_millis: document.transport.connect_timeout_millis,
                request_timeout_millis: document.transport.request_timeout_millis,
                response_body_max_bytes: document.transport.response_body_max_bytes,
            },
            credential_source: crate::secret_provider_runtime::VaultCredentialSourceObservation {
                kind: document.credential_source.kind.clone(),
                identity_binding_digest: document.credential_source.identity_binding_digest.clone(),
                audience_binding_digest: document.credential_source.audience_binding_digest.clone(),
                token_path_binding_digest: document
                    .credential_source
                    .token_path_binding_digest
                    .clone(),
                provider_authentication_digest_contract: document
                    .credential_source
                    .provider_authentication_digest_contract
                    .clone(),
                provider_authentication_binding_digest: document
                    .credential_source
                    .provider_authentication_binding_digest
                    .clone(),
                static_bearer_allowed: document.credential_source.static_bearer_allowed,
                exported_bearer_allowed: document.credential_source.exported_bearer_allowed,
            },
            capability_bindings: document
                .capability_bindings
                .iter()
                .map(
                    |capability| crate::secret_provider_runtime::VaultCapabilityObservation {
                        capability_id: capability.capability_id.clone(),
                        semantic_version: capability.semantic_version.clone(),
                    },
                )
                .collect(),
            retained_consumer_ids: document.retained_consumer_ids.clone(),
            ownership: crate::secret_provider_runtime::VaultRuntimeOwnershipObservation {
                single_runtime_owner: document.ownership.single_runtime_owner,
                ambient_reconfiguration_allowed: document.ownership.ambient_reconfiguration_allowed,
            },
        }
    }

    #[test]
    fn approved_secret_provider_derives_distinct_d_p_r_i_from_measured_leaves() {
        let mut fixture = ActiveFixture::build();
        fixture.install_secret_provider_runtime_binding();
        let prepared = prepare_startup_security_contract(&fixture.pins, fixed_now()).unwrap();
        let provider = &prepared.active_providers["provider:repository-static-dry-run"];
        let binding = provider
            .verified_secret_provider_runtime_binding()
            .expect("fixture provider has an exact runtime binding");
        let observation = operational_observation_from_binding(binding);

        let measured = measured_approved_secret_provider_value(provider, binding, &observation)
            .expect("all independently measured runtime leaves match the binding");
        let RuntimeGuardExpectedValue::ApprovedSecretProvider {
            provider_inventory_digest,
            providers,
            required_capability_ids,
        } = measured
        else {
            panic!("measurement changed guard kind");
        };
        assert_eq!(providers.len(), 1);
        assert_eq!(
            providers[0].provider.configuration_payload_digest,
            provider.payload_digest
        );
        assert_ne!(
            providers[0].runtime_binding_digest, binding.reference.content_digest,
            "R must not be the exact-document digest D"
        );
        assert_ne!(
            providers[0].runtime_binding_digest, provider.payload_digest,
            "R must not be the active-provider payload digest P"
        );
        assert_eq!(
            provider_inventory_digest,
            secret_provider_inventory_digest(&providers, &required_capability_ids).unwrap(),
            "I must use the existing canonical inventory contract"
        );
        assert_eq!(
            required_capability_ids,
            vec![
                "dry-run-only".to_string(),
                "static-human-fixture".to_string()
            ]
        );

        let mut substituted = observation;
        substituted.transport.endpoint_base_url_binding_digest =
            raw_digest(b"substituted live endpoint");
        assert_eq!(
            measured_approved_secret_provider_value(provider, binding, &substituted).unwrap_err(),
            ProductionRuntimeAdmissionError::GuardMeasurementFailed {
                guard_id: GuardId::ApprovedSecretProvider,
            }
        );
    }

    #[test]
    fn retained_secret_provider_binding_rejects_raw_byte_drift() {
        let case = SecretProviderBindingCase::build();
        let mut binding = case.verify().expect("fixture binding verifies");
        binding.raw_bytes[0] ^= 1;
        assert!(binding
            .verify_integrity()
            .unwrap_err()
            .contains("exact digest"));
    }

    #[test]
    fn secret_provider_binding_requires_exact_reference_traversal_and_raw_bytes() {
        let valid = SecretProviderBindingCase::build();
        valid
            .verify()
            .expect("the exact three-way binding must verify");

        let mut raw_substitution = SecretProviderBindingCase::build();
        raw_substitution
            .document_bytes
            .get_mut(SECRET_PROVIDER_RUNTIME_BINDING_PATH)
            .unwrap()
            .push(b' ');
        assert!(raw_substitution
            .verify()
            .unwrap_err()
            .contains("differs across its reference, exact bytes, and verified traversal"));

        let mut traversal_substitution = SecretProviderBindingCase::build();
        traversal_substitution.reference_document_digests.insert(
            SECRET_PROVIDER_RUNTIME_BINDING_PATH.into(),
            raw_digest(b"substituted traversal digest"),
        );
        assert!(traversal_substitution
            .verify()
            .unwrap_err()
            .contains("differs across its reference, exact bytes, and verified traversal"));

        let mut reference_substitution = SecretProviderBindingCase::build();
        reference_substitution.reference.content_digest =
            raw_digest(b"substituted reference digest");
        assert!(reference_substitution
            .verify()
            .unwrap_err()
            .contains("differs across its reference, exact bytes, and verified traversal"));

        let mut parsed_substitution = SecretProviderBindingCase::build();
        parsed_substitution
            .documents
            .get_mut(SECRET_PROVIDER_RUNTIME_BINDING_PATH)
            .unwrap()["protocol_version"] = json!("2.0.0");
        assert!(parsed_substitution
            .verify()
            .unwrap_err()
            .contains("differs across its reference, exact bytes, and verified traversal"));
    }

    #[test]
    fn secret_provider_binding_rejects_authority_and_capability_substitution() {
        for (pointer, substituted) in [
            ("/provider_id", json!("provider:substituted-runtime")),
            ("/provider_configuration_version", json!(2)),
            ("/deployment_id", json!("deployment:substituted-runtime")),
            (
                "/trust_domain_id",
                json!("trust-domain:substituted-runtime"),
            ),
            (
                "/capability_descriptor_id",
                json!("capability-descriptor:substituted-runtime-v1"),
            ),
            ("/capability_descriptor_version", json!(2)),
            ("/adapter_kind", json!("fixture.substituted-runtime")),
            ("/adapter_version", json!("2.0.0")),
        ] {
            let mut case = SecretProviderBindingCase::build();
            let mut document = case.document();
            *document.pointer_mut(pointer).unwrap() = substituted;
            case.repin_document(document);
            let error = case
                .verify()
                .expect_err("authority substitution must fail closed");
            assert!(
                error.contains("does not exactly match its provider, deployment, trust-domain, descriptor, and adapter authority"),
                "{pointer}: {error}"
            );
        }

        let mut capability_substitution = SecretProviderBindingCase::build();
        let mut document = capability_substitution.document();
        document["capability_bindings"][1]["capability_id"] = json!("substituted-capability");
        capability_substitution.repin_document(document);
        assert!(capability_substitution
            .verify()
            .unwrap_err()
            .contains("capability inventory does not exactly match"));
    }

    #[test]
    fn secret_provider_binding_rejects_unsafe_runtime_semantics_and_ordering() {
        for (pointer, unsafe_value) in [
            ("/transport/https_required", json!(false)),
            ("/transport/redirects_allowed", json!(true)),
            ("/transport/ambient_proxy_allowed", json!(true)),
            ("/transport/built_in_roots_allowed", json!(true)),
            ("/transport/connect_timeout_millis", json!(3001)),
            ("/transport/request_timeout_millis", json!(10001)),
            ("/transport/response_body_max_bytes", json!(1048577)),
            ("/credential_source/kind", json!("exported-static-bearer")),
            ("/credential_source/static_bearer_allowed", json!(true)),
            ("/credential_source/exported_bearer_allowed", json!(true)),
            ("/ownership/single_runtime_owner", json!(false)),
            ("/ownership/ambient_reconfiguration_allowed", json!(true)),
        ] {
            let mut case = SecretProviderBindingCase::build();
            let mut document = case.document();
            *document.pointer_mut(pointer).unwrap() = unsafe_value;
            case.repin_document(document);
            assert!(
                case.verify().is_err(),
                "unsafe binding {pointer} was accepted"
            );
        }

        for array_pointer in ["/capability_bindings", "/retained_consumer_ids"] {
            let mut case = SecretProviderBindingCase::build();
            let mut document = case.document();
            document
                .pointer_mut(array_pointer)
                .unwrap()
                .as_array_mut()
                .unwrap()
                .reverse();
            case.repin_document(document);
            assert!(
                case.verify().is_err(),
                "noncanonical ordering at {array_pointer} was accepted"
            );
        }
    }

    #[test]
    fn secret_service_policy_shape_is_new_only_or_complete_legacy_never_mixed() {
        let reference = SecretProviderBindingCase::build().reference;
        let new_only = CapabilityProviderKindConfig {
            configuration_kind: "secret-service".into(),
            adapter_kind: "fixture.repository-static-dry-run".into(),
            runtime_binding_ref: Some(reference.clone()),
            endpoint_policy_ref: None,
            authentication_ref: None,
            capability_policy_ref: None,
            rotation_policy_ref: None,
            revocation_policy_ref: None,
        };
        assert_eq!(new_only.security_binding_summary("secret-service"), Ok(1));

        let mut mixed = new_only.clone();
        mixed.endpoint_policy_ref = Some(reference.clone());
        assert!(mixed
            .security_binding_summary("secret-service")
            .unwrap_err()
            .contains("cannot mix"));

        let partial_legacy = CapabilityProviderKindConfig {
            configuration_kind: "secret-service".into(),
            adapter_kind: "fixture.repository-static-dry-run".into(),
            runtime_binding_ref: None,
            endpoint_policy_ref: Some(reference.clone()),
            authentication_ref: Some(reference.clone()),
            capability_policy_ref: Some(reference.clone()),
            rotation_policy_ref: Some(reference.clone()),
            revocation_policy_ref: None,
        };
        assert!(partial_legacy
            .security_binding_summary("secret-service")
            .unwrap_err()
            .contains("either runtime_binding_ref or all five"));

        let complete_legacy = CapabilityProviderKindConfig {
            revocation_policy_ref: Some(reference.clone()),
            ..partial_legacy
        };
        assert_eq!(
            complete_legacy.security_binding_summary("secret-service"),
            Ok(5)
        );
        for provider_kind in ["key-custody", "certificate-authority"] {
            assert!(new_only
                .security_binding_summary(provider_kind)
                .unwrap_err()
                .contains("cannot use a secret-provider runtime binding"));
            assert_eq!(
                complete_legacy.security_binding_summary(provider_kind),
                Ok(5)
            );
        }
    }

    #[test]
    fn production_activation_refuses_legacy_secret_service_without_downgrade_fallback() {
        let fixture = ActiveFixture::build();
        let prepared = prepare_startup_security_contract(&fixture.pins, fixed_now()).unwrap();
        let provider_locator = prepared
            .profile
            .provider_registry_ref
            .artifact_locator
            .clone();
        let mut registry = prepared.documents[&provider_locator].clone();
        let reference = registry["configurations"][0]["capability_descriptor"]
            ["mandatory_baseline_ref"]
            .clone();
        registry["applicability"]["provider_kinds"] = json!(["secret-service"]);
        let configuration = &mut registry["configurations"][0];
        configuration["kind"] = json!("secret-service");
        configuration["allowed_security_profiles"] = json!(["production"]);
        configuration["capability_descriptor"]["production_eligible"] = json!(true);
        configuration["kind_config"] = json!({
            "configuration_kind": "secret-service",
            "adapter_kind": configuration["capability_descriptor"]["adapter_kind"].clone(),
            "endpoint_policy_ref": reference.clone(),
            "authentication_ref": reference.clone(),
            "capability_policy_ref": reference.clone(),
            "rotation_policy_ref": reference.clone(),
            "revocation_policy_ref": reference
        });
        refresh_provider_payload_digests(&mut registry);
        let mut profile = prepared.profile.clone();
        profile.security_profile = SecurityProfile::Production;

        let error = validate_provider_registry(
            &registry,
            &profile,
            fixed_now(),
            &prepared.documents,
            &prepared.raw_document_bytes,
            &prepared.reference_document_digests,
        )
        .expect_err("production must not activate the legacy secret-service projection");
        assert!(
            error.contains("legacy five-reference policy shape"),
            "{error}"
        );

        let mut bound_fixture = ActiveFixture::build();
        bound_fixture.install_secret_provider_runtime_binding();
        let prepared = prepare_startup_security_contract(&bound_fixture.pins, fixed_now()).unwrap();
        let provider_locator = prepared
            .profile
            .provider_registry_ref
            .artifact_locator
            .clone();
        let mut registry = prepared.documents[&provider_locator].clone();
        registry["configurations"][0]["allowed_security_profiles"] = json!(["production"]);
        registry["configurations"][0]["capability_descriptor"]["production_eligible"] = json!(true);
        refresh_provider_payload_digests(&mut registry);
        let mut profile = prepared.profile.clone();
        profile.security_profile = SecurityProfile::Production;
        validate_provider_registry(
            &registry,
            &profile,
            fixed_now(),
            &prepared.documents,
            &prepared.raw_document_bytes,
            &prepared.reference_document_digests,
        )
        .expect("the exact new binding shape must not be downgraded to legacy diagnostics");
    }

    #[test]
    fn secret_provider_binding_rejects_schema_kind_identity_and_version_mismatch() {
        for (pointer, substituted) in [
            (
                "/$schema",
                json!(
                    "https://ryuki.io/schemas/security-contracts/v1/action-resource-registry.schema.json"
                ),
            ),
            ("/contract_kind", json!("action-resource-registry")),
        ] {
            let mut case = SecretProviderBindingCase::build();
            let mut document = case.document();
            *document.pointer_mut(pointer).unwrap() = substituted;
            case.repin_document(document);
            assert!(
                case.verify().is_err(),
                "schema/contract substitution at {pointer} was accepted"
            );
        }

        let mut identity_mismatch = SecretProviderBindingCase::build();
        identity_mismatch.reference.document_id =
            "secret-provider-runtime-binding:substituted-runtime".into();
        assert!(identity_mismatch
            .verify()
            .unwrap_err()
            .contains("does not exactly match"));

        let mut version_mismatch = SecretProviderBindingCase::build();
        version_mismatch.reference.document_version = 2;
        assert!(version_mismatch
            .verify()
            .unwrap_err()
            .contains("does not exactly match"));
    }

    #[test]
    fn capability_provider_runtime_adapter_must_match_attested_descriptor() {
        let fixture = ActiveFixture::build();
        let registry: Value = serde_json::from_slice(
            &fs::read(
                fixture
                    .root
                    .join("catalog/security-contracts/v1/provider-registry.runtime-test.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let mut configuration = registry["configurations"][0].clone();
        let reference = configuration["capability_descriptor"]["mandatory_baseline_ref"].clone();
        configuration["kind"] = json!("secret-service");
        configuration["kind_config"] = json!({
            "configuration_kind": "secret-service",
            "adapter_kind": "runtime.secret-service",
            "endpoint_policy_ref": reference,
            "authentication_ref": reference,
            "capability_policy_ref": reference,
            "rotation_policy_ref": reference,
            "revocation_policy_ref": reference
        });
        let profile: DeploymentSecurityProfile =
            serde_json::from_slice(&fs::read(fixture.root.join(PROFILE_PATH)).unwrap()).unwrap();
        let documents = BTreeMap::new();
        let document_bytes = BTreeMap::new();
        let reference_document_digests = BTreeMap::new();

        let error = parse_active_provider_configuration(
            &configuration,
            &profile,
            &documents,
            &document_bytes,
            &reference_document_digests,
        )
        .expect_err("a runtime adapter selector cannot diverge from its attestation");
        assert!(error.contains("runtime adapter selector"), "{error}");

        configuration["capability_descriptor"]["adapter_kind"] = json!("runtime.secret-service");
        parse_active_provider_configuration(
            &configuration,
            &profile,
            &documents,
            &document_bytes,
            &reference_document_digests,
        )
        .expect("an exact runtime/descriptor adapter binding must parse");
    }

    #[test]
    fn provider_rotation_selects_latest_active_version_and_rejects_dual_active() {
        let mut fixture = ActiveFixture::build();
        let provider_id = "provider:repository-static-dry-run";
        let drain_digest = write_json(
            &fixture.root,
            "evidence/provider-v1-draining.json",
            &json!({
                "document_id": "transition-receipt:provider-v1-draining",
                "document_version": 1,
                "provider_id": provider_id,
                "config_version": 1,
                "from_lifecycle_record_version": 3,
                "to_lifecycle_record_version": 4,
                "from_state": "active",
                "to_state": "draining",
                "result": "pass"
            }),
        );
        let v2_validated_digest = write_json(
            &fixture.root,
            "evidence/provider-v2-validated.json",
            &json!({
                "document_id": "transition-receipt:provider-v2-validated",
                "document_version": 1,
                "provider_id": provider_id,
                "config_version": 2,
                "from_lifecycle_record_version": 1,
                "to_lifecycle_record_version": 2,
                "from_state": "configured",
                "to_state": "validated",
                "result": "pass"
            }),
        );
        let v2_active_digest = write_json(
            &fixture.root,
            "evidence/provider-v2-active.json",
            &json!({
                "document_id": "transition-receipt:provider-v2-active",
                "document_version": 1,
                "provider_id": provider_id,
                "config_version": 2,
                "from_lifecycle_record_version": 2,
                "to_lifecycle_record_version": 3,
                "from_state": "validated",
                "to_state": "active",
                "result": "pass"
            }),
        );
        let root = fixture.root.clone();
        fixture.rewrite_provider(|provider| {
            provider["configurations"][0]["required_for_profiles"] = json!(["test"]);
            let mut v2 = provider["configurations"][0].clone();
            v2["config_version"] = json!(2);
            v2["required_for_profiles"] = json!([]);
            let v1 = provider["configurations"][0].clone();
            provider["configurations"] = json!([v2, v1]);

            let configured_v1 = provider["provider_lifecycle"][0].clone();
            let validated_v1 = provider["provider_lifecycle"][1].clone();
            let active_v1 = provider["provider_lifecycle"][2].clone();
            let mut draining_v1 = active_v1.clone();
            draining_v1["lifecycle_record_version"] = json!(4);
            draining_v1["state"] = json!("draining");
            draining_v1["effective_at"] = json!("2026-07-16T01:00:00Z");
            draining_v1["supersedes_lifecycle_record_version"] = json!(3);
            draining_v1["transition_receipt_ref"] = json!({
                "document_id": "transition-receipt:provider-v1-draining",
                "document_version": 1,
                "content_digest": drain_digest,
                "artifact_locator": "evidence/provider-v1-draining.json"
            });

            let mut configured_v2 = configured_v1.clone();
            configured_v2["config_version"] = json!(2);
            configured_v2["effective_at"] = json!("2026-07-16T00:30:00Z");
            let mut validated_v2 = configured_v2.clone();
            validated_v2["lifecycle_record_version"] = json!(2);
            validated_v2["state"] = json!("validated");
            validated_v2["effective_at"] = json!("2026-07-16T00:45:00Z");
            validated_v2["supersedes_lifecycle_record_version"] = json!(1);
            validated_v2["transition_receipt_ref"] = json!({
                "document_id": "transition-receipt:provider-v2-validated",
                "document_version": 1,
                "content_digest": v2_validated_digest,
                "artifact_locator": "evidence/provider-v2-validated.json"
            });
            let mut active_v2 = validated_v2.clone();
            active_v2["lifecycle_record_version"] = json!(3);
            active_v2["state"] = json!("active");
            active_v2["effective_at"] = json!("2026-07-16T01:00:00Z");
            active_v2["supersedes_lifecycle_record_version"] = json!(2);
            active_v2["transition_receipt_ref"] = json!({
                "document_id": "transition-receipt:provider-v2-active",
                "document_version": 1,
                "content_digest": v2_active_digest,
                "artifact_locator": "evidence/provider-v2-active.json"
            });

            // Deliberately reverse/interleave both histories: lifecycle record
            // version, not JSON array order, is authoritative.
            provider["provider_lifecycle"] = json!([
                active_v2,
                draining_v1,
                configured_v2,
                active_v1,
                validated_v2,
                configured_v1,
                validated_v1
            ]);
            refresh_reference_digests(provider, &root);
            refresh_provider_payload_digests(provider);
        });

        let context = fixture
            .load()
            .expect("historical draining v1 and active v2 must be admitted");
        let selected = context.active_providers.get(provider_id).unwrap();
        assert_eq!(selected.config_version, 2);
        assert_eq!(selected.active_lifecycle_record_version, 3);

        fixture.rewrite_provider(|provider| {
            provider["provider_lifecycle"]
                .as_array_mut()
                .unwrap()
                .retain(|record| {
                    record["config_version"].as_u64() != Some(1)
                        || record["lifecycle_record_version"].as_u64() != Some(4)
                });
        });
        assert!(fixture
            .load()
            .unwrap_err()
            .contains("multiple active configuration versions"));
    }

    #[test]
    fn provider_lifecycle_rejects_effective_time_regression() {
        let mut fixture = ActiveFixture::build();
        fixture.rewrite_provider(|provider| {
            provider["provider_lifecycle"][2]["effective_at"] = json!("2026-07-15T23:59:59Z");
        });
        assert!(fixture
            .load()
            .unwrap_err()
            .contains("effective_at chronology regresses"));
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
    fn production_rejects_the_legacy_auth_selector_before_guard_admission() {
        let fixture = ActiveFixture::build();
        let mut context = fixture.load().unwrap();
        context.profile.security_profile = SecurityProfile::Production;
        let config = RyukiConfig {
            auth_mode: AuthMode::StaticDryRun,
            ..RyukiConfig::default()
        };

        let error = context
            .validate_runtime_bindings(&config, true, fixed_now())
            .unwrap_err();

        assert!(error.contains("cannot both select authority"));
        assert!(!error.contains("sealed production-boundary proof"));
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
    fn typed_authenticator_runtime_binding_route_rejects_profile_relabeling() {
        let reference = ReferenceBinding {
            locator: "bindings/authenticator-runtime-test.json".into(),
            digest: raw_digest(b"typed authenticator route fixture"),
            artifact_kind: Some("authenticator-runtime-binding".into()),
            document_id: Some("authenticator-runtime-binding:runtime-test".into()),
            document_version: Some(1),
        };
        let document = genuine_authenticator_runtime_binding_document();
        assert!(validate_typed_reference_document(&reference, &document).is_ok());

        let mut relabeled = document;
        relabeled["credential_paths"][0]["credential_profile"]["token_profile"] =
            json!("oidc-id-token");
        relabeled["credential_paths"][0]["credential_profile"]["carrier"] = json!("oauth-callback");
        relabeled["credential_paths"][0]["credential_profile"]["proof_binding"] =
            json!("pkce-s256");
        assert!(validate_typed_reference_document(&reference, &relabeled).is_err());
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
    fn closure_reference_aliases_enter_the_recursive_reference_graph() {
        for (identity_field, identity, digest_field, kind) in [
            (
                "bundle_id",
                "conformance-bundle:fixture",
                "bundle_digest",
                "conformance-bundle",
            ),
            (
                "receipt_id",
                "package-exit-receipt:fixture",
                "receipt_digest",
                "package-exit-receipt",
            ),
            (
                "document_id",
                "control-trace:fixture",
                "ledger_digest",
                "control-trace",
            ),
        ] {
            let mut object = Map::new();
            object.insert("artifact_kind".into(), json!(kind));
            object.insert(identity_field.into(), json!(identity));
            object.insert("document_version".into(), json!(1));
            object.insert(
                digest_field.into(),
                json!(format!("sha256:{}", "a".repeat(64))),
            );
            object.insert(
                "artifact_locator".into(),
                json!(format!("closure/{kind}.json")),
            );

            let reference = reference_binding_from_object(&object)
                .expect("closure locator and digest must form a recursive reference");
            assert_eq!(reference.document_id.as_deref(), Some(identity));
            assert_eq!(reference.artifact_kind.as_deref(), Some(kind));
            assert_eq!(reference.document_version, Some(1));
        }
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
    fn wide_unique_references_are_bounded_by_loaded_documents() {
        let temp = TempDir::new().unwrap();
        let mut bindings = Vec::new();
        for index in 0..=MAX_DOCUMENTS {
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
            .contains("referenced documents"));
    }

    #[test]
    fn json_shape_limits_apply_before_schema_validation() {
        let above_legacy_limit = Value::Array(vec![Value::Null; 4_097]);
        assert!(parse_json_strict(&serde_json::to_vec(&above_legacy_limit).unwrap()).is_ok());

        let maximum = Value::Array(vec![Value::Null; MAX_JSON_ARRAY_ITEMS]);
        assert!(parse_json_strict(&serde_json::to_vec(&maximum).unwrap()).is_ok());

        let oversized = Value::Array(vec![Value::Null; MAX_JSON_ARRAY_ITEMS + 1]);
        let bytes = serde_json::to_vec(&oversized).unwrap();
        assert!(parse_json_strict(&bytes)
            .unwrap_err()
            .to_string()
            .contains("JSON array length"));
    }
}
