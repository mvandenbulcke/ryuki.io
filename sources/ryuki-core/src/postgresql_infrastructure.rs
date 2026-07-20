//! Pure verification for independently observed PostgreSQL infrastructure.
//!
//! A database connection can report useful local facts, but it cannot prove
//! which provider control plane, cluster identity, or durable volumes back the
//! endpoint it reached. This module closes that authority gap without doing
//! any network or database I/O. It creates one canonical nonce-bound request
//! and accepts only a short-lived, domain-separated Ed25519 response from an
//! independently pinned PostgreSQL infrastructure authority.
//!
//! The request commits to the exact receipt-bound `durable-postgresql` value
//! and to a caller-measured PostgreSQL backend session. The response must carry
//! that complete session preimage, the complete database-identity preimage,
//! and the strictly ordered durable-storage preimages. The verifier recomputes
//! every digest before minting a non-cloneable proof.

use std::fmt;
use std::net::IpAddr;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::conformance_trust::{
    ConformanceTrustedTimeWindow, canonical_json_bytes, parse_json_strict,
};
use crate::security_profile::{
    POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_ID_PREFIX, PostgresqlDatabaseIdentity,
    PostgresqlStorageBinding, ProductionDatabaseProvider, postgresql_database_identity_digest,
    postgresql_storage_binding_digest, valid_canonical_scoped_id,
};

pub const POSTGRESQL_INFRASTRUCTURE_PROTOCOL_VERSION: &str = "1.0.0";
pub const POSTGRESQL_INFRASTRUCTURE_REQUEST_DOMAIN: &str =
    "ryuki-v1/postgresql-infrastructure-attestation-request";
pub const POSTGRESQL_INFRASTRUCTURE_RESPONSE_DOMAIN: &str =
    "ryuki-v1/postgresql-infrastructure-attestation-response";
pub const POSTGRESQL_SESSION_BINDING_DIGEST_CONTRACT: &str = "ryuki-postgresql-session-binding-v1";
pub const POSTGRESQL_TLS_CHANNEL_BINDING_DIGEST_CONTRACT: &str =
    "ryuki-postgresql-tls-channel-binding-v1";
pub const POSTGRESQL_TLS_EXPORTER_LABEL: &[u8] =
    b"EXPORTER-ryuki-postgresql-migration-direct-session-v1";
pub const POSTGRESQL_TLS_CHANNEL_VERIFICATION_METHOD: &str =
    "provider-tls-endpoint-exporter-direct-session-v1";
pub const MAX_POSTGRESQL_INFRASTRUCTURE_REQUEST_BYTES: usize = 32 * 1024;
pub const MAX_POSTGRESQL_INFRASTRUCTURE_RESPONSE_BYTES: usize = 64 * 1024;

const REQUEST_KIND: &str = "postgresql-infrastructure-attestation-request";
const RESPONSE_KIND: &str = "postgresql-infrastructure-attestation-response";
const REQUEST_OPERATION: &str = "attest_postgresql_infrastructure";
const CANONICALIZATION: &str = "ryuki-canonical-json-v1";
const SIGNATURE_ALGORITHM: &str = "ed25519";
const GUARD_ID: &str = "durable-postgresql";
const MEASUREMENT_METHOD: &str = "provider-control-plane-postgresql-direct-session-v1";
const MAX_ATTESTATION_LIFETIME_SECONDS: i64 = 300;
const MAX_SESSION_AGE_SECONDS: i64 = 300;
const MAX_JSON_DEPTH: usize = 16;
const MAX_JSON_NODES: usize = 1024;
const MAX_JSON_COLLECTION_ITEMS: usize = 128;
const MAX_JSON_STRING_BYTES: usize = 4096;
const MAX_EXACT_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const REQUEST_TAG_PREFIX: &str = "ryuki-pg-attest-";
const AUTHORITY_ID_PREFIX: &str = "postgresql-infrastructure-attestation-authority:";
const AUTHORITY_KEY_ID_PREFIX: &str = "postgresql-infrastructure-attestation-key:";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PostgresqlInfrastructureError {
    #[error("invalid PostgreSQL infrastructure attestation: {0}")]
    Invalid(String),
    #[error("PostgreSQL infrastructure authority signature verification failed")]
    SignatureVerificationFailed,
}

/// Independent deployment-time pins for the PostgreSQL infrastructure
/// authority and its exact approved measurement profile.
#[derive(Debug, Clone, Copy)]
pub struct PostgresqlInfrastructureAuthorityAnchor<'a> {
    pub authority_id: &'a str,
    pub key_id: &'a str,
    pub public_key: &'a [u8; 32],
    pub public_key_fingerprint: &'a str,
    pub minimum_authority_epoch: u64,
    pub attestation_profile_id: &'a str,
    pub attestation_profile_version: u64,
    pub attestation_profile_digest: &'a str,
}

/// Exact SQL-visible and independently observable identity of the migration
/// backend session selected for one attestation request.
///
/// `application_name` is the nonce-derived request tag returned by
/// [`postgresql_attestation_request_tag`]. Raw connection strings and secrets
/// are deliberately absent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PostgresqlTlsChannelBinding {
    pub provider_route_binding_digest: String,
    pub server_name: String,
    pub peer_address: String,
    pub peer_port: u16,
    pub trust_anchor_bundle_digest: String,
    pub peer_leaf_certificate_digest: String,
    pub peer_certificate_chain_digest: String,
    pub exporter_digest: String,
    pub tls_protocol: String,
    pub tls_cipher_suite: String,
    pub tls_cipher_bits: u16,
}

/// Computes the digest of the exact caller-observed TLS channel preimage.
pub fn postgresql_tls_channel_binding_digest(
    binding: &PostgresqlTlsChannelBinding,
) -> Result<String, PostgresqlInfrastructureError> {
    validate_tls_channel_binding(binding)?;
    let value = serde_json::json!({
        "digest_contract": POSTGRESQL_TLS_CHANNEL_BINDING_DIGEST_CONTRACT,
        "tls_channel_binding": binding,
    });
    let canonical = canonical_json_bytes(&value).map_err(|error| {
        invalid(format!(
            "TLS channel binding canonicalization failed: {error}"
        ))
    })?;
    Ok(sha256_digest(&canonical))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PostgresqlSessionBinding {
    pub application_name: String,
    pub database_name: String,
    pub database_oid: u32,
    pub datid: u32,
    pub server_address: String,
    pub server_port: u16,
    pub server_major_version: u16,
    pub primary: bool,
    pub transaction_writable: bool,
    pub default_transaction_writable: bool,
    pub client_address: String,
    pub client_port: u16,
    pub backend_process_id: u32,
    pub backend_start: DateTime<Utc>,
    pub backend_type: String,
    pub session_login_role: String,
    pub session_user_oid: u32,
    pub current_role: String,
    pub selected_role: String,
    pub tls_enabled: bool,
    pub tls_protocol: String,
    pub tls_cipher_suite: String,
    pub tls_cipher_bits: u16,
    pub client_distinguished_name: Option<String>,
    pub issuer_distinguished_name: Option<String>,
    pub tls_channel_binding: PostgresqlTlsChannelBinding,
}

/// Exact semantic, workload, guard, and receipt-bound facts selected by the
/// caller. The session preimage is retained only by the one-shot request; the
/// canonical request sent to the authority carries its digest and request tag.
#[derive(Debug, Clone, Copy)]
pub struct ExpectedPostgresqlInfrastructure<'a> {
    pub deployment_id: &'a str,
    pub trust_domain_id: &'a str,
    pub workload_id: &'a str,
    pub source_revision: &'a str,
    pub artifact_digest: &'a str,
    pub workload_instance_binding_digest: &'a str,
    pub requirement_digest: &'a str,
    pub challenge_binding_digest: &'a str,
    pub database_provider: ProductionDatabaseProvider,
    pub server_major_version: u16,
    pub provider_route_binding_digest: &'a str,
    pub database_identity_digest: &'a str,
    pub storage_binding_digest: &'a str,
    pub migration_inventory_digest: &'a str,
    pub application_role: &'a str,
    pub migration_role: &'a str,
    pub session_binding: &'a PostgresqlSessionBinding,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AttestationNamespace {
    deployment_id: String,
    trust_domain_id: String,
    workload_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct WorkloadBinding {
    source_revision: String,
    artifact_digest: String,
    workload_instance_binding_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct GuardBinding {
    guard_id: String,
    requirement_digest: String,
    challenge_binding_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AttestationProfileBinding {
    profile_id: String,
    profile_version: u64,
    content_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ExpectedInfrastructureBinding {
    database_provider: ProductionDatabaseProvider,
    server_major_version: u16,
    provider_route_binding_digest: String,
    database_identity_digest: String,
    storage_binding_digest: String,
    migration_inventory_digest: String,
    application_role: String,
    migration_role: String,
    session_request_tag: String,
    session_binding_digest: String,
    tls_channel_binding_digest: String,
}

/// Opaque canonical request consumed by exactly one verification attempt.
pub struct PostgresqlInfrastructureAttestationRequest {
    canonical_bytes: Box<[u8]>,
    digest: String,
    nonce: String,
    requested_at: DateTime<Utc>,
    authority_id: String,
    authority_key_id: String,
    namespace: AttestationNamespace,
    workload: WorkloadBinding,
    guard: GuardBinding,
    profile: AttestationProfileBinding,
    expected: ExpectedInfrastructureBinding,
    session_binding: PostgresqlSessionBinding,
}

impl fmt::Debug for PostgresqlInfrastructureAttestationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresqlInfrastructureAttestationRequest")
            .field("digest", &self.digest)
            .field("requested_at", &self.requested_at)
            .field("request_tag", &self.expected.session_request_tag)
            .field("byte_len", &self.canonical_bytes.len())
            .finish_non_exhaustive()
    }
}

impl PostgresqlInfrastructureAttestationRequest {
    pub fn as_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn request_tag(&self) -> &str {
        &self.expected.session_request_tag
    }

    pub fn session_binding_digest(&self) -> &str {
        &self.expected.session_binding_digest
    }
}

/// Derives the bounded PostgreSQL `application_name` used to correlate one
/// live backend session with one fresh request nonce.
pub fn postgresql_attestation_request_tag(
    request_nonce: &[u8; 32],
    tls_channel_binding_digest: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(POSTGRESQL_INFRASTRUCTURE_REQUEST_DOMAIN.as_bytes());
    hasher.update(request_nonce);
    hasher.update(tls_channel_binding_digest.as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    format!("{REQUEST_TAG_PREFIX}{}", &digest[..40])
}

/// Computes the digest of the exact PostgreSQL session-binding preimage.
pub fn postgresql_session_binding_digest(
    binding: &PostgresqlSessionBinding,
) -> Result<String, PostgresqlInfrastructureError> {
    validate_session_binding(binding)?;
    let value = serde_json::json!({
        "digest_contract": POSTGRESQL_SESSION_BINDING_DIGEST_CONTRACT,
        "session_binding": binding,
    });
    let canonical = canonical_json_bytes(&value)
        .map_err(|error| invalid(format!("session binding canonicalization failed: {error}")))?;
    Ok(sha256_digest(&canonical))
}

/// Creates one bounded canonical request. The nonce must be freshly generated
/// by an operating-system CSPRNG and must not be reused for a retry.
pub fn build_postgresql_infrastructure_attestation_request(
    expected: ExpectedPostgresqlInfrastructure<'_>,
    authority: PostgresqlInfrastructureAuthorityAnchor<'_>,
    request_nonce: [u8; 32],
    requested_at: DateTime<Utc>,
) -> Result<PostgresqlInfrastructureAttestationRequest, PostgresqlInfrastructureError> {
    validate_authority(authority)?;
    validate_expected(expected)?;
    if request_nonce.iter().all(|byte| *byte == 0) {
        return Err(invalid("request nonce cannot be all zero"));
    }
    let tls_channel_binding_digest =
        postgresql_tls_channel_binding_digest(&expected.session_binding.tls_channel_binding)?;
    let request_tag =
        postgresql_attestation_request_tag(&request_nonce, &tls_channel_binding_digest);
    if expected.session_binding.application_name != request_tag {
        return Err(invalid(
            "PostgreSQL session application_name differs from the nonce-derived request tag",
        ));
    }
    if expected.session_binding.backend_start > requested_at
        || requested_at.signed_duration_since(expected.session_binding.backend_start)
            > TimeDelta::seconds(MAX_SESSION_AGE_SECONDS)
    {
        return Err(invalid(
            "PostgreSQL backend session start is after or too far before the attestation request",
        ));
    }

    let nonce = BASE64_STANDARD.encode(request_nonce);
    let namespace = AttestationNamespace {
        deployment_id: expected.deployment_id.to_owned(),
        trust_domain_id: expected.trust_domain_id.to_owned(),
        workload_id: expected.workload_id.to_owned(),
    };
    let workload = WorkloadBinding {
        source_revision: expected.source_revision.to_owned(),
        artifact_digest: expected.artifact_digest.to_owned(),
        workload_instance_binding_digest: expected.workload_instance_binding_digest.to_owned(),
    };
    let guard = GuardBinding {
        guard_id: GUARD_ID.to_owned(),
        requirement_digest: expected.requirement_digest.to_owned(),
        challenge_binding_digest: expected.challenge_binding_digest.to_owned(),
    };
    let profile = AttestationProfileBinding {
        profile_id: authority.attestation_profile_id.to_owned(),
        profile_version: authority.attestation_profile_version,
        content_digest: authority.attestation_profile_digest.to_owned(),
    };
    let expected_binding = ExpectedInfrastructureBinding {
        database_provider: expected.database_provider,
        server_major_version: expected.server_major_version,
        provider_route_binding_digest: expected.provider_route_binding_digest.to_owned(),
        database_identity_digest: expected.database_identity_digest.to_owned(),
        storage_binding_digest: expected.storage_binding_digest.to_owned(),
        migration_inventory_digest: expected.migration_inventory_digest.to_owned(),
        application_role: expected.application_role.to_owned(),
        migration_role: expected.migration_role.to_owned(),
        session_request_tag: request_tag,
        session_binding_digest: postgresql_session_binding_digest(expected.session_binding)?,
        tls_channel_binding_digest,
    };
    let value = serde_json::json!({
        "schema_version": POSTGRESQL_INFRASTRUCTURE_PROTOCOL_VERSION,
        "contract_kind": REQUEST_KIND,
        "operation": REQUEST_OPERATION,
        "canonicalization": CANONICALIZATION,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "authority_id": authority.authority_id,
        "authority_key_id": authority.key_id,
        "namespace": namespace,
        "workload": workload,
        "guard": guard,
        "attestation_profile": profile,
        "expected": expected_binding,
        "caller_session_binding": expected.session_binding,
        "request_nonce": nonce,
        "requested_at": requested_at,
    });
    let canonical_bytes = canonical_json_bytes(&value)
        .map_err(|error| invalid(format!("request canonicalization failed: {error}")))?;
    if canonical_bytes.is_empty()
        || canonical_bytes.len() > MAX_POSTGRESQL_INFRASTRUCTURE_REQUEST_BYTES
    {
        return Err(invalid("request is empty or exceeds 32 KiB"));
    }
    let digest = sha256_digest(&canonical_bytes);

    Ok(PostgresqlInfrastructureAttestationRequest {
        canonical_bytes: canonical_bytes.into_boxed_slice(),
        digest,
        nonce,
        requested_at,
        authority_id: authority.authority_id.to_owned(),
        authority_key_id: authority.key_id.to_owned(),
        namespace,
        workload,
        guard,
        profile,
        expected: expected_binding,
        session_binding: expected.session_binding.clone(),
    })
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AttestationResponse {
    schema_version: String,
    contract_kind: String,
    canonicalization: String,
    signature_algorithm: String,
    authority: ResponseAuthority,
    request_nonce: String,
    request_digest: String,
    namespace: AttestationNamespace,
    workload: WorkloadBinding,
    guard: GuardBinding,
    attestation_profile: AttestationProfileBinding,
    expected: ExpectedInfrastructureBinding,
    outcome: String,
    measurement: PostgresqlInfrastructureMeasurement,
    #[serde(rename = "signature_base64")]
    _signature_base64: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ResponseAuthority {
    authority_id: String,
    key_id: String,
    public_key_fingerprint: String,
    authority_epoch: u64,
    authority_revision: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PostgresqlInfrastructureMeasurement {
    sequence: u64,
    method: String,
    tls_channel_verification_method: String,
    observed_at: TrustedTimeInterval,
    valid_until: DateTime<Utc>,
    restored_state_reconciled: bool,
    session_binding: PostgresqlSessionBinding,
    session_binding_digest: String,
    provider_route_binding_digest: String,
    tls_channel_binding_digest: String,
    database_identity: PostgresqlDatabaseIdentity,
    database_identity_digest: String,
    provider_cluster_uid_digest: String,
    storage_bindings: Vec<PostgresqlStorageBinding>,
    storage_binding_digest: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TrustedTimeInterval {
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

/// Opaque proof that the independently pinned authority freshly observed the
/// exact PostgreSQL backend session, provider target, database identity, and
/// durable storage selected by one final workload-bound guard challenge.
///
/// ```compile_fail
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<
///     ryuki_core::postgresql_infrastructure::VerifiedPostgresqlInfrastructureAttestation,
/// >();
/// ```
pub struct VerifiedPostgresqlInfrastructureAttestation {
    raw_response: Box<[u8]>,
    response_digest: String,
    authority_public_key: [u8; 32],
    response: AttestationResponse,
}

impl fmt::Debug for VerifiedPostgresqlInfrastructureAttestation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedPostgresqlInfrastructureAttestation")
            .field("response_digest", &self.response_digest)
            .field("deployment_id", &self.response.namespace.deployment_id)
            .field("workload_id", &self.response.namespace.workload_id)
            .field("authority_id", &self.response.authority.authority_id)
            .field("authority_epoch", &self.response.authority.authority_epoch)
            .field(
                "authority_revision",
                &self.response.authority.authority_revision,
            )
            .field("measurement_sequence", &self.response.measurement.sequence)
            .field("valid_until", &self.response.measurement.valid_until)
            .field(
                "storage_binding_count",
                &self.response.measurement.storage_bindings.len(),
            )
            .field("byte_len", &self.raw_response.len())
            .finish()
    }
}

impl VerifiedPostgresqlInfrastructureAttestation {
    /// Reparses and rehashes the retained exact response, verifies its original
    /// Ed25519 signature, and recomputes every typed preimage digest.
    pub fn verify_integrity(&self) -> Result<(), PostgresqlInfrastructureError> {
        if sha256_digest(&self.raw_response) != self.response_digest {
            return Err(invalid("retained PostgreSQL attestation bytes changed"));
        }
        let value = parse_and_validate_response_json(&self.raw_response)?;
        verify_response_signature_with_key(&value, &self.authority_public_key)?;
        let response: AttestationResponse = serde_json::from_value(value)
            .map_err(|error| invalid(format!("response typed decoding failed: {error}")))?;
        if response != self.response {
            return Err(invalid(
                "retained PostgreSQL attestation projection changed",
            ));
        }
        validate_self_consistent_response(&response, &self.authority_public_key)
    }

    pub fn ensure_fresh(
        &self,
        trusted_now: ConformanceTrustedTimeWindow,
    ) -> Result<(), PostgresqlInfrastructureError> {
        if trusted_now.not_before > trusted_now.not_after
            || self.response.measurement.observed_at.not_after > trusted_now.not_before
            || trusted_now.not_after >= self.response.measurement.valid_until
        {
            return Err(invalid(
                "verified PostgreSQL infrastructure measurement is stale at the startup fence",
            ));
        }
        Ok(())
    }

    pub fn response_digest(&self) -> &str {
        &self.response_digest
    }

    pub fn deployment_id(&self) -> &str {
        &self.response.namespace.deployment_id
    }

    pub fn trust_domain_id(&self) -> &str {
        &self.response.namespace.trust_domain_id
    }

    pub fn workload_id(&self) -> &str {
        &self.response.namespace.workload_id
    }

    pub fn source_revision(&self) -> &str {
        &self.response.workload.source_revision
    }

    pub fn artifact_digest(&self) -> &str {
        &self.response.workload.artifact_digest
    }

    pub fn workload_instance_binding_digest(&self) -> &str {
        &self.response.workload.workload_instance_binding_digest
    }

    pub fn authority_id(&self) -> &str {
        &self.response.authority.authority_id
    }

    pub fn authority_key_id(&self) -> &str {
        &self.response.authority.key_id
    }

    pub fn authority_public_key_fingerprint(&self) -> &str {
        &self.response.authority.public_key_fingerprint
    }

    pub fn authority_epoch(&self) -> u64 {
        self.response.authority.authority_epoch
    }

    pub fn authority_revision(&self) -> u64 {
        self.response.authority.authority_revision
    }

    pub fn attestation_profile_id(&self) -> &str {
        &self.response.attestation_profile.profile_id
    }

    pub fn attestation_profile_version(&self) -> u64 {
        self.response.attestation_profile.profile_version
    }

    pub fn attestation_profile_digest(&self) -> &str {
        &self.response.attestation_profile.content_digest
    }

    pub fn measurement_sequence(&self) -> u64 {
        self.response.measurement.sequence
    }

    pub fn observed_at_not_before(&self) -> DateTime<Utc> {
        self.response.measurement.observed_at.not_before
    }

    pub fn observed_at_not_after(&self) -> DateTime<Utc> {
        self.response.measurement.observed_at.not_after
    }

    pub fn valid_until(&self) -> DateTime<Utc> {
        self.response.measurement.valid_until
    }

    pub fn requirement_digest(&self) -> &str {
        &self.response.guard.requirement_digest
    }

    pub fn challenge_binding_digest(&self) -> &str {
        &self.response.guard.challenge_binding_digest
    }

    pub fn database_provider(&self) -> ProductionDatabaseProvider {
        self.response.expected.database_provider
    }

    pub fn server_major_version(&self) -> u16 {
        self.response.expected.server_major_version
    }

    pub fn provider_route_binding_digest(&self) -> &str {
        &self.response.expected.provider_route_binding_digest
    }

    pub fn tls_channel_binding_digest(&self) -> &str {
        &self.response.expected.tls_channel_binding_digest
    }

    pub fn database_identity_digest(&self) -> &str {
        &self.response.expected.database_identity_digest
    }

    pub fn storage_binding_digest(&self) -> &str {
        &self.response.expected.storage_binding_digest
    }

    pub fn migration_inventory_digest(&self) -> &str {
        &self.response.expected.migration_inventory_digest
    }

    pub fn application_role(&self) -> &str {
        &self.response.expected.application_role
    }

    pub fn migration_role(&self) -> &str {
        &self.response.expected.migration_role
    }

    pub fn request_tag(&self) -> &str {
        &self.response.expected.session_request_tag
    }

    pub fn session_binding_digest(&self) -> &str {
        &self.response.expected.session_binding_digest
    }

    pub fn session_binding(&self) -> &PostgresqlSessionBinding {
        &self.response.measurement.session_binding
    }

    pub fn database_identity(&self) -> &PostgresqlDatabaseIdentity {
        &self.response.measurement.database_identity
    }

    pub fn storage_bindings(&self) -> &[PostgresqlStorageBinding] {
        &self.response.measurement.storage_bindings
    }

    pub fn provider_cluster_uid_digest(&self) -> &str {
        &self.response.measurement.provider_cluster_uid_digest
    }
}

/// Verifies and consumes one request against one exact signed response.
pub fn verify_postgresql_infrastructure_attestation(
    request: PostgresqlInfrastructureAttestationRequest,
    raw_response: &[u8],
    authority: PostgresqlInfrastructureAuthorityAnchor<'_>,
    trusted_now: ConformanceTrustedTimeWindow,
) -> Result<VerifiedPostgresqlInfrastructureAttestation, PostgresqlInfrastructureError> {
    validate_authority(authority)?;
    if request.authority_id != authority.authority_id
        || request.authority_key_id != authority.key_id
        || request.profile.profile_id != authority.attestation_profile_id
        || request.profile.profile_version != authority.attestation_profile_version
        || request.profile.content_digest != authority.attestation_profile_digest
        || sha256_digest(request.as_bytes()) != request.digest
    {
        return Err(invalid(
            "request was not produced for this authority and attestation profile",
        ));
    }
    if trusted_now.not_before > trusted_now.not_after {
        return Err(invalid("trusted local time interval is inverted"));
    }
    if raw_response.is_empty() || raw_response.len() > MAX_POSTGRESQL_INFRASTRUCTURE_RESPONSE_BYTES
    {
        return Err(invalid("response is empty or exceeds 64 KiB"));
    }

    let value = parse_and_validate_response_json(raw_response)?;
    verify_response_signature(&value, authority)?;
    let response: AttestationResponse = serde_json::from_value(value)
        .map_err(|error| invalid(format!("response typed decoding failed: {error}")))?;

    if response.schema_version != POSTGRESQL_INFRASTRUCTURE_PROTOCOL_VERSION
        || response.contract_kind != RESPONSE_KIND
        || response.canonicalization != CANONICALIZATION
        || response.signature_algorithm != SIGNATURE_ALGORITHM
        || response.authority.authority_id != authority.authority_id
        || response.authority.key_id != authority.key_id
        || response.authority.public_key_fingerprint != authority.public_key_fingerprint
        || response.request_nonce != request.nonce
        || response.request_digest != request.digest
        || response.namespace != request.namespace
        || response.workload != request.workload
        || response.guard != request.guard
        || response.attestation_profile != request.profile
        || response.expected != request.expected
        || response.outcome != "matched"
        || response.measurement.method != MEASUREMENT_METHOD
        || response.measurement.tls_channel_verification_method
            != POSTGRESQL_TLS_CHANNEL_VERIFICATION_METHOD
        || !response.measurement.restored_state_reconciled
    {
        return Err(invalid(
            "response authority, request echo, bindings, expected value, or matched state differs",
        ));
    }
    if response.measurement.session_binding != request.session_binding {
        return Err(invalid(
            "independently observed PostgreSQL session differs from the exact caller session",
        ));
    }
    if !valid_counter(response.authority.authority_epoch)
        || response.authority.authority_epoch < authority.minimum_authority_epoch
        || !valid_counter(response.authority.authority_revision)
        || !valid_counter(response.measurement.sequence)
    {
        return Err(invalid(
            "response authority epoch, revision, or measurement sequence is invalid",
        ));
    }

    validate_self_consistent_response(&response, authority.public_key)?;
    let observed = &response.measurement.observed_at;
    if request.requested_at > observed.not_before
        || observed.not_before > observed.not_after
        || observed.not_after > trusted_now.not_before
        || trusted_now.not_after >= response.measurement.valid_until
        || response.measurement.valid_until <= observed.not_after
        || response
            .measurement
            .valid_until
            .signed_duration_since(observed.not_before)
            > TimeDelta::seconds(MAX_ATTESTATION_LIFETIME_SECONDS)
    {
        return Err(invalid(
            "response observation interval or exclusive freshness bound is invalid",
        ));
    }

    Ok(VerifiedPostgresqlInfrastructureAttestation {
        raw_response: raw_response.to_vec().into_boxed_slice(),
        response_digest: sha256_digest(raw_response),
        authority_public_key: *authority.public_key,
        response,
    })
}

fn validate_authority(
    authority: PostgresqlInfrastructureAuthorityAnchor<'_>,
) -> Result<(), PostgresqlInfrastructureError> {
    if !valid_attestation_scoped_id(authority.authority_id, AUTHORITY_ID_PREFIX)
        || !valid_attestation_scoped_id(authority.key_id, AUTHORITY_KEY_ID_PREFIX)
        || !valid_canonical_scoped_id(
            authority.attestation_profile_id,
            POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_ID_PREFIX,
        )
        || !valid_counter(authority.minimum_authority_epoch)
        || !valid_counter(authority.attestation_profile_version)
        || !is_digest(authority.public_key_fingerprint)
        || !is_digest(authority.attestation_profile_digest)
    {
        return Err(invalid(
            "invalid independent PostgreSQL infrastructure authority anchor",
        ));
    }
    if sha256_digest(authority.public_key) != authority.public_key_fingerprint {
        return Err(invalid(
            "PostgreSQL infrastructure authority key differs from its fingerprint pin",
        ));
    }
    let key = VerifyingKey::from_bytes(authority.public_key)
        .map_err(|_| invalid("invalid PostgreSQL infrastructure authority Ed25519 key"))?;
    if key.is_weak() {
        return Err(invalid(
            "weak PostgreSQL infrastructure authority Ed25519 key",
        ));
    }
    Ok(())
}

fn validate_expected(
    expected: ExpectedPostgresqlInfrastructure<'_>,
) -> Result<(), PostgresqlInfrastructureError> {
    if !valid_canonical_scoped_id(expected.deployment_id, "deployment:")
        || !valid_canonical_scoped_id(expected.trust_domain_id, "trust-domain:")
        || !valid_canonical_scoped_id(expected.workload_id, "workload:")
        || !valid_source_revision(expected.source_revision)
    {
        return Err(invalid(
            "invalid expected PostgreSQL namespace or source revision",
        ));
    }
    for (label, value) in [
        ("artifact", expected.artifact_digest),
        (
            "workload instance binding",
            expected.workload_instance_binding_digest,
        ),
        ("guard requirement", expected.requirement_digest),
        ("guard challenge", expected.challenge_binding_digest),
        (
            "provider route binding",
            expected.provider_route_binding_digest,
        ),
        ("database identity", expected.database_identity_digest),
        ("storage binding", expected.storage_binding_digest),
        ("migration inventory", expected.migration_inventory_digest),
    ] {
        require_digest(label, value)?;
    }
    if expected.requirement_digest == expected.challenge_binding_digest {
        return Err(invalid(
            "guard requirement and workload challenge bindings cannot collapse",
        ));
    }
    if expected.server_major_version != 18
        || !valid_postgresql_identifier(expected.application_role)
        || !valid_postgresql_identifier(expected.migration_role)
        || expected.application_role == "postgres"
        || expected.migration_role == "postgres"
        || expected.application_role == expected.migration_role
    {
        return Err(invalid(
            "expected PostgreSQL major version or role separation is invalid",
        ));
    }
    validate_session_binding(expected.session_binding)?;
    if expected.session_binding.server_major_version != expected.server_major_version
        || expected
            .session_binding
            .tls_channel_binding
            .provider_route_binding_digest
            != expected.provider_route_binding_digest
        || expected.session_binding.current_role != expected.migration_role
        || expected.session_binding.selected_role != expected.migration_role
        || expected.session_binding.session_login_role == expected.application_role
        || expected.session_binding.session_login_role == expected.migration_role
        || expected.session_binding.session_login_role == "postgres"
    {
        return Err(invalid(
            "PostgreSQL session does not satisfy the receipt-bound route and migration-role contract",
        ));
    }
    Ok(())
}

fn validate_expected_binding(
    expected: &ExpectedInfrastructureBinding,
) -> Result<(), PostgresqlInfrastructureError> {
    if expected.server_major_version != 18
        || !valid_postgresql_identifier(&expected.application_role)
        || !valid_postgresql_identifier(&expected.migration_role)
        || expected.application_role == "postgres"
        || expected.migration_role == "postgres"
        || expected.application_role == expected.migration_role
        || !valid_request_tag(&expected.session_request_tag)
    {
        return Err(invalid(
            "response expected PostgreSQL major version, roles, or request tag is invalid",
        ));
    }
    for (label, value) in [
        (
            "database identity",
            expected.database_identity_digest.as_str(),
        ),
        ("storage binding", expected.storage_binding_digest.as_str()),
        (
            "migration inventory",
            expected.migration_inventory_digest.as_str(),
        ),
        (
            "provider route binding",
            expected.provider_route_binding_digest.as_str(),
        ),
        ("session binding", expected.session_binding_digest.as_str()),
        (
            "TLS channel binding",
            expected.tls_channel_binding_digest.as_str(),
        ),
    ] {
        require_digest(label, value)?;
    }
    Ok(())
}

fn validate_session_binding(
    binding: &PostgresqlSessionBinding,
) -> Result<(), PostgresqlInfrastructureError> {
    let canonical_server_address = binding
        .server_address
        .parse::<IpAddr>()
        .is_ok_and(|address| address.to_string() == binding.server_address);
    let canonical_client_address = binding
        .client_address
        .parse::<IpAddr>()
        .is_ok_and(|address| address.to_string() == binding.client_address);
    validate_tls_channel_binding(&binding.tls_channel_binding)?;
    if !valid_request_tag(&binding.application_name)
        || !valid_postgresql_identifier(&binding.database_name)
        || binding.database_name == "postgres"
        || binding.database_oid == 0
        || binding.datid != binding.database_oid
        || !canonical_server_address
        || binding.server_port == 0
        || binding.server_major_version != 18
        || !binding.primary
        || !binding.transaction_writable
        || !binding.default_transaction_writable
        || !canonical_client_address
        || binding.client_port == 0
        || binding.backend_process_id == 0
        || binding.backend_type != "client backend"
        || !valid_postgresql_identifier(&binding.session_login_role)
        || binding.session_login_role == "postgres"
        || binding.session_user_oid == 0
        || !valid_postgresql_identifier(&binding.current_role)
        || !valid_postgresql_identifier(&binding.selected_role)
        || binding.current_role != binding.selected_role
        || binding.session_login_role == binding.selected_role
        || !binding.tls_enabled
        || !matches!(binding.tls_protocol.as_str(), "tlsv1.2" | "tlsv1.3")
        || !valid_runtime_identifier(&binding.tls_cipher_suite)
        || binding.tls_cipher_bits < 128
        || binding.tls_protocol != binding.tls_channel_binding.tls_protocol
        || binding.tls_cipher_suite != binding.tls_channel_binding.tls_cipher_suite
        || binding.tls_cipher_bits != binding.tls_channel_binding.tls_cipher_bits
        || !valid_optional_distinguished_name(binding.client_distinguished_name.as_deref())
        || !valid_optional_distinguished_name(binding.issuer_distinguished_name.as_deref())
        || binding.client_distinguished_name.is_some()
            != binding.issuer_distinguished_name.is_some()
    {
        return Err(invalid(
            "PostgreSQL session binding is incomplete, noncanonical, or unsafe",
        ));
    }
    Ok(())
}

fn validate_tls_channel_binding(
    binding: &PostgresqlTlsChannelBinding,
) -> Result<(), PostgresqlInfrastructureError> {
    let canonical_peer = binding
        .peer_address
        .parse::<IpAddr>()
        .is_ok_and(|address| address.to_string() == binding.peer_address);
    let canonical_dns = !binding.server_name.is_empty()
        && binding.server_name.len() <= 253
        && !binding.server_name.ends_with('.')
        && binding.server_name.split('.').all(|label| {
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
    if !canonical_dns
        || !canonical_peer
        || binding.peer_port == 0
        || !is_digest(&binding.provider_route_binding_digest)
        || !is_digest(&binding.trust_anchor_bundle_digest)
        || !is_digest(&binding.peer_leaf_certificate_digest)
        || !is_digest(&binding.peer_certificate_chain_digest)
        || !is_digest(&binding.exporter_digest)
        || binding.tls_protocol != "tlsv1.3"
        || !valid_runtime_identifier(&binding.tls_cipher_suite)
        || binding.tls_cipher_bits < 128
    {
        return Err(invalid(
            "PostgreSQL TLS channel binding is incomplete, noncanonical, or unsafe",
        ));
    }
    Ok(())
}

fn validate_self_consistent_response(
    response: &AttestationResponse,
    authority_public_key: &[u8; 32],
) -> Result<(), PostgresqlInfrastructureError> {
    if response.schema_version != POSTGRESQL_INFRASTRUCTURE_PROTOCOL_VERSION
        || response.contract_kind != RESPONSE_KIND
        || response.canonicalization != CANONICALIZATION
        || response.signature_algorithm != SIGNATURE_ALGORITHM
        || response.guard.guard_id != GUARD_ID
        || response.outcome != "matched"
        || response.measurement.method != MEASUREMENT_METHOD
        || response.measurement.tls_channel_verification_method
            != POSTGRESQL_TLS_CHANNEL_VERIFICATION_METHOD
        || !response.measurement.restored_state_reconciled
        || !valid_counter(response.authority.authority_epoch)
        || !valid_counter(response.authority.authority_revision)
        || !valid_counter(response.measurement.sequence)
        || sha256_digest(authority_public_key) != response.authority.public_key_fingerprint
    {
        return Err(invalid(
            "retained response protocol, authority, guard, or measurement state is invalid",
        ));
    }
    if !valid_attestation_scoped_id(&response.authority.authority_id, AUTHORITY_ID_PREFIX)
        || !valid_attestation_scoped_id(&response.authority.key_id, AUTHORITY_KEY_ID_PREFIX)
        || !valid_canonical_scoped_id(
            &response.attestation_profile.profile_id,
            POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_ID_PREFIX,
        )
        || !valid_counter(response.attestation_profile.profile_version)
        || !is_digest(&response.attestation_profile.content_digest)
        || !valid_canonical_scoped_id(&response.namespace.deployment_id, "deployment:")
        || !valid_canonical_scoped_id(&response.namespace.trust_domain_id, "trust-domain:")
        || !valid_canonical_scoped_id(&response.namespace.workload_id, "workload:")
        || !valid_source_revision(&response.workload.source_revision)
    {
        return Err(invalid(
            "retained response authority, profile, namespace, or workload is invalid",
        ));
    }
    for (label, value) in [
        ("request", response.request_digest.as_str()),
        ("artifact", response.workload.artifact_digest.as_str()),
        (
            "workload instance binding",
            response.workload.workload_instance_binding_digest.as_str(),
        ),
        (
            "guard requirement",
            response.guard.requirement_digest.as_str(),
        ),
        (
            "guard challenge",
            response.guard.challenge_binding_digest.as_str(),
        ),
    ] {
        require_digest(label, value)?;
    }
    let request_nonce = decode_canonical_base64::<32>(&response.request_nonce, "request nonce")?;
    if request_nonce.iter().all(|byte| *byte == 0)
        || postgresql_attestation_request_tag(
            &request_nonce,
            &response.expected.tls_channel_binding_digest,
        ) != response.expected.session_request_tag
    {
        return Err(invalid(
            "response request nonce does not derive its PostgreSQL session tag",
        ));
    }
    if response.guard.requirement_digest == response.guard.challenge_binding_digest {
        return Err(invalid(
            "guard requirement and workload challenge bindings cannot collapse",
        ));
    }
    validate_expected_binding(&response.expected)?;
    validate_session_binding(&response.measurement.session_binding)?;
    if response.measurement.session_binding.application_name
        != response.expected.session_request_tag
        || response.measurement.session_binding.server_major_version
            != response.expected.server_major_version
        || response.measurement.session_binding.current_role != response.expected.migration_role
        || response.measurement.session_binding.selected_role != response.expected.migration_role
        || response.measurement.session_binding.session_login_role
            == response.expected.application_role
        || response.measurement.session_binding.session_login_role
            == response.expected.migration_role
    {
        return Err(invalid(
            "measured PostgreSQL session differs from the response expected-value binding",
        ));
    }
    let session_digest = postgresql_session_binding_digest(&response.measurement.session_binding)?;
    let tls_channel_digest = postgresql_tls_channel_binding_digest(
        &response.measurement.session_binding.tls_channel_binding,
    )?;
    if session_digest != response.measurement.session_binding_digest
        || session_digest != response.expected.session_binding_digest
        || tls_channel_digest != response.measurement.tls_channel_binding_digest
        || tls_channel_digest != response.expected.tls_channel_binding_digest
        || response.measurement.provider_route_binding_digest
            != response.expected.provider_route_binding_digest
        || response
            .measurement
            .session_binding
            .tls_channel_binding
            .provider_route_binding_digest
            != response.expected.provider_route_binding_digest
    {
        return Err(invalid(
            "measured PostgreSQL session preimage differs from its bound digest",
        ));
    }

    let identity_digest =
        postgresql_database_identity_digest(&response.measurement.database_identity)
            .map_err(|_| invalid("measured PostgreSQL database identity preimage is invalid"))?;
    let identity = &response.measurement.database_identity;
    let session = &response.measurement.session_binding;
    if identity_digest != response.measurement.database_identity_digest
        || identity_digest != response.expected.database_identity_digest
        || identity.deployment_id != response.namespace.deployment_id
        || identity.trust_domain_id != response.namespace.trust_domain_id
        || identity.database_provider != response.expected.database_provider
        || identity.server_major_version != response.expected.server_major_version
        || identity.database_name != session.database_name
        || identity.database_oid != session.database_oid
        || identity.server_address != session.server_address
        || identity.server_port != session.server_port
        || identity.tls_enabled != session.tls_enabled
        || identity.tls_protocol != session.tls_protocol
        || identity.tls_cipher_suite != session.tls_cipher_suite
        || identity.tls_cipher_bits != session.tls_cipher_bits
        || identity.primary != session.primary
        || identity.writable != session.transaction_writable
    {
        return Err(invalid(
            "measured PostgreSQL database identity differs from the session or receipt expectation",
        ));
    }
    let storage_digest = postgresql_storage_binding_digest(&response.measurement.storage_bindings)
        .map_err(|_| invalid("measured PostgreSQL storage preimages are invalid"))?;
    if !is_digest(&response.measurement.provider_cluster_uid_digest)
        || response.measurement.storage_bindings.iter().any(|binding| {
            binding.provider_cluster_uid_digest != response.measurement.provider_cluster_uid_digest
        })
        || storage_digest != response.measurement.storage_binding_digest
        || storage_digest != response.expected.storage_binding_digest
    {
        return Err(invalid(
            "measured PostgreSQL storage preimages differ from the receipt expectation",
        ));
    }

    let observed = &response.measurement.observed_at;
    if response.measurement.session_binding.backend_start > observed.not_before
        || observed
            .not_before
            .signed_duration_since(response.measurement.session_binding.backend_start)
            > TimeDelta::seconds(MAX_SESSION_AGE_SECONDS)
        || observed.not_before > observed.not_after
        || response.measurement.valid_until <= observed.not_after
        || response
            .measurement
            .valid_until
            .signed_duration_since(observed.not_before)
            > TimeDelta::seconds(MAX_ATTESTATION_LIFETIME_SECONDS)
    {
        return Err(invalid(
            "retained PostgreSQL observation interval or lifetime is invalid",
        ));
    }
    Ok(())
}

fn parse_and_validate_response_json(
    raw_response: &[u8],
) -> Result<Value, PostgresqlInfrastructureError> {
    let value = parse_json_strict(raw_response)
        .map_err(|error| invalid(format!("strict response JSON failed: {error}")))?;
    let mut nodes = 0;
    validate_json_shape(&value, 0, &mut nodes)?;
    validate_timestamp_lexemes(&value)?;
    let canonical = canonical_json_bytes(&value)
        .map_err(|error| invalid(format!("response canonicalization failed: {error}")))?;
    if canonical != raw_response {
        return Err(invalid("response is not exact canonical JSON"));
    }
    Ok(value)
}

fn verify_response_signature(
    value: &Value,
    authority: PostgresqlInfrastructureAuthorityAnchor<'_>,
) -> Result<(), PostgresqlInfrastructureError> {
    verify_response_signature_with_key(value, authority.public_key)
}

fn verify_response_signature_with_key(
    value: &Value,
    public_key: &[u8; 32],
) -> Result<(), PostgresqlInfrastructureError> {
    let signature_base64 = value
        .get("signature_base64")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("response omits signature_base64"))?;
    let signature_bytes = decode_canonical_base64::<64>(signature_base64, "response signature")?;
    let signature = Signature::from_bytes(&signature_bytes);

    let mut subject = value.clone();
    subject
        .as_object_mut()
        .ok_or_else(|| invalid("response root is not an object"))?
        .remove("signature_base64");
    let canonical_subject = canonical_json_bytes(&subject)
        .map_err(|error| invalid(format!("response canonicalization failed: {error}")))?;
    let mut signed = Vec::with_capacity(
        16 + POSTGRESQL_INFRASTRUCTURE_RESPONSE_DOMAIN.len() + canonical_subject.len(),
    );
    write_frame(
        &mut signed,
        POSTGRESQL_INFRASTRUCTURE_RESPONSE_DOMAIN.as_bytes(),
    );
    write_frame(&mut signed, &canonical_subject);

    let key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| invalid("invalid PostgreSQL infrastructure authority Ed25519 key"))?;
    key.verify_strict(&signed, &signature)
        .map_err(|_| PostgresqlInfrastructureError::SignatureVerificationFailed)
}

fn validate_timestamp_lexemes(value: &Value) -> Result<(), PostgresqlInfrastructureError> {
    for pointer in [
        "/measurement/observed_at/not_before",
        "/measurement/observed_at/not_after",
        "/measurement/valid_until",
    ] {
        let timestamp = value
            .pointer(pointer)
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(format!("response timestamp {pointer} is missing")))?;
        validate_canonical_timestamp(timestamp, pointer, SecondsFormat::Secs)?;
    }
    let backend_start = value
        .pointer("/measurement/session_binding/backend_start")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("response PostgreSQL backend_start is missing"))?;
    validate_canonical_timestamp(
        backend_start,
        "/measurement/session_binding/backend_start",
        SecondsFormat::AutoSi,
    )
}

fn validate_canonical_timestamp(
    value: &str,
    pointer: &str,
    format: SecondsFormat,
) -> Result<(), PostgresqlInfrastructureError> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| invalid(format!("response timestamp {pointer} is invalid")))?;
    if value.len() > 35 || parsed.to_utc().to_rfc3339_opts(format, true) != value {
        return Err(invalid(format!(
            "response timestamp {pointer} is not canonical UTC RFC3339"
        )));
    }
    Ok(())
}

fn validate_json_shape(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), PostgresqlInfrastructureError> {
    if depth > MAX_JSON_DEPTH {
        return Err(invalid("response JSON exceeds the nesting-depth bound"));
    }
    *nodes = nodes
        .checked_add(1)
        .ok_or_else(|| invalid("response JSON node counter overflowed"))?;
    if *nodes > MAX_JSON_NODES {
        return Err(invalid("response JSON exceeds the node-count bound"));
    }
    match value {
        Value::String(value) if value.len() > MAX_JSON_STRING_BYTES => {
            Err(invalid("response JSON contains an oversized string"))
        }
        Value::Array(values) => {
            if values.len() > MAX_JSON_COLLECTION_ITEMS {
                return Err(invalid("response JSON contains an oversized array"));
            }
            for value in values {
                validate_json_shape(value, depth + 1, nodes)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            if values.len() > MAX_JSON_COLLECTION_ITEMS {
                return Err(invalid("response JSON contains an oversized object"));
            }
            for (key, value) in values {
                if key.len() > MAX_JSON_STRING_BYTES {
                    return Err(invalid("response JSON contains an oversized key"));
                }
                validate_json_shape(value, depth + 1, nodes)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn decode_canonical_base64<const N: usize>(
    value: &str,
    label: &str,
) -> Result<[u8; N], PostgresqlInfrastructureError> {
    let decoded = BASE64_STANDARD
        .decode(value)
        .map_err(|_| invalid(format!("{label} is not valid base64")))?;
    let decoded: [u8; N] = decoded
        .try_into()
        .map_err(|_| invalid(format!("{label} has the wrong decoded length")))?;
    if BASE64_STANDARD.encode(decoded) != value {
        return Err(invalid(format!("{label} is not canonical base64")));
    }
    Ok(decoded)
}

fn write_frame(buffer: &mut Vec<u8>, value: &[u8]) {
    buffer.extend_from_slice(&(value.len() as u64).to_le_bytes());
    buffer.extend_from_slice(value);
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn require_digest(label: &str, value: &str) -> Result<(), PostgresqlInfrastructureError> {
    if is_digest(value) {
        Ok(())
    } else {
        Err(invalid(format!("{label} digest is invalid")))
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value[7..].bytes().any(|byte| byte != b'0')
}

fn valid_counter(value: u64) -> bool {
    value > 0 && value <= MAX_EXACT_JSON_INTEGER
}

fn valid_source_revision(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}

fn valid_attestation_scoped_id(value: &str, prefix: &str) -> bool {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return false;
    };
    (3..=190).contains(&suffix.len())
        && suffix
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && suffix.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
}

fn valid_request_tag(value: &str) -> bool {
    value.len() == REQUEST_TAG_PREFIX.len() + 40
        && value.starts_with(REQUEST_TAG_PREFIX)
        && value[REQUEST_TAG_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_postgresql_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || *byte == b'_')
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

fn valid_runtime_identifier(value: &str) -> bool {
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

fn valid_optional_distinguished_name(value: Option<&str>) -> bool {
    value.is_none_or(|value| {
        !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
    })
}

fn invalid(message: impl Into<String>) -> PostgresqlInfrastructureError {
    PostgresqlInfrastructureError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use chrono::TimeZone;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{Value, json};

    use super::*;
    use crate::security_profile::{
        PostgresqlStoragePurpose, postgresql_database_identity_digest,
        postgresql_storage_binding_digest,
    };

    static TEST_ENTROPY_COUNTER: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        signing_key: SigningKey,
        public_key: [u8; 32],
        public_key_fingerprint: String,
        profile_digest: String,
        requirement_digest: String,
        challenge_binding_digest: String,
        artifact_digest: String,
        workload_instance_binding_digest: String,
        migration_inventory_digest: String,
        provider_route_binding_digest: String,
        nonce: [u8; 32],
        session: PostgresqlSessionBinding,
        identity: PostgresqlDatabaseIdentity,
        identity_digest: String,
        provider_cluster_uid_digest: String,
        storage: Vec<PostgresqlStorageBinding>,
        storage_digest: String,
    }

    impl Fixture {
        fn new() -> Self {
            let signing_key = SigningKey::from_bytes(&test_entropy(b"signing key"));
            let public_key = signing_key.verifying_key().to_bytes();
            let public_key_fingerprint = sha256_digest(&public_key);
            let nonce = test_entropy(b"request nonce");
            let provider_cluster_uid_digest = digest_for(b"provider cluster UID");
            let provider_route_binding_digest = digest_for(b"provider route binding");
            let tls_channel_binding = PostgresqlTlsChannelBinding {
                provider_route_binding_digest: provider_route_binding_digest.clone(),
                server_name: "postgresql.ryuki.test".into(),
                peer_address: "10.20.30.40".into(),
                peer_port: 5432,
                trust_anchor_bundle_digest: digest_for(b"exclusive PostgreSQL trust anchors"),
                peer_leaf_certificate_digest: digest_for(b"PostgreSQL leaf certificate"),
                peer_certificate_chain_digest: digest_for(b"PostgreSQL certificate chain"),
                exporter_digest: digest_for(b"PostgreSQL TLS exporter"),
                tls_protocol: "tlsv1.3".into(),
                tls_cipher_suite: "tls_aes_256_gcm_sha384".into(),
                tls_cipher_bits: 256,
            };
            let tls_channel_binding_digest =
                postgresql_tls_channel_binding_digest(&tls_channel_binding)
                    .expect("fixture TLS channel binding must hash");
            let session = PostgresqlSessionBinding {
                application_name: postgresql_attestation_request_tag(
                    &nonce,
                    &tls_channel_binding_digest,
                ),
                database_name: "ryuki_platform".into(),
                database_oid: 16_384,
                datid: 16_384,
                server_address: "10.20.30.40".into(),
                server_port: 5432,
                server_major_version: 18,
                primary: true,
                transaction_writable: true,
                default_transaction_writable: true,
                client_address: "10.20.30.50".into(),
                client_port: 42_123,
                backend_process_id: 73_421,
                backend_start: instant(-60),
                backend_type: "client backend".into(),
                session_login_role: "ryuki_login".into(),
                session_user_oid: 16_385,
                current_role: "ryuki_schema_migrator".into(),
                selected_role: "ryuki_schema_migrator".into(),
                tls_enabled: true,
                tls_protocol: "tlsv1.3".into(),
                tls_cipher_suite: "tls_aes_256_gcm_sha384".into(),
                tls_cipher_bits: 256,
                client_distinguished_name: None,
                issuer_distinguished_name: None,
                tls_channel_binding,
            };
            let identity = PostgresqlDatabaseIdentity {
                deployment_id: "deployment:test".into(),
                trust_domain_id: "trust-domain:test".into(),
                database_provider: ProductionDatabaseProvider::CloudNativePg,
                database_name: session.database_name.clone(),
                database_oid: session.database_oid,
                cluster_system_identifier: "7425146738260194101".into(),
                server_address: session.server_address.clone(),
                server_port: session.server_port,
                tls_enabled: session.tls_enabled,
                tls_protocol: session.tls_protocol.clone(),
                tls_cipher_suite: session.tls_cipher_suite.clone(),
                tls_cipher_bits: session.tls_cipher_bits,
                server_major_version: session.server_major_version,
                primary: session.primary,
                writable: session.transaction_writable,
            };
            let identity_digest =
                postgresql_database_identity_digest(&identity).expect("fixture identity must hash");
            let storage = vec![
                PostgresqlStorageBinding {
                    purpose: PostgresqlStoragePurpose::Data,
                    provider_cluster_uid_digest: provider_cluster_uid_digest.clone(),
                    persistent_volume_claim_uid_digest: digest_for(b"data PVC"),
                    persistent_volume_uid_digest: digest_for(b"data PV"),
                    csi_driver: "csi.example.test".into(),
                    volume_handle_digest: digest_for(b"data volume"),
                    storage_class: "encrypted_ssd".into(),
                },
                PostgresqlStorageBinding {
                    purpose: PostgresqlStoragePurpose::Wal,
                    provider_cluster_uid_digest: provider_cluster_uid_digest.clone(),
                    persistent_volume_claim_uid_digest: digest_for(b"WAL PVC"),
                    persistent_volume_uid_digest: digest_for(b"WAL PV"),
                    csi_driver: "csi.example.test".into(),
                    volume_handle_digest: digest_for(b"WAL volume"),
                    storage_class: "encrypted_ssd".into(),
                },
            ];
            let storage_digest =
                postgresql_storage_binding_digest(&storage).expect("fixture storage must hash");
            Self {
                signing_key,
                public_key,
                public_key_fingerprint,
                profile_digest: digest_for(b"attestation profile"),
                requirement_digest: digest_for(b"guard requirement"),
                challenge_binding_digest: digest_for(b"guard challenge"),
                artifact_digest: digest_for(b"workload artifact"),
                workload_instance_binding_digest: digest_for(b"workload instance"),
                migration_inventory_digest: digest_for(b"migration inventory"),
                provider_route_binding_digest,
                nonce,
                session,
                identity,
                identity_digest,
                provider_cluster_uid_digest,
                storage,
                storage_digest,
            }
        }

        fn authority(&self) -> PostgresqlInfrastructureAuthorityAnchor<'_> {
            PostgresqlInfrastructureAuthorityAnchor {
                authority_id: "postgresql-infrastructure-attestation-authority:test",
                key_id: "postgresql-infrastructure-attestation-key:test",
                public_key: &self.public_key,
                public_key_fingerprint: &self.public_key_fingerprint,
                minimum_authority_epoch: 7,
                attestation_profile_id: "postgresql-infrastructure-attestation-profile:test",
                attestation_profile_version: 3,
                attestation_profile_digest: &self.profile_digest,
            }
        }

        fn expected(&self) -> ExpectedPostgresqlInfrastructure<'_> {
            ExpectedPostgresqlInfrastructure {
                deployment_id: "deployment:test",
                trust_domain_id: "trust-domain:test",
                workload_id: "workload:ryuki-api-test",
                source_revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                artifact_digest: &self.artifact_digest,
                workload_instance_binding_digest: &self.workload_instance_binding_digest,
                requirement_digest: &self.requirement_digest,
                challenge_binding_digest: &self.challenge_binding_digest,
                database_provider: ProductionDatabaseProvider::CloudNativePg,
                server_major_version: 18,
                provider_route_binding_digest: &self.provider_route_binding_digest,
                database_identity_digest: &self.identity_digest,
                storage_binding_digest: &self.storage_digest,
                migration_inventory_digest: &self.migration_inventory_digest,
                application_role: "ryuki_app",
                migration_role: "ryuki_schema_migrator",
                session_binding: &self.session,
            }
        }

        fn request(&self) -> PostgresqlInfrastructureAttestationRequest {
            build_postgresql_infrastructure_attestation_request(
                self.expected(),
                self.authority(),
                self.nonce,
                instant(0),
            )
            .expect("fixture request must construct")
        }

        fn unsigned_response(&self, request: &PostgresqlInfrastructureAttestationRequest) -> Value {
            json!({
                "schema_version": POSTGRESQL_INFRASTRUCTURE_PROTOCOL_VERSION,
                "contract_kind": RESPONSE_KIND,
                "canonicalization": CANONICALIZATION,
                "signature_algorithm": SIGNATURE_ALGORITHM,
                "authority": {
                    "authority_id": self.authority().authority_id,
                    "key_id": self.authority().key_id,
                    "public_key_fingerprint": self.public_key_fingerprint,
                    "authority_epoch": 7,
                    "authority_revision": 11
                },
                "request_nonce": request.nonce,
                "request_digest": request.digest,
                "namespace": request.namespace,
                "workload": request.workload,
                "guard": request.guard,
                "attestation_profile": request.profile,
                "expected": request.expected,
                "outcome": "matched",
                "measurement": {
                    "sequence": 19,
                    "method": MEASUREMENT_METHOD,
                    "tls_channel_verification_method": POSTGRESQL_TLS_CHANNEL_VERIFICATION_METHOD,
                    "observed_at": {
                        "not_before": instant(1),
                        "not_after": instant(2)
                    },
                    "valid_until": instant(120),
                    "restored_state_reconciled": true,
                    "session_binding": self.session,
                    "session_binding_digest": postgresql_session_binding_digest(&self.session).unwrap(),
                    "provider_route_binding_digest": self.provider_route_binding_digest,
                    "tls_channel_binding_digest": postgresql_tls_channel_binding_digest(
                        &self.session.tls_channel_binding
                    ).unwrap(),
                    "database_identity": self.identity,
                    "database_identity_digest": self.identity_digest,
                    "provider_cluster_uid_digest": self.provider_cluster_uid_digest,
                    "storage_bindings": self.storage,
                    "storage_binding_digest": self.storage_digest
                },
                "signature_base64": ""
            })
        }

        fn signed_response(&self, request: &PostgresqlInfrastructureAttestationRequest) -> Vec<u8> {
            sign_response(self.unsigned_response(request), &self.signing_key)
        }
    }

    fn instant(offset_seconds: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 20, 10, 0, 0).unwrap() + TimeDelta::seconds(offset_seconds)
    }

    fn trusted_now(start: i64, end: i64) -> ConformanceTrustedTimeWindow {
        ConformanceTrustedTimeWindow {
            not_before: instant(start),
            not_after: instant(end),
        }
    }

    fn digest_for(label: &[u8]) -> String {
        let mut material = Vec::with_capacity(label.len() + 32);
        material.extend_from_slice(label);
        material.extend_from_slice(&test_entropy(b"digest fixture"));
        sha256_digest(&material)
    }

    fn test_entropy(label: &[u8]) -> [u8; 32] {
        let counter = TEST_ENTROPY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut hasher = Sha256::new();
        hasher.update(b"ryuki PostgreSQL infrastructure test entropy");
        hasher.update(label);
        hasher.update(std::process::id().to_le_bytes());
        hasher.update(counter.to_le_bytes());
        hasher.update(elapsed.to_le_bytes());
        hasher.finalize().into()
    }

    fn sign_response(mut response: Value, key: &SigningKey) -> Vec<u8> {
        response
            .as_object_mut()
            .expect("fixture response is an object")
            .remove("signature_base64");
        let canonical = canonical_json_bytes(&response).expect("fixture response canonicalizes");
        let mut signed = Vec::with_capacity(
            16 + POSTGRESQL_INFRASTRUCTURE_RESPONSE_DOMAIN.len() + canonical.len(),
        );
        write_frame(
            &mut signed,
            POSTGRESQL_INFRASTRUCTURE_RESPONSE_DOMAIN.as_bytes(),
        );
        write_frame(&mut signed, &canonical);
        let signature = key.sign(&signed);
        response
            .as_object_mut()
            .expect("fixture response is an object")
            .insert(
                "signature_base64".into(),
                Value::String(BASE64_STANDARD.encode(signature.to_bytes())),
            );
        canonical_json_bytes(&response).expect("signed fixture response canonicalizes")
    }

    #[test]
    fn genuine_signed_attestation_verifies_every_exact_preimage() {
        let fixture = Fixture::new();
        let request = fixture.request();
        assert_eq!(request.request_tag(), fixture.session.application_name);
        let response = fixture.signed_response(&request);
        let proof = verify_postgresql_infrastructure_attestation(
            request,
            &response,
            fixture.authority(),
            trusted_now(3, 4),
        )
        .expect("exact signed PostgreSQL infrastructure measurement must verify");

        assert_eq!(proof.session_binding(), &fixture.session);
        assert_eq!(
            proof.provider_route_binding_digest(),
            fixture.provider_route_binding_digest
        );
        assert_eq!(
            proof.tls_channel_binding_digest(),
            postgresql_tls_channel_binding_digest(&fixture.session.tls_channel_binding).unwrap()
        );
        assert_eq!(proof.database_identity(), &fixture.identity);
        assert_eq!(proof.storage_bindings(), fixture.storage);
        assert_eq!(
            proof.provider_cluster_uid_digest(),
            fixture.provider_cluster_uid_digest
        );
        assert_eq!(proof.application_role(), "ryuki_app");
        assert_eq!(proof.migration_role(), "ryuki_schema_migrator");
        proof.verify_integrity().expect("retained proof is intact");
        proof
            .ensure_fresh(trusted_now(5, 6))
            .expect("proof remains fresh before the exclusive fence");
        assert!(!format!("{proof:?}").contains("10.20.30.40"));
    }

    #[test]
    fn signed_fixture_and_closed_storage_order_match_json_schema() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../catalog/security-contracts/v1/postgresql-infrastructure-attestation-envelope.schema.json"
        ))
        .expect("PostgreSQL infrastructure schema must be JSON");
        let validator = jsonschema::draft202012::options()
            .build(&schema)
            .expect("PostgreSQL infrastructure schema must compile");
        let fixture = Fixture::new();
        let response: Value = serde_json::from_slice(&fixture.signed_response(&fixture.request()))
            .expect("signed fixture response must be JSON");
        assert!(validator.is_valid(&response));

        let mut reversed = response.clone();
        reversed["measurement"]["storage_bindings"]
            .as_array_mut()
            .expect("fixture storage exists")
            .reverse();
        assert!(!validator.is_valid(&reversed));

        let mut extra = response;
        extra["measurement"]["unexpected"] = json!(true);
        assert!(!validator.is_valid(&extra));
    }

    #[test]
    fn request_rejects_nonce_tag_role_and_session_substitution() {
        let mut fixture = Fixture::new();
        let mut invalid_nonce = test_entropy(b"invalid zero nonce");
        invalid_nonce.fill(0);
        assert!(
            build_postgresql_infrastructure_attestation_request(
                fixture.expected(),
                fixture.authority(),
                invalid_nonce,
                instant(0),
            )
            .unwrap_err()
            .to_string()
            .contains("nonce")
        );

        fixture.session.application_name = postgresql_attestation_request_tag(
            &test_entropy(b"substituted request tag"),
            &postgresql_tls_channel_binding_digest(&fixture.session.tls_channel_binding).unwrap(),
        );
        assert!(
            build_postgresql_infrastructure_attestation_request(
                fixture.expected(),
                fixture.authority(),
                fixture.nonce,
                instant(0),
            )
            .unwrap_err()
            .to_string()
            .contains("request tag")
        );

        fixture.session.application_name = postgresql_attestation_request_tag(
            &fixture.nonce,
            &postgresql_tls_channel_binding_digest(&fixture.session.tls_channel_binding).unwrap(),
        );
        fixture.session.selected_role = "ryuki_app".into();
        fixture.session.current_role = "ryuki_app".into();
        assert!(
            build_postgresql_infrastructure_attestation_request(
                fixture.expected(),
                fixture.authority(),
                fixture.nonce,
                instant(0),
            )
            .is_err()
        );

        let mut fixture = Fixture::new();
        fixture.provider_route_binding_digest = digest_for(b"substituted expected route");
        assert!(
            build_postgresql_infrastructure_attestation_request(
                fixture.expected(),
                fixture.authority(),
                fixture.nonce,
                instant(0),
            )
            .unwrap_err()
            .to_string()
            .contains("receipt-bound route")
        );
    }

    #[test]
    fn response_rejects_signature_replay_unknown_fields_and_noncanonical_bytes() {
        let fixture = Fixture::new();
        let request = fixture.request();
        let mut response: Value =
            serde_json::from_slice(&fixture.signed_response(&request)).unwrap();
        response["request_nonce"] = Value::String(BASE64_STANDARD.encode(test_entropy(b"replay")));
        let replay = sign_response(response, &fixture.signing_key);
        assert!(
            verify_postgresql_infrastructure_attestation(
                request,
                &replay,
                fixture.authority(),
                trusted_now(3, 4),
            )
            .unwrap_err()
            .to_string()
            .contains("request echo")
        );

        let request = fixture.request();
        let mut unknown = fixture.unsigned_response(&request);
        unknown["measurement"]["unknown"] = json!(true);
        let unknown = sign_response(unknown, &fixture.signing_key);
        assert!(
            verify_postgresql_infrastructure_attestation(
                request,
                &unknown,
                fixture.authority(),
                trusted_now(3, 4),
            )
            .is_err()
        );

        let request = fixture.request();
        let mut noncanonical = fixture.signed_response(&request);
        noncanonical.push(b'\n');
        assert!(
            verify_postgresql_infrastructure_attestation(
                request,
                &noncanonical,
                fixture.authority(),
                trusted_now(3, 4),
            )
            .unwrap_err()
            .to_string()
            .contains("canonical JSON")
        );
    }

    #[test]
    fn response_rejects_database_storage_and_cluster_cross_wiring() {
        let fixture = Fixture::new();
        let request = fixture.request();
        let mut identity_substitution = fixture.unsigned_response(&request);
        identity_substitution["measurement"]["database_identity"]["cluster_system_identifier"] =
            Value::String("7425146738260194102".into());
        let substituted_identity: PostgresqlDatabaseIdentity = serde_json::from_value(
            identity_substitution["measurement"]["database_identity"].clone(),
        )
        .unwrap();
        identity_substitution["measurement"]["database_identity_digest"] =
            Value::String(postgresql_database_identity_digest(&substituted_identity).unwrap());
        let response = sign_response(identity_substitution, &fixture.signing_key);
        assert!(
            verify_postgresql_infrastructure_attestation(
                request,
                &response,
                fixture.authority(),
                trusted_now(3, 4),
            )
            .is_err()
        );

        let request = fixture.request();
        let mut cross_wired = fixture.unsigned_response(&request);
        cross_wired["measurement"]["provider_cluster_uid_digest"] =
            Value::String(digest_for(b"substituted provider cluster"));
        let response = sign_response(cross_wired, &fixture.signing_key);
        assert!(
            verify_postgresql_infrastructure_attestation(
                request,
                &response,
                fixture.authority(),
                trusted_now(3, 4),
            )
            .unwrap_err()
            .to_string()
            .contains("storage")
        );

        let request = fixture.request();
        let mut reordered = fixture.unsigned_response(&request);
        reordered["measurement"]["storage_bindings"]
            .as_array_mut()
            .unwrap()
            .reverse();
        let response = sign_response(reordered, &fixture.signing_key);
        assert!(
            verify_postgresql_infrastructure_attestation(
                request,
                &response,
                fixture.authority(),
                trusted_now(3, 4),
            )
            .is_err()
        );
    }

    #[test]
    fn response_rejects_stale_or_unreconciled_measurements() {
        let fixture = Fixture::new();
        let request = fixture.request();
        let mut stale = fixture.unsigned_response(&request);
        stale["measurement"]["valid_until"] = json!(instant(2));
        let stale = sign_response(stale, &fixture.signing_key);
        assert!(
            verify_postgresql_infrastructure_attestation(
                request,
                &stale,
                fixture.authority(),
                trusted_now(3, 4),
            )
            .is_err()
        );

        let request = fixture.request();
        let mut unreconciled = fixture.unsigned_response(&request);
        unreconciled["measurement"]["restored_state_reconciled"] = json!(false);
        let unreconciled = sign_response(unreconciled, &fixture.signing_key);
        assert!(
            verify_postgresql_infrastructure_attestation(
                request,
                &unreconciled,
                fixture.authority(),
                trusted_now(3, 4),
            )
            .is_err()
        );
    }

    #[test]
    fn retained_proof_integrity_detects_exact_raw_byte_tampering() {
        let fixture = Fixture::new();
        let request = fixture.request();
        let response = fixture.signed_response(&request);
        let mut proof = verify_postgresql_infrastructure_attestation(
            request,
            &response,
            fixture.authority(),
            trusted_now(3, 4),
        )
        .unwrap();
        proof.raw_response[0] ^= 1;
        assert!(proof.verify_integrity().is_err());
    }

    #[test]
    fn session_binding_digest_covers_connection_and_tls_identity() {
        let fixture = Fixture::new();
        let digest = postgresql_session_binding_digest(&fixture.session).unwrap();

        let mut changed = fixture.session.clone();
        changed.backend_process_id += 1;
        assert_ne!(postgresql_session_binding_digest(&changed).unwrap(), digest);

        let mut changed = fixture.session.clone();
        changed.tls_cipher_suite = "tls_aes_128_gcm_sha256".into();
        changed.tls_cipher_bits = 128;
        changed.tls_channel_binding.tls_cipher_suite = "tls_aes_128_gcm_sha256".into();
        changed.tls_channel_binding.tls_cipher_bits = 128;
        assert_ne!(postgresql_session_binding_digest(&changed).unwrap(), digest);

        let mut changed = fixture.session.clone();
        changed.client_address = "10.20.30.51".into();
        assert_ne!(postgresql_session_binding_digest(&changed).unwrap(), digest);
    }

    #[test]
    fn tls_channel_digest_and_request_tag_bind_route_and_exporter() {
        let fixture = Fixture::new();
        let channel = &fixture.session.tls_channel_binding;
        let digest = postgresql_tls_channel_binding_digest(channel).unwrap();
        let request_tag = postgresql_attestation_request_tag(&fixture.nonce, &digest);

        let mut changed = channel.clone();
        changed.provider_route_binding_digest = digest_for(b"substituted provider route");
        let changed_digest = postgresql_tls_channel_binding_digest(&changed).unwrap();
        assert_ne!(changed_digest, digest);
        assert_ne!(
            postgresql_attestation_request_tag(&fixture.nonce, &changed_digest),
            request_tag
        );

        let mut changed = channel.clone();
        changed.exporter_digest = digest_for(b"substituted TLS exporter");
        let changed_digest = postgresql_tls_channel_binding_digest(&changed).unwrap();
        assert_ne!(changed_digest, digest);
        assert_ne!(
            postgresql_attestation_request_tag(&fixture.nonce, &changed_digest),
            request_tag
        );
    }

    #[test]
    fn response_rejects_route_exporter_channel_digest_and_method_substitution() {
        let fixture = Fixture::new();

        let request = fixture.request();
        let mut substituted = fixture.unsigned_response(&request);
        substituted["measurement"]["session_binding"]["tls_channel_binding"]["exporter_digest"] =
            Value::String(digest_for(b"substituted response exporter"));
        let substituted_session: PostgresqlSessionBinding =
            serde_json::from_value(substituted["measurement"]["session_binding"].clone()).unwrap();
        substituted["measurement"]["session_binding_digest"] =
            Value::String(postgresql_session_binding_digest(&substituted_session).unwrap());
        substituted["measurement"]["tls_channel_binding_digest"] = Value::String(
            postgresql_tls_channel_binding_digest(&substituted_session.tls_channel_binding)
                .unwrap(),
        );
        let response = sign_response(substituted, &fixture.signing_key);
        assert!(
            verify_postgresql_infrastructure_attestation(
                request,
                &response,
                fixture.authority(),
                trusted_now(3, 4),
            )
            .unwrap_err()
            .to_string()
            .contains("exact caller session")
        );

        let request = fixture.request();
        let mut substituted = fixture.unsigned_response(&request);
        substituted["measurement"]["provider_route_binding_digest"] =
            Value::String(digest_for(b"substituted measured route"));
        let response = sign_response(substituted, &fixture.signing_key);
        assert!(
            verify_postgresql_infrastructure_attestation(
                request,
                &response,
                fixture.authority(),
                trusted_now(3, 4),
            )
            .unwrap_err()
            .to_string()
            .contains("session preimage")
        );

        let request = fixture.request();
        let mut substituted = fixture.unsigned_response(&request);
        substituted["measurement"]["tls_channel_binding_digest"] =
            Value::String(digest_for(b"substituted channel digest"));
        let response = sign_response(substituted, &fixture.signing_key);
        assert!(
            verify_postgresql_infrastructure_attestation(
                request,
                &response,
                fixture.authority(),
                trusted_now(3, 4),
            )
            .unwrap_err()
            .to_string()
            .contains("session preimage")
        );

        let request = fixture.request();
        let mut substituted = fixture.unsigned_response(&request);
        substituted["measurement"]["tls_channel_verification_method"] =
            Value::String("provider-tls-endpoint-exporter-proxy-session-v1".into());
        let response = sign_response(substituted, &fixture.signing_key);
        assert!(
            verify_postgresql_infrastructure_attestation(
                request,
                &response,
                fixture.authority(),
                trusted_now(3, 4),
            )
            .unwrap_err()
            .to_string()
            .contains("matched state differs")
        );
    }
}
