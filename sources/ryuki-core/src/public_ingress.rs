//! Pure verification for independently observed public ingress state.
//!
//! This module performs no DNS, TLS, ingress-controller, or network I/O. It
//! creates one nonce-bound request and accepts only a short-lived,
//! domain-separated Ed25519 response from an independently pinned authority.
//! The response carries the complete non-secret typed preimages for both
//! receipt-bound digests; the verifier recomputes them locally before minting
//! a non-cloneable witness.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::{Host, Url};

use crate::conformance_trust::{
    ConformanceTrustedTimeWindow, canonical_json_bytes, parse_json_strict,
};
use crate::security_profile::{INGRESS_ATTESTATION_PROFILE_ID_PREFIX, valid_canonical_scoped_id};

pub const PUBLIC_INGRESS_PROTOCOL_VERSION: &str = "1.0.0";
pub const PUBLIC_INGRESS_REQUEST_DOMAIN: &str = "ryuki-v1/public-ingress-attestation-request";
pub const PUBLIC_INGRESS_RESPONSE_DOMAIN: &str = "ryuki-v1/public-ingress-attestation-response";
pub const PUBLIC_ORIGIN_SET_DIGEST_CONTRACT: &str = "ryuki-public-origin-set-binding-v1";
pub const PUBLIC_INGRESS_BINDING_DIGEST_CONTRACT: &str = "ryuki-public-ingress-binding-v1";
pub const MAX_PUBLIC_INGRESS_REQUEST_BYTES: usize = 32 * 1024;
pub const MAX_PUBLIC_INGRESS_RESPONSE_BYTES: usize = 256 * 1024;

const REQUEST_KIND: &str = "public-ingress-attestation-request";
const RESPONSE_KIND: &str = "public-ingress-attestation-response";
const REQUEST_OPERATION: &str = "attest_public_ingress";
const CANONICALIZATION: &str = "ryuki-canonical-json-v1";
const SIGNATURE_ALGORITHM: &str = "ed25519";
const GUARD_ID: &str = "https-public-urls";
const MEASUREMENT_METHOD: &str = "external-dns-tls-ingress-observation-v1";
const MAX_ATTESTATION_LIFETIME_SECONDS: i64 = 300;
const MAX_JSON_DEPTH: usize = 24;
const MAX_JSON_NODES: usize = 4096;
const MAX_JSON_COLLECTION_ITEMS: usize = 256;
const MAX_JSON_STRING_BYTES: usize = 4096;
const MAX_EXACT_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_BINDINGS: usize = 32;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PublicIngressError {
    #[error("invalid public-ingress attestation: {0}")]
    Invalid(String),
    #[error("public-ingress authority signature verification failed")]
    SignatureVerificationFailed,
}

/// Independent deployment-time pins for the external ingress authority.
#[derive(Debug, Clone, Copy)]
pub struct PublicIngressAuthorityAnchor<'a> {
    pub authority_id: &'a str,
    pub key_id: &'a str,
    pub public_key: &'a [u8; 32],
    pub public_key_fingerprint: &'a str,
    pub minimum_authority_epoch: u64,
    pub attestation_profile_id: &'a str,
    pub attestation_profile_version: u64,
    pub attestation_profile_digest: &'a str,
}

/// Exact semantic and workload-bound facts selected by the caller's verified
/// `https-public-urls` runtime-guard challenge.
#[derive(Debug, Clone, Copy)]
pub struct ExpectedPublicIngress<'a> {
    pub deployment_id: &'a str,
    pub trust_domain_id: &'a str,
    pub workload_id: &'a str,
    pub source_revision: &'a str,
    pub artifact_digest: &'a str,
    pub workload_instance_binding_digest: &'a str,
    pub requirement_digest: &'a str,
    pub challenge_binding_digest: &'a str,
    pub public_origin_set_digest: &'a str,
    pub ingress_binding_digest: &'a str,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum PublicOriginRole {
    PlatformApi,
    PortalUi,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct PublicOriginBinding {
    pub role: PublicOriginRole,
    pub canonical_origin: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct DnsBinding {
    pub origin_role: PublicOriginRole,
    pub hostname: String,
    pub authoritative_rrset_digest: String,
    pub dns_generation_digest: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum MinimumTlsProtocol {
    #[serde(rename = "tls-1.2")]
    Tls12,
    #[serde(rename = "tls-1.3")]
    Tls13,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum TlsVerificationMethod {
    WebpkiHostnameAndChain,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct TlsEndpointBinding {
    pub origin_role: PublicOriginRole,
    pub server_name: String,
    pub leaf_spki_digest: String,
    pub certificate_chain_digest: String,
    pub san_dns_names: Vec<String>,
    pub certificate_not_before: DateTime<Utc>,
    pub certificate_not_after: DateTime<Utc>,
    pub minimum_protocol: MinimumTlsProtocol,
    pub verification_method: TlsVerificationMethod,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum IngressPathType {
    Prefix,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct IngressRouteBinding {
    pub origin_role: PublicOriginRole,
    pub path_prefix: String,
    pub path_type: IngressPathType,
    pub route_generation_digest: String,
    pub backend_workload_id: String,
    pub backend_component_id: String,
    pub backend_artifact_digest: String,
    pub backend_binding_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicIngressBinding {
    pub ingress_generation_digest: String,
    pub dns_bindings: Vec<DnsBinding>,
    pub tls_bindings: Vec<TlsEndpointBinding>,
    pub routes: Vec<IngressRouteBinding>,
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

/// Opaque canonical request consumed by exactly one verification attempt.
pub struct PublicIngressAttestationRequest {
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
    expected_public_origin_set_digest: String,
    expected_ingress_binding_digest: String,
}

impl fmt::Debug for PublicIngressAttestationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicIngressAttestationRequest")
            .field("digest", &self.digest)
            .field("requested_at", &self.requested_at)
            .field("byte_len", &self.canonical_bytes.len())
            .finish_non_exhaustive()
    }
}

impl PublicIngressAttestationRequest {
    pub fn as_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// Creates one bounded, canonical, nonce-bound ingress-attestation request.
/// The caller must supply a fresh operating-system CSPRNG nonce for every
/// attempt and must not retry a request with the same nonce.
pub fn build_public_ingress_attestation_request(
    expected: ExpectedPublicIngress<'_>,
    authority: PublicIngressAuthorityAnchor<'_>,
    request_nonce: [u8; 32],
    requested_at: DateTime<Utc>,
) -> Result<PublicIngressAttestationRequest, PublicIngressError> {
    validate_authority(authority)?;
    validate_expected(expected)?;
    if request_nonce.iter().all(|byte| *byte == 0) {
        return Err(invalid("request nonce cannot be all zero"));
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
    let value = serde_json::json!({
        "schema_version": PUBLIC_INGRESS_PROTOCOL_VERSION,
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
        "expected": {
            "public_origin_set_digest": expected.public_origin_set_digest,
            "ingress_binding_digest": expected.ingress_binding_digest,
        },
        "request_nonce": nonce,
        "requested_at": requested_at,
    });
    let canonical_bytes = canonical_json_bytes(&value)
        .map_err(|error| invalid(format!("request canonicalization failed: {error}")))?;
    if canonical_bytes.is_empty() || canonical_bytes.len() > MAX_PUBLIC_INGRESS_REQUEST_BYTES {
        return Err(invalid("request is empty or exceeds 32 KiB"));
    }
    let digest = sha256_digest(&canonical_bytes);

    Ok(PublicIngressAttestationRequest {
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
        expected_public_origin_set_digest: expected.public_origin_set_digest.to_owned(),
        expected_ingress_binding_digest: expected.ingress_binding_digest.to_owned(),
    })
}

/// Computes the receipt-bound digest of the exact sorted role-tagged origins.
pub fn public_origin_set_digest(
    origins: &[PublicOriginBinding],
) -> Result<String, PublicIngressError> {
    validate_origins(origins)?;
    digest_projection(&serde_json::json!({
        "digest_contract": PUBLIC_ORIGIN_SET_DIGEST_CONTRACT,
        "origins": origins,
    }))
}

/// Computes the receipt-bound digest of the exact live ingress projection.
pub fn public_ingress_binding_digest(
    ingress: &PublicIngressBinding,
) -> Result<String, PublicIngressError> {
    validate_ingress_shape(ingress)?;
    digest_projection(&serde_json::json!({
        "digest_contract": PUBLIC_INGRESS_BINDING_DIGEST_CONTRACT,
        "ingress_generation_digest": ingress.ingress_generation_digest,
        "dns_bindings": ingress.dns_bindings,
        "tls_bindings": ingress.tls_bindings,
        "routes": ingress.routes,
    }))
}

#[derive(Debug, Deserialize)]
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
    outcome: String,
    measurement: PublicIngressMeasurement,
    #[serde(rename = "signature_base64")]
    _signature_base64: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseAuthority {
    authority_id: String,
    key_id: String,
    public_key_fingerprint: String,
    authority_epoch: u64,
    authority_revision: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicIngressMeasurement {
    sequence: u64,
    method: String,
    observed_at: TrustedTimeInterval,
    valid_until: DateTime<Utc>,
    restored_state_reconciled: bool,
    public_origins: Vec<PublicOriginBinding>,
    public_origin_set_digest: String,
    ingress: PublicIngressBinding,
    ingress_binding_digest: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TrustedTimeInterval {
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

/// Opaque proof that an independently pinned authority freshly measured the
/// exact public origin, DNS, TLS, route-generation, and backend projection
/// selected by one final workload-bound runtime-guard challenge.
///
/// ```compile_fail
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<ryuki_core::public_ingress::VerifiedHttpsPublicUrlsWitness>();
/// ```
pub struct VerifiedHttpsPublicUrlsWitness {
    raw_response: Box<[u8]>,
    response_digest: String,
    authority_id: String,
    authority_key_id: String,
    authority_public_key_fingerprint: String,
    authority_epoch: u64,
    authority_revision: u64,
    attestation_profile: AttestationProfileBinding,
    measurement_sequence: u64,
    observed_at: TrustedTimeInterval,
    valid_until: DateTime<Utc>,
    minimum_certificate_not_after: DateTime<Utc>,
    requirement_digest: String,
    challenge_binding_digest: String,
    public_origin_set_digest: String,
    ingress_binding_digest: String,
    public_origins: Box<[PublicOriginBinding]>,
    ingress: PublicIngressBinding,
}

impl fmt::Debug for VerifiedHttpsPublicUrlsWitness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedHttpsPublicUrlsWitness")
            .field("response_digest", &self.response_digest)
            .field("authority_epoch", &self.authority_epoch)
            .field("authority_revision", &self.authority_revision)
            .field("measurement_sequence", &self.measurement_sequence)
            .field("valid_until", &self.valid_until)
            .field("origin_count", &self.public_origins.len())
            .field("route_count", &self.ingress.routes.len())
            .field("byte_len", &self.raw_response.len())
            .finish()
    }
}

impl VerifiedHttpsPublicUrlsWitness {
    pub fn ensure_fresh(
        &self,
        trusted_now: ConformanceTrustedTimeWindow,
    ) -> Result<(), PublicIngressError> {
        if trusted_now.not_before > trusted_now.not_after
            || self.observed_at.not_after > trusted_now.not_before
            || trusted_now.not_after >= self.valid_until
            || trusted_now.not_after >= self.minimum_certificate_not_after
        {
            return Err(invalid(
                "verified public-ingress measurement is stale at the startup fence",
            ));
        }
        Ok(())
    }

    pub fn response_digest(&self) -> &str {
        &self.response_digest
    }

    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }

    pub fn authority_key_id(&self) -> &str {
        &self.authority_key_id
    }

    pub fn authority_public_key_fingerprint(&self) -> &str {
        &self.authority_public_key_fingerprint
    }

    pub fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    pub fn authority_revision(&self) -> u64 {
        self.authority_revision
    }

    pub fn attestation_profile_id(&self) -> &str {
        &self.attestation_profile.profile_id
    }

    pub fn attestation_profile_version(&self) -> u64 {
        self.attestation_profile.profile_version
    }

    pub fn attestation_profile_digest(&self) -> &str {
        &self.attestation_profile.content_digest
    }

    pub fn measurement_sequence(&self) -> u64 {
        self.measurement_sequence
    }

    pub fn observed_at_not_before(&self) -> DateTime<Utc> {
        self.observed_at.not_before
    }

    pub fn observed_at_not_after(&self) -> DateTime<Utc> {
        self.observed_at.not_after
    }

    pub fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }

    pub fn requirement_digest(&self) -> &str {
        &self.requirement_digest
    }

    pub fn challenge_binding_digest(&self) -> &str {
        &self.challenge_binding_digest
    }

    pub fn public_origin_set_digest(&self) -> &str {
        &self.public_origin_set_digest
    }

    pub fn ingress_binding_digest(&self) -> &str {
        &self.ingress_binding_digest
    }

    pub fn public_origins(&self) -> &[PublicOriginBinding] {
        &self.public_origins
    }

    pub fn ingress(&self) -> &PublicIngressBinding {
        &self.ingress
    }
}

/// Verifies and consumes one request against one exact signed response.
pub fn verify_public_ingress_attestation(
    request: PublicIngressAttestationRequest,
    raw_response: &[u8],
    authority: PublicIngressAuthorityAnchor<'_>,
    trusted_now: ConformanceTrustedTimeWindow,
) -> Result<VerifiedHttpsPublicUrlsWitness, PublicIngressError> {
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
    if raw_response.is_empty() || raw_response.len() > MAX_PUBLIC_INGRESS_RESPONSE_BYTES {
        return Err(invalid("response is empty or exceeds 256 KiB"));
    }

    let value = parse_json_strict(raw_response)
        .map_err(|error| invalid(format!("strict response JSON failed: {error}")))?;
    let mut nodes = 0;
    validate_json_shape(&value, 0, &mut nodes)?;
    validate_timestamp_lexemes(&value)?;
    verify_response_signature(&value, authority)?;
    let response: AttestationResponse = serde_json::from_value(value)
        .map_err(|error| invalid(format!("response typed decoding failed: {error}")))?;

    if response.schema_version != PUBLIC_INGRESS_PROTOCOL_VERSION
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
        || response.outcome != "matched"
        || response.measurement.method != MEASUREMENT_METHOD
        || !response.measurement.restored_state_reconciled
    {
        return Err(invalid(
            "response authority, request echo, namespace, workload, guard, profile, or matched state differs",
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

    validate_origins(&response.measurement.public_origins)?;
    validate_ingress_for_request(
        &response.measurement.ingress,
        &response.measurement.public_origins,
        &request,
    )?;
    let origin_digest = public_origin_set_digest(&response.measurement.public_origins)?;
    let ingress_digest = public_ingress_binding_digest(&response.measurement.ingress)?;
    if origin_digest != response.measurement.public_origin_set_digest
        || origin_digest != request.expected_public_origin_set_digest
        || ingress_digest != response.measurement.ingress_binding_digest
        || ingress_digest != request.expected_ingress_binding_digest
    {
        return Err(invalid(
            "measured public-origin or ingress preimage differs from the receipt-bound expectation",
        ));
    }

    let observed = &response.measurement.observed_at;
    let valid_until = response.measurement.valid_until;
    if request.requested_at > observed.not_before
        || observed.not_before > observed.not_after
        || observed.not_after > trusted_now.not_before
        || trusted_now.not_after >= valid_until
        || valid_until <= observed.not_after
        || valid_until.signed_duration_since(observed.not_before)
            > TimeDelta::seconds(MAX_ATTESTATION_LIFETIME_SECONDS)
    {
        return Err(invalid(
            "response observation interval or exclusive freshness bound is invalid",
        ));
    }
    let minimum_certificate_not_after = response
        .measurement
        .ingress
        .tls_bindings
        .iter()
        .map(|binding| binding.certificate_not_after)
        .min()
        .ok_or_else(|| invalid("response has no TLS bindings"))?;
    if response
        .measurement
        .ingress
        .tls_bindings
        .iter()
        .any(|binding| {
            binding.certificate_not_before > observed.not_before
                || binding.certificate_not_after <= observed.not_after
                || binding.certificate_not_after < valid_until
        })
    {
        return Err(invalid(
            "TLS certificate validity does not cover the complete attestation window",
        ));
    }

    Ok(VerifiedHttpsPublicUrlsWitness {
        raw_response: raw_response.to_vec().into_boxed_slice(),
        response_digest: sha256_digest(raw_response),
        authority_id: response.authority.authority_id,
        authority_key_id: response.authority.key_id,
        authority_public_key_fingerprint: response.authority.public_key_fingerprint,
        authority_epoch: response.authority.authority_epoch,
        authority_revision: response.authority.authority_revision,
        attestation_profile: response.attestation_profile,
        measurement_sequence: response.measurement.sequence,
        observed_at: response.measurement.observed_at,
        valid_until,
        minimum_certificate_not_after,
        requirement_digest: response.guard.requirement_digest,
        challenge_binding_digest: response.guard.challenge_binding_digest,
        public_origin_set_digest: origin_digest,
        ingress_binding_digest: ingress_digest,
        public_origins: response.measurement.public_origins.into_boxed_slice(),
        ingress: response.measurement.ingress,
    })
}

fn validate_authority(
    authority: PublicIngressAuthorityAnchor<'_>,
) -> Result<(), PublicIngressError> {
    if !valid_attestation_scoped_id(
        authority.authority_id,
        "public-ingress-attestation-authority:",
    ) || !valid_attestation_scoped_id(authority.key_id, "public-ingress-attestation-key:")
        || !valid_canonical_scoped_id(
            authority.attestation_profile_id,
            INGRESS_ATTESTATION_PROFILE_ID_PREFIX,
        )
        || !valid_counter(authority.minimum_authority_epoch)
        || !valid_counter(authority.attestation_profile_version)
        || !is_digest(authority.public_key_fingerprint)
        || !is_digest(authority.attestation_profile_digest)
    {
        return Err(invalid(
            "invalid independent public-ingress authority anchor",
        ));
    }
    if sha256_digest(authority.public_key) != authority.public_key_fingerprint {
        return Err(invalid(
            "public-ingress authority key differs from its fingerprint pin",
        ));
    }
    let key = VerifyingKey::from_bytes(authority.public_key)
        .map_err(|_| invalid("invalid public-ingress authority Ed25519 key"))?;
    if key.is_weak() {
        return Err(invalid("weak public-ingress authority Ed25519 key"));
    }
    Ok(())
}

fn validate_expected(expected: ExpectedPublicIngress<'_>) -> Result<(), PublicIngressError> {
    if !valid_canonical_scoped_id(expected.deployment_id, "deployment:")
        || !valid_canonical_scoped_id(expected.trust_domain_id, "trust-domain:")
        || !valid_canonical_scoped_id(expected.workload_id, "workload:")
        || !valid_source_revision(expected.source_revision)
    {
        return Err(invalid(
            "invalid expected public-ingress namespace or source revision",
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
        ("public origin set", expected.public_origin_set_digest),
        ("public ingress binding", expected.ingress_binding_digest),
    ] {
        require_digest(label, value)?;
    }
    if expected.requirement_digest == expected.challenge_binding_digest {
        return Err(invalid(
            "guard requirement and workload challenge bindings cannot collapse",
        ));
    }
    Ok(())
}

fn validate_origins(origins: &[PublicOriginBinding]) -> Result<(), PublicIngressError> {
    let required_roles = [PublicOriginRole::PlatformApi, PublicOriginRole::PortalUi];
    if origins.len() != required_roles.len()
        || origins.len() > MAX_BINDINGS
        || !strictly_sorted_unique(origins)
    {
        return Err(invalid(
            "public origins must be the exact sorted API and portal inventory",
        ));
    }
    for (origin, expected_role) in origins.iter().zip(required_roles) {
        if origin.role != expected_role {
            return Err(invalid(
                "public origins must contain each required role exactly once",
            ));
        }
        canonical_origin_hostname(&origin.canonical_origin)?;
    }
    Ok(())
}

fn validate_ingress_shape(ingress: &PublicIngressBinding) -> Result<(), PublicIngressError> {
    require_digest("ingress generation", &ingress.ingress_generation_digest)?;
    if ingress.dns_bindings.len() != 2
        || ingress.tls_bindings.len() != 2
        || ingress.routes.len() != 2
        || ingress.dns_bindings.len() > MAX_BINDINGS
        || ingress.tls_bindings.len() > MAX_BINDINGS
        || ingress.routes.len() > MAX_BINDINGS
        || !strictly_sorted_unique(&ingress.dns_bindings)
        || !strictly_sorted_unique(&ingress.tls_bindings)
        || !strictly_sorted_unique(&ingress.routes)
    {
        return Err(invalid(
            "ingress DNS, TLS, and route inventories must be exact, sorted, and unique",
        ));
    }

    let required_roles = [PublicOriginRole::PlatformApi, PublicOriginRole::PortalUi];
    for (binding, role) in ingress.dns_bindings.iter().zip(required_roles) {
        if binding.origin_role != role || !valid_dns_name(&binding.hostname) {
            return Err(invalid("DNS binding role or canonical hostname is invalid"));
        }
        require_digest(
            "authoritative DNS RRset",
            &binding.authoritative_rrset_digest,
        )?;
        require_digest("DNS generation", &binding.dns_generation_digest)?;
    }

    for (binding, role) in ingress.tls_bindings.iter().zip(required_roles) {
        if binding.origin_role != role
            || !valid_dns_name(&binding.server_name)
            || binding.certificate_not_before >= binding.certificate_not_after
            || binding.certificate_not_before.timestamp_subsec_nanos() != 0
            || binding.certificate_not_after.timestamp_subsec_nanos() != 0
            || binding.san_dns_names.is_empty()
            || binding.san_dns_names.len() > MAX_BINDINGS
            || !strictly_sorted_unique(&binding.san_dns_names)
            || binding
                .san_dns_names
                .iter()
                .any(|name| !valid_dns_name(name))
            || !binding.san_dns_names.contains(&binding.server_name)
        {
            return Err(invalid(
                "TLS binding identity, certificate interval, or SAN inventory is invalid",
            ));
        }
        require_digest("TLS leaf SPKI", &binding.leaf_spki_digest)?;
        require_digest("TLS certificate chain", &binding.certificate_chain_digest)?;
    }

    for (binding, role) in ingress.routes.iter().zip(required_roles) {
        let required_path = match role {
            PublicOriginRole::PlatformApi => "/api",
            PublicOriginRole::PortalUi => "/",
        };
        let required_component = match role {
            PublicOriginRole::PlatformApi => "component:ryuki-api",
            PublicOriginRole::PortalUi => "component:ryuki-portal-ui",
        };
        if binding.origin_role != role
            || binding.path_prefix != required_path
            || binding.path_type != IngressPathType::Prefix
            || binding.backend_component_id != required_component
            || !valid_canonical_scoped_id(&binding.backend_workload_id, "workload:")
        {
            return Err(invalid(
                "ingress route role, prefix, component, or workload identity is invalid",
            ));
        }
        for (label, value) in [
            ("route generation", binding.route_generation_digest.as_str()),
            ("backend artifact", binding.backend_artifact_digest.as_str()),
            ("backend binding", binding.backend_binding_digest.as_str()),
        ] {
            require_digest(label, value)?;
        }
    }
    Ok(())
}

fn validate_ingress_for_request(
    ingress: &PublicIngressBinding,
    origins: &[PublicOriginBinding],
    request: &PublicIngressAttestationRequest,
) -> Result<(), PublicIngressError> {
    validate_ingress_shape(ingress)?;
    validate_origins(origins)?;
    for role in [PublicOriginRole::PlatformApi, PublicOriginRole::PortalUi] {
        let origin = origins
            .iter()
            .find(|origin| origin.role == role)
            .ok_or_else(|| invalid("public origin role is missing"))?;
        let hostname = canonical_origin_hostname(&origin.canonical_origin)?;
        let dns = ingress
            .dns_bindings
            .iter()
            .find(|binding| binding.origin_role == role)
            .ok_or_else(|| invalid("public origin has no DNS binding"))?;
        let tls = ingress
            .tls_bindings
            .iter()
            .find(|binding| binding.origin_role == role)
            .ok_or_else(|| invalid("public origin has no TLS binding"))?;
        if dns.hostname != hostname || tls.server_name != hostname {
            return Err(invalid(
                "public origin hostname differs from its DNS or TLS binding",
            ));
        }
    }

    let api_route = ingress
        .routes
        .iter()
        .find(|binding| binding.origin_role == PublicOriginRole::PlatformApi)
        .ok_or_else(|| invalid("platform API route is missing"))?;
    let portal_route = ingress
        .routes
        .iter()
        .find(|binding| binding.origin_role == PublicOriginRole::PortalUi)
        .ok_or_else(|| invalid("portal route is missing"))?;
    if api_route.backend_workload_id != request.namespace.workload_id
        || api_route.backend_artifact_digest != request.workload.artifact_digest
        || api_route.backend_binding_digest != request.workload.workload_instance_binding_digest
        || portal_route.backend_workload_id == request.namespace.workload_id
    {
        return Err(invalid(
            "ingress backend does not bind the challenged API workload and distinct portal workload",
        ));
    }
    Ok(())
}

fn canonical_origin_hostname(origin: &str) -> Result<String, PublicIngressError> {
    let parsed = Url::parse(origin).map_err(|_| invalid("public origin is not a valid URL"))?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(invalid(
            "public origin must be canonical HTTPS on port 443 without credentials, path, query, or fragment",
        ));
    }
    let Host::Domain(hostname) = parsed
        .host()
        .ok_or_else(|| invalid("public origin has no DNS hostname"))?
    else {
        return Err(invalid("public origin cannot use an IP literal"));
    };
    if !valid_dns_name(hostname) || origin != format!("https://{hostname}") {
        return Err(invalid("public origin is not in canonical lowercase form"));
    }
    Ok(hostname.to_owned())
}

fn valid_dns_name(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 || value.ends_with('.') {
        return false;
    }
    let valid = value.split('.').all(|label| {
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
    valid && value.contains('.')
}

fn verify_response_signature(
    value: &Value,
    authority: PublicIngressAuthorityAnchor<'_>,
) -> Result<(), PublicIngressError> {
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
    let mut signed =
        Vec::with_capacity(16 + PUBLIC_INGRESS_RESPONSE_DOMAIN.len() + canonical_subject.len());
    write_frame(&mut signed, PUBLIC_INGRESS_RESPONSE_DOMAIN.as_bytes());
    write_frame(&mut signed, &canonical_subject);

    let key = VerifyingKey::from_bytes(authority.public_key)
        .map_err(|_| invalid("invalid public-ingress authority Ed25519 key"))?;
    key.verify_strict(&signed, &signature)
        .map_err(|_| PublicIngressError::SignatureVerificationFailed)
}

fn validate_timestamp_lexemes(value: &Value) -> Result<(), PublicIngressError> {
    for pointer in [
        "/measurement/observed_at/not_before",
        "/measurement/observed_at/not_after",
        "/measurement/valid_until",
    ] {
        let timestamp = value
            .pointer(pointer)
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(format!("response timestamp {pointer} is missing")))?;
        validate_canonical_timestamp(timestamp, pointer)?;
    }
    let tls_bindings = value
        .pointer("/measurement/ingress/tls_bindings")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("response TLS bindings are missing"))?;
    for (index, binding) in tls_bindings.iter().enumerate() {
        for field in ["certificate_not_before", "certificate_not_after"] {
            let timestamp = binding
                .get(field)
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("response TLS certificate timestamp is missing"))?;
            validate_canonical_timestamp(
                timestamp,
                &format!("/measurement/ingress/tls_bindings/{index}/{field}"),
            )?;
        }
    }
    Ok(())
}

fn validate_canonical_timestamp(value: &str, pointer: &str) -> Result<(), PublicIngressError> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| invalid(format!("response timestamp {pointer} is invalid")))?;
    if value.len() > 35 || parsed.to_utc().to_rfc3339_opts(SecondsFormat::Secs, true) != value {
        return Err(invalid(format!(
            "response timestamp {pointer} is not canonical UTC-second RFC3339"
        )));
    }
    Ok(())
}

fn validate_json_shape(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), PublicIngressError> {
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
) -> Result<[u8; N], PublicIngressError> {
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

fn digest_projection(value: &Value) -> Result<String, PublicIngressError> {
    let canonical = canonical_json_bytes(value)
        .map_err(|error| invalid(format!("digest canonicalization failed: {error}")))?;
    Ok(sha256_digest(&canonical))
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn require_digest(label: &str, value: &str) -> Result<(), PublicIngressError> {
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
    (3..=191).contains(&suffix.len())
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

fn strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn invalid(message: impl Into<String>) -> PublicIngressError {
    PublicIngressError::Invalid(message.into())
}

#[cfg(any(test, feature = "security-test-support"))]
pub mod tests {
    #![cfg_attr(not(test), allow(dead_code, unused_imports))]

    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use chrono::TimeZone;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{Value, json};

    use super::*;
    use crate::security_profile::{
        RuntimeGuardExpectedValue, validate_runtime_guard_expected_value,
    };

    static TEST_ENTROPY_COUNTER: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        signing_key: SigningKey,
        public_key: [u8; 32],
        public_key_fingerprint: String,
        profile_id: String,
        profile_version: u64,
        profile_digest: String,
        origins: Vec<PublicOriginBinding>,
        ingress: PublicIngressBinding,
        origin_digest: String,
        ingress_digest: String,
        workload_instance_binding_digest: String,
        requirement_digest: String,
        challenge_binding_digest: String,
    }

    impl Fixture {
        fn new() -> Self {
            let signing_key = SigningKey::from_bytes(&test_entropy(b"ingress signing key"));
            let public_key = signing_key.verifying_key().to_bytes();
            let public_key_fingerprint = sha256_digest(&public_key);
            let profile_digest = digest_for(b"public ingress profile");
            let workload_instance_binding_digest = digest_for(b"workload instance");
            let origins = vec![
                PublicOriginBinding {
                    role: PublicOriginRole::PlatformApi,
                    canonical_origin: "https://api.ryuki.example.test".into(),
                },
                PublicOriginBinding {
                    role: PublicOriginRole::PortalUi,
                    canonical_origin: "https://portal.ryuki.example.test".into(),
                },
            ];
            let ingress = PublicIngressBinding {
                ingress_generation_digest: digest_for(b"ingress generation"),
                dns_bindings: vec![
                    DnsBinding {
                        origin_role: PublicOriginRole::PlatformApi,
                        hostname: "api.ryuki.example.test".into(),
                        authoritative_rrset_digest: digest_for(b"api RRset"),
                        dns_generation_digest: digest_for(b"api DNS generation"),
                    },
                    DnsBinding {
                        origin_role: PublicOriginRole::PortalUi,
                        hostname: "portal.ryuki.example.test".into(),
                        authoritative_rrset_digest: digest_for(b"portal RRset"),
                        dns_generation_digest: digest_for(b"portal DNS generation"),
                    },
                ],
                tls_bindings: vec![
                    TlsEndpointBinding {
                        origin_role: PublicOriginRole::PlatformApi,
                        server_name: "api.ryuki.example.test".into(),
                        leaf_spki_digest: digest_for(b"api leaf SPKI"),
                        certificate_chain_digest: digest_for(b"api certificate chain"),
                        san_dns_names: vec!["api.ryuki.example.test".into()],
                        certificate_not_before: instant(-3_600),
                        certificate_not_after: instant(86_400),
                        minimum_protocol: MinimumTlsProtocol::Tls12,
                        verification_method: TlsVerificationMethod::WebpkiHostnameAndChain,
                    },
                    TlsEndpointBinding {
                        origin_role: PublicOriginRole::PortalUi,
                        server_name: "portal.ryuki.example.test".into(),
                        leaf_spki_digest: digest_for(b"portal leaf SPKI"),
                        certificate_chain_digest: digest_for(b"portal certificate chain"),
                        san_dns_names: vec!["portal.ryuki.example.test".into()],
                        certificate_not_before: instant(-3_600),
                        certificate_not_after: instant(86_400),
                        minimum_protocol: MinimumTlsProtocol::Tls13,
                        verification_method: TlsVerificationMethod::WebpkiHostnameAndChain,
                    },
                ],
                routes: vec![
                    IngressRouteBinding {
                        origin_role: PublicOriginRole::PlatformApi,
                        path_prefix: "/api".into(),
                        path_type: IngressPathType::Prefix,
                        route_generation_digest: digest_for(b"api route generation"),
                        backend_workload_id: "workload:ryuki-api-test".into(),
                        backend_component_id: "component:ryuki-api".into(),
                        backend_artifact_digest: digest_for(b"API artifact"),
                        backend_binding_digest: workload_instance_binding_digest.clone(),
                    },
                    IngressRouteBinding {
                        origin_role: PublicOriginRole::PortalUi,
                        path_prefix: "/".into(),
                        path_type: IngressPathType::Prefix,
                        route_generation_digest: digest_for(b"portal route generation"),
                        backend_workload_id: "workload:ryuki-portal-test".into(),
                        backend_component_id: "component:ryuki-portal-ui".into(),
                        backend_artifact_digest: digest_for(b"portal artifact"),
                        backend_binding_digest: digest_for(b"portal backend binding"),
                    },
                ],
            };
            let origin_digest =
                public_origin_set_digest(&origins).expect("fixture origins must hash");
            let ingress_digest =
                public_ingress_binding_digest(&ingress).expect("fixture ingress must hash");
            let requirement_digest = digest_for(b"guard requirement");
            let challenge_binding_digest = digest_for(b"guard challenge");
            Self {
                signing_key,
                public_key,
                public_key_fingerprint,
                profile_id: "ingress-attestation-profile:test".into(),
                profile_version: 3,
                profile_digest,
                origins,
                ingress,
                origin_digest,
                ingress_digest,
                workload_instance_binding_digest,
                requirement_digest,
                challenge_binding_digest,
            }
        }

        fn authority(&self) -> PublicIngressAuthorityAnchor<'_> {
            PublicIngressAuthorityAnchor {
                authority_id: "public-ingress-attestation-authority:test",
                key_id: "public-ingress-attestation-key:test",
                public_key: &self.public_key,
                public_key_fingerprint: &self.public_key_fingerprint,
                minimum_authority_epoch: 7,
                attestation_profile_id: &self.profile_id,
                attestation_profile_version: self.profile_version,
                attestation_profile_digest: &self.profile_digest,
            }
        }

        fn expected(&self) -> ExpectedPublicIngress<'_> {
            ExpectedPublicIngress {
                deployment_id: "deployment:test",
                trust_domain_id: "trust-domain:test",
                workload_id: "workload:ryuki-api-test",
                source_revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                artifact_digest: &self.ingress.routes[0].backend_artifact_digest,
                workload_instance_binding_digest: &self.workload_instance_binding_digest,
                requirement_digest: &self.requirement_digest,
                challenge_binding_digest: &self.challenge_binding_digest,
                public_origin_set_digest: &self.origin_digest,
                ingress_binding_digest: &self.ingress_digest,
            }
        }

        fn request(&self) -> PublicIngressAttestationRequest {
            build_public_ingress_attestation_request(
                self.expected(),
                self.authority(),
                test_entropy(b"ingress request nonce"),
                instant(0),
            )
            .expect("fixture request must construct")
        }

        fn unsigned_response(&self, request: &PublicIngressAttestationRequest) -> Value {
            json!({
                "schema_version": PUBLIC_INGRESS_PROTOCOL_VERSION,
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
                "outcome": "matched",
                "measurement": {
                    "sequence": 19,
                    "method": MEASUREMENT_METHOD,
                    "observed_at": {
                        "not_before": instant(1),
                        "not_after": instant(2)
                    },
                    "valid_until": instant(120),
                    "restored_state_reconciled": true,
                    "public_origins": self.origins,
                    "public_origin_set_digest": self.origin_digest,
                    "ingress": self.ingress,
                    "ingress_binding_digest": self.ingress_digest
                },
                "signature_base64": ""
            })
        }

        fn signed_response(&self, request: &PublicIngressAttestationRequest) -> Vec<u8> {
            sign_response(
                self.unsigned_response(request),
                &self.signing_key,
                PUBLIC_INGRESS_RESPONSE_DOMAIN,
            )
        }
    }

    fn instant(offset_seconds: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 19, 10, 0, 0).unwrap() + TimeDelta::seconds(offset_seconds)
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
        hasher.update(b"ryuki public-ingress test entropy");
        hasher.update(label);
        hasher.update(std::process::id().to_le_bytes());
        hasher.update(counter.to_le_bytes());
        hasher.update(elapsed.to_le_bytes());
        hasher.finalize().into()
    }

    fn sign_response(mut response: Value, key: &SigningKey, domain: &str) -> Vec<u8> {
        response
            .as_object_mut()
            .expect("fixture response is an object")
            .remove("signature_base64");
        let canonical = canonical_json_bytes(&response).expect("fixture response canonicalizes");
        let mut signed = Vec::with_capacity(16 + domain.len() + canonical.len());
        write_frame(&mut signed, domain.as_bytes());
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

    /// Independent golden for the exact role-tagged production-composition
    /// origins below. Keep the closure fixture's copy separate so changing a
    /// fixture constructor cannot silently bless a new expected value.
    #[cfg(feature = "security-test-support")]
    pub const GENUINE_PUBLIC_ORIGIN_SET_DIGEST: &str =
        "sha256:bbecce0b5f74832b9e6cd285a60e3d0df2edd97f4aab88da09cd0300398589b5";

    /// Independent golden for the complete deterministic DNS, TLS, route,
    /// artifact, and workload-instance projection below.
    #[cfg(feature = "security-test-support")]
    pub const GENUINE_PUBLIC_INGRESS_BINDING_DIGEST: &str =
        "sha256:2982c5fad2f24909662f88025ee5049f1a4d4c0a9d21109b9a216c7dba688064";

    #[cfg(feature = "security-test-support")]
    pub struct GenuinePublicIngressFixtureInput<'a> {
        pub deployment_id: &'a str,
        pub trust_domain_id: &'a str,
        pub workload_id: &'a str,
        pub source_revision: &'a str,
        pub artifact_digest: &'a str,
        pub workload_instance_binding_digest: &'a str,
        pub requirement_digest: &'a str,
        pub challenge_binding_digest: &'a str,
        pub attestation_profile_id: &'a str,
        pub attestation_profile_version: u64,
        pub attestation_profile_digest: &'a str,
        pub valid_for_seconds: i64,
    }

    #[cfg(feature = "security-test-support")]
    fn genuine_public_origins() -> Vec<PublicOriginBinding> {
        vec![
            PublicOriginBinding {
                role: PublicOriginRole::PlatformApi,
                canonical_origin: "https://api.ryuki.example.test".into(),
            },
            PublicOriginBinding {
                role: PublicOriginRole::PortalUi,
                canonical_origin: "https://portal.ryuki.example.test".into(),
            },
        ]
    }

    #[cfg(feature = "security-test-support")]
    fn genuine_public_ingress(
        workload_id: &str,
        artifact_digest: &str,
        workload_instance_binding_digest: &str,
        composition_base: DateTime<Utc>,
    ) -> PublicIngressBinding {
        PublicIngressBinding {
            ingress_generation_digest: sha256_digest(b"ryuki genuine public ingress generation v1"),
            dns_bindings: vec![
                DnsBinding {
                    origin_role: PublicOriginRole::PlatformApi,
                    hostname: "api.ryuki.example.test".into(),
                    authoritative_rrset_digest: sha256_digest(
                        b"ryuki genuine API authoritative RRset v1",
                    ),
                    dns_generation_digest: sha256_digest(b"ryuki genuine API DNS generation v1"),
                },
                DnsBinding {
                    origin_role: PublicOriginRole::PortalUi,
                    hostname: "portal.ryuki.example.test".into(),
                    authoritative_rrset_digest: sha256_digest(
                        b"ryuki genuine portal authoritative RRset v1",
                    ),
                    dns_generation_digest: sha256_digest(b"ryuki genuine portal DNS generation v1"),
                },
            ],
            tls_bindings: vec![
                TlsEndpointBinding {
                    origin_role: PublicOriginRole::PlatformApi,
                    server_name: "api.ryuki.example.test".into(),
                    leaf_spki_digest: sha256_digest(b"ryuki genuine API TLS leaf SPKI v1"),
                    certificate_chain_digest: sha256_digest(
                        b"ryuki genuine API TLS certificate chain v1",
                    ),
                    san_dns_names: vec!["api.ryuki.example.test".into()],
                    certificate_not_before: composition_base - TimeDelta::days(1),
                    certificate_not_after: composition_base + TimeDelta::days(1),
                    minimum_protocol: MinimumTlsProtocol::Tls13,
                    verification_method: TlsVerificationMethod::WebpkiHostnameAndChain,
                },
                TlsEndpointBinding {
                    origin_role: PublicOriginRole::PortalUi,
                    server_name: "portal.ryuki.example.test".into(),
                    leaf_spki_digest: sha256_digest(b"ryuki genuine portal TLS leaf SPKI v1"),
                    certificate_chain_digest: sha256_digest(
                        b"ryuki genuine portal TLS certificate chain v1",
                    ),
                    san_dns_names: vec!["portal.ryuki.example.test".into()],
                    certificate_not_before: composition_base - TimeDelta::days(1),
                    certificate_not_after: composition_base + TimeDelta::days(1),
                    minimum_protocol: MinimumTlsProtocol::Tls13,
                    verification_method: TlsVerificationMethod::WebpkiHostnameAndChain,
                },
            ],
            routes: vec![
                IngressRouteBinding {
                    origin_role: PublicOriginRole::PlatformApi,
                    path_prefix: "/api".into(),
                    path_type: IngressPathType::Prefix,
                    route_generation_digest: sha256_digest(
                        b"ryuki genuine API route generation v1",
                    ),
                    backend_workload_id: workload_id.into(),
                    backend_component_id: "component:ryuki-api".into(),
                    backend_artifact_digest: artifact_digest.into(),
                    backend_binding_digest: workload_instance_binding_digest.into(),
                },
                IngressRouteBinding {
                    origin_role: PublicOriginRole::PortalUi,
                    path_prefix: "/".into(),
                    path_type: IngressPathType::Prefix,
                    route_generation_digest: sha256_digest(
                        b"ryuki genuine portal route generation v1",
                    ),
                    backend_workload_id: "workload:ryuki-portal-fixture".into(),
                    backend_component_id: "component:ryuki-portal-ui".into(),
                    backend_artifact_digest: sha256_digest(b"ryuki genuine portal artifact v1"),
                    backend_binding_digest: sha256_digest(
                        b"ryuki genuine portal workload binding v1",
                    ),
                },
            ],
        }
    }

    /// Produces one genuinely signed deterministic ingress measurement for
    /// API admission composition tests. The production verifier remains the
    /// only constructor of the returned opaque witness.
    #[cfg(feature = "security-test-support")]
    pub fn genuine_public_ingress_fixture(
        input: GenuinePublicIngressFixtureInput<'_>,
    ) -> Result<VerifiedHttpsPublicUrlsWitness, PublicIngressError> {
        let composition_base = Utc
            .with_ymd_and_hms(2026, 7, 16, 12, 0, 0)
            .single()
            .expect("composition fixture instant is valid");
        let mut fixture = Fixture::new();
        fixture.profile_id = input.attestation_profile_id.into();
        fixture.profile_version = input.attestation_profile_version;
        fixture.profile_digest = input.attestation_profile_digest.into();
        fixture.workload_instance_binding_digest = input.workload_instance_binding_digest.into();
        fixture.requirement_digest = input.requirement_digest.into();
        fixture.challenge_binding_digest = input.challenge_binding_digest.into();
        fixture.origins = genuine_public_origins();
        fixture.ingress = genuine_public_ingress(
            input.workload_id,
            input.artifact_digest,
            input.workload_instance_binding_digest,
            composition_base,
        );
        fixture.origin_digest = public_origin_set_digest(&fixture.origins)?;
        fixture.ingress_digest = public_ingress_binding_digest(&fixture.ingress)?;
        if fixture.origin_digest != GENUINE_PUBLIC_ORIGIN_SET_DIGEST
            || fixture.ingress_digest != GENUINE_PUBLIC_INGRESS_BINDING_DIGEST
        {
            return Err(invalid(format!(
                "genuine public-ingress preimage drifted from its independent golden digests (origin {}, ingress {})",
                fixture.origin_digest, fixture.ingress_digest
            )));
        }

        let authority = fixture.authority();
        let request = build_public_ingress_attestation_request(
            ExpectedPublicIngress {
                deployment_id: input.deployment_id,
                trust_domain_id: input.trust_domain_id,
                workload_id: input.workload_id,
                source_revision: input.source_revision,
                artifact_digest: input.artifact_digest,
                workload_instance_binding_digest: input.workload_instance_binding_digest,
                requirement_digest: input.requirement_digest,
                challenge_binding_digest: input.challenge_binding_digest,
                public_origin_set_digest: &fixture.origin_digest,
                ingress_binding_digest: &fixture.ingress_digest,
            },
            authority,
            test_entropy(b"genuine public-ingress composition request nonce"),
            composition_base + TimeDelta::seconds(6),
        )?;
        let mut response = fixture.unsigned_response(&request);
        response["measurement"]["observed_at"]["not_before"] =
            json!(composition_base + TimeDelta::seconds(7));
        response["measurement"]["observed_at"]["not_after"] =
            json!(composition_base + TimeDelta::seconds(8));
        response["measurement"]["valid_until"] =
            json!(composition_base + TimeDelta::seconds(input.valid_for_seconds));
        let response = sign_response(
            response,
            &fixture.signing_key,
            PUBLIC_INGRESS_RESPONSE_DOMAIN,
        );
        verify_public_ingress_attestation(
            request,
            &response,
            authority,
            ConformanceTrustedTimeWindow {
                not_before: composition_base + TimeDelta::seconds(9),
                not_after: composition_base + TimeDelta::seconds(10),
            },
        )
    }

    #[test]
    fn attestation_profile_namespace_matches_authoritative_guard_contract() {
        let fixture = Fixture::new();
        let authority = fixture.authority();
        let expected_value = RuntimeGuardExpectedValue::HttpsPublicUrls {
            public_origin_set_digest: fixture.origin_digest.clone(),
            ingress_binding_digest: fixture.ingress_digest.clone(),
            attestation_profile_id: authority.attestation_profile_id.to_owned(),
            attestation_profile_version: authority.attestation_profile_version,
            attestation_profile_digest: authority.attestation_profile_digest.to_owned(),
        };
        let mut errors = Vec::new();
        validate_runtime_guard_expected_value(&expected_value, &mut errors);
        assert!(
            errors.is_empty(),
            "guard rejected ingress profile: {errors:?}"
        );
        fixture.request();
    }

    #[test]
    fn signed_fixture_and_closed_role_order_match_the_json_schema() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../catalog/security-contracts/v1/public-ingress-attestation-envelope.schema.json"
        ))
        .expect("public-ingress schema must be JSON");
        let validator = jsonschema::draft202012::options()
            .build(&schema)
            .expect("public-ingress schema must compile");
        let fixture = Fixture::new();
        let response: Value = serde_json::from_slice(&fixture.signed_response(&fixture.request()))
            .expect("signed fixture response must be JSON");
        assert!(validator.is_valid(&response));

        for pointer in [
            "/measurement/public_origins",
            "/measurement/ingress/dns_bindings",
            "/measurement/ingress/tls_bindings",
            "/measurement/ingress/routes",
        ] {
            let mut reversed = response.clone();
            reversed
                .pointer_mut(pointer)
                .and_then(Value::as_array_mut)
                .expect("fixture inventory must exist")
                .reverse();
            assert!(
                !validator.is_valid(&reversed),
                "schema accepted reversed inventory at {pointer}"
            );
        }

        let mut duplicate_role = response.clone();
        duplicate_role["measurement"]["ingress"]["routes"][1]["origin_role"] =
            Value::String("platform-api".into());
        assert!(!validator.is_valid(&duplicate_role));

        for (pointer, invalid_value) in [
            ("/namespace/deployment_id", "deployment:abc/def"),
            ("/namespace/trust_domain_id", "trust-domain:abc/def"),
            ("/namespace/workload_id", "workload:abc/def"),
            (
                "/attestation_profile/profile_id",
                "ingress-attestation-profile:abc/def",
            ),
            (
                "/workload/source_revision",
                "0000000000000000000000000000000000000000",
            ),
        ] {
            let mut invalid = response.clone();
            *invalid
                .pointer_mut(pointer)
                .expect("fixture binding must exist") = Value::String(invalid_value.into());
            assert!(
                !validator.is_valid(&invalid),
                "schema accepted noncanonical binding at {pointer}"
            );
        }
    }

    #[test]
    fn genuine_signed_public_ingress_attestation_verifies_exact_live_projection() {
        let fixture = Fixture::new();
        let request = fixture.request();
        let response = fixture.signed_response(&request);
        let witness = verify_public_ingress_attestation(
            request,
            &response,
            fixture.authority(),
            trusted_now(3, 4),
        )
        .expect("exact signed public-ingress measurement must verify");
        assert_eq!(witness.public_origin_set_digest(), fixture.origin_digest);
        assert_eq!(witness.ingress_binding_digest(), fixture.ingress_digest);
        assert_eq!(witness.public_origins(), fixture.origins);
        assert_eq!(witness.ingress(), &fixture.ingress);
        witness
            .ensure_fresh(trusted_now(5, 6))
            .expect("witness remains fresh before the exclusive fence");
        assert!(!format!("{witness:?}").contains("api.ryuki.example.test"));
    }

    #[test]
    fn request_and_origin_validation_reject_noncanonical_or_unbound_inputs() {
        let fixture = Fixture::new();
        let error = build_public_ingress_attestation_request(
            fixture.expected(),
            fixture.authority(),
            [0; 32],
            instant(0),
        )
        .unwrap_err();
        assert!(error.to_string().contains("nonce"));

        let mut invalid = fixture.expected();
        invalid.deployment_id = "deployment:abc/def";
        assert!(
            build_public_ingress_attestation_request(
                invalid,
                fixture.authority(),
                test_entropy(b"invalid deployment ID"),
                instant(0),
            )
            .is_err()
        );

        let mut invalid = fixture.expected();
        invalid.source_revision = "0000000000000000000000000000000000000000";
        assert!(
            build_public_ingress_attestation_request(
                invalid,
                fixture.authority(),
                test_entropy(b"zero source revision"),
                instant(0),
            )
            .is_err()
        );

        let mut invalid_authority = fixture.authority();
        invalid_authority.attestation_profile_id = "ingress-attestation-profile:abc/def";
        assert!(
            build_public_ingress_attestation_request(
                fixture.expected(),
                invalid_authority,
                test_entropy(b"invalid profile ID"),
                instant(0),
            )
            .is_err()
        );

        for origin in [
            "http://api.ryuki.example.test",
            "https://API.ryuki.example.test",
            "https://api.ryuki.example.test:443",
            "https://api.ryuki.example.test/",
            "https://127.0.0.1",
        ] {
            let mut origins = fixture.origins.clone();
            origins[0].canonical_origin = origin.into();
            assert!(public_origin_set_digest(&origins).is_err(), "{origin}");
        }
    }

    #[test]
    fn signature_domain_and_signed_measurement_substitution_fail_closed() {
        let fixture = Fixture::new();
        let request = fixture.request();
        let wrong_domain = sign_response(
            fixture.unsigned_response(&request),
            &fixture.signing_key,
            "ryuki-v1/not-public-ingress",
        );
        assert_eq!(
            verify_public_ingress_attestation(
                request,
                &wrong_domain,
                fixture.authority(),
                trusted_now(3, 4),
            )
            .unwrap_err(),
            PublicIngressError::SignatureVerificationFailed
        );

        let request = fixture.request();
        let mut altered = fixture.unsigned_response(&request);
        altered["measurement"]["ingress"]["routes"][0]["backend_artifact_digest"] =
            Value::String(digest_for(b"substituted artifact"));
        let altered = sign_response(
            altered,
            &fixture.signing_key,
            PUBLIC_INGRESS_RESPONSE_DOMAIN,
        );
        let error = verify_public_ingress_attestation(
            request,
            &altered,
            fixture.authority(),
            trusted_now(3, 4),
        )
        .unwrap_err();
        assert!(matches!(error, PublicIngressError::Invalid(_)));
    }

    #[test]
    fn workload_challenge_and_namespace_replay_fail_even_when_resigned() {
        let fixture = Fixture::new();
        let request = fixture.request();
        let mut altered = fixture.unsigned_response(&request);
        altered["guard"]["challenge_binding_digest"] =
            Value::String(digest_for(b"other workload challenge"));
        let altered = sign_response(
            altered,
            &fixture.signing_key,
            PUBLIC_INGRESS_RESPONSE_DOMAIN,
        );
        assert!(
            verify_public_ingress_attestation(
                request,
                &altered,
                fixture.authority(),
                trusted_now(3, 4),
            )
            .unwrap_err()
            .to_string()
            .contains("request echo")
        );

        let request = fixture.request();
        let mut altered = fixture.unsigned_response(&request);
        altered["namespace"]["deployment_id"] = Value::String("deployment:other".into());
        let altered = sign_response(
            altered,
            &fixture.signing_key,
            PUBLIC_INGRESS_RESPONSE_DOMAIN,
        );
        assert!(
            verify_public_ingress_attestation(
                request,
                &altered,
                fixture.authority(),
                trusted_now(3, 4),
            )
            .is_err()
        );
    }

    #[test]
    fn freshness_certificate_and_epoch_bounds_are_exclusive() {
        let fixture = Fixture::new();
        let request = fixture.request();
        let response = fixture.signed_response(&request);
        assert!(
            verify_public_ingress_attestation(
                request,
                &response,
                fixture.authority(),
                trusted_now(119, 120),
            )
            .is_err()
        );

        let request = fixture.request();
        let mut altered = fixture.unsigned_response(&request);
        altered["authority"]["authority_epoch"] = Value::from(6);
        let altered = sign_response(
            altered,
            &fixture.signing_key,
            PUBLIC_INGRESS_RESPONSE_DOMAIN,
        );
        assert!(
            verify_public_ingress_attestation(
                request,
                &altered,
                fixture.authority(),
                trusted_now(3, 4),
            )
            .is_err()
        );

        let request = fixture.request();
        let mut altered = fixture.unsigned_response(&request);
        altered["measurement"]["ingress"]["tls_bindings"][0]["certificate_not_after"] =
            json!(instant(100));
        let altered = sign_response(
            altered,
            &fixture.signing_key,
            PUBLIC_INGRESS_RESPONSE_DOMAIN,
        );
        assert!(
            verify_public_ingress_attestation(
                request,
                &altered,
                fixture.authority(),
                trusted_now(3, 4),
            )
            .is_err()
        );

        let mut ingress = fixture.ingress.clone();
        ingress.tls_bindings[0].certificate_not_after += TimeDelta::milliseconds(1);
        assert!(public_ingress_binding_digest(&ingress).is_err());
    }

    #[test]
    fn sorted_exact_role_and_backend_coverage_is_mandatory() {
        let fixture = Fixture::new();
        let mut origins = fixture.origins.clone();
        origins.swap(0, 1);
        assert!(public_origin_set_digest(&origins).is_err());

        let mut ingress = fixture.ingress.clone();
        ingress.routes[0].backend_workload_id = "workload:other-api".into();
        let ingress_digest =
            public_ingress_binding_digest(&ingress).expect("shape remains canonical");
        let request = fixture.request();
        let mut altered = fixture.unsigned_response(&request);
        altered["measurement"]["ingress"] = serde_json::to_value(&ingress).unwrap();
        altered["measurement"]["ingress_binding_digest"] = Value::String(ingress_digest);
        let altered = sign_response(
            altered,
            &fixture.signing_key,
            PUBLIC_INGRESS_RESPONSE_DOMAIN,
        );
        assert!(
            verify_public_ingress_attestation(
                request,
                &altered,
                fixture.authority(),
                trusted_now(3, 4),
            )
            .is_err()
        );
    }

    #[test]
    fn challenged_api_instance_must_be_the_routed_backend_instance() {
        let fixture = Fixture::new();
        let mut ingress = fixture.ingress.clone();
        ingress.routes[0].backend_binding_digest = digest_for(b"different API instance");
        let ingress_digest =
            public_ingress_binding_digest(&ingress).expect("alternate ingress remains canonical");
        let mut expected = fixture.expected();
        expected.ingress_binding_digest = &ingress_digest;
        let request = build_public_ingress_attestation_request(
            expected,
            fixture.authority(),
            test_entropy(b"different instance request nonce"),
            instant(0),
        )
        .expect("alternate request must construct");
        let mut altered = fixture.unsigned_response(&request);
        altered["measurement"]["ingress"] = serde_json::to_value(&ingress).unwrap();
        altered["measurement"]["ingress_binding_digest"] = Value::String(ingress_digest);
        let altered = sign_response(
            altered,
            &fixture.signing_key,
            PUBLIC_INGRESS_RESPONSE_DOMAIN,
        );
        assert!(
            verify_public_ingress_attestation(
                request,
                &altered,
                fixture.authority(),
                trusted_now(3, 4),
            )
            .is_err()
        );
    }

    #[test]
    fn strict_json_unknown_duplicate_and_size_bounds_fail_before_authority() {
        let fixture = Fixture::new();
        let request = fixture.request();
        let mut unknown = fixture.unsigned_response(&request);
        unknown["unexpected"] = Value::Bool(true);
        let unknown = sign_response(
            unknown,
            &fixture.signing_key,
            PUBLIC_INGRESS_RESPONSE_DOMAIN,
        );
        assert!(
            verify_public_ingress_attestation(
                request,
                &unknown,
                fixture.authority(),
                trusted_now(3, 4),
            )
            .is_err()
        );

        let request = fixture.request();
        let response = String::from_utf8(fixture.signed_response(&request)).unwrap();
        let duplicate = response.replacen(
            "\"outcome\":\"matched\"",
            "\"outcome\":\"matched\",\"outcome\":\"matched\"",
            1,
        );
        assert!(
            verify_public_ingress_attestation(
                request,
                duplicate.as_bytes(),
                fixture.authority(),
                trusted_now(3, 4),
            )
            .is_err()
        );

        let request = fixture.request();
        let oversized = vec![b' '; MAX_PUBLIC_INGRESS_RESPONSE_BYTES + 1];
        assert!(
            verify_public_ingress_attestation(
                request,
                &oversized,
                fixture.authority(),
                trusted_now(3, 4),
            )
            .is_err()
        );
    }
}
