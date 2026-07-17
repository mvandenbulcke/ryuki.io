//! Pure, fail-closed verification for signed conformance closure documents.
//!
//! This module deliberately performs no file or network I/O. Callers load and
//! independently pin registry bytes to construct a
//! [`ValidatedConformanceRegistryLineage`], exchange its opaque canonical
//! request through a bounded transport, and obtain document-verification
//! authority only as a [`VerifiedConformanceTrustCheckpoint`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{DateTime, TimeDelta, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const TRUST_REGISTRY_SCHEMA_URI: &str =
    "https://ryuki.io/schemas/security-contracts/v1/conformance-trust-root-registry.schema.json";
pub const TRUST_REGISTRY_SCHEMA_VERSION: &str = "1.0.0";
pub const TRUST_REGISTRY_CONTRACT_KIND: &str = "conformance-trust-root-registry";
pub const SIGNATURE_VERSION: &str = "1.0.0";
pub const CANONICALIZATION_PROFILE: &str = "ryuki-canonical-json-v1";
pub const SIGNATURE_ALGORITHM: &str = "ed25519";
pub const CONFORMANCE_BUNDLE_DOMAIN: &str = "ryuki-v1/conformance-bundle";
pub const PACKAGE_EXIT_RECEIPT_DOMAIN: &str = "ryuki-v1/package-exit-receipt";
pub const TRUST_RECONCILIATION_REQUEST_KIND: &str = "conformance-trust-reconciliation-request";
pub const TRUST_RECONCILIATION_RESPONSE_KIND: &str = "conformance-trust-reconciliation-response";
pub const TRUST_RECONCILIATION_REQUEST_DOMAIN: &str =
    "ryuki-v1/conformance-trust-reconciliation-request";
pub const TRUST_RECONCILIATION_RESPONSE_DOMAIN: &str =
    "ryuki-v1/conformance-trust-reconciliation-response";

const MAX_REGISTRY_LINEAGE: usize = 16;
const MAX_REGISTRY_BYTES: usize = 4 * 1024 * 1024;
const MAX_KEYS_PER_REGISTRY: usize = 256;
const MAX_TOMBSTONES_PER_REGISTRY: usize = 4096;
const MAX_SCOPE_ITEMS: usize = 256;
const MAX_RECONCILIATION_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
const MAX_RECONCILIATION_REQUEST_BYTES: usize = 512 * 1024;
const MAX_ACCEPTANCE_RECORDS: usize = 4096;
const MAX_CHECKPOINT_STRING_BYTES: usize = 1024;
const MAX_RECONCILIATION_LIFETIME_SECONDS: i64 = 300;
const MAX_CONFORMANCE_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_CANONICAL_JSON_COUNTER: u64 = 9_007_199_254_740_991;

const CONFORMANCE_BUNDLE_SCHEMA_URI: &str =
    "https://ryuki.io/schemas/security-contracts/v1/conformance-bundle.schema.json";
const PACKAGE_EXIT_RECEIPT_SCHEMA_URI: &str =
    "https://ryuki.io/schemas/security-contracts/v1/package-exit-receipt.schema.json";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConformanceTrustError {
    #[error("invalid conformance trust contract: {0}")]
    InvalidContract(String),
    #[error("unknown field or invalid typed value: {0}")]
    InvalidTypedValue(String),
    #[error("non-integer JSON number is forbidden by ryuki-canonical-json-v1")]
    NonIntegerNumber,
    #[error("invalid canonical base64 in {0}")]
    InvalidBase64(&'static str),
    #[error("unknown conformance signing key {0}")]
    UnknownKey(String),
    #[error("conformance signing key is not currently authorized: {0}")]
    KeyNotAuthorized(String),
    #[error("conformance signature scope mismatch: {0}")]
    ScopeMismatch(String),
    #[error("conformance signed-subject digest mismatch")]
    SubjectDigestMismatch,
    #[error("conformance signature verification failed")]
    InvalidSignature,
    #[error("invalid external conformance trust checkpoint: {0}")]
    InvalidCheckpoint(String),
    #[error("external conformance trust checkpoint authority signature verification failed")]
    InvalidCheckpointSignature,
    #[error("external conformance trust checkpoint requires operator action: {0}")]
    ReconciliationRequired(String),
    #[error("trusted document acceptance record is missing or invalid: {0}")]
    InvalidAcceptance(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformancePurpose {
    ConformanceBundle,
    PackageExitReceipt,
}

impl ConformancePurpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::ConformanceBundle => "conformance_bundle",
            Self::PackageExitReceipt => "package_exit_receipt",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceTier {
    RepositoryLocal,
    OperatorEnvironment,
    ExternallyAttested,
}

impl EvidenceTier {
    fn as_str(self) -> &'static str {
        match self {
            Self::RepositoryLocal => "repository_local",
            Self::OperatorEnvironment => "operator_environment",
            Self::ExternallyAttested => "externally_attested",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConformanceDocumentKind {
    ConformanceBundle,
    PackageExitReceipt,
}

impl ConformanceDocumentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConformanceBundle => "conformance-bundle",
            Self::PackageExitReceipt => "package-exit-receipt",
        }
    }

    fn purpose(self) -> ConformancePurpose {
        match self {
            Self::ConformanceBundle => ConformancePurpose::ConformanceBundle,
            Self::PackageExitReceipt => ConformancePurpose::PackageExitReceipt,
        }
    }

    fn domain(self) -> &'static str {
        match self {
            Self::ConformanceBundle => CONFORMANCE_BUNDLE_DOMAIN,
            Self::PackageExitReceipt => PACKAGE_EXIT_RECEIPT_DOMAIN,
        }
    }

    fn schema_uri(self) -> &'static str {
        match self {
            Self::ConformanceBundle => CONFORMANCE_BUNDLE_SCHEMA_URI,
            Self::PackageExitReceipt => PACKAGE_EXIT_RECEIPT_SCHEMA_URI,
        }
    }
}

/// One exact trust-registry artifact in oldest-to-current order.
#[derive(Debug, Clone, Copy)]
pub struct ConformanceRegistryArtifact<'a> {
    pub artifact_locator: &'a str,
    pub raw_bytes: &'a [u8],
}

/// The independently configured pin for the current trust-registry head.
#[derive(Debug, Clone, Copy)]
pub struct ConformanceTrustAnchor<'a> {
    pub artifact_locator: &'a str,
    pub document_id: &'a str,
    pub document_version: u64,
    pub content_digest: &'a str,
}

/// Exact external checkpoint namespace. The registry id is taken from the
/// validated lineage; callers only supply the deployment and trust domain.
#[derive(Debug, Clone, Copy)]
pub struct ConformanceTrustScope<'a> {
    pub deployment_id: &'a str,
    pub trust_domain_id: &'a str,
}

/// Independently provisioned external checkpoint authority pin.
///
/// The raw public key and its fingerprint are both required so a text/config
/// substitution cannot silently change key material. `minimum_authority_epoch`
/// is an independently retained rollback fence.
#[derive(Debug, Clone, Copy)]
pub struct ConformanceCheckpointAuthorityAnchor<'a> {
    pub authority_id: &'a str,
    pub key_id: &'a str,
    pub public_key: &'a [u8; 32],
    pub public_key_fingerprint: &'a str,
    pub minimum_authority_epoch: u64,
}

/// Caller-provided trusted-clock uncertainty used only for response freshness.
/// It never supplies document acceptance time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConformanceTrustedTimeWindow {
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CheckpointNamespace {
    deployment_id: String,
    trust_domain_id: String,
    registry_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CheckpointRegistryHead {
    registry_version: u64,
    content_digest: String,
    artifact_locator: String,
}

/// Opaque canonical request for the semantic-free checkpoint transport.
#[derive(Debug, Clone)]
pub struct ConformanceCheckpointRequest {
    canonical_bytes: Vec<u8>,
    digest: String,
    nonce: String,
    authority_id: String,
    authority_key_id: String,
    namespace: CheckpointNamespace,
    candidate_head: CheckpointRegistryHead,
    validated_lineage_digest: String,
    requested_document_digests: Vec<String>,
}

impl ConformanceCheckpointRequest {
    pub fn as_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// Pure classification of local and externally retained heads. Only `Matched`
/// can produce a runtime verification capability in this protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConformanceReconciliationDecision {
    Missing,
    Matched,
    Rollback,
    SameVersionFork,
    RelocationRequired,
    AdvanceRequired,
    NonDescendant,
    WrongScope,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconciliationResponse {
    schema_version: String,
    contract_kind: String,
    canonicalization: String,
    signature_algorithm: String,
    authority: ResponseAuthority,
    request_nonce: String,
    request_digest: String,
    namespace: CheckpointNamespace,
    candidate_head: CheckpointRegistryHead,
    current_head: CheckpointRegistryHead,
    validated_lineage_digest: String,
    state: String,
    outcome: String,
    reconciliation: ResponseReconciliation,
    checkpoint: ResponseCheckpoint,
    acceptance_records: Vec<TrustedAcceptanceRecord>,
    #[serde(rename = "signature_base64")]
    _signature_base64: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseAuthority {
    authority_id: String,
    key_id: String,
    public_key_fingerprint: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseReconciliation {
    candidate_matches_current: bool,
    restored_state_reconciled: bool,
    no_auto_advance: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseCheckpoint {
    sequence: u64,
    authority_epoch: u64,
    authority_revision: u64,
    observed_at: TrustedTimeInterval,
    valid_until: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TrustedTimeInterval {
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedAcceptanceRecord {
    acceptance_record_id: String,
    document: AcceptedDocument,
    signer: AcceptedSigner,
    registry: AcceptedRegistry,
    deployment_id: String,
    trust_domain_id: String,
    work_package_id: String,
    purpose: ConformancePurpose,
    evidence_tier: EvidenceTier,
    authority_sequence: u64,
    authority_epoch: u64,
    accepted_at: TrustedTimeInterval,
    lifecycle: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptedDocument {
    contract_kind: String,
    document_id: String,
    document_version: u64,
    complete_document_digest: String,
    signature_digest: String,
    signed_subject_digest: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptedSigner {
    key_id: String,
    public_key_fingerprint: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptedRegistry {
    registry_id: String,
    registry_version: u64,
    registry_digest: String,
    artifact_locator: String,
    head_sequence: u64,
    head_authority_revision: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TrustRegistryDocument {
    #[serde(rename = "$schema")]
    schema_uri: String,
    schema_version: String,
    contract_kind: String,
    document_id: String,
    document_version: u64,
    predecessor_registry_ref: Option<PredecessorRegistryRef>,
    acceptance_status: RegistryAcceptanceStatus,
    production_accepted: bool,
    lifecycle: RegistryLifecycle,
    applicability: RegistryApplicability,
    trust_policy_version: u64,
    canonicalization_profiles: Vec<String>,
    signature_algorithms: Vec<String>,
    keys: Vec<VerificationKeyMetadata>,
    key_tombstones: Vec<KeyTombstone>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PredecessorRegistryRef {
    artifact_kind: String,
    document_id: String,
    document_version: u64,
    content_digest: String,
    artifact_locator: String,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RegistryAcceptanceStatus {
    ImplementationOnly,
    ProductionCandidate,
    ProductionAccepted,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RegistryLifecycle {
    state: RegistryLifecycleState,
    effective_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RegistryLifecycleState {
    ImplementationOnly,
    Candidate,
    Active,
    Deprecated,
    Retired,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RegistryApplicability {
    evaluation_scope: String,
    security_profiles: Vec<SecurityProfile>,
    deployment_ids: Vec<String>,
    trust_domain_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum SecurityProfile {
    Development,
    Test,
    Production,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct VerificationKeyMetadata {
    key_id: String,
    signer_identity: String,
    algorithm: String,
    public_key_base64: String,
    public_key_fingerprint: String,
    allowed_purposes: Vec<ConformancePurpose>,
    allowed_evidence_tiers: Vec<EvidenceTier>,
    allowed_package_ids: Vec<String>,
    deployment_ids: Vec<String>,
    trust_domain_ids: Vec<String>,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    lifecycle: KeyLifecycle,
    supersedes_key_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum KeyLifecycle {
    Active,
    Overlap,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct KeyTombstone {
    key_id: String,
    signer_identity: String,
    algorithm: String,
    public_key_fingerprint: String,
    terminal_state: KeyTerminalState,
    terminated_at: DateTime<Utc>,
    signatures_valid_before: Option<DateTime<Utc>>,
    reason: String,
    superseded_by_key_id: Option<String>,
    trust_policy_version: u64,
    subsequent_revocation: Option<SubsequentRevocation>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SubsequentRevocation {
    revoked_at: DateTime<Utc>,
    reason: String,
    trust_policy_version: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum KeyTerminalState {
    Retired,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceSignatureMetadata {
    pub signature_version: String,
    pub identity: String,
    pub key_id: String,
    pub algorithm: String,
    pub canonicalization: String,
    pub purpose: ConformancePurpose,
    pub domain: String,
    pub trust_registry_id: String,
    pub trust_registry_version: u64,
    pub trust_registry_digest: String,
    pub signed_at: DateTime<Utc>,
    pub signed_subject_digest: String,
    pub signature_base64: String,
}

#[derive(Debug, Clone, Copy)]
pub struct ConformanceVerificationContext<'a> {
    pub deployment_id: &'a str,
    pub trust_domain_id: &'a str,
    pub package_id: &'a str,
    pub evidence_tier: EvidenceTier,
}

#[derive(Debug, Clone)]
struct TrustedKey {
    metadata: VerificationKeyMetadata,
    verifying_key: VerifyingKey,
}

#[derive(Debug, Clone)]
struct TrustedRegistrySnapshot {
    registry_digest: String,
    artifact_locator: String,
    effective_at: DateTime<Utc>,
    authority_until: Option<DateTime<Utc>>,
    deployment_ids: BTreeSet<String>,
    trust_domain_ids: BTreeSet<String>,
    keys: BTreeMap<String, TrustedKey>,
}

#[derive(Debug)]
struct ParsedRegistryArtifact {
    artifact_locator: String,
    raw_digest: String,
    registry: TrustRegistryDocument,
}

/// An independently pinned and internally validated append-only registry
/// lineage. This type is deliberately not a document-verification authority;
/// only an authenticated external reconciliation can consume it and produce
/// [`VerifiedConformanceTrustCheckpoint`].
#[derive(Debug, Clone)]
pub struct ValidatedConformanceRegistryLineage {
    registry_id: String,
    current_registry_version: u64,
    current_registry_digest: String,
    current_artifact_locator: String,
    validated_lineage_digest: String,
    snapshots: BTreeMap<u64, TrustedRegistrySnapshot>,
    terminal_keys: BTreeMap<String, KeyTombstone>,
    historic_key_fingerprints: BTreeSet<String>,
}

/// Opaque proof that the complete local lineage exactly matched fresh,
/// independently authenticated, externally strongly consistent state.
#[derive(Debug)]
pub struct VerifiedConformanceTrustCheckpoint {
    lineage: ValidatedConformanceRegistryLineage,
    namespace: CheckpointNamespace,
    authority_id: String,
    authority_key_id: String,
    authority_epoch: u64,
    authority_revision: u64,
    checkpoint_sequence: u64,
    observed_at: TrustedTimeInterval,
    valid_until: DateTime<Utc>,
    acceptance_records: Vec<TrustedAcceptanceRecord>,
}

/// Proof that one exact conformance document passed registry, scope, lifetime,
/// subject-digest, and strict Ed25519 verification. Its fields are private so
/// callers cannot manufacture trusted closure authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedConformanceDocument {
    kind: ConformanceDocumentKind,
    document_id: String,
    document_version: u64,
    key_id: String,
    registry_id: String,
    registry_version: u64,
    registry_digest: String,
    complete_document_digest: String,
    signature_digest: String,
    signed_subject_digest: String,
    claimed_signed_at: DateTime<Utc>,
    accepted_at_not_before: DateTime<Utc>,
    accepted_at_not_after: DateTime<Utc>,
    acceptance_record_id: String,
    acceptance_sequence: u64,
    authority_id: String,
    authority_epoch: u64,
    authority_revision: u64,
    checkpoint_sequence: u64,
    deployment_id: String,
    trust_domain_id: String,
    package_id: String,
    evidence_tier: EvidenceTier,
}

impl VerifiedConformanceDocument {
    pub fn kind(&self) -> ConformanceDocumentKind {
        self.kind
    }
    pub fn document_id(&self) -> &str {
        &self.document_id
    }
    pub fn document_version(&self) -> u64 {
        self.document_version
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub fn registry_id(&self) -> &str {
        &self.registry_id
    }
    pub fn registry_version(&self) -> u64 {
        self.registry_version
    }
    pub fn registry_digest(&self) -> &str {
        &self.registry_digest
    }
    pub fn signed_subject_digest(&self) -> &str {
        &self.signed_subject_digest
    }
    pub fn complete_document_digest(&self) -> &str {
        &self.complete_document_digest
    }
    pub fn signature_digest(&self) -> &str {
        &self.signature_digest
    }
    pub fn claimed_signed_at(&self) -> DateTime<Utc> {
        self.claimed_signed_at
    }
    pub fn accepted_at_not_before(&self) -> DateTime<Utc> {
        self.accepted_at_not_before
    }
    pub fn accepted_at_not_after(&self) -> DateTime<Utc> {
        self.accepted_at_not_after
    }
    pub fn acceptance_record_id(&self) -> &str {
        &self.acceptance_record_id
    }
    pub fn acceptance_sequence(&self) -> u64 {
        self.acceptance_sequence
    }
    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }
    pub fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }
    pub fn authority_revision(&self) -> u64 {
        self.authority_revision
    }
    pub fn checkpoint_sequence(&self) -> u64 {
        self.checkpoint_sequence
    }
    pub fn deployment_id(&self) -> &str {
        &self.deployment_id
    }
    pub fn trust_domain_id(&self) -> &str {
        &self.trust_domain_id
    }
    pub fn package_id(&self) -> &str {
        &self.package_id
    }
    pub fn evidence_tier(&self) -> EvidenceTier {
        self.evidence_tier
    }
}

impl ValidatedConformanceRegistryLineage {
    pub fn from_registry_chain(
        oldest_to_current: &[ConformanceRegistryArtifact<'_>],
        anchor: ConformanceTrustAnchor<'_>,
        now: DateTime<Utc>,
    ) -> Result<Self, ConformanceTrustError> {
        if oldest_to_current.is_empty() || oldest_to_current.len() > MAX_REGISTRY_LINEAGE {
            return Err(invalid(format!(
                "registry lineage must contain 1..={MAX_REGISTRY_LINEAGE} artifacts"
            )));
        }
        require_digest(anchor.content_digest, "registry anchor digest")?;
        if !valid_artifact_locator(anchor.artifact_locator)
            || !valid_scoped_id(anchor.document_id, "conformance-trust-root-registry:")
            || anchor.document_version == 0
        {
            return Err(invalid("invalid independent registry anchor"));
        }

        let mut seen_locators = BTreeSet::new();
        let mut parsed = Vec::with_capacity(oldest_to_current.len());
        for artifact in oldest_to_current {
            if !valid_artifact_locator(artifact.artifact_locator)
                || !seen_locators.insert(artifact.artifact_locator.to_owned())
                || artifact.raw_bytes.is_empty()
                || artifact.raw_bytes.len() > MAX_REGISTRY_BYTES
            {
                return Err(invalid(
                    "invalid, duplicate, empty, or oversized registry artifact",
                ));
            }
            let raw_digest = sha256_digest(artifact.raw_bytes);
            let value = parse_json_strict(artifact.raw_bytes)?;
            validate_json_shape(&value, 0)?;
            canonical_json_bytes(&value)?;
            validate_required_nullable_fields(&value)?;
            let registry: TrustRegistryDocument = serde_json::from_value(value)
                .map_err(|error| ConformanceTrustError::InvalidTypedValue(error.to_string()))?;
            validate_registry_contract(&registry, now)?;
            parsed.push(ParsedRegistryArtifact {
                artifact_locator: artifact.artifact_locator.to_owned(),
                raw_digest,
                registry,
            });
        }

        let head = parsed.last().expect("non-empty lineage checked above");
        if head.artifact_locator != anchor.artifact_locator
            || head.registry.document_id != anchor.document_id
            || head.registry.document_version != anchor.document_version
            || head.raw_digest != anchor.content_digest
        {
            return Err(invalid(
                "registry head does not match its independent locator/id/version/digest anchor",
            ));
        }

        let registry_id = parsed[0].registry.document_id.clone();
        let mut id_to_fingerprint = BTreeMap::<String, String>::new();
        let mut fingerprint_to_id = BTreeMap::<String, String>::new();
        let mut historic_keys = BTreeMap::<String, VerificationKeyMetadata>::new();
        let mut supersession_edges = BTreeMap::<String, String>::new();
        let mut previous_live = BTreeMap::<String, VerificationKeyMetadata>::new();
        let mut previous_tombstones = BTreeMap::<String, KeyTombstone>::new();
        let mut snapshots = BTreeMap::new();

        for (index, artifact) in parsed.iter().enumerate() {
            let registry = &artifact.registry;
            let expected_version = u64::try_from(index + 1)
                .map_err(|_| invalid("registry lineage version overflow"))?;
            if registry.document_id != registry_id || registry.document_version != expected_version
            {
                return Err(invalid(
                    "registry lineage must keep one id and start at version 1 without gaps",
                ));
            }
            match (index, &registry.predecessor_registry_ref) {
                (0, None) => {}
                (0, Some(_)) => {
                    return Err(invalid("registry version 1 must not have a predecessor"));
                }
                (_, None) => {
                    return Err(invalid("registry version after 1 requires a predecessor"));
                }
                (_, Some(reference)) => {
                    let prior = &parsed[index - 1];
                    if reference.artifact_kind != TRUST_REGISTRY_CONTRACT_KIND
                        || reference.document_id != prior.registry.document_id
                        || reference.document_version != prior.registry.document_version
                        || reference.content_digest != prior.raw_digest
                        || reference.artifact_locator != prior.artifact_locator
                    {
                        return Err(invalid(
                            "registry predecessor reference is not the exact prior artifact",
                        ));
                    }
                }
            }

            if index > 0 {
                let prior = &parsed[index - 1].registry;
                if registry.lifecycle.effective_at <= prior.lifecycle.effective_at {
                    return Err(invalid("registry effective_at must strictly increase"));
                }
                if registry.applicability != prior.applicability {
                    return Err(invalid(
                        "registry applicability cannot change within one approved lineage",
                    ));
                }
                validate_registry_lifecycle_transition(
                    prior.lifecycle.state,
                    registry.lifecycle.state,
                )?;
                if registry.trust_policy_version < prior.trust_policy_version
                    || prior
                        .trust_policy_version
                        .checked_add(1)
                        .is_none_or(|maximum| registry.trust_policy_version > maximum)
                {
                    return Err(invalid(
                        "trust policy version must be monotonic and advance by at most one",
                    ));
                }
                if registry.trust_policy_version == prior.trust_policy_version
                    && authority_projection_changed(prior, registry)
                {
                    return Err(invalid(
                        "authority changed without advancing trust policy version",
                    ));
                }
            }

            let deployment_ids = registry
                .applicability
                .deployment_ids
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            let trust_domain_ids = registry
                .applicability
                .trust_domain_ids
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            let mut live = BTreeMap::<String, VerificationKeyMetadata>::new();
            let mut trusted_keys = BTreeMap::new();
            let mut live_fingerprints = BTreeSet::new();
            for metadata in &registry.keys {
                validate_key_metadata(metadata)?;
                if metadata
                    .deployment_ids
                    .iter()
                    .any(|id| !deployment_ids.contains(id))
                    || metadata
                        .trust_domain_ids
                        .iter()
                        .any(|id| !trust_domain_ids.contains(id))
                {
                    return Err(invalid("key scope exceeds registry applicability"));
                }
                let public_key =
                    decode_canonical_base64::<32>(&metadata.public_key_base64, "public key")?;
                let fingerprint = sha256_digest(&public_key);
                if metadata.public_key_fingerprint != fingerprint {
                    return Err(invalid(
                        "public-key fingerprint does not match decoded key bytes",
                    ));
                }
                if live.contains_key(&metadata.key_id)
                    || !live_fingerprints.insert(fingerprint.clone())
                {
                    return Err(invalid("duplicate live key id or fingerprint"));
                }
                if let Some(prior) = previous_live.get(&metadata.key_id) {
                    if !same_key_authority(prior, metadata) {
                        return Err(invalid("recurring key metadata was relabelled or changed"));
                    }
                    validate_key_lifecycle_transition(prior.lifecycle, metadata.lifecycle)?;
                } else {
                    if previous_tombstones.contains_key(&metadata.key_id)
                        || id_to_fingerprint.contains_key(&metadata.key_id)
                        || fingerprint_to_id.contains_key(&fingerprint)
                    {
                        return Err(invalid("historic key id or key material was reused"));
                    }
                    if metadata.valid_from < registry.lifecycle.effective_at {
                        return Err(invalid(
                            "new key valid_from predates its introducing registry",
                        ));
                    }
                }
                bind_key_identity(
                    &mut id_to_fingerprint,
                    &mut fingerprint_to_id,
                    &metadata.key_id,
                    &fingerprint,
                )?;
                historic_keys
                    .entry(metadata.key_id.clone())
                    .or_insert_with(|| metadata.clone());
                if let Some(predecessor) = &metadata.supersedes_key_id {
                    supersession_edges.insert(metadata.key_id.clone(), predecessor.clone());
                }
                let verifying_key = VerifyingKey::from_bytes(&public_key)
                    .map_err(|_| invalid("invalid Ed25519 public key"))?;
                live.insert(metadata.key_id.clone(), metadata.clone());
                trusted_keys.insert(
                    metadata.key_id.clone(),
                    TrustedKey {
                        metadata: metadata.clone(),
                        verifying_key,
                    },
                );
            }

            let mut tombstones = BTreeMap::<String, KeyTombstone>::new();
            let mut tombstone_fingerprints = BTreeSet::new();
            for tombstone in &registry.key_tombstones {
                validate_tombstone_shape(tombstone, registry.trust_policy_version)?;
                if tombstones.contains_key(&tombstone.key_id)
                    || !tombstone_fingerprints.insert(tombstone.public_key_fingerprint.clone())
                    || live.contains_key(&tombstone.key_id)
                    || live_fingerprints.contains(&tombstone.public_key_fingerprint)
                {
                    return Err(invalid("duplicate or overlapping live/tombstoned key"));
                }
                let original = historic_keys
                    .get(&tombstone.key_id)
                    .ok_or_else(|| invalid("tombstone does not identify a previously live key"))?;
                validate_tombstone_against_key(
                    tombstone,
                    original,
                    registry.lifecycle.effective_at,
                )?;
                bind_key_identity(
                    &mut id_to_fingerprint,
                    &mut fingerprint_to_id,
                    &tombstone.key_id,
                    &tombstone.public_key_fingerprint,
                )?;
                tombstones.insert(tombstone.key_id.clone(), tombstone.clone());
            }

            if index == 0 && !tombstones.is_empty() {
                return Err(invalid(
                    "genesis registry cannot contain historic tombstones",
                ));
            }
            for (key_id, prior_tombstone) in &previous_tombstones {
                let current = tombstones
                    .get(key_id)
                    .ok_or_else(|| invalid("prior tombstone was dropped"))?;
                if current != prior_tombstone
                    && !valid_retired_to_revoked_transition(prior_tombstone, current)
                {
                    return Err(invalid("prior tombstone was mutated or weakened"));
                }
            }
            for (key_id, prior_key) in &previous_live {
                if live.contains_key(key_id) {
                    continue;
                }
                let tombstone = tombstones.get(key_id).ok_or_else(|| {
                    invalid("live key disappeared without an immediate tombstone")
                })?;
                if tombstone.signer_identity != prior_key.signer_identity
                    || tombstone.algorithm != prior_key.algorithm
                    || tombstone.public_key_fingerprint != prior_key.public_key_fingerprint
                    || tombstone.trust_policy_version != registry.trust_policy_version
                    || tombstone.subsequent_revocation.is_some()
                {
                    return Err(invalid(
                        "new tombstone does not exactly terminate the prior key",
                    ));
                }
            }

            validate_supersession(&live, &tombstones, &historic_keys, &supersession_edges)?;

            snapshots.insert(
                registry.document_version,
                TrustedRegistrySnapshot {
                    registry_digest: artifact.raw_digest.clone(),
                    artifact_locator: artifact.artifact_locator.clone(),
                    effective_at: registry.lifecycle.effective_at,
                    authority_until: parsed
                        .get(index + 1)
                        .map(|next| next.registry.lifecycle.effective_at),
                    deployment_ids,
                    trust_domain_ids,
                    keys: trusted_keys,
                },
            );
            previous_live = live;
            previous_tombstones = tombstones;
        }

        let lineage_binding = Value::Array(
            parsed
                .iter()
                .map(|artifact| {
                    serde_json::json!({
                        "artifact_locator": artifact.artifact_locator,
                        "document_id": artifact.registry.document_id,
                        "document_version": artifact.registry.document_version,
                        "raw_content_digest": artifact.raw_digest,
                    })
                })
                .collect(),
        );
        let validated_lineage_digest = sha256_digest(&canonical_json_bytes(&lineage_binding)?);
        let current_registry_digest = parsed
            .last()
            .expect("non-empty lineage checked above")
            .raw_digest
            .clone();
        let current_artifact_locator = parsed
            .last()
            .expect("non-empty lineage checked above")
            .artifact_locator
            .clone();

        Ok(Self {
            registry_id,
            current_registry_version: anchor.document_version,
            current_registry_digest,
            current_artifact_locator,
            validated_lineage_digest,
            snapshots,
            terminal_keys: previous_tombstones,
            historic_key_fingerprints: fingerprint_to_id.into_keys().collect(),
        })
    }

    /// Builds the only serving-time operation supported by protocol v1. The
    /// request asks for a read/reconcile proof and pre-existing acceptance
    /// records; it cannot bootstrap, relocate, advance, or accept anything.
    pub fn reconciliation_request(
        &self,
        scope: ConformanceTrustScope<'_>,
        authority: ConformanceCheckpointAuthorityAnchor<'_>,
        request_nonce: [u8; 32],
        requested_at: DateTime<Utc>,
        requested_document_digests: &[String],
    ) -> Result<ConformanceCheckpointRequest, ConformanceTrustError> {
        validate_checkpoint_authority(authority, &self.historic_key_fingerprints)?;
        if !valid_counter(self.current_registry_version) {
            return Err(invalid_checkpoint(
                "registry version exceeds the canonical checkpoint counter bound",
            ));
        }
        if request_nonce.iter().all(|byte| *byte == 0) {
            return Err(invalid_checkpoint("request nonce cannot be all zero"));
        }
        if requested_document_digests.len() > MAX_ACCEPTANCE_RECORDS
            || requested_document_digests
                .iter()
                .any(|digest| !is_digest(digest))
            || requested_document_digests
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid_checkpoint(
                "requested document digests must be valid, unique, sorted, and bounded to 4096",
            ));
        }
        let snapshot = self
            .snapshots
            .get(&self.current_registry_version)
            .expect("validated lineage always contains its current snapshot");
        if !valid_scoped_id(scope.deployment_id, "deployment:")
            || !valid_scoped_id(scope.trust_domain_id, "trust-domain:")
            || !snapshot.deployment_ids.contains(scope.deployment_id)
            || !snapshot.trust_domain_ids.contains(scope.trust_domain_id)
        {
            return Err(ConformanceTrustError::ScopeMismatch(
                "checkpoint namespace is outside the validated registry applicability".into(),
            ));
        }

        let nonce = BASE64_STANDARD.encode(request_nonce);
        let namespace = CheckpointNamespace {
            deployment_id: scope.deployment_id.to_owned(),
            trust_domain_id: scope.trust_domain_id.to_owned(),
            registry_id: self.registry_id.clone(),
        };
        let candidate_head = CheckpointRegistryHead {
            registry_version: self.current_registry_version,
            content_digest: self.current_registry_digest.clone(),
            artifact_locator: self.current_artifact_locator.clone(),
        };
        let value = serde_json::json!({
            "schema_version": TRUST_REGISTRY_SCHEMA_VERSION,
            "contract_kind": TRUST_RECONCILIATION_REQUEST_KIND,
            "operation": "read_reconcile",
            "canonicalization": CANONICALIZATION_PROFILE,
            "signature_algorithm": SIGNATURE_ALGORITHM,
            "authority_id": authority.authority_id,
            "authority_key_id": authority.key_id,
            "namespace": namespace,
            "candidate_head": candidate_head,
            "validated_lineage_digest": self.validated_lineage_digest,
            "request_nonce": nonce,
            "requested_at": requested_at,
            "requested_document_digests": requested_document_digests,
        });
        let canonical_bytes = canonical_json_bytes(&value)?;
        if canonical_bytes.len() > MAX_RECONCILIATION_REQUEST_BYTES {
            return Err(invalid_checkpoint("request exceeds 512 KiB"));
        }
        let digest = sha256_digest(&canonical_bytes);
        Ok(ConformanceCheckpointRequest {
            canonical_bytes,
            digest,
            nonce,
            authority_id: authority.authority_id.to_owned(),
            authority_key_id: authority.key_id.to_owned(),
            namespace,
            candidate_head,
            validated_lineage_digest: self.validated_lineage_digest.clone(),
            requested_document_digests: requested_document_digests.to_vec(),
        })
    }

    /// Consumes the unprivileged lineage and returns an opaque production
    /// verification capability only after exact external reconciliation.
    pub fn verify_reconciliation_response(
        self,
        request: &ConformanceCheckpointRequest,
        raw_response: &[u8],
        authority: ConformanceCheckpointAuthorityAnchor<'_>,
        trusted_now: ConformanceTrustedTimeWindow,
    ) -> Result<VerifiedConformanceTrustCheckpoint, ConformanceTrustError> {
        validate_checkpoint_authority(authority, &self.historic_key_fingerprints)?;
        if request.authority_id != authority.authority_id
            || request.authority_key_id != authority.key_id
            || request.namespace.registry_id != self.registry_id
            || request.candidate_head.registry_version != self.current_registry_version
            || request.candidate_head.content_digest != self.current_registry_digest
            || request.candidate_head.artifact_locator != self.current_artifact_locator
            || request.validated_lineage_digest != self.validated_lineage_digest
            || sha256_digest(request.as_bytes()) != request.digest
        {
            return Err(invalid_checkpoint(
                "request was not produced for this lineage and authority",
            ));
        }
        if trusted_now.not_before > trusted_now.not_after {
            return Err(invalid_checkpoint(
                "trusted local time interval is inverted",
            ));
        }
        if raw_response.is_empty() || raw_response.len() > MAX_RECONCILIATION_RESPONSE_BYTES {
            return Err(invalid_checkpoint("response is empty or exceeds 32 MiB"));
        }

        let value = parse_json_strict(raw_response)?;
        validate_checkpoint_json_shape(&value, 0)?;
        canonical_json_bytes(&value)?;
        verify_checkpoint_envelope_signature(&value, authority)?;
        validate_checkpoint_timestamp_lexemes(&value)?;
        let response: ReconciliationResponse = serde_json::from_value(value)
            .map_err(|error| ConformanceTrustError::InvalidTypedValue(error.to_string()))?;

        if response.schema_version != TRUST_REGISTRY_SCHEMA_VERSION
            || response.contract_kind != TRUST_RECONCILIATION_RESPONSE_KIND
            || response.canonicalization != CANONICALIZATION_PROFILE
            || response.signature_algorithm != SIGNATURE_ALGORITHM
            || response.authority.authority_id != authority.authority_id
            || response.authority.key_id != authority.key_id
            || response.authority.public_key_fingerprint != authority.public_key_fingerprint
            || response.request_nonce != request.nonce
            || response.request_digest != request.digest
            || response.validated_lineage_digest != request.validated_lineage_digest
            || response.state != "external_strongly_consistent"
            || response.outcome != "matched"
            || !response.reconciliation.candidate_matches_current
            || !response.reconciliation.restored_state_reconciled
            || !response.reconciliation.no_auto_advance
        {
            return Err(invalid_checkpoint(
                "response profile, authority, request echo, or reconciled state mismatch",
            ));
        }

        let decision = reconciliation_decision(
            &request.namespace,
            &request.candidate_head,
            Some((&response.namespace, &response.current_head)),
            false,
        );
        if response.candidate_head != request.candidate_head
            || response.namespace != request.namespace
            || decision != ConformanceReconciliationDecision::Matched
        {
            return Err(ConformanceTrustError::ReconciliationRequired(format!(
                "external head decision is {decision:?}"
            )));
        }

        let checkpoint = &response.checkpoint;
        if !valid_counter(checkpoint.sequence)
            || checkpoint.authority_epoch < authority.minimum_authority_epoch
            || !valid_counter(checkpoint.authority_epoch)
            || !valid_counter(checkpoint.authority_revision)
            || !valid_trusted_interval(&checkpoint.observed_at)
            || checkpoint.valid_until <= checkpoint.observed_at.not_after
            || checkpoint
                .valid_until
                .signed_duration_since(checkpoint.observed_at.not_before)
                > TimeDelta::seconds(MAX_RECONCILIATION_LIFETIME_SECONDS)
            || checkpoint.observed_at.not_after > trusted_now.not_before
            || trusted_now.not_after >= checkpoint.valid_until
        {
            return Err(invalid_checkpoint(
                "checkpoint epoch, sequence, trusted time, or freshness is invalid",
            ));
        }
        if response.acceptance_records.len() > MAX_ACCEPTANCE_RECORDS {
            return Err(invalid_checkpoint(
                "response has more than 4096 acceptance records",
            ));
        }
        validate_acceptance_record_set(
            &response.acceptance_records,
            &self,
            &request.namespace,
            checkpoint,
            &request.requested_document_digests,
        )?;

        Ok(VerifiedConformanceTrustCheckpoint {
            lineage: self,
            namespace: response.namespace,
            authority_id: response.authority.authority_id,
            authority_key_id: response.authority.key_id,
            authority_epoch: checkpoint.authority_epoch,
            authority_revision: checkpoint.authority_revision,
            checkpoint_sequence: checkpoint.sequence,
            observed_at: checkpoint.observed_at.clone(),
            valid_until: checkpoint.valid_until,
            acceptance_records: response.acceptance_records,
        })
    }
}

impl VerifiedConformanceTrustCheckpoint {
    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }

    pub fn authority_key_id(&self) -> &str {
        &self.authority_key_id
    }

    pub fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    pub fn authority_revision(&self) -> u64 {
        self.authority_revision
    }

    pub fn checkpoint_sequence(&self) -> u64 {
        self.checkpoint_sequence
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

    /// Rechecks the externally authenticated proof at the final startup fence.
    /// `valid_until` is exclusive, so an uncertainty interval touching it is
    /// already stale.
    pub fn ensure_fresh(
        &self,
        trusted_now: ConformanceTrustedTimeWindow,
    ) -> Result<(), ConformanceTrustError> {
        if trusted_now.not_before > trusted_now.not_after
            || self.observed_at.not_after > trusted_now.not_before
            || trusted_now.not_after >= self.valid_until
        {
            return Err(invalid_checkpoint(
                "verified checkpoint is stale at the final startup fence",
            ));
        }
        Ok(())
    }

    /// Verifies one exact raw document digest against a pre-existing acceptance
    /// record returned by the reconciled authority. This operation is lookup
    /// only and cannot create acceptance on first sight.
    pub fn verify_document(
        &self,
        raw_document: &[u8],
        context: ConformanceVerificationContext<'_>,
        trusted_now: ConformanceTrustedTimeWindow,
    ) -> Result<VerifiedConformanceDocument, ConformanceTrustError> {
        self.ensure_fresh(trusted_now)?;
        if raw_document.is_empty() || raw_document.len() > MAX_CONFORMANCE_DOCUMENT_BYTES {
            return Err(invalid("conformance document is empty or exceeds 16 MiB"));
        }
        let document = parse_json_strict(raw_document)?;
        validate_json_shape(&document, 0)?;
        canonical_json_bytes(&document)?;
        let complete_document_digest = sha256_digest(raw_document);
        if context.deployment_id != self.namespace.deployment_id
            || context.trust_domain_id != self.namespace.trust_domain_id
        {
            return Err(ConformanceTrustError::ScopeMismatch(
                "document context does not match the reconciled namespace".into(),
            ));
        }

        let identity = document_identity(&document)?;
        require_document_scope(&document, identity.kind, context)?;
        let signer_value = document
            .get("signer")
            .ok_or_else(|| invalid("missing signer"))?;
        let signer: ConformanceSignatureMetadata = serde_json::from_value(signer_value.clone())
            .map_err(|error| ConformanceTrustError::InvalidTypedValue(error.to_string()))?;
        validate_signature_contract(&signer, identity.kind)?;
        let prepared = prepare_signed_subject(&document)?;
        if prepared.digest != signer.signed_subject_digest {
            return Err(ConformanceTrustError::SubjectDigestMismatch);
        }
        let signature_bytes = decode_canonical_base64::<64>(&signer.signature_base64, "signature")?;
        let signature_digest = sha256_digest(&signature_bytes);

        let record = self
            .acceptance_records
            .iter()
            .find(|record| record.document.complete_document_digest == complete_document_digest)
            .ok_or_else(|| {
                ConformanceTrustError::InvalidAcceptance(
                    "no exact pre-existing acceptance lookup result".into(),
                )
            })?;
        if record.document.contract_kind != identity.kind.as_str()
            || record.document.document_id != identity.id
            || record.document.document_version != identity.version
            || record.document.signature_digest != signature_digest
            || record.document.signed_subject_digest != prepared.digest
            || record.signer.key_id != signer.key_id
            || record.registry.registry_id != signer.trust_registry_id
            || record.registry.registry_version != signer.trust_registry_version
            || record.registry.registry_digest != signer.trust_registry_digest
            || record.deployment_id != context.deployment_id
            || record.trust_domain_id != context.trust_domain_id
            || record.work_package_id != context.package_id
            || record.purpose != signer.purpose
            || record.evidence_tier != context.evidence_tier
            || record.authority_epoch != self.authority_epoch
            || record.authority_sequence > self.checkpoint_sequence
        {
            return Err(ConformanceTrustError::InvalidAcceptance(
                "acceptance record does not bind the exact document, signer, registry, or scope"
                    .into(),
            ));
        }

        let snapshot = self
            .lineage
            .snapshots
            .get(&signer.trust_registry_version)
            .filter(|snapshot| {
                signer.trust_registry_id == self.lineage.registry_id
                    && signer.trust_registry_digest == snapshot.registry_digest
                    && record.registry.artifact_locator == snapshot.artifact_locator
            })
            .ok_or_else(|| {
                ConformanceTrustError::ScopeMismatch(
                    "accepted registry identity/version/digest/locator is not in the reconciled lineage"
                        .into(),
                )
            })?;
        let key = snapshot
            .keys
            .get(&signer.key_id)
            .ok_or_else(|| ConformanceTrustError::UnknownKey(signer.key_id.clone()))?;
        if record.signer.public_key_fingerprint != key.metadata.public_key_fingerprint {
            return Err(ConformanceTrustError::InvalidAcceptance(
                "acceptance signer fingerprint mismatch".into(),
            ));
        }
        authorize_key_at_acceptance(
            key,
            &signer,
            context,
            snapshot,
            &record.accepted_at,
            self.lineage.terminal_keys.get(&signer.key_id),
        )?;

        let signature = Signature::from_bytes(&signature_bytes);
        key.verifying_key
            .verify_strict(&prepared.signing_bytes, &signature)
            .map_err(|_| ConformanceTrustError::InvalidSignature)?;

        Ok(VerifiedConformanceDocument {
            kind: identity.kind,
            document_id: identity.id,
            document_version: identity.version,
            key_id: signer.key_id,
            registry_id: self.lineage.registry_id.clone(),
            registry_version: signer.trust_registry_version,
            registry_digest: signer.trust_registry_digest,
            complete_document_digest,
            signature_digest,
            signed_subject_digest: prepared.digest,
            claimed_signed_at: signer.signed_at,
            accepted_at_not_before: record.accepted_at.not_before,
            accepted_at_not_after: record.accepted_at.not_after,
            acceptance_record_id: record.acceptance_record_id.clone(),
            acceptance_sequence: record.authority_sequence,
            authority_id: self.authority_id.clone(),
            authority_epoch: self.authority_epoch,
            authority_revision: self.authority_revision,
            checkpoint_sequence: self.checkpoint_sequence,
            deployment_id: context.deployment_id.to_owned(),
            trust_domain_id: context.trust_domain_id.to_owned(),
            package_id: context.package_id.to_owned(),
            evidence_tier: context.evidence_tier,
        })
    }
}

fn validate_checkpoint_authority(
    authority: ConformanceCheckpointAuthorityAnchor<'_>,
    conformance_key_fingerprints: &BTreeSet<String>,
) -> Result<(), ConformanceTrustError> {
    if !valid_scoped_id(
        authority.authority_id,
        "conformance-trust-checkpoint-authority:",
    ) || !valid_scoped_id(authority.key_id, "conformance-trust-checkpoint-key:")
        || !valid_counter(authority.minimum_authority_epoch)
        || !is_digest(authority.public_key_fingerprint)
    {
        return Err(invalid_checkpoint("invalid independent authority anchor"));
    }
    let fingerprint = sha256_digest(authority.public_key);
    if fingerprint != authority.public_key_fingerprint {
        return Err(invalid_checkpoint(
            "authority public key does not match its raw-key fingerprint pin",
        ));
    }
    if conformance_key_fingerprints.contains(&fingerprint) {
        return Err(invalid_checkpoint(
            "checkpoint authority key reuses conformance signing key material",
        ));
    }
    let key = VerifyingKey::from_bytes(authority.public_key)
        .map_err(|_| invalid_checkpoint("invalid checkpoint authority Ed25519 key"))?;
    if key.is_weak() {
        return Err(invalid_checkpoint("weak checkpoint authority Ed25519 key"));
    }
    Ok(())
}

fn validate_checkpoint_json_shape(
    value: &Value,
    depth: usize,
) -> Result<(), ConformanceTrustError> {
    if depth > 32 {
        return Err(invalid_checkpoint(
            "checkpoint JSON exceeds maximum nesting depth",
        ));
    }
    match value {
        Value::String(value) if value.len() > MAX_CHECKPOINT_STRING_BYTES => {
            return Err(invalid_checkpoint(
                "checkpoint JSON string exceeds maximum byte length",
            ));
        }
        Value::Array(values) => {
            if values.len() > MAX_ACCEPTANCE_RECORDS {
                return Err(invalid_checkpoint(
                    "checkpoint JSON array exceeds maximum length",
                ));
            }
            for value in values {
                validate_checkpoint_json_shape(value, depth + 1)?;
            }
        }
        Value::Object(values) => {
            if values.len() > 64 {
                return Err(invalid_checkpoint(
                    "checkpoint JSON object exceeds maximum field count",
                ));
            }
            for value in values.values() {
                validate_checkpoint_json_shape(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_checkpoint_timestamp_lexemes(value: &Value) -> Result<(), ConformanceTrustError> {
    for pointer in [
        "/checkpoint/observed_at/not_before",
        "/checkpoint/observed_at/not_after",
        "/checkpoint/valid_until",
    ] {
        let timestamp = value
            .pointer(pointer)
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_checkpoint("missing checkpoint timestamp"))?;
        if !valid_checkpoint_timestamp(timestamp) {
            return Err(invalid_checkpoint(
                "checkpoint timestamp is not bounded RFC3339",
            ));
        }
    }
    let records = value
        .get("acceptance_records")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_checkpoint("acceptance_records must be an array"))?;
    for record in records {
        for pointer in ["/accepted_at/not_before", "/accepted_at/not_after"] {
            let timestamp = record
                .pointer(pointer)
                .and_then(Value::as_str)
                .ok_or_else(|| invalid_checkpoint("missing acceptance timestamp"))?;
            if !valid_checkpoint_timestamp(timestamp) {
                return Err(invalid_checkpoint(
                    "acceptance timestamp is not bounded RFC3339",
                ));
            }
        }
    }
    Ok(())
}

fn valid_checkpoint_timestamp(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 35
        && value.trim() == value
        && DateTime::parse_from_rfc3339(value).is_ok()
}

fn verify_checkpoint_envelope_signature(
    value: &Value,
    authority: ConformanceCheckpointAuthorityAnchor<'_>,
) -> Result<(), ConformanceTrustError> {
    let mut subject = value.clone();
    let signature_base64 = subject
        .as_object_mut()
        .and_then(|object| object.remove("signature_base64"))
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| invalid_checkpoint("missing checkpoint signature"))?;
    let canonical = canonical_json_bytes(&subject)?;
    let mut signing_bytes =
        Vec::with_capacity(TRUST_RECONCILIATION_RESPONSE_DOMAIN.len() + canonical.len() + 16);
    write_frame(
        &mut signing_bytes,
        TRUST_RECONCILIATION_RESPONSE_DOMAIN.as_bytes(),
    );
    write_frame(&mut signing_bytes, &canonical);
    let signature_bytes = decode_canonical_base64::<64>(&signature_base64, "checkpoint signature")?;
    let signature = Signature::from_bytes(&signature_bytes);
    let key = VerifyingKey::from_bytes(authority.public_key)
        .map_err(|_| invalid_checkpoint("invalid checkpoint authority Ed25519 key"))?;
    key.verify_strict(&signing_bytes, &signature)
        .map_err(|_| ConformanceTrustError::InvalidCheckpointSignature)
}

fn reconciliation_decision(
    local_namespace: &CheckpointNamespace,
    local_head: &CheckpointRegistryHead,
    external: Option<(&CheckpointNamespace, &CheckpointRegistryHead)>,
    higher_head_descends_from_local: bool,
) -> ConformanceReconciliationDecision {
    let Some((external_namespace, external_head)) = external else {
        return ConformanceReconciliationDecision::Missing;
    };
    if external_namespace != local_namespace {
        return ConformanceReconciliationDecision::WrongScope;
    }
    if external_head.registry_version < local_head.registry_version {
        return ConformanceReconciliationDecision::Rollback;
    }
    if external_head.registry_version == local_head.registry_version {
        if external_head.content_digest != local_head.content_digest {
            return ConformanceReconciliationDecision::SameVersionFork;
        }
        if external_head.artifact_locator != local_head.artifact_locator {
            return ConformanceReconciliationDecision::RelocationRequired;
        }
        return ConformanceReconciliationDecision::Matched;
    }
    if higher_head_descends_from_local {
        ConformanceReconciliationDecision::AdvanceRequired
    } else {
        ConformanceReconciliationDecision::NonDescendant
    }
}

fn valid_trusted_interval(interval: &TrustedTimeInterval) -> bool {
    interval.not_before <= interval.not_after
}

fn valid_counter(value: u64) -> bool {
    (1..=MAX_CANONICAL_JSON_COUNTER).contains(&value)
}

fn validate_acceptance_record_set(
    records: &[TrustedAcceptanceRecord],
    lineage: &ValidatedConformanceRegistryLineage,
    namespace: &CheckpointNamespace,
    checkpoint: &ResponseCheckpoint,
    requested_document_digests: &[String],
) -> Result<(), ConformanceTrustError> {
    let requested = requested_document_digests
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut record_ids = BTreeSet::new();
    let mut document_digests = BTreeSet::new();
    let mut acceptance_sequences = BTreeSet::new();
    let mut document_identities = BTreeSet::new();
    let mut registry_head_facts = BTreeMap::<u64, (u64, u64)>::new();
    for record in records {
        if !valid_scoped_id(&record.acceptance_record_id, "conformance-acceptance:")
            || !record_ids.insert(record.acceptance_record_id.clone())
            || !document_digests.insert(record.document.complete_document_digest.clone())
            || !acceptance_sequences.insert(record.authority_sequence)
            || !document_identities.insert((
                record.document.contract_kind.clone(),
                record.document.document_id.clone(),
                record.document.document_version,
            ))
            || !requested.contains(&record.document.complete_document_digest)
            || !valid_document_id(&record.document.document_id)
            || !valid_counter(record.document.document_version)
            || !is_digest(&record.document.complete_document_digest)
            || !is_digest(&record.document.signature_digest)
            || !is_digest(&record.document.signed_subject_digest)
            || !valid_scoped_id(&record.signer.key_id, "conformance-key:")
            || !is_digest(&record.signer.public_key_fingerprint)
            || record.deployment_id != namespace.deployment_id
            || record.trust_domain_id != namespace.trust_domain_id
            || !valid_package_id(&record.work_package_id)
            || !valid_counter(record.authority_sequence)
            || record.authority_sequence > checkpoint.sequence
            || record.authority_epoch != checkpoint.authority_epoch
            || record.lifecycle != "accepted"
            || !valid_trusted_interval(&record.accepted_at)
            || record.accepted_at.not_after > checkpoint.observed_at.not_after
            || record.registry.registry_id != namespace.registry_id
            || !valid_counter(record.registry.registry_version)
            || !is_digest(&record.registry.registry_digest)
            || !valid_artifact_locator(&record.registry.artifact_locator)
            || !valid_counter(record.registry.head_sequence)
            || record.registry.head_sequence > record.authority_sequence
            || !valid_counter(record.registry.head_authority_revision)
            || record.registry.head_authority_revision > checkpoint.authority_revision
        {
            return Err(ConformanceTrustError::InvalidAcceptance(
                "malformed, duplicate, unsolicited, stale, or cross-scope acceptance record".into(),
            ));
        }
        let expected_kind = match record.purpose {
            ConformancePurpose::ConformanceBundle => "conformance-bundle",
            ConformancePurpose::PackageExitReceipt => "package-exit-receipt",
        };
        if record.document.contract_kind != expected_kind {
            return Err(ConformanceTrustError::InvalidAcceptance(
                "acceptance document kind and purpose differ".into(),
            ));
        }
        let head_facts = (
            record.registry.head_sequence,
            record.registry.head_authority_revision,
        );
        if registry_head_facts
            .insert(record.registry.registry_version, head_facts)
            .is_some_and(|known| known != head_facts)
        {
            return Err(ConformanceTrustError::InvalidAcceptance(
                "one exact registry snapshot has conflicting external head facts".into(),
            ));
        }
        let snapshot = lineage
            .snapshots
            .get(&record.registry.registry_version)
            .filter(|snapshot| {
                snapshot.registry_digest == record.registry.registry_digest
                    && snapshot.artifact_locator == record.registry.artifact_locator
                    && snapshot.deployment_ids.contains(&record.deployment_id)
                    && snapshot.trust_domain_ids.contains(&record.trust_domain_id)
            })
            .ok_or_else(|| {
                ConformanceTrustError::InvalidAcceptance(
                    "acceptance registry is not an exact snapshot in the validated lineage".into(),
                )
            })?;
        if record.accepted_at.not_before < snapshot.effective_at
            || snapshot
                .authority_until
                .is_some_and(|until| record.accepted_at.not_after >= until)
        {
            return Err(ConformanceTrustError::InvalidAcceptance(
                "acceptance time uncertainty straddles registry authority".into(),
            ));
        }
    }
    let mut prior_head = None;
    for (version, (sequence, revision)) in registry_head_facts {
        if let Some((prior_version, prior_sequence, prior_revision)) = prior_head
            && (version <= prior_version
                || sequence <= prior_sequence
                || revision <= prior_revision)
        {
            return Err(ConformanceTrustError::InvalidAcceptance(
                "registry head sequence or authority revision is non-monotonic".into(),
            ));
        }
        prior_head = Some((version, sequence, revision));
    }
    if document_digests != requested {
        return Err(ConformanceTrustError::InvalidAcceptance(
            "authority omitted a requested pre-existing acceptance record".into(),
        ));
    }
    Ok(())
}

fn authorize_key_at_acceptance(
    key: &TrustedKey,
    signer: &ConformanceSignatureMetadata,
    context: ConformanceVerificationContext<'_>,
    snapshot: &TrustedRegistrySnapshot,
    accepted_at: &TrustedTimeInterval,
    terminal: Option<&KeyTombstone>,
) -> Result<(), ConformanceTrustError> {
    let metadata = &key.metadata;
    if metadata.algorithm != SIGNATURE_ALGORITHM
        || metadata.signer_identity != signer.identity
        || metadata.lifecycle != KeyLifecycle::Active
        || !metadata.allowed_purposes.contains(&signer.purpose)
        || !metadata
            .allowed_evidence_tiers
            .contains(&context.evidence_tier)
        || !metadata
            .allowed_package_ids
            .iter()
            .any(|id| id == context.package_id)
        || !metadata
            .deployment_ids
            .iter()
            .any(|id| id == context.deployment_id)
        || !metadata
            .trust_domain_ids
            .iter()
            .any(|id| id == context.trust_domain_id)
    {
        return Err(ConformanceTrustError::KeyNotAuthorized(
            "key was not active for the accepted purpose, tier, package, or namespace".into(),
        ));
    }
    if !valid_trusted_interval(accepted_at)
        || accepted_at.not_before < snapshot.effective_at
        || snapshot
            .authority_until
            .is_some_and(|until| accepted_at.not_after >= until)
        || accepted_at.not_before < metadata.valid_from
        || accepted_at.not_after >= metadata.valid_until
    {
        return Err(ConformanceTrustError::KeyNotAuthorized(
            "trusted acceptance-time uncertainty straddles registry or key authority".into(),
        ));
    }
    if signer.signed_at < snapshot.effective_at
        || signer.signed_at < metadata.valid_from
        || signer.signed_at >= metadata.valid_until
        || signer.signed_at > accepted_at.not_before
    {
        return Err(ConformanceTrustError::KeyNotAuthorized(
            "signer-controlled signed_at is inconsistent with trusted acceptance".into(),
        ));
    }
    if let Some(tombstone) = terminal {
        match tombstone.terminal_state {
            KeyTerminalState::Revoked => {
                return Err(ConformanceTrustError::KeyNotAuthorized(
                    "direct revocation invalidates every acceptance".into(),
                ));
            }
            KeyTerminalState::Retired if tombstone.subsequent_revocation.is_some() => {
                return Err(ConformanceTrustError::KeyNotAuthorized(
                    "subsequent revocation invalidates every acceptance".into(),
                ));
            }
            KeyTerminalState::Retired => {
                let cutoff = tombstone
                    .signatures_valid_before
                    .expect("validated retired tombstone has a cutoff");
                if accepted_at.not_after >= cutoff {
                    return Err(ConformanceTrustError::KeyNotAuthorized(
                        "trusted acceptance was not strictly before retirement cutoff".into(),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn valid_document_id(value: &str) -> bool {
    (3..=160).contains(&value.len())
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn invalid_checkpoint(message: impl Into<String>) -> ConformanceTrustError {
    ConformanceTrustError::InvalidCheckpoint(message.into())
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
        Ok(DuplicateCheckedValue(Value::String(value.to_owned())))
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

fn parse_json_strict(bytes: &[u8]) -> Result<Value, ConformanceTrustError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = DuplicateCheckedValue::deserialize(&mut deserializer)
        .map_err(|error| ConformanceTrustError::InvalidTypedValue(error.to_string()))?
        .0;
    deserializer
        .end()
        .map_err(|error| ConformanceTrustError::InvalidTypedValue(error.to_string()))?;
    Ok(value)
}

fn validate_json_shape(value: &Value, depth: usize) -> Result<(), ConformanceTrustError> {
    if depth > 64 {
        return Err(invalid("registry JSON exceeds maximum nesting depth"));
    }
    match value {
        Value::Array(values) => {
            if values.len() > MAX_TOMBSTONES_PER_REGISTRY {
                return Err(invalid("registry JSON array exceeds maximum length"));
            }
            for value in values {
                validate_json_shape(value, depth + 1)?;
            }
        }
        Value::Object(values) => {
            if values.len() > MAX_SCOPE_ITEMS {
                return Err(invalid("registry JSON object exceeds maximum field count"));
            }
            for value in values.values() {
                validate_json_shape(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Canonical JSON bytes for `ryuki-canonical-json-v1`.
pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, ConformanceTrustError> {
    let mut output = Vec::new();
    write_canonical_json(value, &mut output)?;
    Ok(output)
}

/// Digest claimed in `signer.signed_subject_digest`.
pub fn conformance_signed_subject_digest(
    document: &Value,
) -> Result<String, ConformanceTrustError> {
    Ok(prepare_signed_subject(document)?.digest)
}

/// Exact domain-separated bytes signed by Ed25519.
pub fn conformance_signing_bytes(document: &Value) -> Result<Vec<u8>, ConformanceTrustError> {
    Ok(prepare_signed_subject(document)?.signing_bytes)
}

#[derive(Debug)]
struct DocumentIdentity {
    kind: ConformanceDocumentKind,
    id: String,
    version: u64,
}

#[derive(Debug)]
struct PreparedSubject {
    digest: String,
    signing_bytes: Vec<u8>,
}

fn prepare_signed_subject(document: &Value) -> Result<PreparedSubject, ConformanceTrustError> {
    let identity = document_identity(document)?;
    let signer_value = document
        .get("signer")
        .ok_or_else(|| invalid("missing signer"))?;
    let signer: ConformanceSignatureMetadata = serde_json::from_value(signer_value.clone())
        .map_err(|error| ConformanceTrustError::InvalidTypedValue(error.to_string()))?;
    validate_signature_contract(&signer, identity.kind)?;

    let mut subject = document.clone();
    let signer_object = subject
        .get_mut("signer")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| invalid("signer must be an object"))?;
    if signer_object.remove("signature_base64").is_none()
        || signer_object.remove("signed_subject_digest").is_none()
    {
        return Err(invalid("signed subject exclusions are missing"));
    }
    let canonical = canonical_json_bytes(&subject)?;
    let digest = sha256_digest(&canonical);
    let mut signing_bytes = Vec::with_capacity(identity.kind.domain().len() + canonical.len() + 16);
    write_frame(&mut signing_bytes, identity.kind.domain().as_bytes());
    write_frame(&mut signing_bytes, &canonical);
    Ok(PreparedSubject {
        digest,
        signing_bytes,
    })
}

fn document_identity(document: &Value) -> Result<DocumentIdentity, ConformanceTrustError> {
    let object = document
        .as_object()
        .ok_or_else(|| invalid("document root must be an object"))?;
    let kind = match object.get("contract_kind").and_then(Value::as_str) {
        Some("conformance-bundle") => ConformanceDocumentKind::ConformanceBundle,
        Some("package-exit-receipt") => ConformanceDocumentKind::PackageExitReceipt,
        _ => return Err(invalid("unknown conformance document kind")),
    };
    if object.get("$schema").and_then(Value::as_str) != Some(kind.schema_uri())
        || object.get("schema_version").and_then(Value::as_str)
            != Some(TRUST_REGISTRY_SCHEMA_VERSION)
    {
        return Err(invalid("document schema or version mismatch"));
    }
    let version = object
        .get("document_version")
        .and_then(Value::as_u64)
        .filter(|version| *version > 0)
        .ok_or_else(|| invalid("document_version must be a positive integer"))?;
    let id_field = match kind {
        ConformanceDocumentKind::ConformanceBundle => "bundle_id",
        ConformanceDocumentKind::PackageExitReceipt => "receipt_id",
    };
    let id = object
        .get(id_field)
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| invalid("missing conformance document id"))?
        .to_owned();
    Ok(DocumentIdentity { kind, id, version })
}

fn require_document_scope(
    document: &Value,
    kind: ConformanceDocumentKind,
    context: ConformanceVerificationContext<'_>,
) -> Result<(), ConformanceTrustError> {
    if !valid_package_id(context.package_id) {
        return Err(ConformanceTrustError::ScopeMismatch(
            "invalid package id".into(),
        ));
    }
    let (deployment, evidence_tier) = match kind {
        ConformanceDocumentKind::ConformanceBundle => (
            document
                .pointer("/bindings/deployment_profile/deployment_id")
                .and_then(Value::as_str),
            document
                .pointer("/provenance/evidence_tier/name")
                .and_then(Value::as_str),
        ),
        ConformanceDocumentKind::PackageExitReceipt => {
            if document.get("package_id").and_then(Value::as_str) != Some(context.package_id) {
                return Err(ConformanceTrustError::ScopeMismatch(
                    "receipt package mismatch".into(),
                ));
            }
            (
                document
                    .pointer("/closure_context/deployment_profile/deployment_id")
                    .and_then(Value::as_str),
                document
                    .pointer("/evidence_tier/name")
                    .and_then(Value::as_str),
            )
        }
    };
    if deployment != Some(context.deployment_id)
        || evidence_tier != Some(context.evidence_tier.as_str())
    {
        return Err(ConformanceTrustError::ScopeMismatch(
            "document deployment or evidence tier mismatch".into(),
        ));
    }
    Ok(())
}

fn validate_signature_contract(
    signer: &ConformanceSignatureMetadata,
    kind: ConformanceDocumentKind,
) -> Result<(), ConformanceTrustError> {
    if signer.signature_version != SIGNATURE_VERSION
        || signer.algorithm != SIGNATURE_ALGORITHM
        || signer.canonicalization != CANONICALIZATION_PROFILE
        || signer.purpose != kind.purpose()
        || signer.purpose.as_str() != kind.purpose().as_str()
        || signer.domain != kind.domain()
        || !is_digest(&signer.trust_registry_digest)
        || !is_digest(&signer.signed_subject_digest)
    {
        return Err(invalid(
            "signature version/algorithm/canonicalization/purpose/domain mismatch",
        ));
    }
    Ok(())
}

fn validate_registry_contract(
    registry: &TrustRegistryDocument,
    now: DateTime<Utc>,
) -> Result<(), ConformanceTrustError> {
    if registry.schema_uri != TRUST_REGISTRY_SCHEMA_URI
        || registry.schema_version != TRUST_REGISTRY_SCHEMA_VERSION
        || registry.contract_kind != TRUST_REGISTRY_CONTRACT_KIND
        || !valid_scoped_id(&registry.document_id, "conformance-trust-root-registry:")
        || registry.document_version == 0
    {
        return Err(invalid("unsupported registry schema, kind, id, or version"));
    }
    if registry.acceptance_status != RegistryAcceptanceStatus::ProductionAccepted
        || !registry.production_accepted
        || registry.lifecycle.state != RegistryLifecycleState::Active
        || registry.lifecycle.effective_at > now
    {
        return Err(invalid(
            "every lineage snapshot must be active production-accepted authority",
        ));
    }
    if registry.trust_policy_version == 0
        || registry.applicability.evaluation_scope != "deployment"
        || !registry
            .applicability
            .security_profiles
            .contains(&SecurityProfile::Production)
        || registry.canonicalization_profiles.as_slice() != [CANONICALIZATION_PROFILE]
        || registry.signature_algorithms.as_slice() != [SIGNATURE_ALGORITHM]
    {
        return Err(invalid(
            "registry policy, applicability, or crypto profile is not closed",
        ));
    }
    if registry.keys.is_empty()
        || registry.keys.len() > MAX_KEYS_PER_REGISTRY
        || !registry
            .keys
            .iter()
            .any(|key| key.lifecycle == KeyLifecycle::Active)
        || registry.key_tombstones.len() > MAX_TOMBSTONES_PER_REGISTRY
        || registry.applicability.security_profiles.len() > 3
        || registry.applicability.deployment_ids.is_empty()
        || registry.applicability.deployment_ids.len() > MAX_SCOPE_ITEMS
        || registry.applicability.trust_domain_ids.is_empty()
        || registry.applicability.trust_domain_ids.len() > MAX_SCOPE_ITEMS
        || registry.canonicalization_profiles.len() > MAX_SCOPE_ITEMS
        || registry.signature_algorithms.len() > MAX_SCOPE_ITEMS
    {
        return Err(invalid(
            "registry collection is empty or exceeds a hard bound",
        ));
    }
    require_unique(
        &registry.applicability.security_profiles,
        "security profiles",
    )?;
    require_unique(
        &registry.applicability.deployment_ids,
        "registry deployments",
    )?;
    require_unique(
        &registry.applicability.trust_domain_ids,
        "registry trust domains",
    )?;
    if let Some(reference) = &registry.predecessor_registry_ref
        && (reference.artifact_kind != TRUST_REGISTRY_CONTRACT_KIND
            || !valid_scoped_id(&reference.document_id, "conformance-trust-root-registry:")
            || reference.document_version == 0
            || !is_digest(&reference.content_digest)
            || !valid_artifact_locator(&reference.artifact_locator))
    {
        return Err(invalid("invalid predecessor registry reference"));
    }
    Ok(())
}

fn validate_key_metadata(key: &VerificationKeyMetadata) -> Result<(), ConformanceTrustError> {
    if !valid_scoped_id(&key.key_id, "conformance-key:")
        || key.signer_identity.is_empty()
        || key.algorithm != SIGNATURE_ALGORITHM
        || !is_digest(&key.public_key_fingerprint)
        || key.valid_from >= key.valid_until
        || key.allowed_purposes.is_empty()
        || key.allowed_evidence_tiers.is_empty()
        || key.allowed_package_ids.is_empty()
        || key.deployment_ids.is_empty()
        || key.trust_domain_ids.is_empty()
    {
        return Err(invalid("invalid verification-key metadata"));
    }
    if key.allowed_purposes.len() > 2
        || key.allowed_evidence_tiers.len() > 3
        || key.allowed_package_ids.len() > 10
        || key.deployment_ids.len() > MAX_SCOPE_ITEMS
        || key.trust_domain_ids.len() > MAX_SCOPE_ITEMS
    {
        return Err(invalid("verification-key scope exceeds a hard bound"));
    }
    require_unique(&key.allowed_purposes, "key purposes")?;
    require_unique(&key.allowed_evidence_tiers, "key evidence tiers")?;
    require_unique(&key.allowed_package_ids, "key package ids")?;
    require_unique(&key.deployment_ids, "key deployments")?;
    require_unique(&key.trust_domain_ids, "key trust domains")?;
    if key
        .allowed_package_ids
        .iter()
        .any(|id| !valid_package_id(id))
    {
        return Err(invalid("unknown package id in key scope"));
    }
    Ok(())
}

fn validate_tombstone_shape(
    tombstone: &KeyTombstone,
    trust_policy_version: u64,
) -> Result<(), ConformanceTrustError> {
    if !valid_scoped_id(&tombstone.key_id, "conformance-key:")
        || tombstone.signer_identity.is_empty()
        || tombstone.algorithm != SIGNATURE_ALGORITHM
        || !is_digest(&tombstone.public_key_fingerprint)
        || !(16..=1000).contains(&tombstone.reason.chars().count())
        || tombstone.trust_policy_version == 0
        || tombstone.trust_policy_version > trust_policy_version
        || tombstone.superseded_by_key_id.as_deref() == Some(tombstone.key_id.as_str())
    {
        return Err(invalid("invalid key tombstone"));
    }
    match tombstone.terminal_state {
        KeyTerminalState::Retired => {
            if tombstone.signatures_valid_before.is_none() {
                return Err(invalid("retired tombstone requires a signature cutoff"));
            }
        }
        KeyTerminalState::Revoked => {
            if tombstone.signatures_valid_before.is_some()
                || tombstone.subsequent_revocation.is_some()
            {
                return Err(invalid(
                    "direct revocation cannot preserve a cutoff or carry an overlay",
                ));
            }
        }
    }
    if let Some(revocation) = &tombstone.subsequent_revocation
        && (!(16..=1000).contains(&revocation.reason.chars().count())
            || revocation.trust_policy_version <= tombstone.trust_policy_version
            || revocation.trust_policy_version > trust_policy_version
            || revocation.revoked_at < tombstone.terminated_at)
    {
        return Err(invalid("invalid subsequent key revocation"));
    }
    Ok(())
}

fn validate_tombstone_against_key(
    tombstone: &KeyTombstone,
    key: &VerificationKeyMetadata,
    registry_effective_at: DateTime<Utc>,
) -> Result<(), ConformanceTrustError> {
    if tombstone.signer_identity != key.signer_identity
        || tombstone.algorithm != key.algorithm
        || tombstone.public_key_fingerprint != key.public_key_fingerprint
        || tombstone.terminated_at > registry_effective_at
        || tombstone
            .subsequent_revocation
            .as_ref()
            .is_some_and(|revocation| revocation.revoked_at > registry_effective_at)
    {
        return Err(invalid(
            "tombstone does not match its historic key or transition time",
        ));
    }
    match tombstone.terminal_state {
        KeyTerminalState::Retired => {
            let cutoff = tombstone
                .signatures_valid_before
                .ok_or_else(|| invalid("retired key is missing its signature cutoff"))?;
            if cutoff != tombstone.terminated_at
                || cutoff < key.valid_from
                || cutoff > key.valid_until
            {
                return Err(invalid("retired signature cutoff is outside key validity"));
            }
        }
        KeyTerminalState::Revoked => {
            if tombstone.terminated_at < key.valid_from || tombstone.terminated_at > key.valid_until
            {
                return Err(invalid("direct revocation is outside key validity"));
            }
        }
    }
    Ok(())
}

fn validate_registry_lifecycle_transition(
    prior: RegistryLifecycleState,
    current: RegistryLifecycleState,
) -> Result<(), ConformanceTrustError> {
    let allowed = matches!(
        (prior, current),
        (
            RegistryLifecycleState::ImplementationOnly,
            RegistryLifecycleState::ImplementationOnly | RegistryLifecycleState::Candidate
        ) | (
            RegistryLifecycleState::Candidate,
            RegistryLifecycleState::Candidate | RegistryLifecycleState::Active
        ) | (
            RegistryLifecycleState::Active,
            RegistryLifecycleState::Active
                | RegistryLifecycleState::Deprecated
                | RegistryLifecycleState::Retired
        ) | (
            RegistryLifecycleState::Deprecated,
            RegistryLifecycleState::Deprecated | RegistryLifecycleState::Retired
        ) | (
            RegistryLifecycleState::Retired,
            RegistryLifecycleState::Retired
        )
    );
    if allowed {
        Ok(())
    } else {
        Err(invalid("forbidden registry lifecycle transition"))
    }
}

fn validate_key_lifecycle_transition(
    prior: KeyLifecycle,
    current: KeyLifecycle,
) -> Result<(), ConformanceTrustError> {
    if matches!(
        (prior, current),
        (
            KeyLifecycle::Active,
            KeyLifecycle::Active | KeyLifecycle::Overlap
        ) | (KeyLifecycle::Overlap, KeyLifecycle::Overlap)
    ) {
        Ok(())
    } else {
        Err(invalid("forbidden key lifecycle transition"))
    }
}

fn authority_projection_changed(
    prior: &TrustRegistryDocument,
    current: &TrustRegistryDocument,
) -> bool {
    prior.applicability != current.applicability
        || prior.canonicalization_profiles != current.canonicalization_profiles
        || prior.signature_algorithms != current.signature_algorithms
        || prior.keys != current.keys
        || prior.key_tombstones != current.key_tombstones
}

fn same_key_authority(prior: &VerificationKeyMetadata, current: &VerificationKeyMetadata) -> bool {
    prior.key_id == current.key_id
        && prior.signer_identity == current.signer_identity
        && prior.algorithm == current.algorithm
        && prior.public_key_base64 == current.public_key_base64
        && prior.public_key_fingerprint == current.public_key_fingerprint
        && prior.allowed_purposes == current.allowed_purposes
        && prior.allowed_evidence_tiers == current.allowed_evidence_tiers
        && prior.allowed_package_ids == current.allowed_package_ids
        && prior.deployment_ids == current.deployment_ids
        && prior.trust_domain_ids == current.trust_domain_ids
        && prior.valid_from == current.valid_from
        && prior.valid_until == current.valid_until
        && prior.supersedes_key_id == current.supersedes_key_id
}

fn bind_key_identity(
    id_to_fingerprint: &mut BTreeMap<String, String>,
    fingerprint_to_id: &mut BTreeMap<String, String>,
    key_id: &str,
    fingerprint: &str,
) -> Result<(), ConformanceTrustError> {
    if id_to_fingerprint
        .get(key_id)
        .is_some_and(|known| known != fingerprint)
        || fingerprint_to_id
            .get(fingerprint)
            .is_some_and(|known| known != key_id)
    {
        return Err(invalid(
            "key id and public-key fingerprint are not a stable bijection",
        ));
    }
    id_to_fingerprint
        .entry(key_id.to_owned())
        .or_insert_with(|| fingerprint.to_owned());
    fingerprint_to_id
        .entry(fingerprint.to_owned())
        .or_insert_with(|| key_id.to_owned());
    Ok(())
}

fn valid_retired_to_revoked_transition(prior: &KeyTombstone, current: &KeyTombstone) -> bool {
    prior.terminal_state == KeyTerminalState::Retired
        && current.terminal_state == KeyTerminalState::Retired
        && prior.subsequent_revocation.is_none()
        && current.subsequent_revocation.is_some()
        && prior.key_id == current.key_id
        && prior.signer_identity == current.signer_identity
        && prior.algorithm == current.algorithm
        && prior.public_key_fingerprint == current.public_key_fingerprint
        && prior.terminated_at == current.terminated_at
        && prior.signatures_valid_before == current.signatures_valid_before
        && prior.reason == current.reason
        && prior.superseded_by_key_id == current.superseded_by_key_id
        && prior.trust_policy_version == current.trust_policy_version
}

fn validate_supersession(
    live: &BTreeMap<String, VerificationKeyMetadata>,
    tombstones: &BTreeMap<String, KeyTombstone>,
    historic_keys: &BTreeMap<String, VerificationKeyMetadata>,
    edges: &BTreeMap<String, String>,
) -> Result<(), ConformanceTrustError> {
    let mut live_successors = BTreeMap::<String, String>::new();
    for key in live.values() {
        let Some(predecessor_id) = &key.supersedes_key_id else {
            continue;
        };
        if key.lifecycle != KeyLifecycle::Active {
            return Err(invalid("a superseding key must be active"));
        }
        if live_successors
            .insert(predecessor_id.clone(), key.key_id.clone())
            .is_some()
        {
            return Err(invalid("a live key cannot have multiple live successors"));
        }
        let predecessor = historic_keys
            .get(predecessor_id)
            .ok_or_else(|| invalid("key supersession target is unknown"))?;
        if predecessor_id == &key.key_id
            || predecessor.signer_identity != key.signer_identity
            || predecessor.algorithm != key.algorithm
            || predecessor.public_key_fingerprint == key.public_key_fingerprint
            || predecessor.valid_from >= key.valid_from
        {
            return Err(invalid(
                "key supersession is self-referential, relabelled, or non-monotonic",
            ));
        }
        if live
            .get(predecessor_id)
            .is_some_and(|predecessor| predecessor.lifecycle != KeyLifecycle::Overlap)
        {
            return Err(invalid(
                "a live supersession target must be verification-only overlap",
            ));
        }
        if let Some(tombstone) = tombstones.get(predecessor_id)
            && tombstone.superseded_by_key_id.as_deref() != Some(key.key_id.as_str())
        {
            return Err(invalid("key/tombstone supersession links are inconsistent"));
        }
    }
    for tombstone in tombstones.values() {
        let Some(successor_id) = &tombstone.superseded_by_key_id else {
            continue;
        };
        let successor = historic_keys
            .get(successor_id)
            .ok_or_else(|| invalid("tombstone successor is unknown"))?;
        if successor_id == &tombstone.key_id
            || successor.signer_identity != tombstone.signer_identity
            || successor.algorithm != tombstone.algorithm
            || successor.public_key_fingerprint == tombstone.public_key_fingerprint
            || successor.supersedes_key_id.as_deref() != Some(tombstone.key_id.as_str())
        {
            return Err(invalid("tombstone successor is inconsistent"));
        }
    }
    require_acyclic_supersession(edges)
}

fn validate_required_nullable_fields(value: &Value) -> Result<(), ConformanceTrustError> {
    let root = value
        .as_object()
        .ok_or_else(|| invalid("registry root must be an object"))?;
    if !root.contains_key("predecessor_registry_ref") {
        return Err(invalid("missing required predecessor_registry_ref"));
    }
    let keys = root
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("keys must be an array"))?;
    for key in keys {
        if !key
            .as_object()
            .is_some_and(|object| object.contains_key("supersedes_key_id"))
        {
            return Err(invalid("missing required supersedes_key_id"));
        }
    }
    let tombstones = root
        .get("key_tombstones")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("key_tombstones must be an array"))?;
    for tombstone in tombstones {
        let Some(object) = tombstone.as_object() else {
            return Err(invalid("key tombstone must be an object"));
        };
        for field in [
            "signatures_valid_before",
            "superseded_by_key_id",
            "subsequent_revocation",
        ] {
            if !object.contains_key(field) {
                return Err(invalid(format!("missing required tombstone field {field}")));
            }
        }
    }
    Ok(())
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<(), ConformanceTrustError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => {
            if !value.is_i64() && !value.is_u64() {
                return Err(ConformanceTrustError::NonIntegerNumber);
            }
            output.extend_from_slice(value.to_string().as_bytes());
        }
        Value::String(value) => output.extend_from_slice(
            serde_json::to_string(value)
                .expect("serializing a string cannot fail")
                .as_bytes(),
        ),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let ordered: BTreeMap<&str, &Value> = values
                .iter()
                .map(|(key, value)| (key.as_str(), value))
                .collect();
            for (index, (key, value)) in ordered.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(
                    serde_json::to_string(key)
                        .expect("serializing an object key cannot fail")
                        .as_bytes(),
                );
                output.push(b':');
                write_canonical_json(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn write_frame(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    output.extend_from_slice(bytes);
}

fn decode_canonical_base64<const N: usize>(
    encoded: &str,
    label: &'static str,
) -> Result<[u8; N], ConformanceTrustError> {
    let decoded = BASE64_STANDARD
        .decode(encoded)
        .map_err(|_| ConformanceTrustError::InvalidBase64(label))?;
    if decoded.len() != N || BASE64_STANDARD.encode(&decoded) != encoded {
        return Err(ConformanceTrustError::InvalidBase64(label));
    }
    decoded
        .try_into()
        .map_err(|_| ConformanceTrustError::InvalidBase64(label))
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn require_digest(value: &str, label: &'static str) -> Result<(), ConformanceTrustError> {
    if is_digest(value) {
        Ok(())
    } else {
        Err(invalid(label))
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

fn require_acyclic_supersession(
    edges: &BTreeMap<String, String>,
) -> Result<(), ConformanceTrustError> {
    for start in edges.keys() {
        let mut seen = BTreeSet::new();
        let mut current = start.as_str();
        while let Some(next) = edges.get(current) {
            if !seen.insert(current.to_owned()) {
                return Err(invalid("key supersession graph contains a cycle"));
            }
            current = next;
        }
    }
    Ok(())
}

fn require_unique<T: Ord + Clone>(values: &[T], label: &str) -> Result<(), ConformanceTrustError> {
    let unique: BTreeSet<T> = values.iter().cloned().collect();
    if unique.len() == values.len() {
        Ok(())
    } else {
        Err(invalid(format!("duplicate {label}")))
    }
}

fn valid_package_id(value: &str) -> bool {
    matches!(
        value,
        "SB-0" | "SB-1" | "SB-2" | "SB-3" | "SB-4" | "SB-5" | "SB-6" | "SB-7" | "SB-8" | "SB-9"
    )
}

fn valid_artifact_locator(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.contains('\0')
        && value.ends_with(".json")
        && value.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        })
}

fn valid_scoped_id(value: &str, prefix: &str) -> bool {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return false;
    };
    (3..=127).contains(&suffix.len())
        && suffix
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && suffix.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
}

fn invalid(message: impl Into<String>) -> ConformanceTrustError {
    ConformanceTrustError::InvalidContract(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn at(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn pin() -> &'static str {
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }

    fn fingerprint(key: &SigningKey) -> String {
        sha256_digest(&key.verifying_key().to_bytes())
    }

    fn registry(
        key: &SigningKey,
        version: u64,
        effective_at: &str,
        trust_policy_version: u64,
        predecessor_registry_ref: Option<Value>,
    ) -> Value {
        json!({
            "$schema": TRUST_REGISTRY_SCHEMA_URI,
            "schema_version": "1.0.0",
            "contract_kind": TRUST_REGISTRY_CONTRACT_KIND,
            "document_id": "conformance-trust-root-registry:test-root",
            "document_version": version,
            "predecessor_registry_ref": predecessor_registry_ref,
            "acceptance_status": "production_accepted",
            "production_accepted": true,
            "lifecycle": {"state": "active", "effective_at": effective_at},
            "applicability": {
                "evaluation_scope": "deployment",
                "security_profiles": ["production"],
                "deployment_ids": ["deployment:test"],
                "trust_domain_ids": ["trust-domain:test"]
            },
            "trust_policy_version": trust_policy_version,
            "canonicalization_profiles": [CANONICALIZATION_PROFILE],
            "signature_algorithms": [SIGNATURE_ALGORITHM],
            "keys": [{
                "key_id": "conformance-key:test-key",
                "signer_identity": "signer:test",
                "algorithm": SIGNATURE_ALGORITHM,
                "public_key_base64": BASE64_STANDARD.encode(key.verifying_key().to_bytes()),
                "public_key_fingerprint": fingerprint(key),
                "allowed_purposes": ["conformance_bundle", "package_exit_receipt"],
                "allowed_evidence_tiers": ["externally_attested"],
                "allowed_package_ids": ["SB-0"],
                "deployment_ids": ["deployment:test"],
                "trust_domain_ids": ["trust-domain:test"],
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
                "lifecycle": "active",
                "supersedes_key_id": null
            }],
            "key_tombstones": []
        })
    }

    fn two_version_chain(key: &SigningKey) -> (Vec<u8>, Vec<u8>, String, String) {
        let first = serde_json::to_vec(&registry(key, 1, "2026-01-01T00:00:00Z", 1, None)).unwrap();
        let first_digest = sha256_digest(&first);
        let predecessor = json!({
            "artifact_kind": TRUST_REGISTRY_CONTRACT_KIND,
            "document_id": "conformance-trust-root-registry:test-root",
            "document_version": 1,
            "content_digest": first_digest,
            "artifact_locator": "registry/v1.json"
        });
        let second = serde_json::to_vec(&registry(
            key,
            2,
            "2026-07-01T00:00:00Z",
            1,
            Some(predecessor),
        ))
        .unwrap();
        let second_digest = sha256_digest(&second);
        (first, second, first_digest, second_digest)
    }

    fn lineage_for_chain(
        first: &[u8],
        second: &[u8],
        second_digest: &str,
    ) -> Result<ValidatedConformanceRegistryLineage, ConformanceTrustError> {
        ValidatedConformanceRegistryLineage::from_registry_chain(
            &[
                ConformanceRegistryArtifact {
                    artifact_locator: "registry/v1.json",
                    raw_bytes: first,
                },
                ConformanceRegistryArtifact {
                    artifact_locator: "registry/v2.json",
                    raw_bytes: second,
                },
            ],
            ConformanceTrustAnchor {
                artifact_locator: "registry/v2.json",
                document_id: "conformance-trust-root-registry:test-root",
                document_version: 2,
                content_digest: second_digest,
            },
            at("2026-07-16T10:01:00Z"),
        )
    }

    fn unsigned(registry_version: u64, registry_digest: &str, signed_at: &str) -> Value {
        json!({
            "$schema": CONFORMANCE_BUNDLE_SCHEMA_URI,
            "schema_version": "1.0.0",
            "contract_kind": "conformance-bundle",
            "bundle_id": "bundle:test",
            "document_version": 1,
            "bindings": {"deployment_profile": {"deployment_id": "deployment:test"}},
            "provenance": {"evidence_tier": {"name": "externally_attested"}},
            "signer": {
                "signature_version": SIGNATURE_VERSION,
                "identity": "signer:test",
                "key_id": "conformance-key:test-key",
                "algorithm": SIGNATURE_ALGORITHM,
                "canonicalization": CANONICALIZATION_PROFILE,
                "purpose": "conformance_bundle",
                "domain": CONFORMANCE_BUNDLE_DOMAIN,
                "trust_registry_id": "conformance-trust-root-registry:test-root",
                "trust_registry_version": registry_version,
                "trust_registry_digest": registry_digest,
                "signed_at": signed_at,
                "signed_subject_digest": pin(),
                "signature_base64": BASE64_STANDARD.encode([0u8; 64])
            }
        })
    }

    fn sign(mut document: Value, key: &SigningKey) -> Value {
        let digest = conformance_signed_subject_digest(&document).unwrap();
        document["signer"]["signed_subject_digest"] = json!(digest);
        let signature = key.sign(&conformance_signing_bytes(&document).unwrap());
        document["signer"]["signature_base64"] =
            json!(BASE64_STANDARD.encode(signature.to_bytes()));
        document
    }

    fn context() -> ConformanceVerificationContext<'static> {
        ConformanceVerificationContext {
            deployment_id: "deployment:test",
            trust_domain_id: "trust-domain:test",
            package_id: "SB-0",
            evidence_tier: EvidenceTier::ExternallyAttested,
        }
    }

    struct AuthorityFixture {
        signing_key: SigningKey,
        public_key: [u8; 32],
        fingerprint: String,
    }

    impl AuthorityFixture {
        fn new(seed: u8) -> Self {
            let signing_key = SigningKey::from_bytes(&[seed; 32]);
            let public_key = signing_key.verifying_key().to_bytes();
            let fingerprint = sha256_digest(&public_key);
            Self {
                signing_key,
                public_key,
                fingerprint,
            }
        }

        fn anchor(&self, minimum_authority_epoch: u64) -> ConformanceCheckpointAuthorityAnchor<'_> {
            ConformanceCheckpointAuthorityAnchor {
                authority_id: "conformance-trust-checkpoint-authority:test",
                key_id: "conformance-trust-checkpoint-key:test",
                public_key: &self.public_key,
                public_key_fingerprint: &self.fingerprint,
                minimum_authority_epoch,
            }
        }
    }

    fn complete_document_digest(document: &Value) -> String {
        sha256_digest(&serde_json::to_vec(document).unwrap())
    }

    fn acceptance_record(
        document: &Value,
        complete_digest: &str,
        key_fingerprint: &str,
        registry_locator: &str,
        accepted_not_before: &str,
        accepted_not_after: &str,
        authority_sequence: u64,
    ) -> Value {
        let identity = document_identity(document).unwrap();
        let signer: ConformanceSignatureMetadata =
            serde_json::from_value(document["signer"].clone()).unwrap();
        let registry_version = signer.trust_registry_version;
        let signature =
            decode_canonical_base64::<64>(&signer.signature_base64, "signature").unwrap();
        json!({
            "acceptance_record_id": format!("conformance-acceptance:evt-{authority_sequence}"),
            "document": {
                "contract_kind": identity.kind.as_str(),
                "document_id": identity.id,
                "document_version": identity.version,
                "complete_document_digest": complete_digest,
                "signature_digest": sha256_digest(&signature),
                "signed_subject_digest": signer.signed_subject_digest,
            },
            "signer": {
                "key_id": signer.key_id,
                "public_key_fingerprint": key_fingerprint,
            },
            "registry": {
                "registry_id": signer.trust_registry_id,
                "registry_version": signer.trust_registry_version,
                "registry_digest": signer.trust_registry_digest,
                "artifact_locator": registry_locator,
                "head_sequence": registry_version,
                "head_authority_revision": registry_version,
            },
            "deployment_id": "deployment:test",
            "trust_domain_id": "trust-domain:test",
            "work_package_id": "SB-0",
            "purpose": signer.purpose,
            "evidence_tier": "externally_attested",
            "authority_sequence": authority_sequence,
            "authority_epoch": 7,
            "accepted_at": {
                "not_before": accepted_not_before,
                "not_after": accepted_not_after,
            },
            "lifecycle": "accepted",
        })
    }

    fn response_value(
        request: &ConformanceCheckpointRequest,
        authority: &AuthorityFixture,
        acceptance_records: Vec<Value>,
    ) -> Value {
        json!({
            "schema_version": TRUST_REGISTRY_SCHEMA_VERSION,
            "contract_kind": TRUST_RECONCILIATION_RESPONSE_KIND,
            "canonicalization": CANONICALIZATION_PROFILE,
            "signature_algorithm": SIGNATURE_ALGORITHM,
            "authority": {
                "authority_id": "conformance-trust-checkpoint-authority:test",
                "key_id": "conformance-trust-checkpoint-key:test",
                "public_key_fingerprint": authority.fingerprint,
            },
            "request_nonce": request.nonce,
            "request_digest": request.digest,
            "namespace": request.namespace,
            "candidate_head": request.candidate_head,
            "current_head": request.candidate_head,
            "validated_lineage_digest": request.validated_lineage_digest,
            "state": "external_strongly_consistent",
            "outcome": "matched",
            "reconciliation": {
                "candidate_matches_current": true,
                "restored_state_reconciled": true,
                "no_auto_advance": true,
            },
            "checkpoint": {
                "sequence": 20,
                "authority_epoch": 7,
                "authority_revision": 3,
                "observed_at": {
                    "not_before": "2026-07-16T10:00:00Z",
                    "not_after": "2026-07-16T10:00:01Z",
                },
                "valid_until": "2026-07-16T10:04:00Z",
            },
            "acceptance_records": acceptance_records,
            "signature_base64": BASE64_STANDARD.encode([0u8; 64]),
        })
    }

    fn sign_response(mut response: Value, authority: &AuthorityFixture) -> Vec<u8> {
        let mut subject = response.clone();
        subject.as_object_mut().unwrap().remove("signature_base64");
        let canonical = canonical_json_bytes(&subject).unwrap();
        let mut signing_bytes = Vec::new();
        write_frame(
            &mut signing_bytes,
            TRUST_RECONCILIATION_RESPONSE_DOMAIN.as_bytes(),
        );
        write_frame(&mut signing_bytes, &canonical);
        let signature = authority.signing_key.sign(&signing_bytes);
        response["signature_base64"] = json!(BASE64_STANDARD.encode(signature.to_bytes()));
        serde_json::to_vec(&response).unwrap()
    }

    fn trusted_now() -> ConformanceTrustedTimeWindow {
        ConformanceTrustedTimeWindow {
            not_before: at("2026-07-16T10:00:02Z"),
            not_after: at("2026-07-16T10:00:03Z"),
        }
    }

    fn request_for(
        lineage: &ValidatedConformanceRegistryLineage,
        authority: &AuthorityFixture,
        document_digests: &[String],
    ) -> ConformanceCheckpointRequest {
        lineage
            .reconciliation_request(
                ConformanceTrustScope {
                    deployment_id: "deployment:test",
                    trust_domain_id: "trust-domain:test",
                },
                authority.anchor(7),
                [42; 32],
                at("2026-07-16T09:59:59Z"),
                document_digests,
            )
            .unwrap()
    }

    #[test]
    fn reconciliation_decision_classifies_all_head_states() {
        let namespace = CheckpointNamespace {
            deployment_id: "deployment:test".into(),
            trust_domain_id: "trust-domain:test".into(),
            registry_id: "conformance-trust-root-registry:test-root".into(),
        };
        let local = CheckpointRegistryHead {
            registry_version: 2,
            content_digest: pin().into(),
            artifact_locator: "registry/v2.json".into(),
        };
        assert_eq!(
            reconciliation_decision(&namespace, &local, None, false),
            ConformanceReconciliationDecision::Missing
        );
        assert_eq!(
            reconciliation_decision(&namespace, &local, Some((&namespace, &local)), false),
            ConformanceReconciliationDecision::Matched
        );

        let rollback = CheckpointRegistryHead {
            registry_version: 1,
            content_digest: pin().into(),
            artifact_locator: "registry/v1.json".into(),
        };
        assert_eq!(
            reconciliation_decision(&namespace, &local, Some((&namespace, &rollback)), true),
            ConformanceReconciliationDecision::Rollback
        );
        let fork = CheckpointRegistryHead {
            registry_version: 2,
            content_digest:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            artifact_locator: "registry/v2.json".into(),
        };
        assert_eq!(
            reconciliation_decision(&namespace, &local, Some((&namespace, &fork)), false),
            ConformanceReconciliationDecision::SameVersionFork
        );
        let relocated = CheckpointRegistryHead {
            artifact_locator: "relocated/v2.json".into(),
            ..local.clone()
        };
        assert_eq!(
            reconciliation_decision(&namespace, &local, Some((&namespace, &relocated)), false),
            ConformanceReconciliationDecision::RelocationRequired
        );
        let higher = CheckpointRegistryHead {
            registry_version: 3,
            content_digest:
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
            artifact_locator: "registry/v3.json".into(),
        };
        assert_eq!(
            reconciliation_decision(&namespace, &local, Some((&namespace, &higher)), true),
            ConformanceReconciliationDecision::AdvanceRequired
        );
        assert_eq!(
            reconciliation_decision(&namespace, &local, Some((&namespace, &higher)), false),
            ConformanceReconciliationDecision::NonDescendant
        );
        let wrong_scope = CheckpointNamespace {
            deployment_id: "deployment:other".into(),
            ..namespace.clone()
        };
        assert_eq!(
            reconciliation_decision(&namespace, &local, Some((&wrong_scope, &local)), false,),
            ConformanceReconciliationDecision::WrongScope
        );
    }

    #[test]
    fn checkpoint_response_rejects_bad_signature_nonce_duplicate_and_stale_boundaries() {
        let key = SigningKey::from_bytes(&[70; 32]);
        let (first, second, _, second_digest) = two_version_chain(&key);
        let lineage = lineage_for_chain(&first, &second, &second_digest).unwrap();
        let authority = AuthorityFixture::new(102);
        let request = request_for(&lineage, &authority, &[]);

        let valid = sign_response(response_value(&request, &authority, vec![]), &authority);
        assert!(
            lineage
                .clone()
                .verify_reconciliation_response(
                    &request,
                    &valid,
                    authority.anchor(7),
                    trusted_now(),
                )
                .is_ok()
        );

        let rogue = AuthorityFixture::new(103);
        let bad_signature = sign_response(response_value(&request, &authority, vec![]), &rogue);
        assert!(matches!(
            lineage.clone().verify_reconciliation_response(
                &request,
                &bad_signature,
                authority.anchor(7),
                trusted_now(),
            ),
            Err(ConformanceTrustError::InvalidCheckpointSignature)
        ));

        let mut wrong_nonce = response_value(&request, &authority, vec![]);
        wrong_nonce["request_nonce"] = json!(BASE64_STANDARD.encode([43u8; 32]));
        let wrong_nonce = sign_response(wrong_nonce, &authority);
        assert!(matches!(
            lineage.clone().verify_reconciliation_response(
                &request,
                &wrong_nonce,
                authority.anchor(7),
                trusted_now(),
            ),
            Err(ConformanceTrustError::InvalidCheckpoint(_))
        ));

        let mut rollback = response_value(&request, &authority, vec![]);
        rollback["current_head"]["registry_version"] = json!(1);
        let mut fork = response_value(&request, &authority, vec![]);
        fork["current_head"]["content_digest"] =
            json!("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let mut relocation = response_value(&request, &authority, vec![]);
        relocation["current_head"]["artifact_locator"] = json!("relocated/v2.json");
        let mut wrong_namespace = response_value(&request, &authority, vec![]);
        wrong_namespace["namespace"]["deployment_id"] = json!("deployment:other");
        let mut unreconciled_restore = response_value(&request, &authority, vec![]);
        unreconciled_restore["reconciliation"]["restored_state_reconciled"] = json!(false);
        let mut auto_advance = response_value(&request, &authority, vec![]);
        auto_advance["reconciliation"]["no_auto_advance"] = json!(false);
        for semantic_failure in [
            rollback,
            fork,
            relocation,
            wrong_namespace,
            unreconciled_restore,
            auto_advance,
        ] {
            let response = sign_response(semantic_failure, &authority);
            assert!(
                lineage
                    .clone()
                    .verify_reconciliation_response(
                        &request,
                        &response,
                        authority.anchor(7),
                        trusted_now(),
                    )
                    .is_err()
            );
        }

        let mut over_counter = response_value(&request, &authority, vec![]);
        over_counter["checkpoint"]["sequence"] = json!(MAX_CANONICAL_JSON_COUNTER + 1);
        let over_counter = sign_response(over_counter, &authority);
        assert!(
            lineage
                .clone()
                .verify_reconciliation_response(
                    &request,
                    &over_counter,
                    authority.anchor(7),
                    trusted_now(),
                )
                .is_err()
        );

        let mut expires_at_now = response_value(&request, &authority, vec![]);
        expires_at_now["checkpoint"]["valid_until"] = json!("2026-07-16T10:00:03Z");
        let expires_at_now = sign_response(expires_at_now, &authority);
        assert!(
            lineage
                .clone()
                .verify_reconciliation_response(
                    &request,
                    &expires_at_now,
                    authority.anchor(7),
                    trusted_now(),
                )
                .is_err()
        );

        let mut no_fresh_interval = response_value(&request, &authority, vec![]);
        no_fresh_interval["checkpoint"]["valid_until"] = json!("2026-07-16T10:00:01Z");
        let no_fresh_interval = sign_response(no_fresh_interval, &authority);
        assert!(
            lineage
                .clone()
                .verify_reconciliation_response(
                    &request,
                    &no_fresh_interval,
                    authority.anchor(7),
                    trusted_now(),
                )
                .is_err()
        );

        let mut fractional_overrun = response_value(&request, &authority, vec![]);
        fractional_overrun["checkpoint"]["valid_until"] = json!("2026-07-16T10:05:00.001Z");
        let fractional_overrun = sign_response(fractional_overrun, &authority);
        assert!(
            lineage
                .clone()
                .verify_reconciliation_response(
                    &request,
                    &fractional_overrun,
                    authority.anchor(7),
                    trusted_now(),
                )
                .is_err()
        );

        let signed = String::from_utf8(valid).unwrap();
        let duplicate = signed.replacen(
            "\"state\":",
            "\"state\":\"external_strongly_consistent\",\"state\":",
            1,
        );
        assert!(matches!(
            lineage.verify_reconciliation_response(
                &request,
                duplicate.as_bytes(),
                authority.anchor(7),
                trusted_now(),
            ),
            Err(ConformanceTrustError::InvalidTypedValue(message))
                if message.contains("duplicate JSON object key")
        ));
    }

    #[test]
    fn checkpoint_authority_is_independently_scoped_key_separated_and_epoch_fenced() {
        let key = SigningKey::from_bytes(&[73; 32]);
        let (first, second, _, second_digest) = two_version_chain(&key);
        let lineage = lineage_for_chain(&first, &second, &second_digest).unwrap();
        let reused_authority = AuthorityFixture::new(73);
        assert!(matches!(
            lineage.reconciliation_request(
                ConformanceTrustScope {
                    deployment_id: "deployment:test",
                    trust_domain_id: "trust-domain:test",
                },
                reused_authority.anchor(7),
                [1; 32],
                at("2026-07-16T09:59:59Z"),
                &[],
            ),
            Err(ConformanceTrustError::InvalidCheckpoint(message))
                if message.contains("reuses")
        ));

        let authority = AuthorityFixture::new(107);
        assert!(
            lineage
                .reconciliation_request(
                    ConformanceTrustScope {
                        deployment_id: "deployment:other",
                        trust_domain_id: "trust-domain:test",
                    },
                    authority.anchor(7),
                    [1; 32],
                    at("2026-07-16T09:59:59Z"),
                    &[],
                )
                .is_err()
        );
        assert!(
            lineage
                .reconciliation_request(
                    ConformanceTrustScope {
                        deployment_id: "deployment:test",
                        trust_domain_id: "trust-domain:test",
                    },
                    authority.anchor(7),
                    [0; 32],
                    at("2026-07-16T09:59:59Z"),
                    &[],
                )
                .is_err()
        );

        let request = lineage
            .reconciliation_request(
                ConformanceTrustScope {
                    deployment_id: "deployment:test",
                    trust_domain_id: "trust-domain:test",
                },
                authority.anchor(8),
                [1; 32],
                at("2026-07-16T09:59:59Z"),
                &[],
            )
            .unwrap();
        let response = sign_response(response_value(&request, &authority, vec![]), &authority);
        assert!(
            lineage
                .verify_reconciliation_response(
                    &request,
                    &response,
                    authority.anchor(8),
                    trusted_now(),
                )
                .is_err()
        );
    }

    #[test]
    fn reconciliation_request_covers_the_complete_bounded_contract_inventory() {
        let key = SigningKey::from_bytes(&[74; 32]);
        let (first, second, _, second_digest) = two_version_chain(&key);
        let lineage = lineage_for_chain(&first, &second, &second_digest).unwrap();
        let authority = AuthorityFixture::new(108);
        let complete_inventory = (1..=MAX_ACCEPTANCE_RECORDS)
            .map(|index| format!("sha256:{index:064x}"))
            .collect::<Vec<_>>();

        let request = lineage
            .reconciliation_request(
                ConformanceTrustScope {
                    deployment_id: "deployment:test",
                    trust_domain_id: "trust-domain:test",
                },
                authority.anchor(7),
                [1; 32],
                at("2026-07-16T09:59:59Z"),
                &complete_inventory,
            )
            .expect("the complete bounded contract inventory must fit one reconciliation");
        assert!(request.as_bytes().len() <= MAX_RECONCILIATION_REQUEST_BYTES);

        let mut oversized = complete_inventory;
        oversized.push(format!("sha256:{:064x}", MAX_ACCEPTANCE_RECORDS + 1));
        assert!(
            lineage
                .reconciliation_request(
                    ConformanceTrustScope {
                        deployment_id: "deployment:test",
                        trust_domain_id: "trust-domain:test",
                    },
                    authority.anchor(7),
                    [1; 32],
                    at("2026-07-16T09:59:59Z"),
                    &oversized,
                )
                .unwrap_err()
                .to_string()
                .contains("bounded to 4096")
        );
    }

    #[test]
    fn lookup_request_and_response_reject_missing_unsolicited_and_reused_events() {
        let key = SigningKey::from_bytes(&[71; 32]);
        let (first, second, first_digest, second_digest) = two_version_chain(&key);
        let lineage = lineage_for_chain(&first, &second, &second_digest).unwrap();
        let authority = AuthorityFixture::new(104);
        let document = sign(unsigned(2, &second_digest, "2026-07-16T09:59:00Z"), &key);
        let digest = complete_document_digest(&document);

        let duplicate = vec![digest.clone(), digest.clone()];
        assert!(
            lineage
                .reconciliation_request(
                    ConformanceTrustScope {
                        deployment_id: "deployment:test",
                        trust_domain_id: "trust-domain:test",
                    },
                    authority.anchor(7),
                    [1; 32],
                    at("2026-07-16T09:59:59Z"),
                    &duplicate,
                )
                .is_err()
        );
        let unsorted = vec![
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned(),
            digest.clone(),
        ];
        assert!(
            lineage
                .reconciliation_request(
                    ConformanceTrustScope {
                        deployment_id: "deployment:test",
                        trust_domain_id: "trust-domain:test",
                    },
                    authority.anchor(7),
                    [1; 32],
                    at("2026-07-16T09:59:59Z"),
                    &unsorted,
                )
                .is_err()
        );

        let request = request_for(&lineage, &authority, std::slice::from_ref(&digest));
        let missing = sign_response(response_value(&request, &authority, vec![]), &authority);
        assert!(matches!(
            lineage.clone().verify_reconciliation_response(
                &request,
                &missing,
                authority.anchor(7),
                trusted_now(),
            ),
            Err(ConformanceTrustError::InvalidAcceptance(_))
        ));

        let empty_request = request_for(&lineage, &authority, &[]);
        let unsolicited_record = acceptance_record(
            &document,
            &digest,
            &fingerprint(&key),
            "registry/v2.json",
            "2026-07-16T09:59:58Z",
            "2026-07-16T09:59:59Z",
            10,
        );
        let unsolicited = sign_response(
            response_value(&empty_request, &authority, vec![unsolicited_record]),
            &authority,
        );
        assert!(matches!(
            lineage.clone().verify_reconciliation_response(
                &empty_request,
                &unsolicited,
                authority.anchor(7),
                trusted_now(),
            ),
            Err(ConformanceTrustError::InvalidAcceptance(_))
        ));

        let mut historic = unsigned(1, &first_digest, "2026-06-01T00:00:00Z");
        historic["bundle_id"] = json!("bundle:historic");
        let historic = sign(historic, &key);
        let historic_digest = complete_document_digest(&historic);
        let mut both = vec![digest.clone(), historic_digest.clone()];
        both.sort();
        let request = request_for(&lineage, &authority, &both);
        let reused_sequence = vec![
            acceptance_record(
                &document,
                &digest,
                &fingerprint(&key),
                "registry/v2.json",
                "2026-07-16T09:59:58Z",
                "2026-07-16T09:59:59Z",
                10,
            ),
            acceptance_record(
                &historic,
                &historic_digest,
                &fingerprint(&key),
                "registry/v1.json",
                "2026-06-01T00:00:01Z",
                "2026-06-01T00:00:02Z",
                10,
            ),
        ];
        let reused_sequence = sign_response(
            response_value(&request, &authority, reused_sequence),
            &authority,
        );
        assert!(matches!(
            lineage.verify_reconciliation_response(
                &request,
                &reused_sequence,
                authority.anchor(7),
                trusted_now(),
            ),
            Err(ConformanceTrustError::InvalidAcceptance(_))
        ));
    }

    #[test]
    fn acceptance_set_rejects_head_conflicts_inversion_and_document_forks() {
        let key = SigningKey::from_bytes(&[74; 32]);
        let (first, second, first_digest, second_digest) = two_version_chain(&key);
        let lineage = lineage_for_chain(&first, &second, &second_digest).unwrap();
        let authority = AuthorityFixture::new(106);
        let first_current = sign(unsigned(2, &second_digest, "2026-07-16T09:58:00Z"), &key);
        let mut second_current = unsigned(2, &second_digest, "2026-07-16T09:58:01Z");
        second_current["bundle_id"] = json!("bundle:second");
        second_current["document_version"] = json!(2);
        let second_current = sign(second_current, &key);
        let first_current_digest = complete_document_digest(&first_current);
        let second_current_digest = complete_document_digest(&second_current);
        let mut requested = vec![first_current_digest.clone(), second_current_digest.clone()];
        requested.sort();
        let request = request_for(&lineage, &authority, &requested);
        let first_record = acceptance_record(
            &first_current,
            &first_current_digest,
            &fingerprint(&key),
            "registry/v2.json",
            "2026-07-16T09:59:56Z",
            "2026-07-16T09:59:57Z",
            10,
        );
        let mut conflicting_record = acceptance_record(
            &second_current,
            &second_current_digest,
            &fingerprint(&key),
            "registry/v2.json",
            "2026-07-16T09:59:58Z",
            "2026-07-16T09:59:59Z",
            11,
        );
        conflicting_record["registry"]["head_sequence"] = json!(3);
        let response = sign_response(
            response_value(&request, &authority, vec![first_record, conflicting_record]),
            &authority,
        );
        assert!(matches!(
            lineage.clone().verify_reconciliation_response(
                &request,
                &response,
                authority.anchor(7),
                trusted_now(),
            ),
            Err(ConformanceTrustError::InvalidAcceptance(_))
        ));

        let mut historic = unsigned(1, &first_digest, "2026-06-01T00:00:00Z");
        historic["bundle_id"] = json!("bundle:historic");
        let historic = sign(historic, &key);
        let historic_digest = complete_document_digest(&historic);
        let mut requested = vec![historic_digest.clone(), first_current_digest.clone()];
        requested.sort();
        let request = request_for(&lineage, &authority, &requested);
        let historic_record = acceptance_record(
            &historic,
            &historic_digest,
            &fingerprint(&key),
            "registry/v1.json",
            "2026-06-01T00:00:01Z",
            "2026-06-01T00:00:02Z",
            9,
        );
        let mut inverted_record = acceptance_record(
            &first_current,
            &first_current_digest,
            &fingerprint(&key),
            "registry/v2.json",
            "2026-07-16T09:59:58Z",
            "2026-07-16T09:59:59Z",
            10,
        );
        inverted_record["registry"]["head_sequence"] = json!(1);
        inverted_record["registry"]["head_authority_revision"] = json!(1);
        let response = sign_response(
            response_value(&request, &authority, vec![historic_record, inverted_record]),
            &authority,
        );
        assert!(matches!(
            lineage.clone().verify_reconciliation_response(
                &request,
                &response,
                authority.anchor(7),
                trusted_now(),
            ),
            Err(ConformanceTrustError::InvalidAcceptance(_))
        ));

        let mut fork = unsigned(2, &second_digest, "2026-07-16T09:58:02Z");
        fork["fork_marker"] = json!("different signed bytes");
        let fork = sign(fork, &key);
        let fork_digest = complete_document_digest(&fork);
        let mut requested = vec![first_current_digest.clone(), fork_digest.clone()];
        requested.sort();
        let request = request_for(&lineage, &authority, &requested);
        let response = sign_response(
            response_value(
                &request,
                &authority,
                vec![
                    acceptance_record(
                        &first_current,
                        &first_current_digest,
                        &fingerprint(&key),
                        "registry/v2.json",
                        "2026-07-16T09:59:56Z",
                        "2026-07-16T09:59:57Z",
                        10,
                    ),
                    acceptance_record(
                        &fork,
                        &fork_digest,
                        &fingerprint(&key),
                        "registry/v2.json",
                        "2026-07-16T09:59:58Z",
                        "2026-07-16T09:59:59Z",
                        11,
                    ),
                ],
            ),
            &authority,
        );
        assert!(matches!(
            lineage.verify_reconciliation_response(
                &request,
                &response,
                authority.anchor(7),
                trusted_now(),
            ),
            Err(ConformanceTrustError::InvalidAcceptance(_))
        ));
    }

    #[test]
    fn authenticated_acceptance_verifies_current_and_historic_active_snapshots() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let (first, second, first_digest, second_digest) = two_version_chain(&key);
        let lineage = lineage_for_chain(&first, &second, &second_digest).unwrap();
        let authority = AuthorityFixture::new(101);

        let current = sign(unsigned(2, &second_digest, "2026-07-16T09:59:00Z"), &key);
        let current_digest = complete_document_digest(&current);
        let mut historic = unsigned(1, &first_digest, "2026-06-01T00:00:00Z");
        historic["bundle_id"] = json!("bundle:historic");
        let historic = sign(historic, &key);
        let historic_digest = complete_document_digest(&historic);
        let mut requested = vec![current_digest.clone(), historic_digest.clone()];
        requested.sort();
        let request = request_for(&lineage, &authority, &requested);
        let records = vec![
            acceptance_record(
                &current,
                &current_digest,
                &fingerprint(&key),
                "registry/v2.json",
                "2026-07-16T09:59:58Z",
                "2026-07-16T09:59:59Z",
                11,
            ),
            acceptance_record(
                &historic,
                &historic_digest,
                &fingerprint(&key),
                "registry/v1.json",
                "2026-06-01T00:00:01Z",
                "2026-06-01T00:00:02Z",
                9,
            ),
        ];
        let raw_response = sign_response(response_value(&request, &authority, records), &authority);
        let checkpoint = lineage
            .verify_reconciliation_response(
                &request,
                &raw_response,
                authority.anchor(7),
                trusted_now(),
            )
            .unwrap();

        let current_verified = checkpoint
            .verify_document(
                &serde_json::to_vec(&current).unwrap(),
                context(),
                trusted_now(),
            )
            .unwrap();
        assert_eq!(current_verified.registry_version(), 2);
        assert_eq!(current_verified.registry_digest(), second_digest);
        assert_eq!(current_verified.acceptance_sequence(), 11);
        assert_eq!(current_verified.authority_epoch(), 7);

        let historic_verified = checkpoint
            .verify_document(
                &serde_json::to_vec(&historic).unwrap(),
                context(),
                trusted_now(),
            )
            .unwrap();
        assert_eq!(historic_verified.registry_version(), 1);
        assert_eq!(
            historic_verified.complete_document_digest(),
            historic_digest
        );
    }

    #[test]
    fn exact_raw_bytes_and_trusted_acceptance_time_are_authoritative() {
        let key = SigningKey::from_bytes(&[72; 32]);
        let (first, second, _, second_digest) = two_version_chain(&key);
        let lineage = lineage_for_chain(&first, &second, &second_digest).unwrap();
        let authority = AuthorityFixture::new(105);
        let document = sign(unsigned(2, &second_digest, "2026-07-16T09:59:00Z"), &key);
        let raw = serde_json::to_vec(&document).unwrap();
        let digest = sha256_digest(&raw);
        let request = request_for(&lineage, &authority, std::slice::from_ref(&digest));
        let record = acceptance_record(
            &document,
            &digest,
            &fingerprint(&key),
            "registry/v2.json",
            "2026-07-16T09:59:58Z",
            "2026-07-16T09:59:59Z",
            10,
        );
        let response = sign_response(
            response_value(&request, &authority, vec![record]),
            &authority,
        );
        let checkpoint = lineage
            .clone()
            .verify_reconciliation_response(&request, &response, authority.anchor(7), trusted_now())
            .unwrap();
        checkpoint
            .verify_document(&raw, context(), trusted_now())
            .unwrap();
        let expires_exactly = ConformanceTrustedTimeWindow {
            not_before: at("2026-07-16T10:03:59Z"),
            not_after: at("2026-07-16T10:04:00Z"),
        };
        assert!(checkpoint.ensure_fresh(expires_exactly).is_err());
        assert!(
            checkpoint
                .verify_document(&raw, context(), expires_exactly)
                .is_err()
        );

        let semantically_equal_but_different_raw = serde_json::to_vec_pretty(&document).unwrap();
        assert!(matches!(
            checkpoint.verify_document(
                &semantically_equal_but_different_raw,
                context(),
                trusted_now(),
            ),
            Err(ConformanceTrustError::InvalidAcceptance(_))
        ));

        let inconsistent = sign(unsigned(2, &second_digest, "2026-07-16T10:00:00Z"), &key);
        let inconsistent_raw = serde_json::to_vec(&inconsistent).unwrap();
        let inconsistent_digest = sha256_digest(&inconsistent_raw);
        let request = request_for(
            &lineage,
            &authority,
            std::slice::from_ref(&inconsistent_digest),
        );
        let record = acceptance_record(
            &inconsistent,
            &inconsistent_digest,
            &fingerprint(&key),
            "registry/v2.json",
            "2026-07-16T09:59:58Z",
            "2026-07-16T09:59:59Z",
            12,
        );
        let response = sign_response(
            response_value(&request, &authority, vec![record]),
            &authority,
        );
        let checkpoint = lineage
            .verify_reconciliation_response(&request, &response, authority.anchor(7), trusted_now())
            .unwrap();
        assert!(matches!(
            checkpoint.verify_document(&inconsistent_raw, context(), trusted_now()),
            Err(ConformanceTrustError::KeyNotAuthorized(message))
                if message.contains("signed_at")
        ));
    }

    #[test]
    fn exact_links_anchor_policy_and_applicability_fail_closed() {
        let key = SigningKey::from_bytes(&[8; 32]);
        let successor_key = SigningKey::from_bytes(&[14; 32]);
        let (first, second, _, _) = two_version_chain(&key);

        let mut wrong_link: Value = serde_json::from_slice(&second).unwrap();
        wrong_link["predecessor_registry_ref"]["content_digest"] = json!(pin());
        let wrong_link = serde_json::to_vec(&wrong_link).unwrap();
        let wrong_link_digest = sha256_digest(&wrong_link);
        assert!(lineage_for_chain(&first, &wrong_link, &wrong_link_digest).is_err());

        assert!(lineage_for_chain(&first, &second, pin()).is_err());

        let mut authority_change: Value = serde_json::from_slice(&second).unwrap();
        authority_change["keys"][0]["lifecycle"] = json!("overlap");
        let authority_change = serde_json::to_vec(&authority_change).unwrap();
        let authority_change_digest = sha256_digest(&authority_change);
        assert!(lineage_for_chain(&first, &authority_change, &authority_change_digest).is_err());

        let mut applicability_change: Value = serde_json::from_slice(&second).unwrap();
        applicability_change["applicability"]["deployment_ids"] = json!(["deployment:other"]);
        applicability_change["keys"][0]["deployment_ids"] = json!(["deployment:other"]);
        applicability_change["trust_policy_version"] = json!(2);
        let applicability_change = serde_json::to_vec(&applicability_change).unwrap();
        let applicability_digest = sha256_digest(&applicability_change);
        assert!(lineage_for_chain(&first, &applicability_change, &applicability_digest).is_err());

        let mut unfenced_predecessor: Value = serde_json::from_slice(&second).unwrap();
        let mut successor = unfenced_predecessor["keys"][0].clone();
        successor["key_id"] = json!("conformance-key:successor-key");
        successor["public_key_base64"] =
            json!(BASE64_STANDARD.encode(successor_key.verifying_key().to_bytes()));
        successor["public_key_fingerprint"] = json!(fingerprint(&successor_key));
        successor["valid_from"] = json!("2026-07-01T00:00:00Z");
        successor["supersedes_key_id"] = json!("conformance-key:test-key");
        unfenced_predecessor["keys"]
            .as_array_mut()
            .unwrap()
            .push(successor);
        unfenced_predecessor["trust_policy_version"] = json!(2);
        let unfenced_predecessor = serde_json::to_vec(&unfenced_predecessor).unwrap();
        let unfenced_digest = sha256_digest(&unfenced_predecessor);
        assert!(lineage_for_chain(&first, &unfenced_predecessor, &unfenced_digest).is_err());

        let mut fenced_predecessor: Value = serde_json::from_slice(&unfenced_predecessor).unwrap();
        fenced_predecessor["keys"][0]["lifecycle"] = json!("overlap");
        let fenced_predecessor = serde_json::to_vec(&fenced_predecessor).unwrap();
        let fenced_digest = sha256_digest(&fenced_predecessor);
        let lineage = lineage_for_chain(&first, &fenced_predecessor, &fenced_digest).unwrap();
        assert_eq!(
            lineage.snapshots[&2].keys["conformance-key:test-key"]
                .metadata
                .lifecycle,
            KeyLifecycle::Overlap
        );
        let authority = AuthorityFixture::new(108);
        let overlap_document = sign(unsigned(2, &fenced_digest, "2026-07-16T09:59:00Z"), &key);
        let raw = serde_json::to_vec(&overlap_document).unwrap();
        let digest = sha256_digest(&raw);
        let request = request_for(&lineage, &authority, std::slice::from_ref(&digest));
        let response = sign_response(
            response_value(
                &request,
                &authority,
                vec![acceptance_record(
                    &overlap_document,
                    &digest,
                    &fingerprint(&key),
                    "registry/v2.json",
                    "2026-07-16T09:59:58Z",
                    "2026-07-16T09:59:59Z",
                    10,
                )],
            ),
            &authority,
        );
        let checkpoint = lineage
            .verify_reconciliation_response(&request, &response, authority.anchor(7), trusted_now())
            .unwrap();
        assert!(matches!(
            checkpoint.verify_document(&raw, context(), trusted_now()),
            Err(ConformanceTrustError::KeyNotAuthorized(_))
        ));
    }

    #[test]
    fn key_material_relabel_and_fingerprint_mismatch_are_rejected() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let replacement = SigningKey::from_bytes(&[10; 32]);
        let (first, second, _, _) = two_version_chain(&key);

        let mut relabel: Value = serde_json::from_slice(&second).unwrap();
        relabel["keys"][0]["public_key_base64"] =
            json!(BASE64_STANDARD.encode(replacement.verifying_key().to_bytes()));
        relabel["keys"][0]["public_key_fingerprint"] = json!(fingerprint(&replacement));
        relabel["trust_policy_version"] = json!(2);
        let relabel = serde_json::to_vec(&relabel).unwrap();
        let relabel_digest = sha256_digest(&relabel);
        assert!(lineage_for_chain(&first, &relabel, &relabel_digest).is_err());

        let mut mismatch: Value = serde_json::from_slice(&second).unwrap();
        mismatch["keys"][0]["public_key_fingerprint"] = json!(pin());
        mismatch["trust_policy_version"] = json!(2);
        let mismatch = serde_json::to_vec(&mismatch).unwrap();
        let mismatch_digest = sha256_digest(&mismatch);
        assert!(lineage_for_chain(&first, &mismatch, &mismatch_digest).is_err());
    }

    #[test]
    fn rotation_tombstone_and_later_revocation_overlay_are_append_only() {
        let retired_key = SigningKey::from_bytes(&[12; 32]);
        let active_key = SigningKey::from_bytes(&[13; 32]);
        let first_value = registry(&retired_key, 1, "2026-01-01T00:00:00Z", 1, None);
        let first = serde_json::to_vec(&first_value).unwrap();
        let first_digest = sha256_digest(&first);

        let mut second = registry(
            &active_key,
            2,
            "2026-07-01T00:00:00Z",
            2,
            Some(json!({
                "artifact_kind": TRUST_REGISTRY_CONTRACT_KIND,
                "document_id": "conformance-trust-root-registry:test-root",
                "document_version": 1,
                "content_digest": first_digest,
                "artifact_locator": "registry/v1.json"
            })),
        );
        second["keys"][0]["key_id"] = json!("conformance-key:rotation-key");
        second["keys"][0]["valid_from"] = json!("2026-07-01T00:00:00Z");
        second["keys"][0]["supersedes_key_id"] = json!("conformance-key:test-key");
        second["key_tombstones"] = json!([{
            "key_id": "conformance-key:test-key",
            "signer_identity": "signer:test",
            "algorithm": SIGNATURE_ALGORITHM,
            "public_key_fingerprint": fingerprint(&retired_key),
            "terminal_state": "retired",
            "terminated_at": "2026-06-30T00:00:00Z",
            "signatures_valid_before": "2026-06-30T00:00:00Z",
            "subsequent_revocation": null,
            "reason": "scheduled signing key retirement",
            "superseded_by_key_id": "conformance-key:rotation-key",
            "trust_policy_version": 2
        }]);
        let second = serde_json::to_vec(&second).unwrap();
        let second_digest = sha256_digest(&second);

        let historic_document = sign(
            unsigned(1, &first_digest, "2026-06-01T00:00:00Z"),
            &retired_key,
        );
        let historic_raw = serde_json::to_vec(&historic_document).unwrap();
        let historic_digest = sha256_digest(&historic_raw);
        let authority = AuthorityFixture::new(109);
        let retired_lineage = lineage_for_chain(&first, &second, &second_digest).unwrap();
        let request = request_for(
            &retired_lineage,
            &authority,
            std::slice::from_ref(&historic_digest),
        );
        let historic_record = acceptance_record(
            &historic_document,
            &historic_digest,
            &fingerprint(&retired_key),
            "registry/v1.json",
            "2026-06-01T00:00:01Z",
            "2026-06-01T00:00:02Z",
            9,
        );
        let response = sign_response(
            response_value(&request, &authority, vec![historic_record.clone()]),
            &authority,
        );
        let checkpoint = retired_lineage
            .verify_reconciliation_response(&request, &response, authority.anchor(7), trusted_now())
            .unwrap();
        checkpoint
            .verify_document(&historic_raw, context(), trusted_now())
            .unwrap();

        let retired_lineage = lineage_for_chain(&first, &second, &second_digest).unwrap();
        let request = request_for(
            &retired_lineage,
            &authority,
            std::slice::from_ref(&historic_digest),
        );
        let cutoff_straddle = acceptance_record(
            &historic_document,
            &historic_digest,
            &fingerprint(&retired_key),
            "registry/v1.json",
            "2026-06-29T23:59:59Z",
            "2026-06-30T00:00:00Z",
            9,
        );
        let response = sign_response(
            response_value(&request, &authority, vec![cutoff_straddle]),
            &authority,
        );
        let checkpoint = retired_lineage
            .verify_reconciliation_response(&request, &response, authority.anchor(7), trusted_now())
            .unwrap();
        assert!(matches!(
            checkpoint.verify_document(&historic_raw, context(), trusted_now()),
            Err(ConformanceTrustError::KeyNotAuthorized(message))
                if message.contains("retirement cutoff")
        ));

        let mut direct_revocation: Value = serde_json::from_slice(&second).unwrap();
        direct_revocation["key_tombstones"][0]["terminal_state"] = json!("revoked");
        direct_revocation["key_tombstones"][0]["signatures_valid_before"] = Value::Null;
        let direct_revocation = serde_json::to_vec(&direct_revocation).unwrap();
        let direct_digest = sha256_digest(&direct_revocation);
        let directly_revoked_lineage =
            lineage_for_chain(&first, &direct_revocation, &direct_digest).unwrap();
        let request = request_for(
            &directly_revoked_lineage,
            &authority,
            std::slice::from_ref(&historic_digest),
        );
        let response = sign_response(
            response_value(&request, &authority, vec![historic_record.clone()]),
            &authority,
        );
        let checkpoint = directly_revoked_lineage
            .verify_reconciliation_response(&request, &response, authority.anchor(7), trusted_now())
            .unwrap();
        assert!(matches!(
            checkpoint.verify_document(&historic_raw, context(), trusted_now()),
            Err(ConformanceTrustError::KeyNotAuthorized(message))
                if message.contains("direct revocation")
        ));

        let mut third: Value = serde_json::from_slice(&second).unwrap();
        third["document_version"] = json!(3);
        third["lifecycle"]["effective_at"] = json!("2026-07-15T00:00:00Z");
        third["trust_policy_version"] = json!(3);
        third["predecessor_registry_ref"] = json!({
            "artifact_kind": TRUST_REGISTRY_CONTRACT_KIND,
            "document_id": "conformance-trust-root-registry:test-root",
            "document_version": 2,
            "content_digest": second_digest,
            "artifact_locator": "registry/v2.json"
        });
        third["key_tombstones"][0]["subsequent_revocation"] = json!({
            "revoked_at": "2026-07-15T00:00:00Z",
            "reason": "post-retirement compromise evidence",
            "trust_policy_version": 3
        });
        let third = serde_json::to_vec(&third).unwrap();
        let third_digest = sha256_digest(&third);
        let artifacts = [
            ConformanceRegistryArtifact {
                artifact_locator: "registry/v1.json",
                raw_bytes: &first,
            },
            ConformanceRegistryArtifact {
                artifact_locator: "registry/v2.json",
                raw_bytes: &second,
            },
            ConformanceRegistryArtifact {
                artifact_locator: "registry/v3.json",
                raw_bytes: &third,
            },
        ];
        let lineage = ValidatedConformanceRegistryLineage::from_registry_chain(
            &artifacts,
            ConformanceTrustAnchor {
                artifact_locator: "registry/v3.json",
                document_id: "conformance-trust-root-registry:test-root",
                document_version: 3,
                content_digest: &third_digest,
            },
            at("2026-07-16T10:01:00Z"),
        )
        .unwrap();
        assert!(
            lineage.terminal_keys["conformance-key:test-key"]
                .subsequent_revocation
                .is_some()
        );
        let request = request_for(&lineage, &authority, std::slice::from_ref(&historic_digest));
        let response = sign_response(
            response_value(&request, &authority, vec![historic_record]),
            &authority,
        );
        let checkpoint = lineage
            .verify_reconciliation_response(&request, &response, authority.anchor(7), trusted_now())
            .unwrap();
        assert!(matches!(
            checkpoint.verify_document(&historic_raw, context(), trusted_now()),
            Err(ConformanceTrustError::KeyNotAuthorized(message))
                if message.contains("subsequent revocation")
        ));

        let mut dropped: Value = serde_json::from_slice(&third).unwrap();
        dropped["key_tombstones"] = json!([]);
        let dropped = serde_json::to_vec(&dropped).unwrap();
        let dropped_digest = sha256_digest(&dropped);
        let dropped_artifacts = [
            artifacts[0],
            artifacts[1],
            ConformanceRegistryArtifact {
                artifact_locator: "registry/v3.json",
                raw_bytes: &dropped,
            },
        ];
        assert!(
            ValidatedConformanceRegistryLineage::from_registry_chain(
                &dropped_artifacts,
                ConformanceTrustAnchor {
                    artifact_locator: "registry/v3.json",
                    document_id: "conformance-trust-root-registry:test-root",
                    document_version: 3,
                    content_digest: &dropped_digest,
                },
                at("2026-07-16T10:01:00Z"),
            )
            .is_err()
        );
    }

    #[test]
    fn missing_required_null_duplicate_json_and_bounds_are_rejected() {
        let key = SigningKey::from_bytes(&[11; 32]);
        let mut genesis = registry(&key, 1, "2026-01-01T00:00:00Z", 1, None);
        genesis
            .as_object_mut()
            .unwrap()
            .remove("predecessor_registry_ref");
        let bytes = serde_json::to_vec(&genesis).unwrap();
        let digest = sha256_digest(&bytes);
        assert!(
            ValidatedConformanceRegistryLineage::from_registry_chain(
                &[ConformanceRegistryArtifact {
                    artifact_locator: "registry/v1.json",
                    raw_bytes: &bytes,
                }],
                ConformanceTrustAnchor {
                    artifact_locator: "registry/v1.json",
                    document_id: "conformance-trust-root-registry:test-root",
                    document_version: 1,
                    content_digest: &digest,
                },
                at("2026-07-16T10:01:00Z"),
            )
            .is_err()
        );

        let valid =
            serde_json::to_string(&registry(&key, 1, "2026-01-01T00:00:00Z", 1, None)).unwrap();
        let duplicate = valid.replacen(
            "\"schema_version\":",
            "\"schema_version\":\"1.0.0\",\"schema_version\":",
            1,
        );
        let duplicate_digest = sha256_digest(duplicate.as_bytes());
        assert!(matches!(
            ValidatedConformanceRegistryLineage::from_registry_chain(
                &[ConformanceRegistryArtifact {
                    artifact_locator: "registry/v1.json",
                    raw_bytes: duplicate.as_bytes(),
                }],
                ConformanceTrustAnchor {
                    artifact_locator: "registry/v1.json",
                    document_id: "conformance-trust-root-registry:test-root",
                    document_version: 1,
                    content_digest: &duplicate_digest,
                },
                at("2026-07-16T10:01:00Z"),
            ),
            Err(ConformanceTrustError::InvalidTypedValue(message))
                if message.contains("duplicate JSON object key")
        ));

        let mut oversized = registry(&key, 1, "2026-01-01T00:00:00Z", 1, None);
        let one = oversized["keys"][0].clone();
        oversized["keys"] = Value::Array(vec![one; MAX_KEYS_PER_REGISTRY + 1]);
        let oversized = serde_json::to_vec(&oversized).unwrap();
        let oversized_digest = sha256_digest(&oversized);
        assert!(
            ValidatedConformanceRegistryLineage::from_registry_chain(
                &[ConformanceRegistryArtifact {
                    artifact_locator: "registry/v1.json",
                    raw_bytes: &oversized,
                }],
                ConformanceTrustAnchor {
                    artifact_locator: "registry/v1.json",
                    document_id: "conformance-trust-root-registry:test-root",
                    document_version: 1,
                    content_digest: &oversized_digest,
                },
                at("2026-07-16T10:01:00Z"),
            )
            .is_err()
        );
    }

    #[test]
    fn ac_055_external_checkpoint_reconciliation_contract() {
        reconciliation_decision_classifies_all_head_states();
        checkpoint_response_rejects_bad_signature_nonce_duplicate_and_stale_boundaries();
        checkpoint_authority_is_independently_scoped_key_separated_and_epoch_fenced();
        lookup_request_and_response_reject_missing_unsolicited_and_reused_events();
        acceptance_set_rejects_head_conflicts_inversion_and_document_forks();
        authenticated_acceptance_verifies_current_and_historic_active_snapshots();
        exact_raw_bytes_and_trusted_acceptance_time_are_authoritative();
        exact_links_anchor_policy_and_applicability_fail_closed();
        rotation_tombstone_and_later_revocation_overlay_are_append_only();
        missing_required_null_duplicate_json_and_bounds_are_rejected();
    }

    #[test]
    fn canonical_json_is_order_and_whitespace_independent_and_integer_only() {
        let left: Value =
            serde_json::from_str(r#"{ "z": [3, 2, 1], "a": {"b": true, "a": "x"} }"#).unwrap();
        let right: Value = serde_json::from_str(r#"{"a":{"a":"x","b":true},"z":[3,2,1]}"#).unwrap();
        assert_eq!(
            canonical_json_bytes(&left).unwrap(),
            canonical_json_bytes(&right).unwrap()
        );
        assert_eq!(
            canonical_json_bytes(&left).unwrap(),
            br#"{"a":{"a":"x","b":true},"z":[3,2,1]}"#
        );
        assert_eq!(
            canonical_json_bytes(&json!({"float": 1.5})),
            Err(ConformanceTrustError::NonIntegerNumber)
        );
        assert!(valid_artifact_locator("registry/v1.json"));
        assert!(!valid_artifact_locator("registry/bad name.json"));
        assert!(!valid_artifact_locator("registry/bad:name.json"));
        assert!(!valid_artifact_locator("registry/café.json"));
    }

    #[test]
    fn accepted_document_id_length_matches_checkpoint_schema_boundary() {
        let accepted = format!("d{}", "a".repeat(159));
        let rejected = format!("d{}", "a".repeat(160));
        assert_eq!(accepted.len(), 160);
        assert_eq!(rejected.len(), 161);
        assert!(valid_document_id(&accepted));
        assert!(!valid_document_id(&rejected));
    }
}
