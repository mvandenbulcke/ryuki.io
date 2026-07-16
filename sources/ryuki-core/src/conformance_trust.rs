//! Pure, fail-closed verification for signed conformance closure documents.
//!
//! This module deliberately performs no file or network I/O. Callers must load
//! and schema-check the registry and document, and must independently pin the
//! registry bytes before constructing [`ConformanceTrustStore`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{DateTime, Utc};
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

const MAX_REGISTRY_LINEAGE: usize = 16;
const MAX_REGISTRY_BYTES: usize = 4 * 1024 * 1024;
const MAX_KEYS_PER_REGISTRY: usize = 256;
const MAX_TOMBSTONES_PER_REGISTRY: usize = 4096;
const MAX_SCOPE_ITEMS: usize = 256;

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

/// An independently pinned, append-only trust-registry lineage.
///
/// Historic snapshots are retained only to validate lineage. Until trusted
/// acceptance-time evidence exists, documents must name the current head.
#[derive(Debug, Clone)]
pub struct ConformanceTrustStore {
    registry_id: String,
    current_registry_version: u64,
    snapshots: BTreeMap<u64, TrustedRegistrySnapshot>,
    terminal_keys: BTreeMap<String, KeyTombstone>,
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
    signed_subject_digest: String,
    signed_at: DateTime<Utc>,
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
    pub fn signed_at(&self) -> DateTime<Utc> {
        self.signed_at
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

impl ConformanceTrustStore {
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

        Ok(Self {
            registry_id,
            current_registry_version: anchor.document_version,
            snapshots,
            terminal_keys: previous_tombstones,
        })
    }

    pub fn verify_document(
        &self,
        document: &Value,
        context: ConformanceVerificationContext<'_>,
        now: DateTime<Utc>,
    ) -> Result<VerifiedConformanceDocument, ConformanceTrustError> {
        let identity = document_identity(document)?;
        require_document_scope(document, identity.kind, context)?;
        let signer_value = document
            .get("signer")
            .ok_or_else(|| invalid("missing signer"))?;
        let signer: ConformanceSignatureMetadata = serde_json::from_value(signer_value.clone())
            .map_err(|error| ConformanceTrustError::InvalidTypedValue(error.to_string()))?;
        validate_signature_contract(&signer, identity.kind)?;
        if signer.trust_registry_version != self.current_registry_version {
            return Err(ConformanceTrustError::KeyNotAuthorized(
                "historic registry signatures require trusted acceptance-time evidence".into(),
            ));
        }
        let snapshot = self
            .snapshots
            .get(&signer.trust_registry_version)
            .filter(|snapshot| {
                signer.trust_registry_id == self.registry_id
                    && signer.trust_registry_digest == snapshot.registry_digest
            })
            .ok_or_else(|| {
                ConformanceTrustError::ScopeMismatch(
                    "signer registry identity/version/digest is not in the pinned lineage".into(),
                )
            })?;
        if !snapshot.deployment_ids.contains(context.deployment_id)
            || !snapshot.trust_domain_ids.contains(context.trust_domain_id)
        {
            return Err(ConformanceTrustError::ScopeMismatch(
                "selected registry is not applicable to deployment and trust domain".into(),
            ));
        }
        if signer.signed_at < snapshot.effective_at
            || snapshot
                .authority_until
                .is_some_and(|until| signer.signed_at >= until)
            || signer.signed_at > now
        {
            return Err(ConformanceTrustError::KeyNotAuthorized(
                "signature timestamp is outside the selected registry authority interval".into(),
            ));
        }
        let key = snapshot
            .keys
            .get(&signer.key_id)
            .ok_or_else(|| ConformanceTrustError::UnknownKey(signer.key_id.clone()))?;
        if self.terminal_keys.contains_key(&signer.key_id) {
            return Err(ConformanceTrustError::KeyNotAuthorized(
                "terminal key history cannot authorize a current document".into(),
            ));
        }
        authorize_key(key, &signer, context, now)?;

        let prepared = prepare_signed_subject(document)?;
        if prepared.digest != signer.signed_subject_digest {
            return Err(ConformanceTrustError::SubjectDigestMismatch);
        }
        let signature_bytes = decode_canonical_base64::<64>(&signer.signature_base64, "signature")?;
        let signature = Signature::from_bytes(&signature_bytes);
        key.verifying_key
            .verify_strict(&prepared.signing_bytes, &signature)
            .map_err(|_| ConformanceTrustError::InvalidSignature)?;

        Ok(VerifiedConformanceDocument {
            kind: identity.kind,
            document_id: identity.id,
            document_version: identity.version,
            key_id: signer.key_id,
            registry_id: self.registry_id.clone(),
            registry_version: signer.trust_registry_version,
            registry_digest: signer.trust_registry_digest,
            signed_subject_digest: prepared.digest,
            signed_at: signer.signed_at,
            deployment_id: context.deployment_id.to_owned(),
            trust_domain_id: context.trust_domain_id.to_owned(),
            package_id: context.package_id.to_owned(),
            evidence_tier: context.evidence_tier,
        })
    }
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

fn authorize_key(
    key: &TrustedKey,
    signer: &ConformanceSignatureMetadata,
    context: ConformanceVerificationContext<'_>,
    now: DateTime<Utc>,
) -> Result<(), ConformanceTrustError> {
    let metadata = &key.metadata;
    if metadata.algorithm != SIGNATURE_ALGORITHM
        || metadata.signer_identity != signer.identity
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
            "identity, purpose, tier, package, deployment, or trust domain".into(),
        ));
    }
    if metadata.lifecycle != KeyLifecycle::Active
        || signer.signed_at < metadata.valid_from
        || signer.signed_at >= metadata.valid_until
        || now < metadata.valid_from
        || now >= metadata.valid_until
    {
        return Err(ConformanceTrustError::KeyNotAuthorized(
            "key lifecycle, revocation, or validity window".into(),
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
        && value
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
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

    fn store_for_chain(
        first: &[u8],
        second: &[u8],
        second_digest: &str,
    ) -> Result<ConformanceTrustStore, ConformanceTrustError> {
        ConformanceTrustStore::from_registry_chain(
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

    #[test]
    fn current_head_signature_verifies_but_historic_signature_is_fenced() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let (first, second, first_digest, second_digest) = two_version_chain(&key);
        let store = store_for_chain(&first, &second, &second_digest).unwrap();
        let now = at("2026-07-16T10:01:00Z");

        let current = sign(unsigned(2, &second_digest, "2026-07-16T10:00:00Z"), &key);
        let verified = store.verify_document(&current, context(), now).unwrap();
        assert_eq!(verified.registry_version(), 2);
        assert_eq!(verified.registry_digest(), second_digest);

        let historic = sign(unsigned(1, &first_digest, "2026-06-01T00:00:00Z"), &key);
        assert!(matches!(
            store.verify_document(&historic, context(), now),
            Err(ConformanceTrustError::KeyNotAuthorized(message))
                if message.contains("acceptance-time")
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
        assert!(store_for_chain(&first, &wrong_link, &wrong_link_digest).is_err());

        assert!(store_for_chain(&first, &second, pin()).is_err());

        let mut authority_change: Value = serde_json::from_slice(&second).unwrap();
        authority_change["keys"][0]["lifecycle"] = json!("overlap");
        let authority_change = serde_json::to_vec(&authority_change).unwrap();
        let authority_change_digest = sha256_digest(&authority_change);
        assert!(store_for_chain(&first, &authority_change, &authority_change_digest).is_err());

        let mut applicability_change: Value = serde_json::from_slice(&second).unwrap();
        applicability_change["applicability"]["deployment_ids"] = json!(["deployment:other"]);
        applicability_change["keys"][0]["deployment_ids"] = json!(["deployment:other"]);
        applicability_change["trust_policy_version"] = json!(2);
        let applicability_change = serde_json::to_vec(&applicability_change).unwrap();
        let applicability_digest = sha256_digest(&applicability_change);
        assert!(store_for_chain(&first, &applicability_change, &applicability_digest).is_err());

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
        assert!(store_for_chain(&first, &unfenced_predecessor, &unfenced_digest).is_err());

        let mut fenced_predecessor: Value = serde_json::from_slice(&unfenced_predecessor).unwrap();
        fenced_predecessor["keys"][0]["lifecycle"] = json!("overlap");
        let fenced_predecessor = serde_json::to_vec(&fenced_predecessor).unwrap();
        let fenced_digest = sha256_digest(&fenced_predecessor);
        let store = store_for_chain(&first, &fenced_predecessor, &fenced_digest).unwrap();
        let old_signature = sign(unsigned(2, &fenced_digest, "2026-07-16T10:00:00Z"), &key);
        assert!(matches!(
            store.verify_document(&old_signature, context(), at("2026-07-16T10:01:00Z")),
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
        assert!(store_for_chain(&first, &relabel, &relabel_digest).is_err());

        let mut mismatch: Value = serde_json::from_slice(&second).unwrap();
        mismatch["keys"][0]["public_key_fingerprint"] = json!(pin());
        mismatch["trust_policy_version"] = json!(2);
        let mismatch = serde_json::to_vec(&mismatch).unwrap();
        let mismatch_digest = sha256_digest(&mismatch);
        assert!(store_for_chain(&first, &mismatch, &mismatch_digest).is_err());
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
            "terminated_at": "2026-07-01T00:00:00Z",
            "signatures_valid_before": "2026-07-01T00:00:00Z",
            "subsequent_revocation": null,
            "reason": "scheduled signing key retirement",
            "superseded_by_key_id": "conformance-key:rotation-key",
            "trust_policy_version": 2
        }]);
        let second = serde_json::to_vec(&second).unwrap();
        let second_digest = sha256_digest(&second);

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
        let store = ConformanceTrustStore::from_registry_chain(
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
        let mut document = unsigned(3, &third_digest, "2026-07-16T10:00:00Z");
        document["signer"]["key_id"] = json!("conformance-key:rotation-key");
        assert!(
            store
                .verify_document(
                    &sign(document, &active_key),
                    context(),
                    at("2026-07-16T10:01:00Z")
                )
                .is_ok()
        );

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
            ConformanceTrustStore::from_registry_chain(
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
            ConformanceTrustStore::from_registry_chain(
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
            ConformanceTrustStore::from_registry_chain(
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
            ConformanceTrustStore::from_registry_chain(
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
    }
}
