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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustRegistryDocument {
    #[serde(rename = "$schema")]
    schema_uri: String,
    schema_version: String,
    contract_kind: String,
    document_id: String,
    document_version: u64,
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

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RegistryAcceptanceStatus {
    ImplementationOnly,
    ProductionCandidate,
    ProductionAccepted,
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationKeyMetadata {
    key_id: String,
    signer_identity: String,
    algorithm: String,
    public_key_base64: String,
    allowed_purposes: Vec<ConformancePurpose>,
    allowed_evidence_tiers: Vec<EvidenceTier>,
    allowed_package_ids: Vec<String>,
    deployment_ids: Vec<String>,
    trust_domain_ids: Vec<String>,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    lifecycle: KeyLifecycle,
    revoked_at: Option<DateTime<Utc>>,
    supersedes_key_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum KeyLifecycle {
    Active,
    Overlap,
    Revoked,
    Retired,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyTombstone {
    key_id: String,
    signer_identity: String,
    algorithm: String,
    revoked_at: DateTime<Utc>,
    reason: String,
    superseded_by_key_id: Option<String>,
    trust_policy_version: u64,
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

/// A registry whose identity and raw-byte digest were independently pinned by
/// its caller. Construction validates every security-relevant registry field.
#[derive(Debug, Clone)]
pub struct ConformanceTrustStore {
    registry_id: String,
    registry_version: u64,
    registry_digest: String,
    effective_at: DateTime<Utc>,
    deployment_ids: BTreeSet<String>,
    trust_domain_ids: BTreeSet<String>,
    keys: BTreeMap<String, TrustedKey>,
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
    pub fn from_bytes(
        bytes: &[u8],
        expected_registry_id: &str,
        expected_registry_version: u64,
        expected_registry_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<Self, ConformanceTrustError> {
        require_digest(expected_registry_digest, "registry pin")?;
        if sha256_digest(bytes) != expected_registry_digest {
            return Err(invalid(
                "registry raw bytes do not match the independent digest pin",
            ));
        }
        let value = parse_json_strict(bytes)?;
        Self::from_value(
            &value,
            expected_registry_id,
            expected_registry_version,
            expected_registry_digest,
            now,
        )
    }

    fn from_value(
        value: &Value,
        expected_registry_id: &str,
        expected_registry_version: u64,
        expected_registry_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<Self, ConformanceTrustError> {
        canonical_json_bytes(value)?;
        require_digest(expected_registry_digest, "registry pin")?;
        let registry: TrustRegistryDocument = serde_json::from_value(value.clone())
            .map_err(|error| ConformanceTrustError::InvalidTypedValue(error.to_string()))?;

        if registry.schema_uri != TRUST_REGISTRY_SCHEMA_URI
            || registry.schema_version != TRUST_REGISTRY_SCHEMA_VERSION
            || registry.contract_kind != TRUST_REGISTRY_CONTRACT_KIND
        {
            return Err(invalid("unsupported registry schema, kind, or version"));
        }
        if registry.document_id != expected_registry_id
            || registry.document_version != expected_registry_version
            || registry.document_version == 0
        {
            return Err(invalid(
                "registry identity/version does not match its independent pin",
            ));
        }
        if registry.acceptance_status != RegistryAcceptanceStatus::ProductionAccepted
            || !registry.production_accepted
            || registry.lifecycle.state != RegistryLifecycleState::Active
            || registry.lifecycle.effective_at > now
        {
            return Err(invalid(
                "registry is not active production-accepted authority",
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
        if registry.applicability.deployment_ids.is_empty()
            || registry.applicability.trust_domain_ids.is_empty()
            || registry.keys.is_empty()
        {
            return Err(invalid(
                "registry authority scopes and keys must be non-empty",
            ));
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
        let mut tombstones = BTreeMap::new();
        for tombstone in &registry.key_tombstones {
            validate_tombstone(tombstone, registry.trust_policy_version, now)?;
            if tombstones
                .insert(tombstone.key_id.clone(), tombstone.clone())
                .is_some()
            {
                return Err(invalid("duplicate tombstoned key id"));
            }
        }

        let mut keys = BTreeMap::new();
        let mut public_key_material = BTreeSet::new();
        for metadata in registry.keys {
            validate_key_metadata(&metadata, now)?;
            if tombstones.contains_key(&metadata.key_id) {
                return Err(invalid("live and tombstoned key ids overlap"));
            }
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
            if !public_key_material.insert(public_key) {
                return Err(invalid("duplicate Ed25519 public-key material"));
            }
            let verifying_key = VerifyingKey::from_bytes(&public_key)
                .map_err(|_| invalid("invalid Ed25519 public key"))?;
            let key_id = metadata.key_id.clone();
            if keys
                .insert(
                    key_id,
                    TrustedKey {
                        metadata,
                        verifying_key,
                    },
                )
                .is_some()
            {
                return Err(invalid("duplicate verification key id"));
            }
        }

        let mut supersession_edges = BTreeMap::new();
        for key in keys.values() {
            if let Some(predecessor) = &key.metadata.supersedes_key_id {
                if predecessor == &key.metadata.key_id
                    || (!keys.contains_key(predecessor) && !tombstones.contains_key(predecessor))
                {
                    return Err(invalid("key supersession target is self or unknown"));
                }
                if let Some(target) = keys.get(predecessor)
                    && (target.metadata.signer_identity != key.metadata.signer_identity
                        || target.metadata.algorithm != key.metadata.algorithm
                        || target.metadata.valid_from >= key.metadata.valid_from)
                {
                    return Err(invalid(
                        "key supersession changes identity/algorithm or is not monotonic",
                    ));
                }
                if let Some(target) = tombstones.get(predecessor)
                    && (target.signer_identity != key.metadata.signer_identity
                        || target.algorithm != key.metadata.algorithm)
                {
                    return Err(invalid("key supersession changes identity or algorithm"));
                }
                supersession_edges.insert(key.metadata.key_id.clone(), predecessor.clone());
            }
        }
        require_acyclic_supersession(&supersession_edges)?;
        for tombstone in &registry.key_tombstones {
            if let Some(successor) = &tombstone.superseded_by_key_id {
                if successor == &tombstone.key_id || !keys.contains_key(successor) {
                    return Err(invalid("tombstone successor is self or unknown"));
                }
                let successor = &keys[successor].metadata;
                if successor.signer_identity != tombstone.signer_identity
                    || successor.algorithm != tombstone.algorithm
                {
                    return Err(invalid("tombstone successor changes identity or algorithm"));
                }
            }
        }
        Ok(Self {
            registry_id: registry.document_id,
            registry_version: registry.document_version,
            registry_digest: expected_registry_digest.to_owned(),
            effective_at: registry.lifecycle.effective_at,
            deployment_ids,
            trust_domain_ids,
            keys,
        })
    }

    pub fn verify_document(
        &self,
        document: &Value,
        context: ConformanceVerificationContext<'_>,
        now: DateTime<Utc>,
    ) -> Result<VerifiedConformanceDocument, ConformanceTrustError> {
        if self.effective_at > now
            || !self.deployment_ids.contains(context.deployment_id)
            || !self.trust_domain_ids.contains(context.trust_domain_id)
        {
            return Err(ConformanceTrustError::ScopeMismatch(
                "registry is not current/applicable to deployment and trust domain".into(),
            ));
        }
        let identity = document_identity(document)?;
        require_document_scope(document, identity.kind, context)?;
        let signer_value = document
            .get("signer")
            .ok_or_else(|| invalid("missing signer"))?;
        let signer: ConformanceSignatureMetadata = serde_json::from_value(signer_value.clone())
            .map_err(|error| ConformanceTrustError::InvalidTypedValue(error.to_string()))?;
        validate_signature_contract(&signer, identity.kind)?;
        if signer.trust_registry_id != self.registry_id
            || signer.trust_registry_version != self.registry_version
            || signer.trust_registry_digest != self.registry_digest
        {
            return Err(ConformanceTrustError::ScopeMismatch(
                "signer registry identity/version/digest is not the independent pin".into(),
            ));
        }
        if signer.signed_at < self.effective_at || signer.signed_at > now {
            return Err(ConformanceTrustError::KeyNotAuthorized(
                "signature timestamp predates the registry or is in the future".into(),
            ));
        }
        let key = self
            .keys
            .get(&signer.key_id)
            .ok_or_else(|| ConformanceTrustError::UnknownKey(signer.key_id.clone()))?;
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
            registry_version: self.registry_version,
            registry_digest: self.registry_digest.clone(),
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
    if !matches!(
        metadata.lifecycle,
        KeyLifecycle::Active | KeyLifecycle::Overlap
    ) || metadata.revoked_at.is_some()
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

fn validate_key_metadata(
    key: &VerificationKeyMetadata,
    now: DateTime<Utc>,
) -> Result<(), ConformanceTrustError> {
    if !valid_scoped_id(&key.key_id, "conformance-key:")
        || key.signer_identity.is_empty()
        || key.algorithm != SIGNATURE_ALGORITHM
        || key.valid_from >= key.valid_until
        || key.allowed_purposes.is_empty()
        || key.allowed_evidence_tiers.is_empty()
        || key.allowed_package_ids.is_empty()
        || key.deployment_ids.is_empty()
        || key.trust_domain_ids.is_empty()
    {
        return Err(invalid("invalid verification-key metadata"));
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
    match key.lifecycle {
        KeyLifecycle::Revoked => {
            if key.revoked_at.is_none_or(|revoked_at| {
                revoked_at > now || revoked_at < key.valid_from || revoked_at > key.valid_until
            }) {
                return Err(invalid("revoked key requires an effective revoked_at"));
            }
        }
        _ if key.revoked_at.is_some() => {
            return Err(invalid("non-revoked key cannot carry revoked_at"));
        }
        _ => {}
    }
    Ok(())
}

fn validate_tombstone(
    tombstone: &KeyTombstone,
    trust_policy_version: u64,
    now: DateTime<Utc>,
) -> Result<(), ConformanceTrustError> {
    if !valid_scoped_id(&tombstone.key_id, "conformance-key:")
        || tombstone.signer_identity.is_empty()
        || tombstone.algorithm != SIGNATURE_ALGORITHM
        || tombstone.revoked_at > now
        || !(16..=1000).contains(&tombstone.reason.chars().count())
        || tombstone.trust_policy_version == 0
        || tombstone.trust_policy_version > trust_policy_version
        || tombstone.superseded_by_key_id.as_deref() == Some(tombstone.key_id.as_str())
    {
        return Err(invalid("invalid key tombstone"));
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

    fn registry(key: &SigningKey) -> Value {
        json!({
            "$schema": TRUST_REGISTRY_SCHEMA_URI,
            "schema_version": "1.0.0",
            "contract_kind": "conformance-trust-root-registry",
            "document_id": "conformance-trust-root-registry:test-root",
            "document_version": 3,
            "acceptance_status": "production_accepted",
            "production_accepted": true,
            "lifecycle": {"state": "active", "effective_at": "2026-01-01T00:00:00Z"},
            "applicability": {
                "evaluation_scope": "deployment",
                "security_profiles": ["production"],
                "deployment_ids": ["deployment:test"],
                "trust_domain_ids": ["trust-domain:test"]
            },
            "trust_policy_version": 2,
            "canonicalization_profiles": [CANONICALIZATION_PROFILE],
            "signature_algorithms": [SIGNATURE_ALGORITHM],
            "keys": [{
                "key_id": "conformance-key:test-key",
                "signer_identity": "signer:test",
                "algorithm": "ed25519",
                "public_key_base64": BASE64_STANDARD.encode(key.verifying_key().to_bytes()),
                "allowed_purposes": ["conformance_bundle", "package_exit_receipt"],
                "allowed_evidence_tiers": ["externally_attested"],
                "allowed_package_ids": ["SB-0"],
                "deployment_ids": ["deployment:test"],
                "trust_domain_ids": ["trust-domain:test"],
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
                "lifecycle": "active",
                "revoked_at": null,
                "supersedes_key_id": null
            }],
            "key_tombstones": []
        })
    }

    fn unsigned(kind: ConformanceDocumentKind) -> Value {
        let (schema, contract_kind, id_field, id, purpose, domain) = match kind {
            ConformanceDocumentKind::ConformanceBundle => (
                CONFORMANCE_BUNDLE_SCHEMA_URI,
                "conformance-bundle",
                "bundle_id",
                "bundle:test",
                "conformance_bundle",
                CONFORMANCE_BUNDLE_DOMAIN,
            ),
            ConformanceDocumentKind::PackageExitReceipt => (
                PACKAGE_EXIT_RECEIPT_SCHEMA_URI,
                "package-exit-receipt",
                "receipt_id",
                "receipt:SB-0:test",
                "package_exit_receipt",
                PACKAGE_EXIT_RECEIPT_DOMAIN,
            ),
        };
        let mut document = json!({
            "$schema": schema,
            "schema_version": "1.0.0",
            "contract_kind": contract_kind,
            "document_version": 1,
            "signer": {
                "signature_version": "1.0.0",
                "identity": "signer:test",
                "key_id": "conformance-key:test-key",
                "algorithm": "ed25519",
                "canonicalization": CANONICALIZATION_PROFILE,
                "purpose": purpose,
                "domain": domain,
                "trust_registry_id": "conformance-trust-root-registry:test-root",
                "trust_registry_version": 3,
                "trust_registry_digest": pin(),
                "signed_at": "2026-07-16T10:00:00Z",
                "signed_subject_digest": pin(),
                "signature_base64": BASE64_STANDARD.encode([0u8; 64])
            }
        });
        document[id_field] = json!(id);
        match kind {
            ConformanceDocumentKind::ConformanceBundle => {
                document["bindings"] =
                    json!({"deployment_profile": {"deployment_id": "deployment:test"}});
                document["provenance"] = json!({"evidence_tier": {"name": "externally_attested"}});
            }
            ConformanceDocumentKind::PackageExitReceipt => {
                document["package_id"] = json!("SB-0");
                document["closure_context"] =
                    json!({"deployment_profile": {"deployment_id": "deployment:test"}});
                document["evidence_tier"] = json!({"name": "externally_attested"});
            }
        }
        document
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
    fn bundle_and_receipt_round_trip_and_confusion_fail_closed() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let now = at("2026-07-16T10:01:00Z");
        let store = ConformanceTrustStore::from_value(
            &registry(&key),
            "conformance-trust-root-registry:test-root",
            3,
            pin(),
            now,
        )
        .unwrap();
        for kind in [
            ConformanceDocumentKind::ConformanceBundle,
            ConformanceDocumentKind::PackageExitReceipt,
        ] {
            let document = sign(unsigned(kind), &key);
            let verified = store.verify_document(&document, context(), now).unwrap();
            assert_eq!(verified.kind(), kind);
            assert_eq!(verified.deployment_id(), "deployment:test");
            assert_eq!(verified.trust_domain_id(), "trust-domain:test");
            assert_eq!(verified.package_id(), "SB-0");
            assert_eq!(verified.evidence_tier(), EvidenceTier::ExternallyAttested);

            let mut field_mutation = document.clone();
            field_mutation["document_version"] = json!(2);
            assert_eq!(
                store.verify_document(&field_mutation, context(), now),
                Err(ConformanceTrustError::SubjectDigestMismatch)
            );

            let mut signature_mutation = document.clone();
            let mut bytes = BASE64_STANDARD
                .decode(
                    signature_mutation["signer"]["signature_base64"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap();
            bytes[0] ^= 1;
            signature_mutation["signer"]["signature_base64"] = json!(BASE64_STANDARD.encode(bytes));
            assert_eq!(
                store.verify_document(&signature_mutation, context(), now),
                Err(ConformanceTrustError::InvalidSignature)
            );

            let mut wrong_domain = document.clone();
            wrong_domain["signer"]["domain"] =
                json!(if kind == ConformanceDocumentKind::ConformanceBundle {
                    PACKAGE_EXIT_RECEIPT_DOMAIN
                } else {
                    CONFORMANCE_BUNDLE_DOMAIN
                });
            assert!(matches!(
                store.verify_document(&wrong_domain, context(), now),
                Err(ConformanceTrustError::InvalidContract(_))
            ));
        }
    }

    #[test]
    fn key_identity_registry_and_scope_confusion_are_rejected() {
        let key = SigningKey::from_bytes(&[8; 32]);
        let now = at("2026-07-16T10:01:00Z");
        let store = ConformanceTrustStore::from_value(
            &registry(&key),
            "conformance-trust-root-registry:test-root",
            3,
            pin(),
            now,
        )
        .unwrap();
        let document = sign(unsigned(ConformanceDocumentKind::ConformanceBundle), &key);
        for (pointer, replacement) in [
            ("/signer/identity", json!("signer:other")),
            ("/signer/key_id", json!("conformance-key:other-key")),
            ("/signer/purpose", json!("package_exit_receipt")),
            (
                "/signer/trust_registry_digest",
                json!("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            ),
        ] {
            let mut mutated = document.clone();
            *mutated.pointer_mut(pointer).unwrap() = replacement;
            assert!(store.verify_document(&mutated, context(), now).is_err());
        }
        let wrong_scope = ConformanceVerificationContext {
            deployment_id: "deployment:other",
            ..context()
        };
        assert!(matches!(
            store.verify_document(&document, wrong_scope, now),
            Err(ConformanceTrustError::ScopeMismatch(_))
        ));

        let mut later_registry = registry(&key);
        later_registry["lifecycle"]["effective_at"] = json!("2026-07-16T10:00:30Z");
        let later_store = ConformanceTrustStore::from_value(
            &later_registry,
            "conformance-trust-root-registry:test-root",
            3,
            pin(),
            now,
        )
        .unwrap();
        assert!(matches!(
            later_store.verify_document(&document, context(), now),
            Err(ConformanceTrustError::KeyNotAuthorized(_))
        ));
    }

    #[test]
    fn malformed_noncanonical_base64_and_key_lifecycles_are_rejected() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let now = at("2026-07-16T10:01:00Z");
        let mut malformed = registry(&key);
        malformed["keys"][0]["public_key_base64"] = json!("not-base64");
        assert!(matches!(
            ConformanceTrustStore::from_value(
                &malformed,
                "conformance-trust-root-registry:test-root",
                3,
                pin(),
                now
            ),
            Err(ConformanceTrustError::InvalidBase64(_))
        ));

        for (field, value) in [
            ("valid_from", json!("2026-08-01T00:00:00Z")),
            ("valid_until", json!("2026-07-01T00:00:00Z")),
            ("lifecycle", json!("retired")),
        ] {
            let mut candidate = registry(&key);
            candidate["keys"][0][field] = value;
            let store = ConformanceTrustStore::from_value(
                &candidate,
                "conformance-trust-root-registry:test-root",
                3,
                pin(),
                now,
            )
            .unwrap();
            let document = sign(unsigned(ConformanceDocumentKind::ConformanceBundle), &key);
            assert!(matches!(
                store.verify_document(&document, context(), now),
                Err(ConformanceTrustError::KeyNotAuthorized(_))
            ));
        }
        let mut revoked = registry(&key);
        revoked["keys"][0]["lifecycle"] = json!("revoked");
        revoked["keys"][0]["revoked_at"] = json!("2026-07-01T00:00:00Z");
        let store = ConformanceTrustStore::from_value(
            &revoked,
            "conformance-trust-root-registry:test-root",
            3,
            pin(),
            now,
        )
        .unwrap();
        assert!(matches!(
            store.verify_document(
                &sign(unsigned(ConformanceDocumentKind::ConformanceBundle), &key),
                context(),
                now
            ),
            Err(ConformanceTrustError::KeyNotAuthorized(_))
        ));
    }

    #[test]
    fn duplicate_and_tombstoned_keys_and_unknown_registry_fields_fail() {
        let key = SigningKey::from_bytes(&[10; 32]);
        let now = at("2026-07-16T10:01:00Z");
        let registry_bytes = serde_json::to_vec(&registry(&key)).unwrap();
        let registry_digest = sha256_digest(&registry_bytes);
        assert!(
            ConformanceTrustStore::from_bytes(
                &registry_bytes,
                "conformance-trust-root-registry:test-root",
                3,
                &registry_digest,
                now,
            )
            .is_ok()
        );
        assert!(
            ConformanceTrustStore::from_bytes(
                &registry_bytes,
                "conformance-trust-root-registry:test-root",
                3,
                pin(),
                now,
            )
            .is_err()
        );

        let registry_json = String::from_utf8(registry_bytes).unwrap();
        let duplicate_json = registry_json.replacen(
            "\"schema_version\":",
            "\"schema_version\":\"1.0.0\",\"schema_version\":",
            1,
        );
        let duplicate_digest = sha256_digest(duplicate_json.as_bytes());
        assert!(matches!(
            ConformanceTrustStore::from_bytes(
                duplicate_json.as_bytes(),
                "conformance-trust-root-registry:test-root",
                3,
                &duplicate_digest,
                now,
            ),
            Err(ConformanceTrustError::InvalidTypedValue(message))
                if message.contains("duplicate JSON object key")
        ));

        let mut duplicate = registry(&key);
        let duplicate_key = duplicate["keys"][0].clone();
        duplicate["keys"]
            .as_array_mut()
            .unwrap()
            .push(duplicate_key);
        assert!(
            ConformanceTrustStore::from_value(
                &duplicate,
                "conformance-trust-root-registry:test-root",
                3,
                pin(),
                now
            )
            .is_err()
        );

        let mut duplicate_material = registry(&key);
        let mut alias = duplicate_material["keys"][0].clone();
        alias["key_id"] = json!("conformance-key:alias-key");
        duplicate_material["keys"]
            .as_array_mut()
            .unwrap()
            .push(alias);
        assert!(matches!(
            ConformanceTrustStore::from_value(
                &duplicate_material,
                "conformance-trust-root-registry:test-root",
                3,
                pin(),
                now
            ),
            Err(ConformanceTrustError::InvalidContract(message))
                if message.contains("duplicate Ed25519 public-key material")
        ));

        let mut tombstoned = registry(&key);
        tombstoned["key_tombstones"] = json!([{
            "key_id": "conformance-key:test-key", "signer_identity": "signer:test",
            "algorithm": "ed25519", "revoked_at": "2026-06-01T00:00:00Z",
            "reason": "operator revocation evidence", "superseded_by_key_id": null,
            "trust_policy_version": 2
        }]);
        assert!(
            ConformanceTrustStore::from_value(
                &tombstoned,
                "conformance-trust-root-registry:test-root",
                3,
                pin(),
                now
            )
            .is_err()
        );

        let mut unknown = registry(&key);
        unknown["unknown_critical"] = json!(true);
        assert!(matches!(
            ConformanceTrustStore::from_value(
                &unknown,
                "conformance-trust-root-registry:test-root",
                3,
                pin(),
                now
            ),
            Err(ConformanceTrustError::InvalidTypedValue(_))
        ));

        assert!(
            ConformanceTrustStore::from_value(
                &registry(&key),
                "conformance-trust-root-registry:test-root",
                3,
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                now,
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
