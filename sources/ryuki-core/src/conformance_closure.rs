//! Pure, fail-closed semantic verification for production conformance closure.
//!
//! Cryptographic document admission is deliberately owned by
//! [`crate::conformance_trust`]. This module consumes only exact, already-loaded
//! JSON values and the opaque proofs produced by that boundary. It performs no
//! filesystem, network, clock, or database I/O.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::conformance_applicability::{
    ApplicabilityDimension, ApplicabilityDimensionValue, ApplicabilityInstance,
    ApplicabilityInventoryBinding, ApplicabilityScalar, ApplicabilityScope,
    MAX_APPLICABILITY_INVENTORY_INSTANCES,
};
use crate::conformance_trust::{
    ConformanceDocumentKind, ConformanceTrustedTimeWindow, EvidenceTier,
    VerifiedConformanceArtifact, VerifiedConformanceProductionRoot,
    VerifiedConformanceTrustCheckpoint, canonical_json_bytes, parse_json_strict,
};
use crate::production_build::ProductionBuildManifest;
use crate::production_deployment_applicability::{
    ActiveProviderApplicabilityClaim, DerivedProductionApplicability,
    ProductionDeploymentApplicabilityClaims, derive_complete_production_applicability,
};
use crate::security_profile::{
    ArtifactKind, DeploymentSecurityProfile, ExpectedAuthenticatorBinding, ExpectedProviderBinding,
    ExpectedSecretProviderBinding, GuardId, ProductionAuthenticatorKind, RuntimeGuardExpectedValue,
    RuntimeGuardMode, VersionedContentReference, authenticator_inventory_digest,
    secret_provider_inventory_digest,
};

pub const DEPLOYMENT_PROFILE_CONFORMANCE_BINDING_DIGEST_CONTRACT: &str =
    "ryuki-deployment-profile-conformance-binding-v1";
pub const DEPLOYMENT_PROFILE_CONFORMANCE_RECEIPT_DIGEST_SENTINEL: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
pub const RUNTIME_GUARD_REQUIREMENT_BINDING_DIGEST_CONTRACT: &str =
    "ryuki-runtime-guard-requirement-binding-v1";
pub const RUNTIME_GUARD_SEMANTIC_CHALLENGE_BINDING_DIGEST_CONTRACT: &str =
    "ryuki-runtime-guard-semantic-challenge-binding-v1";

const CONTROL_TRACE_SCHEMA: &str =
    "https://ryuki.io/schemas/security-contracts/v1/control-trace.schema.json";
const CONTROL_TRACE_DOCUMENT_ID: &str = "control-trace:ryuki-security-boundary-v1";
const CONTROL_TRACE_LEDGER_ID: &str = "ryuki-security-boundary";
const CANONICAL_CONTROL_SET_DIGEST: &str =
    "sha256:6643595698420b3820772b6abb666d0c7bfcd91a686d6455c99338e84b93d512";
const CANONICAL_CASE_SET_DIGEST: &str =
    "sha256:e85db6dbcc2bb50045b712d264feb918e8ecd7f60750873b5b5fc5d8a6bc8002";
const MAX_LEDGER_ROWS: usize = 4096;
const MAX_CONTROL_TRACE_BYTES: usize = 4 * 1024 * 1024;
const MAX_DEPLOYMENT_PROFILE_BYTES: usize = 1024 * 1024;
const MAX_CONTROL_TRACE_JSON_DEPTH: usize = 32;
const MAX_CONTROL_TRACE_JSON_NODES: usize = 100_000;
const MAX_CONTROL_TRACE_COLLECTION_ITEMS: usize = 4096;
const MAX_CONTROL_TRACE_STRING_BYTES: usize = 64 * 1024;
const MAX_CLOSURE_DOCUMENTS: usize = 4096;
const MAX_SUPERSESSION_DEPTH: usize = 16;
const MAX_GRAPH_EDGES: usize = MAX_CLOSURE_DOCUMENTS * 10;

const PACKAGES: [&str; 10] = [
    "SB-0", "SB-1", "SB-2", "SB-3", "SB-4", "SB-5", "SB-6", "SB-7", "SB-8", "SB-9",
];

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConformanceClosureError {
    #[error("invalid production conformance closure: {0}")]
    Invalid(String),
}

/// Opaque, non-cloneable ControlTrace whose exact bytes, strict parse, raw
/// digest, locator, and profile reference cannot detach after construction.
pub struct VerifiedControlTraceArtifact {
    artifact_locator: String,
    raw_bytes: Box<[u8]>,
    raw_digest: String,
    document: Value,
}

impl fmt::Debug for VerifiedControlTraceArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedControlTraceArtifact")
            .field("artifact_locator", &self.artifact_locator)
            .field("raw_digest", &self.raw_digest)
            .field("byte_len", &self.raw_bytes.len())
            .field(
                "document_id",
                &self.document.get("document_id").and_then(Value::as_str),
            )
            .finish()
    }
}

impl VerifiedControlTraceArtifact {
    pub fn artifact_locator(&self) -> &str {
        &self.artifact_locator
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw_bytes
    }

    pub fn raw_digest(&self) -> &str {
        &self.raw_digest
    }

    pub fn document(&self) -> &Value {
        &self.document
    }
}

/// Strictly loads and binds one exact ControlTrace to its typed profile
/// reference. Schema validation remains an outer admission responsibility;
/// this constructor owns the raw-byte/digest/value identity boundary used by
/// semantic closure.
pub fn verify_control_trace_artifact(
    reference: &VersionedContentReference,
    raw_bytes: Vec<u8>,
) -> Result<VerifiedControlTraceArtifact, ConformanceClosureError> {
    if reference.artifact_kind != ArtifactKind::ControlTrace
        || raw_bytes.is_empty()
        || raw_bytes.len() > MAX_CONTROL_TRACE_BYTES
    {
        return Err(invalid("invalid ControlTrace reference or empty artifact"));
    }
    let raw_digest = digest_bytes(&raw_bytes);
    if raw_digest != reference.content_digest {
        return Err(invalid(
            "ControlTrace raw bytes do not match the profile reference digest",
        ));
    }
    let document = parse_json_strict(&raw_bytes)
        .map_err(|error| invalid(format!("ControlTrace strict JSON failed: {error}")))?;
    let mut node_count = 0;
    validate_control_trace_json_shape(&document, 0, &mut node_count)?;
    if document.get("contract_kind").and_then(Value::as_str) != Some("control-trace")
        || document.get("document_id").and_then(Value::as_str)
            != Some(reference.document_id.as_str())
        || document.get("document_version").and_then(Value::as_u64)
            != Some(reference.document_version)
    {
        return Err(invalid(
            "ControlTrace identity does not match the profile reference",
        ));
    }
    Ok(VerifiedControlTraceArtifact {
        artifact_locator: reference.artifact_locator.clone(),
        raw_bytes: raw_bytes.into_boxed_slice(),
        raw_digest,
        document,
    })
}

fn validate_control_trace_json_shape(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), ConformanceClosureError> {
    if depth > MAX_CONTROL_TRACE_JSON_DEPTH {
        return Err(invalid("ControlTrace JSON exceeds the nesting-depth bound"));
    }
    *nodes = nodes
        .checked_add(1)
        .ok_or_else(|| invalid("ControlTrace JSON node counter overflows"))?;
    if *nodes > MAX_CONTROL_TRACE_JSON_NODES {
        return Err(invalid("ControlTrace JSON exceeds the node-count bound"));
    }
    match value {
        Value::String(value) if value.len() > MAX_CONTROL_TRACE_STRING_BYTES => {
            Err(invalid("ControlTrace JSON contains an oversized string"))
        }
        Value::Array(values) => {
            if values.len() > MAX_CONTROL_TRACE_COLLECTION_ITEMS {
                return Err(invalid("ControlTrace JSON contains an oversized array"));
            }
            for value in values {
                validate_control_trace_json_shape(value, depth + 1, nodes)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            if values.len() > MAX_CONTROL_TRACE_COLLECTION_ITEMS {
                return Err(invalid("ControlTrace JSON contains an oversized object"));
            }
            for (key, value) in values {
                if key.len() > MAX_CONTROL_TRACE_STRING_BYTES {
                    return Err(invalid(
                        "ControlTrace JSON contains an oversized object key",
                    ));
                }
                validate_control_trace_json_shape(value, depth + 1, nodes)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[derive(Debug, Clone, Copy)]
struct LoadedConformanceDocument<'a> {
    artifact_locator: &'a str,
    raw_digest: &'a str,
    value: &'a Value,
}

#[derive(Debug, Clone, Copy)]
struct ControlTraceArtifact<'a> {
    value: &'a Value,
    raw_digest: &'a str,
    artifact_locator: &'a str,
}

/// Exact deployment/profile bindings expected by the serving process.
#[derive(Debug, Clone, Copy)]
pub struct ConformanceClosureContext<'a> {
    pub deployment_id: &'a str,
    pub trust_domain_id: &'a str,
    pub source_revision: &'a str,
    pub artifact_digest: &'a str,
    pub deployment_profile: &'a Value,
    pub policy_versions: &'a Value,
    pub configuration_versions: &'a Value,
    pub provider_versions: &'a Value,
    pub adapter_versions: &'a Value,
    pub security_limit_profile: &'a Value,
    pub deployment_profile_document: &'a Value,
    pub production_acceptance_receipt_ref: &'a VersionedContentReference,
}

/// Exact, independently derived context bindings consumed by production
/// conformance closure verification.
///
/// Keeping these values behind one constructor prevents an admission layer
/// from reimplementing the profile/provider/build projection rules and
/// accidentally drifting from the verifier. This value is data, not an
/// authority capability; only [`verify_production_conformance_closure`] can
/// mint the opaque closure proof.
#[derive(Debug, Clone, PartialEq)]
pub struct DerivedConformanceClosureContext {
    deployment_id: String,
    trust_domain_id: String,
    source_revision: String,
    artifact_digest: String,
    deployment_profile: Value,
    policy_versions: Value,
    configuration_versions: Value,
    provider_versions: Value,
    adapter_versions: Value,
    security_limit_profile: Value,
    deployment_profile_document: Value,
    deployment_profile_raw_bytes: Box<[u8]>,
    deployment_profile_raw_digest: String,
    production_acceptance_receipt_ref: VersionedContentReference,
}

impl DerivedConformanceClosureContext {
    pub fn as_context(&self) -> ConformanceClosureContext<'_> {
        ConformanceClosureContext {
            deployment_id: &self.deployment_id,
            trust_domain_id: &self.trust_domain_id,
            source_revision: &self.source_revision,
            artifact_digest: &self.artifact_digest,
            deployment_profile: &self.deployment_profile,
            policy_versions: &self.policy_versions,
            configuration_versions: &self.configuration_versions,
            provider_versions: &self.provider_versions,
            adapter_versions: &self.adapter_versions,
            security_limit_profile: &self.security_limit_profile,
            deployment_profile_document: &self.deployment_profile_document,
            production_acceptance_receipt_ref: &self.production_acceptance_receipt_ref,
        }
    }

    pub fn deployment_profile_raw_digest(&self) -> &str {
        &self.deployment_profile_raw_digest
    }
}

/// Derives every semantic-context value whose ownership belongs to the exact
/// profile, measured build, and independently retained deployment claims.
pub fn derive_production_conformance_closure_context(
    manifest: &ProductionBuildManifest,
    profile: &DeploymentSecurityProfile,
    deployment_claims: &ProductionDeploymentApplicabilityClaims,
    deployment_profile_raw_bytes: &[u8],
) -> Result<DerivedConformanceClosureContext, ConformanceClosureError> {
    if deployment_profile_raw_bytes.is_empty()
        || deployment_profile_raw_bytes.len() > MAX_DEPLOYMENT_PROFILE_BYTES
    {
        return Err(invalid(
            "exact deployment profile bytes are empty or exceed the bounded maximum",
        ));
    }
    let deployment_profile_document = parse_json_strict(deployment_profile_raw_bytes)
        .map_err(|error| invalid(format!("invalid exact deployment profile JSON: {error}")))?;
    let exact_profile: DeploymentSecurityProfile =
        serde_json::from_value(deployment_profile_document.clone())
            .map_err(|error| invalid(format!("invalid exact deployment profile: {error}")))?;
    if profile != &exact_profile || !profile.security_profile.is_production() {
        return Err(invalid(
            "typed deployment profile differs from the exact production profile document",
        ));
    }
    let [trust_domain_id] = profile.trust_topology.trust_domain_ids.as_slice() else {
        return Err(invalid(
            "production conformance closure requires exactly one trust domain",
        ));
    };
    let production_acceptance_receipt_ref = profile
        .production_acceptance_receipt_ref
        .clone()
        .ok_or_else(|| invalid("production profile omits its acceptance receipt reference"))?;
    let deployment_profile_digest =
        deployment_profile_conformance_binding_digest(&deployment_profile_document)?;
    let deployment_profile = json!({
        "deployment_id": profile.deployment_id,
        "id": profile.document_id,
        "version": profile.document_version.to_string(),
        "digest_contract": DEPLOYMENT_PROFILE_CONFORMANCE_BINDING_DIGEST_CONTRACT,
        "digest": deployment_profile_digest,
    });
    let policy_versions = Value::Array(profile_policy_version_bindings(profile));
    let configuration_versions = Value::Array(profile_configuration_version_bindings(profile));
    let mut providers = deployment_claims
        .provider_registry
        .active_providers
        .iter()
        .map(|provider| {
            json!({
                "id": provider.provider_id,
                "version": provider.configuration_version.to_string(),
                "digest": provider.configuration_payload_digest,
            })
        })
        .collect::<Vec<_>>();
    providers.sort_by(|left, right| {
        left.get("id")
            .and_then(Value::as_str)
            .cmp(&right.get("id").and_then(Value::as_str))
    });
    let mut adapters = manifest
        .shipped_adapters
        .iter()
        .map(|adapter| {
            json!({
                "id": adapter.adapter_kind,
                "version": adapter.adapter_version,
                "digest": adapter.mandatory_baseline.content_digest,
            })
        })
        .collect::<Vec<_>>();
    adapters.sort_by(|left, right| {
        left.get("id")
            .and_then(Value::as_str)
            .cmp(&right.get("id").and_then(Value::as_str))
    });
    let limit = &deployment_claims.security_limit_profile;
    let derived = DerivedConformanceClosureContext {
        deployment_id: profile.deployment_id.clone(),
        trust_domain_id: trust_domain_id.clone(),
        source_revision: manifest.source.revision.clone(),
        artifact_digest: deployment_claims.deployed_artifact.subject_digest.clone(),
        deployment_profile,
        policy_versions,
        configuration_versions,
        provider_versions: Value::Array(providers),
        adapter_versions: Value::Array(adapters),
        security_limit_profile: json!({
            "id": limit.document_id,
            "version": limit.profile_version.to_string(),
            "digest": limit.content_digest,
        }),
        deployment_profile_document,
        deployment_profile_raw_bytes: deployment_profile_raw_bytes.to_vec().into_boxed_slice(),
        deployment_profile_raw_digest: digest_bytes(deployment_profile_raw_bytes),
        production_acceptance_receipt_ref,
    };
    validate_context(derived.as_context())?;
    Ok(derived)
}

/// Independently bound inputs from which the closure derives the complete v2
/// implementation-plus-deployment applicability universe.
#[derive(Debug, Clone, Copy)]
pub struct ProductionConformanceClosureInputs<'a> {
    pub manifest: &'a ProductionBuildManifest,
    pub profile: &'a DeploymentSecurityProfile,
    pub deployment_claims: &'a ProductionDeploymentApplicabilityClaims,
    pub context: &'a DerivedConformanceClosureContext,
}

#[derive(Debug)]
pub struct VerifiedRuntimeGuardRequirement {
    guard_id: GuardId,
    control_ids: BTreeSet<String>,
    receipt_id: String,
    receipt_version: u64,
    receipt_digest: String,
    receipt_locator: String,
    expected_value: RuntimeGuardExpectedValue,
    requirement_digest: String,
    semantic_challenge_binding_digest: String,
}

impl VerifiedRuntimeGuardRequirement {
    pub fn guard_id(&self) -> GuardId {
        self.guard_id
    }

    pub fn control_ids(&self) -> &BTreeSet<String> {
        &self.control_ids
    }

    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }

    pub fn receipt_version(&self) -> u64 {
        self.receipt_version
    }

    pub fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }

    pub fn receipt_locator(&self) -> &str {
        &self.receipt_locator
    }

    pub fn expected_value(&self) -> &RuntimeGuardExpectedValue {
        &self.expected_value
    }

    pub fn requirement_digest(&self) -> &str {
        &self.requirement_digest
    }

    pub fn semantic_challenge_binding_digest(&self) -> &str {
        &self.semantic_challenge_binding_digest
    }
}

/// Opaque semantic proof that the exact ledger, evidence, receipts, deployment
/// context, and prerequisite graph form one complete production closure.
///
/// This capability deliberately does not prove that the constructible build,
/// deployment, provider, or limit claims came from live production. The API
/// admission layer retains its independently pinned build and verified opaque
/// workload proof alongside this value, then must verify typed live guard
/// witnesses before treating the combined aggregate as runtime authority.
pub struct VerifiedConformanceClosure {
    checkpoint: VerifiedConformanceTrustCheckpoint,
    _current_root: VerifiedConformanceProductionRoot,
    _artifacts: Box<[VerifiedConformanceArtifact]>,
    _control_trace: VerifiedControlTraceArtifact,
    applicability: DerivedProductionApplicability,
    _manifest: ProductionBuildManifest,
    _profile: DeploymentSecurityProfile,
    _profile_raw_bytes: Box<[u8]>,
    profile_raw_digest: String,
    closure_digest: String,
    ledger_digest: String,
    deployment_id: String,
    trust_domain_id: String,
    source_revision: String,
    artifact_digest: String,
    context_digest: String,
    semantic_context: Value,
    authority_id: String,
    authority_epoch: u64,
    authority_revision: u64,
    checkpoint_sequence: u64,
    snapshot_binding_digest: String,
    semantic_valid_until: DateTime<Utc>,
    root_receipt_id: String,
    root_receipt_version: u64,
    root_receipt_digest: String,
    root_receipt_locator: String,
    receipt_digests: BTreeMap<String, String>,
    evidence_digests: BTreeSet<String>,
    runtime_guard_requirements: Vec<VerifiedRuntimeGuardRequirement>,
}

impl fmt::Debug for VerifiedConformanceClosure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedConformanceClosure")
            .field("closure_digest", &self.closure_digest)
            .field("ledger_digest", &self.ledger_digest)
            .field("deployment_id", &self.deployment_id)
            .field("trust_domain_id", &self.trust_domain_id)
            .field("source_revision", &self.source_revision)
            .field("artifact_digest", &self.artifact_digest)
            .field("authority_id", &self.authority_id)
            .field("authority_epoch", &self.authority_epoch)
            .field("authority_revision", &self.authority_revision)
            .field("checkpoint_sequence", &self.checkpoint_sequence)
            .field("root_receipt_id", &self.root_receipt_id)
            .field("package_count", &self.receipt_digests.len())
            .field("evidence_count", &self.evidence_digests.len())
            .field("semantic_valid_until", &self.semantic_valid_until)
            .finish()
    }
}

impl VerifiedConformanceClosure {
    /// Rechecks the independently authenticated checkpoint at every later
    /// startup fence. Artifact `accepted_at` and signer `signed_at` values are
    /// historical evidence only and never establish present freshness.
    pub fn ensure_fresh(
        &self,
        trusted_now: ConformanceTrustedTimeWindow,
    ) -> Result<(), ConformanceClosureError> {
        self.checkpoint
            .ensure_fresh(trusted_now)
            .map_err(|error| invalid(format!("conformance checkpoint is stale: {error}")))?;
        if trusted_now.not_after >= self.semantic_valid_until {
            return Err(invalid(
                "conformance evidence expires at or before the final startup time fence",
            ));
        }
        Ok(())
    }

    pub fn applicability_binding(&self) -> &ApplicabilityInventoryBinding {
        &self.applicability.binding
    }

    pub fn applicability_instances(&self) -> &[ApplicabilityInstance] {
        &self.applicability.instances
    }

    pub fn closure_digest(&self) -> &str {
        &self.closure_digest
    }

    pub fn ledger_digest(&self) -> &str {
        &self.ledger_digest
    }

    pub fn deployment_id(&self) -> &str {
        &self.deployment_id
    }

    pub fn trust_domain_id(&self) -> &str {
        &self.trust_domain_id
    }

    pub fn source_revision(&self) -> &str {
        &self.source_revision
    }

    pub fn artifact_digest(&self) -> &str {
        &self.artifact_digest
    }

    pub fn context_digest(&self) -> &str {
        &self.context_digest
    }

    /// Exact canonical semantic context retained when this proof was minted.
    /// The returned value is read-only and the proof remains non-cloneable.
    pub fn semantic_context(&self) -> &Value {
        &self.semantic_context
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

    pub fn snapshot_binding_digest(&self) -> &str {
        &self.snapshot_binding_digest
    }

    pub fn semantic_valid_until(&self) -> DateTime<Utc> {
        self.semantic_valid_until
    }

    pub fn root_receipt_id(&self) -> &str {
        &self.root_receipt_id
    }

    pub fn root_receipt_version(&self) -> u64 {
        self.root_receipt_version
    }

    pub fn root_receipt_digest(&self) -> &str {
        &self.root_receipt_digest
    }

    pub fn root_receipt_locator(&self) -> &str {
        &self.root_receipt_locator
    }

    pub fn package_count(&self) -> usize {
        self.receipt_digests.len()
    }

    pub fn evidence_count(&self) -> usize {
        self.evidence_digests.len()
    }

    pub fn receipt_digest(&self, package_id: &str) -> Option<&str> {
        self.receipt_digests.get(package_id).map(String::as_str)
    }

    pub fn runtime_guard_requirements(&self) -> &[VerifiedRuntimeGuardRequirement] {
        &self.runtime_guard_requirements
    }

    /// Exact typed manifest retained by the non-cloneable closure proof.
    pub fn production_build_manifest(&self) -> &ProductionBuildManifest {
        &self._manifest
    }

    /// Exact typed deployment profile retained by the non-cloneable closure
    /// proof.
    pub fn deployment_profile(&self) -> &DeploymentSecurityProfile {
        &self._profile
    }

    pub fn deployment_profile_raw_digest(&self) -> &str {
        &self.profile_raw_digest
    }
}

#[derive(Debug, Clone)]
struct ProofFacts {
    kind: ConformanceDocumentKind,
    document_id: String,
    document_version: u64,
    complete_document_digest: String,
    accepted_at_not_before: DateTime<Utc>,
    accepted_at_not_after: DateTime<Utc>,
    acceptance_record_id: String,
    acceptance_sequence: u64,
    authority_id: String,
    authority_epoch: u64,
    authority_revision: u64,
    checkpoint_sequence: u64,
    registry_id: String,
    registry_version: u64,
    registry_digest: String,
    deployment_id: String,
    trust_domain_id: String,
    package_id: String,
    evidence_tier: EvidenceTier,
    snapshot_binding_digest: String,
}

impl From<&VerifiedConformanceArtifact> for ProofFacts {
    fn from(proof: &VerifiedConformanceArtifact) -> Self {
        Self {
            kind: proof.kind(),
            document_id: proof.document_id().to_owned(),
            document_version: proof.document_version(),
            complete_document_digest: proof.complete_document_digest().to_owned(),
            accepted_at_not_before: proof.accepted_at_not_before(),
            accepted_at_not_after: proof.accepted_at_not_after(),
            acceptance_record_id: proof.acceptance_record_id().to_owned(),
            acceptance_sequence: proof.acceptance_sequence(),
            authority_id: proof.authority_id().to_owned(),
            authority_epoch: proof.authority_epoch(),
            authority_revision: proof.authority_revision(),
            checkpoint_sequence: proof.checkpoint_sequence(),
            registry_id: proof.registry_id().to_owned(),
            registry_version: proof.registry_version(),
            registry_digest: proof.registry_digest().to_owned(),
            deployment_id: proof.deployment_id().to_owned(),
            trust_domain_id: proof.trust_domain_id().to_owned(),
            package_id: proof.package_id().to_owned(),
            evidence_tier: proof.evidence_tier(),
            snapshot_binding_digest: proof.snapshot_binding_digest().to_owned(),
        }
    }
}

/// Verifies one exact production conformance closure.
///
/// This consumes the checkpoint, exact external current-root capability, and
/// every authenticated closure artifact. The returned proof owns them all.
/// Applicability is derived inside this boundary from independently bound
/// build/deployment facts; receipt-authored inventories cannot reduce it.
pub fn verify_production_conformance_closure(
    checkpoint: VerifiedConformanceTrustCheckpoint,
    current_root: VerifiedConformanceProductionRoot,
    artifacts: Vec<VerifiedConformanceArtifact>,
    control_trace: VerifiedControlTraceArtifact,
    inputs: ProductionConformanceClosureInputs<'_>,
    trusted_now: ConformanceTrustedTimeWindow,
) -> Result<VerifiedConformanceClosure, ConformanceClosureError> {
    let context = inputs.context.as_context();
    checkpoint
        .ensure_fresh(trusted_now)
        .map_err(|error| invalid(format!("conformance checkpoint is stale: {error}")))?;
    let snapshot = checkpoint.snapshot_binding_digest();
    if current_root.snapshot_binding_digest() != snapshot
        || artifacts
            .iter()
            .any(|artifact| artifact.snapshot_binding_digest() != snapshot)
    {
        return Err(invalid(
            "closure artifacts do not all belong to the exact same checkpoint snapshot",
        ));
    }
    let exact_profile: DeploymentSecurityProfile =
        serde_json::from_value(context.deployment_profile_document.clone())
            .map_err(|error| invalid(format!("invalid exact deployment profile: {error}")))?;
    let profile_errors = exact_profile.validate_structure_at(trusted_now.not_before);
    if !profile_errors.is_empty() {
        return Err(invalid(format!(
            "deployment profile fails complete production semantics: {}",
            profile_errors.join("; ")
        )));
    }
    if inputs.profile != &exact_profile {
        return Err(invalid(
            "typed deployment profile differs from the exact bound profile document",
        ));
    }
    let migration_overlay_retirement_deadline = exact_profile
        .migration_overlay
        .as_ref()
        .map(|overlay| {
            DateTime::parse_from_rfc3339(&overlay.retirement_deadline)
                .map(|deadline| deadline.with_timezone(&Utc))
                .map_err(|_| invalid("migration overlay retirement_deadline is not RFC3339"))
        })
        .transpose()?;
    if migration_overlay_retirement_deadline
        .is_some_and(|deadline| deadline <= trusted_now.not_after)
    {
        return Err(invalid(
            "migration overlay retirement_deadline does not remain valid through the trusted-time verification window",
        ));
    }
    if inputs.profile.control_trace_ref.artifact_locator != control_trace.artifact_locator
        || inputs.profile.control_trace_ref.content_digest != control_trace.raw_digest
        || inputs.manifest.control_trace_ref != inputs.profile.control_trace_ref
    {
        return Err(invalid(
            "ControlTrace is not exactly bound by both profile and measured build manifest",
        ));
    }
    if context.source_revision != inputs.manifest.source.revision
        || context.artifact_digest != inputs.deployment_claims.deployed_artifact.subject_digest
    {
        return Err(invalid(
            "closure source revision or deployed artifact digest differs from the measured production inputs",
        ));
    }
    validate_claim_context_bindings(&checkpoint, inputs)?;
    let applicability = derive_complete_production_applicability(
        &control_trace.document,
        inputs.manifest,
        inputs.profile,
        inputs.deployment_claims,
    )
    .map_err(|error| {
        invalid(format!(
            "production applicability derivation failed: {error}"
        ))
    })?;
    validate_runtime_guard_provider_bindings(
        inputs.profile,
        &inputs.deployment_claims.provider_registry.active_providers,
    )?;

    let root_artifact = current_root.artifact();
    let mut bundles = Vec::new();
    let mut receipts = Vec::new();
    let mut proof_facts = BTreeMap::new();
    for artifact in artifacts.iter().chain(std::iter::once(root_artifact)) {
        if proof_facts
            .insert(
                artifact.complete_document_digest().to_owned(),
                ProofFacts::from(artifact),
            )
            .is_some()
        {
            return Err(invalid("duplicate authenticated closure document digest"));
        }
        let loaded = LoadedConformanceDocument {
            artifact_locator: artifact.source_locator(),
            raw_digest: artifact.complete_document_digest(),
            value: artifact.document(),
        };
        match artifact.kind() {
            ConformanceDocumentKind::ConformanceBundle => bundles.push(loaded),
            ConformanceDocumentKind::PackageExitReceipt => receipts.push(loaded),
        }
    }
    let ledger = ControlTraceArtifact {
        value: &control_trace.document,
        raw_digest: &control_trace.raw_digest,
        artifact_locator: &control_trace.artifact_locator,
    };
    let semantic = verify_with_proof_facts(
        ledger,
        &bundles,
        &receipts,
        &proof_facts,
        context,
        &applicability,
        trusted_now,
        migration_overlay_retirement_deadline,
        &inputs.context.deployment_profile_raw_digest,
        current_root.artifact().complete_document_digest(),
        current_root.artifact().acceptance_record_id(),
    )?;

    let ClosureProjection {
        closure_digest,
        ledger_digest,
        deployment_id,
        trust_domain_id,
        source_revision,
        artifact_digest,
        context_digest,
        semantic_context,
        authority_id,
        authority_epoch,
        authority_revision,
        checkpoint_sequence,
        snapshot_binding_digest,
        semantic_valid_until,
        root_receipt_id,
        root_receipt_version,
        root_receipt_digest,
        root_receipt_locator,
        receipt_digests,
        evidence_digests,
        runtime_guard_requirements,
    } = semantic;
    Ok(VerifiedConformanceClosure {
        checkpoint,
        _current_root: current_root,
        _artifacts: artifacts.into_boxed_slice(),
        _control_trace: control_trace,
        applicability,
        _manifest: inputs.manifest.clone(),
        _profile: inputs.profile.clone(),
        _profile_raw_bytes: inputs.context.deployment_profile_raw_bytes.clone(),
        profile_raw_digest: inputs.context.deployment_profile_raw_digest.clone(),
        closure_digest,
        ledger_digest,
        deployment_id,
        trust_domain_id,
        source_revision,
        artifact_digest,
        context_digest,
        semantic_context,
        authority_id,
        authority_epoch,
        authority_revision,
        checkpoint_sequence,
        snapshot_binding_digest,
        semantic_valid_until,
        root_receipt_id,
        root_receipt_version,
        root_receipt_digest,
        root_receipt_locator,
        receipt_digests,
        evidence_digests,
        runtime_guard_requirements,
    })
}

fn validate_claim_context_bindings(
    checkpoint: &VerifiedConformanceTrustCheckpoint,
    inputs: ProductionConformanceClosureInputs<'_>,
) -> Result<(), ConformanceClosureError> {
    let context = inputs.context.as_context();
    let claims = &inputs.deployment_claims.checkpoints;
    let profile_registry = &inputs.profile.conformance_trust_root_registry_ref;
    if claims.len() != 1
        || claims[0].trust_domain_id != checkpoint.trust_domain_id()
        || claims[0].authority_id != checkpoint.authority_id()
        || claims[0].authority_epoch != checkpoint.authority_epoch()
        || claims[0].sequence != checkpoint.checkpoint_sequence()
        || claims[0].trust_registry_digest != checkpoint.registry_digest()
        || claims[0].trust_registry_locator != checkpoint.registry_locator()
        || context.deployment_id != checkpoint.deployment_id()
        || context.trust_domain_id != checkpoint.trust_domain_id()
        || profile_registry.document_id != checkpoint.registry_id()
        || profile_registry.document_version != checkpoint.registry_version()
        || profile_registry.content_digest != checkpoint.registry_digest()
        || profile_registry.artifact_locator != checkpoint.registry_locator()
    {
        return Err(invalid(
            "deployment checkpoint claims, profile trust registry, and opaque checkpoint are not one exact authority snapshot",
        ));
    }
    let policies = profile_policy_version_bindings(inputs.profile);
    let configurations = profile_configuration_version_bindings(inputs.profile);
    let mut providers = inputs
        .deployment_claims
        .provider_registry
        .active_providers
        .iter()
        .map(|provider| {
            json!({
                "id": provider.provider_id,
                "version": provider.configuration_version.to_string(),
                "digest": provider.configuration_payload_digest,
            })
        })
        .collect::<Vec<_>>();
    providers.sort_by(|left, right| {
        left.get("id")
            .and_then(Value::as_str)
            .cmp(&right.get("id").and_then(Value::as_str))
    });
    let mut adapters = inputs
        .manifest
        .shipped_adapters
        .iter()
        .map(|adapter| {
            json!({
                "id": adapter.adapter_kind,
                "version": adapter.adapter_version,
                "digest": adapter.mandatory_baseline.content_digest,
            })
        })
        .collect::<Vec<_>>();
    adapters.sort_by(|left, right| {
        left.get("id")
            .and_then(Value::as_str)
            .cmp(&right.get("id").and_then(Value::as_str))
    });
    let limit = &inputs.deployment_claims.security_limit_profile;
    let expected_limit = json!({
        "id": limit.document_id,
        "version": limit.profile_version.to_string(),
        "digest": limit.content_digest,
    });
    if context.policy_versions != &Value::Array(policies)
        || context.configuration_versions != &Value::Array(configurations)
        || context.provider_versions != &Value::Array(providers)
        || context.adapter_versions != &Value::Array(adapters)
        || context.security_limit_profile != &expected_limit
    {
        return Err(invalid(
            "closure policy, configuration, provider, adapter, or security-limit bindings differ from the independently retained inputs",
        ));
    }
    Ok(())
}

fn validate_runtime_guard_provider_bindings(
    profile: &DeploymentSecurityProfile,
    active_providers: &[ActiveProviderApplicabilityClaim],
) -> Result<(), ConformanceClosureError> {
    let [trust_domain_id] = profile.trust_topology.trust_domain_ids.as_slice() else {
        return Err(invalid(
            "runtime guard provider binding requires exactly one production trust domain",
        ));
    };
    let claims_by_id = active_providers
        .iter()
        .map(|claim| (claim.provider_id.as_str(), claim))
        .collect::<BTreeMap<_, _>>();
    if claims_by_id.len() != active_providers.len() {
        return Err(invalid(
            "runtime guard provider binding received duplicate active provider ids",
        ));
    }

    for guard in &profile.runtime_guard_evidence.guards {
        match &guard.expected_value {
            RuntimeGuardExpectedValue::ApprovedSecretProvider {
                provider_inventory_digest,
                providers,
                required_capability_ids,
            } => validate_secret_provider_bindings(
                provider_inventory_digest,
                providers,
                required_capability_ids,
                active_providers,
                &claims_by_id,
                trust_domain_id,
            )?,
            RuntimeGuardExpectedValue::NonDevelopmentAuthenticator {
                authenticator_inventory_digest,
                authenticators,
            } => validate_authenticator_provider_bindings(
                authenticator_inventory_digest,
                authenticators,
                active_providers,
                &claims_by_id,
                trust_domain_id,
            )?,
            _ => {}
        }
    }
    Ok(())
}

fn validate_secret_provider_bindings(
    expected_inventory_digest: &str,
    providers: &[ExpectedSecretProviderBinding],
    required_capability_ids: &[String],
    active_providers: &[ActiveProviderApplicabilityClaim],
    claims_by_id: &BTreeMap<&str, &ActiveProviderApplicabilityClaim>,
    trust_domain_id: &str,
) -> Result<(), ConformanceClosureError> {
    validate_digest(
        expected_inventory_digest,
        "approved-secret-provider provider inventory digest",
    )?;
    if providers.is_empty()
        || !providers
            .windows(2)
            .all(|pair| pair[0].provider.provider_id < pair[1].provider.provider_id)
    {
        return Err(invalid(
            "approved-secret-provider providers must be nonempty, strictly sorted, and unique by provider_id",
        ));
    }
    if required_capability_ids.is_empty()
        || !required_capability_ids
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    {
        return Err(invalid(
            "approved-secret-provider required capability ids must be nonempty, strictly sorted, and unique",
        ));
    }
    for provider in providers {
        validate_digest(
            &provider.runtime_binding_digest,
            "approved-secret-provider runtime binding digest",
        )?;
    }
    let recomputed_inventory_digest =
        secret_provider_inventory_digest(providers, required_capability_ids)
            .map_err(|_| invalid("approved-secret-provider inventory cannot be canonicalized"))?;
    if expected_inventory_digest != recomputed_inventory_digest {
        return Err(invalid(
            "approved-secret-provider inventory digest does not equal its canonical binding and capability inventory",
        ));
    }

    let expected_ids = providers
        .iter()
        .map(|provider| provider.provider.provider_id.as_str())
        .collect::<BTreeSet<_>>();
    let active_secret_ids = active_providers
        .iter()
        .filter(|claim| claim.provider_kind == "secret-service")
        .map(|claim| claim.provider_id.as_str())
        .collect::<BTreeSet<_>>();
    if expected_ids != active_secret_ids {
        return Err(invalid(
            "approved-secret-provider expectation is not the exact active secret-service provider inventory",
        ));
    }
    for expected in providers {
        let claim = exact_guard_provider_claim(
            "approved-secret-provider",
            &expected.provider,
            claims_by_id,
            trust_domain_id,
        )?;
        if claim.provider_kind != "secret-service"
            || required_capability_ids.iter().any(|capability_id| {
                claim
                    .advertised_capability_ids
                    .binary_search(capability_id)
                    .is_err()
            })
        {
            return Err(invalid(format!(
                "approved-secret-provider {} is not a secret-service provider advertising every required capability",
                expected.provider.provider_id
            )));
        }
    }
    Ok(())
}

fn validate_authenticator_provider_bindings(
    expected_inventory_digest: &str,
    authenticators: &[ExpectedAuthenticatorBinding],
    active_providers: &[ActiveProviderApplicabilityClaim],
    claims_by_id: &BTreeMap<&str, &ActiveProviderApplicabilityClaim>,
    trust_domain_id: &str,
) -> Result<(), ConformanceClosureError> {
    let recomputed_inventory_digest = authenticator_inventory_digest(authenticators)
        .map_err(|_| invalid("non-development-authenticator inventory cannot be canonicalized"))?;
    if expected_inventory_digest != recomputed_inventory_digest {
        return Err(invalid(
            "non-development-authenticator inventory digest does not equal its canonical binding inventory",
        ));
    }

    let expected_ids = authenticators
        .iter()
        .map(|authenticator| authenticator.provider.provider_id.as_str())
        .collect::<BTreeSet<_>>();
    let active_authenticator_ids = active_providers
        .iter()
        .filter(|claim| production_authenticator_provider_kind(&claim.provider_kind))
        .map(|claim| claim.provider_id.as_str())
        .collect::<BTreeSet<_>>();
    if expected_ids != active_authenticator_ids {
        return Err(invalid(
            "non-development-authenticator expectation is not the exact active authenticator provider inventory",
        ));
    }
    if !active_providers
        .iter()
        .any(|claim| production_human_authenticator_provider_kind(&claim.provider_kind))
    {
        return Err(invalid(
            "non-development-authenticator inventory has no active human oidc, oidc-broker, or local-webauthn provider",
        ));
    }
    for authenticator in authenticators {
        let claim = exact_guard_provider_claim(
            "non-development-authenticator",
            &authenticator.provider,
            claims_by_id,
            trust_domain_id,
        )?;
        if !provider_kind_supports_authenticator(
            &claim.provider_kind,
            authenticator.authenticator_kind,
        ) {
            return Err(invalid(format!(
                "non-development-authenticator {} provider kind does not match its typed authenticator kind",
                authenticator.provider.provider_id
            )));
        }
    }
    Ok(())
}

fn exact_guard_provider_claim<'a>(
    guard_label: &str,
    expected: &ExpectedProviderBinding,
    claims_by_id: &BTreeMap<&str, &'a ActiveProviderApplicabilityClaim>,
    trust_domain_id: &str,
) -> Result<&'a ActiveProviderApplicabilityClaim, ConformanceClosureError> {
    let claim = claims_by_id
        .get(expected.provider_id.as_str())
        .copied()
        .ok_or_else(|| {
            invalid(format!(
                "{guard_label} expected provider {} is absent from the exact active provider inventory",
                expected.provider_id
            ))
        })?;
    if !claim.production_eligible
        || claim.trust_domain_id != trust_domain_id
        || expected.configuration_version != claim.configuration_version
        || expected.configuration_payload_digest != claim.configuration_payload_digest
        || expected.lifecycle_record_version != claim.lifecycle_record_version
        || expected.lifecycle_state != claim.lifecycle_state
        || expected.capability_descriptor_id != claim.descriptor_id
        || expected.capability_descriptor_version != claim.descriptor_version
        || expected.adapter_kind != claim.adapter_kind
        || expected.adapter_version != claim.adapter_version
    {
        return Err(invalid(format!(
            "{guard_label} expected provider {} does not exactly match its production-eligible active provider claim",
            expected.provider_id
        )));
    }
    Ok(claim)
}

fn production_authenticator_provider_kind(provider_kind: &str) -> bool {
    matches!(
        provider_kind,
        "oidc" | "oidc-broker" | "local-webauthn" | "oauth-service" | "api-token" | "workload"
    )
}

fn production_human_authenticator_provider_kind(provider_kind: &str) -> bool {
    matches!(provider_kind, "oidc" | "oidc-broker" | "local-webauthn")
}

fn provider_kind_supports_authenticator(
    provider_kind: &str,
    authenticator_kind: ProductionAuthenticatorKind,
) -> bool {
    match authenticator_kind {
        ProductionAuthenticatorKind::Oidc => provider_kind == "oidc",
        ProductionAuthenticatorKind::OidcBroker => provider_kind == "oidc-broker",
        ProductionAuthenticatorKind::Passkey => provider_kind == "local-webauthn",
        ProductionAuthenticatorKind::OauthService => provider_kind == "oauth-service",
        ProductionAuthenticatorKind::ApiToken => provider_kind == "api-token",
        ProductionAuthenticatorKind::Workload => provider_kind == "workload",
        ProductionAuthenticatorKind::MutualTls | ProductionAuthenticatorKind::Composite => false,
    }
}

fn profile_policy_version_bindings(profile: &DeploymentSecurityProfile) -> Vec<Value> {
    let mut references = vec![
        &profile.action_resource_registry_ref,
        &profile.egress_policy_ref,
        &profile.retention_policy_ref,
    ];
    if let Some(reference) = &profile.trust_topology.federation_policy_ref {
        references.push(reference);
    }
    version_bindings_from_references(references)
}

fn profile_configuration_version_bindings(profile: &DeploymentSecurityProfile) -> Vec<Value> {
    version_bindings_from_references(vec![
        &profile.provider_registry_ref,
        &profile.control_plane_topology_ref,
    ])
}

fn version_bindings_from_references(references: Vec<&VersionedContentReference>) -> Vec<Value> {
    let mut bindings = references
        .into_iter()
        .map(|reference| {
            json!({
                "id": reference.document_id,
                "version": reference.document_version.to_string(),
                "digest": reference.content_digest,
            })
        })
        .collect::<Vec<_>>();
    bindings.sort_by(|left, right| {
        left.get("id")
            .and_then(Value::as_str)
            .cmp(&right.get("id").and_then(Value::as_str))
    });
    bindings
}

/// Computes the cycle-free digest used by conformance bundle and receipt
/// deployment-profile bindings. The full profile remains independently pinned.
/// The cycle-free projection removes the top-level production receipt reference
/// and replaces each runtime-guard receipt digest plus the optional migration
/// overlay's zero-consumer receipt digest with the canonical zero sentinel;
/// every other receipt-reference field remains covered.
pub fn deployment_profile_conformance_binding_digest(
    profile: &Value,
) -> Result<String, ConformanceClosureError> {
    let _: DeploymentSecurityProfile = serde_json::from_value(profile.clone())
        .map_err(|error| invalid(format!("invalid deployment security profile: {error}")))?;
    let mut projection = profile.clone();
    if projection
        .as_object_mut()
        .ok_or_else(|| invalid("deployment security profile must be an object"))?
        .remove("production_acceptance_receipt_ref")
        .is_none()
    {
        return Err(invalid(
            "deployment security profile omits production_acceptance_receipt_ref",
        ));
    }
    let guards = projection
        .pointer_mut("/runtime_guard_evidence/guards")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| invalid("deployment security profile omits runtime guard evidence"))?;
    for guard in guards {
        let digest = guard
            .pointer_mut("/receipt_ref/content_digest")
            .filter(|value| value.is_string())
            .ok_or_else(|| invalid("runtime guard receipt reference omits content_digest"))?;
        *digest = Value::String(DEPLOYMENT_PROFILE_CONFORMANCE_RECEIPT_DIGEST_SENTINEL.to_owned());
    }
    if let Some(overlay) = projection.get_mut("migration_overlay")
        && !overlay.is_null()
    {
        let digest = overlay
            .pointer_mut("/zero_consumer_receipt_ref/content_digest")
            .filter(|value| value.is_string())
            .ok_or_else(|| invalid("migration overlay receipt reference omits content_digest"))?;
        *digest = Value::String(DEPLOYMENT_PROFILE_CONFORMANCE_RECEIPT_DIGEST_SENTINEL.to_owned());
    }
    let bytes = canonical_json_bytes(&projection).map_err(|error| {
        invalid(format!(
            "cannot canonicalize deployment profile conformance projection: {error}"
        ))
    })?;
    Ok(digest_bytes(&bytes))
}

/// Digest of every immutable semantic binding consumed by the closure.
pub fn conformance_closure_context_digest(
    context: ConformanceClosureContext<'_>,
) -> Result<String, ConformanceClosureError> {
    let projection = conformance_context_projection(context);
    let bytes = canonical_json_bytes(&projection).map_err(|error| {
        invalid(format!(
            "cannot canonicalize conformance closure context: {error}"
        ))
    })?;
    Ok(digest_bytes(&bytes))
}

#[derive(Debug, Clone, Copy)]
struct LedgerFacts<'a> {
    document_id: &'a str,
    document_version: u64,
    ledger_id: &'a str,
    ledger_version: &'a str,
}

#[derive(Debug, Clone)]
struct TraceFacts<'a> {
    value: &'a Value,
    control_id: &'a str,
    acceptance_case_id: &'a str,
    package_id: &'a str,
}

#[derive(Debug, Clone, Copy)]
struct TierFacts {
    tier: EvidenceTier,
    rank: u64,
}

#[derive(Debug, Clone, Copy)]
struct DocumentFacts<'a> {
    input: LoadedConformanceDocument<'a>,
    id: &'a str,
    version: u64,
    package_id: &'a str,
    tier: TierFacts,
}

#[derive(Debug)]
struct SupersessionFacts {
    graph: BTreeMap<String, BTreeSet<String>>,
    superseded: BTreeSet<String>,
}

struct ClosureProjection {
    closure_digest: String,
    ledger_digest: String,
    deployment_id: String,
    trust_domain_id: String,
    source_revision: String,
    artifact_digest: String,
    context_digest: String,
    semantic_context: Value,
    authority_id: String,
    authority_epoch: u64,
    authority_revision: u64,
    checkpoint_sequence: u64,
    snapshot_binding_digest: String,
    semantic_valid_until: DateTime<Utc>,
    root_receipt_id: String,
    root_receipt_version: u64,
    root_receipt_digest: String,
    root_receipt_locator: String,
    receipt_digests: BTreeMap<String, String>,
    evidence_digests: BTreeSet<String>,
    runtime_guard_requirements: Vec<VerifiedRuntimeGuardRequirement>,
}

#[allow(clippy::too_many_arguments)]
fn verify_with_proof_facts(
    ledger: ControlTraceArtifact<'_>,
    bundles: &[LoadedConformanceDocument<'_>],
    receipts: &[LoadedConformanceDocument<'_>],
    proofs_by_digest: &BTreeMap<String, ProofFacts>,
    context: ConformanceClosureContext<'_>,
    applicability: &DerivedProductionApplicability,
    trusted_now: ConformanceTrustedTimeWindow,
    semantic_validity_ceiling: Option<DateTime<Utc>>,
    deployment_profile_raw_digest: &str,
    current_root_digest: &str,
    current_root_acceptance_record_id: &str,
) -> Result<ClosureProjection, ConformanceClosureError> {
    validate_context(context)?;
    if bundles.len().saturating_add(receipts.len()) > MAX_CLOSURE_DOCUMENTS {
        return Err(invalid(format!(
            "closure exceeds {MAX_CLOSURE_DOCUMENTS} loaded documents"
        )));
    }

    let (ledger_facts, traces) = validate_ledger(ledger)?;
    validate_profile_ledger_reference(context.deployment_profile_document, ledger, ledger_facts)?;
    let mut loaded_digests = BTreeSet::new();
    let mut loaded_locators = BTreeSet::new();
    let mut logical_documents = BTreeSet::new();
    let mut bundle_ids = BTreeSet::new();
    let mut bundle_by_evidence = BTreeMap::new();
    let mut bundle_by_digest = BTreeMap::new();
    let mut receipt_by_id = BTreeMap::new();
    let mut receipt_by_digest = BTreeMap::new();

    for input in bundles {
        validate_loaded_identity(
            *input,
            ConformanceDocumentKind::ConformanceBundle,
            &mut loaded_digests,
            &mut loaded_locators,
            &mut logical_documents,
        )?;
        let value = input.value;
        let bundle_id = required_str(value, "bundle_id", "conformance bundle")?;
        if !bundle_ids.insert(bundle_id) {
            return Err(invalid(format!("duplicate bundle_id {bundle_id}")));
        }
        let evidence_id = required_str(value, "evidence_instance_id", bundle_id)?;
        let version = required_positive_u64(value, "document_version", bundle_id)?;
        let trace_id = required_str(value, "trace_id", bundle_id)?;
        let trace = traces.get(trace_id).ok_or_else(|| {
            invalid(format!(
                "bundle {bundle_id} references unknown trace {trace_id}"
            ))
        })?;
        require_equal_field(value, trace.value, "control_id", bundle_id)?;
        require_equal_field(value, trace.value, "acceptance_case_id", bundle_id)?;
        let tier = parse_tier(
            value
                .pointer("/provenance/evidence_tier")
                .ok_or_else(|| invalid(format!("bundle {bundle_id} omits provenance tier")))?,
            bundle_id,
        )?;
        validate_bundle_timestamps(value, bundle_id)?;
        let facts = DocumentFacts {
            input: *input,
            id: bundle_id,
            version,
            package_id: trace.package_id,
            tier,
        };
        if bundle_by_evidence.insert(evidence_id, facts).is_some() {
            return Err(invalid(format!(
                "duplicate evidence_instance_id {evidence_id}"
            )));
        }
        bundle_by_digest.insert(input.raw_digest, facts);
    }

    for input in receipts {
        validate_loaded_identity(
            *input,
            ConformanceDocumentKind::PackageExitReceipt,
            &mut loaded_digests,
            &mut loaded_locators,
            &mut logical_documents,
        )?;
        let value = input.value;
        let receipt_id = required_str(value, "receipt_id", "package receipt")?;
        let package_id = required_package(value, "package_id", receipt_id)?;
        let version = required_positive_u64(value, "document_version", receipt_id)?;
        let tier = parse_tier(
            value
                .get("evidence_tier")
                .ok_or_else(|| invalid(format!("receipt {receipt_id} omits evidence tier")))?,
            receipt_id,
        )?;
        validate_receipt_timestamps(value, receipt_id)?;
        let facts = DocumentFacts {
            input: *input,
            id: receipt_id,
            version,
            package_id,
            tier,
        };
        if receipt_by_id.insert(receipt_id, facts).is_some() {
            return Err(invalid(format!("duplicate receipt_id {receipt_id}")));
        }
        receipt_by_digest.insert(input.raw_digest, facts);
    }

    validate_exact_proofs(
        &bundle_by_digest,
        &receipt_by_digest,
        &loaded_digests,
        proofs_by_digest,
        context,
        trusted_now,
    )?;

    let superseded_evidence =
        validate_bundle_supersession(&bundle_by_evidence, proofs_by_digest, context, trusted_now)?;
    let superseded_receipts =
        validate_receipt_supersession(&receipt_by_id, proofs_by_digest, trusted_now)?;
    let current_receipts =
        select_current_receipts(&receipt_by_id, &superseded_receipts, trusted_now)?;
    validate_root_receipt_reference(context.production_acceptance_receipt_ref, &current_receipts)?;
    let selected_root = current_receipts
        .get("SB-9")
        .ok_or_else(|| invalid("selected closure has no current SB-9 receipt"))?;
    let selected_root_proof = proofs_by_digest
        .get(selected_root.input.raw_digest)
        .ok_or_else(|| invalid("selected SB-9 receipt has no authenticated proof"))?;
    if selected_root.input.raw_digest != current_root_digest
        || selected_root_proof.acceptance_record_id != current_root_acceptance_record_id
        || selected_root_proof.package_id != "SB-9"
    {
        return Err(invalid(
            "semantic SB-9 root is not the exact opaque externally current root",
        ));
    }
    let mut used_evidence_ids = BTreeSet::new();
    let mut receipt_digests = BTreeMap::new();
    let mut prerequisite_graph = BTreeMap::new();

    for package_id in PACKAGES {
        let receipt = current_receipts
            .get(package_id)
            .expect("all ten current receipts were checked");
        let prerequisites = validate_current_receipt(
            package_id,
            *receipt,
            ledger,
            ledger_facts,
            &traces,
            &bundle_by_evidence,
            &superseded_evidence.superseded,
            &current_receipts,
            &mut used_evidence_ids,
            context,
            applicability,
            proofs_by_digest,
            trusted_now,
        )?;
        prerequisite_graph.insert(receipt.id.to_owned(), prerequisites);
        receipt_digests.insert(package_id.to_owned(), receipt.input.raw_digest.to_owned());
    }
    reject_cycles("prerequisite receipt", &prerequisite_graph)?;

    validate_complete_history(
        "evidence supersession",
        &used_evidence_ids,
        &bundle_by_evidence
            .keys()
            .map(|id| (*id).to_owned())
            .collect(),
        &superseded_evidence.graph,
    )?;
    let current_evidence: BTreeSet<String> = bundle_by_evidence
        .keys()
        .filter(|id| !superseded_evidence.superseded.contains(**id))
        .map(|id| (*id).to_owned())
        .collect();
    if current_evidence != used_evidence_ids {
        return Err(invalid(format!(
            "current production evidence set is not exact: current={current_evidence:?}, bound={used_evidence_ids:?}"
        )));
    }

    let authority = proofs_by_digest
        .values()
        .next()
        .expect("ten receipts require a non-empty proof set");
    let evidence_digests = used_evidence_ids
        .iter()
        .map(|id| {
            bundle_by_evidence
                .get(id.as_str())
                .expect("bound evidence was resolved")
                .input
                .raw_digest
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    let mut runtime_guard_requirements = validate_runtime_guard_requirements(
        context.deployment_profile_document,
        &current_receipts,
        &traces,
        proofs_by_digest,
        selected_root_proof,
    )?;
    let mut semantic_valid_until = semantic_validity_ceiling;
    for receipt in current_receipts.values() {
        let expires = parse_timestamp(receipt.input.value, "expires_at", receipt.id)?;
        semantic_valid_until = Some(
            semantic_valid_until.map_or(expires, |current: DateTime<Utc>| current.min(expires)),
        );
    }
    for evidence_id in &used_evidence_ids {
        let bundle = bundle_by_evidence
            .get(evidence_id.as_str())
            .expect("every used evidence id was resolved");
        let expires = parse_timestamp(bundle.input.value, "expires_at", bundle.id)?;
        semantic_valid_until = Some(
            semantic_valid_until.map_or(expires, |current: DateTime<Utc>| current.min(expires)),
        );
    }
    let semantic_valid_until = semantic_valid_until
        .ok_or_else(|| invalid("verified semantic closure has no expiring evidence"))?;
    let semantic_context = conformance_context_projection(context);
    let context_digest = conformance_closure_context_digest(context)?;
    let closure_projection = json!({
        "ledger_digest": ledger.raw_digest,
        "conformance_context": &semantic_context,
        "context_digest": context_digest,
        "authority_id": authority.authority_id,
        "authority_epoch": authority.authority_epoch,
        "authority_revision": authority.authority_revision,
        "checkpoint_sequence": authority.checkpoint_sequence,
        "snapshot_binding_digest": authority.snapshot_binding_digest,
        "applicability_binding": &applicability.binding,
        "root_receipt": {
            "artifact_kind": "package-exit-receipt",
            "document_id": context.production_acceptance_receipt_ref.document_id,
            "document_version": context.production_acceptance_receipt_ref.document_version,
            "content_digest": context.production_acceptance_receipt_ref.content_digest,
            "artifact_locator": context.production_acceptance_receipt_ref.artifact_locator,
            "acceptance_record_id": selected_root_proof.acceptance_record_id,
            "acceptance_sequence": selected_root_proof.acceptance_sequence,
            "expires_at": selected_root.input.value.get("expires_at"),
        },
        "receipts": receipt_digests,
        "evidence_digests": evidence_digests,
        "runtime_guard_requirements": runtime_guard_projection(&runtime_guard_requirements),
    });
    let closure_digest =
        digest_bytes(&canonical_json_bytes(&closure_projection).map_err(|error| {
            invalid(format!(
                "cannot canonicalize verified closure projection: {error}"
            ))
        })?);
    for requirement in &mut runtime_guard_requirements {
        requirement.semantic_challenge_binding_digest =
            runtime_guard_semantic_challenge_binding_digest(
                &closure_digest,
                &context_digest,
                deployment_profile_raw_digest,
                context,
                authority,
                requirement,
            )?;
    }

    Ok(ClosureProjection {
        closure_digest,
        ledger_digest: ledger.raw_digest.to_owned(),
        deployment_id: context.deployment_id.to_owned(),
        trust_domain_id: context.trust_domain_id.to_owned(),
        source_revision: context.source_revision.to_owned(),
        artifact_digest: context.artifact_digest.to_owned(),
        context_digest,
        semantic_context,
        authority_id: authority.authority_id.clone(),
        authority_epoch: authority.authority_epoch,
        authority_revision: authority.authority_revision,
        checkpoint_sequence: authority.checkpoint_sequence,
        snapshot_binding_digest: authority.snapshot_binding_digest.clone(),
        semantic_valid_until,
        root_receipt_id: context
            .production_acceptance_receipt_ref
            .document_id
            .clone(),
        root_receipt_version: context.production_acceptance_receipt_ref.document_version,
        root_receipt_digest: context
            .production_acceptance_receipt_ref
            .content_digest
            .clone(),
        root_receipt_locator: context
            .production_acceptance_receipt_ref
            .artifact_locator
            .clone(),
        receipt_digests,
        evidence_digests,
        runtime_guard_requirements,
    })
}

fn invalid(message: impl Into<String>) -> ConformanceClosureError {
    ConformanceClosureError::Invalid(message.into())
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn validate_context(context: ConformanceClosureContext<'_>) -> Result<(), ConformanceClosureError> {
    let profile: DeploymentSecurityProfile =
        serde_json::from_value(context.deployment_profile_document.clone()).map_err(|error| {
            invalid(format!(
                "invalid exact deployment security profile document: {error}"
            ))
        })?;
    let profile_version = profile.document_version.to_string();
    for (label, value) in [
        ("deployment_id", context.deployment_id),
        ("trust_domain_id", context.trust_domain_id),
    ] {
        if value.is_empty() {
            return Err(invalid(format!("expected {label} is empty")));
        }
    }
    if !matches!(context.source_revision.len(), 40 | 64)
        || !context
            .source_revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid(
            "expected source_revision is not a lowercase Git object id",
        ));
    }
    validate_digest(context.artifact_digest, "expected artifact_digest")?;
    if !profile.security_profile.is_production()
        || profile.deployment_id != context.deployment_id
        || profile.trust_topology.trust_domain_ids.as_slice() != [context.trust_domain_id]
        || context
            .deployment_profile
            .get("deployment_id")
            .and_then(Value::as_str)
            != Some(context.deployment_id)
        || context.deployment_profile.get("id").and_then(Value::as_str)
            != Some(profile.document_id.as_str())
        || context
            .deployment_profile
            .get("version")
            .and_then(Value::as_str)
            != Some(profile_version.as_str())
    {
        return Err(invalid(
            "expected deployment profile binding does not exactly identify the production profile",
        ));
    }
    if context
        .deployment_profile
        .get("digest_contract")
        .and_then(Value::as_str)
        != Some(DEPLOYMENT_PROFILE_CONFORMANCE_BINDING_DIGEST_CONTRACT)
    {
        return Err(invalid(
            "deployment profile binding uses the wrong digest contract",
        ));
    }
    let expected_profile_digest =
        deployment_profile_conformance_binding_digest(context.deployment_profile_document)?;
    if context
        .deployment_profile
        .get("digest")
        .and_then(Value::as_str)
        != Some(expected_profile_digest.as_str())
    {
        return Err(invalid(
            "deployment profile binding digest does not match its named projection",
        ));
    }
    let root = context.production_acceptance_receipt_ref;
    if root.artifact_kind != ArtifactKind::PackageExitReceipt
        || root.document_id.is_empty()
        || root.document_version == 0
        || !valid_artifact_locator(&root.artifact_locator)
    {
        return Err(invalid(
            "invalid production acceptance receipt reference in deployment profile",
        ));
    }
    if profile.production_acceptance_receipt_ref.as_ref() != Some(root) {
        return Err(invalid(
            "context production acceptance receipt reference differs from the exact profile",
        ));
    }
    validate_digest(
        &root.content_digest,
        "production acceptance receipt reference digest",
    )?;
    for (label, bindings) in [
        ("policy_versions", context.policy_versions),
        ("configuration_versions", context.configuration_versions),
        ("provider_versions", context.provider_versions),
        ("adapter_versions", context.adapter_versions),
    ] {
        validate_version_binding_set(bindings, label)?;
    }
    if context.policy_versions != &Value::Array(profile_policy_version_bindings(&profile))
        || context.configuration_versions
            != &Value::Array(profile_configuration_version_bindings(&profile))
    {
        return Err(invalid(
            "policy or configuration bindings are not the exact profile-derived artifact sets",
        ));
    }
    validate_version_binding(context.security_limit_profile, "security_limit_profile")
}

fn validate_version_binding_set(
    value: &Value,
    context: &str,
) -> Result<(), ConformanceClosureError> {
    let values = value
        .as_array()
        .ok_or_else(|| invalid(format!("{context} is not an array")))?;
    if values.len() > MAX_CLOSURE_DOCUMENTS {
        return Err(invalid(format!("{context} exceeds the bounded maximum")));
    }
    let mut ids = BTreeSet::new();
    let mut prior: Option<&str> = None;
    for binding in values {
        validate_version_binding(binding, context)?;
        let id = required_str(binding, "id", context)?;
        if prior.is_some_and(|previous| previous >= id) || !ids.insert(id) {
            return Err(invalid(format!(
                "{context} is not strictly id-sorted and unique"
            )));
        }
        prior = Some(id);
    }
    Ok(())
}

fn validate_version_binding(value: &Value, context: &str) -> Result<(), ConformanceClosureError> {
    required_str(value, "id", context)?;
    required_str(value, "version", context)?;
    validate_digest(required_str(value, "digest", context)?, context)
}

fn conformance_context_projection(context: ConformanceClosureContext<'_>) -> Value {
    json!({
        "deployment_id": context.deployment_id,
        "trust_domain_id": context.trust_domain_id,
        "source_revision": context.source_revision,
        "artifact_digest": context.artifact_digest,
        "deployment_profile": context.deployment_profile,
        "policy_versions": context.policy_versions,
        "configuration_versions": context.configuration_versions,
        "provider_versions": context.provider_versions,
        "adapter_versions": context.adapter_versions,
        "security_limit_profile": context.security_limit_profile,
        "deployment_profile_document": context.deployment_profile_document,
        "production_acceptance_receipt_ref": context.production_acceptance_receipt_ref,
    })
}

fn validate_digest(value: &str, context: &str) -> Result<(), ConformanceClosureError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(invalid(format!("{context} is not a sha256 digest")));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || !hex.bytes().any(|byte| byte != b'0')
    {
        return Err(invalid(format!(
            "{context} is not a canonical sha256 digest"
        )));
    }
    Ok(())
}

fn validate_profile_ledger_reference(
    profile_document: &Value,
    ledger: ControlTraceArtifact<'_>,
    facts: LedgerFacts<'_>,
) -> Result<(), ConformanceClosureError> {
    let profile: DeploymentSecurityProfile = serde_json::from_value(profile_document.clone())
        .map_err(|error| invalid(format!("invalid deployment security profile: {error}")))?;
    let reference = profile.control_trace_ref;
    if reference.artifact_kind != ArtifactKind::ControlTrace
        || reference.document_id != facts.document_id
        || reference.document_version != facts.document_version
        || reference.content_digest != ledger.raw_digest
        || reference.artifact_locator != ledger.artifact_locator
    {
        return Err(invalid(
            "deployment profile does not exactly bind the loaded production ControlTrace ledger",
        ));
    }
    Ok(())
}

fn valid_artifact_locator(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.contains('/')
        && !value.starts_with('/')
        && value.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        })
}

fn validate_loaded_identity<'a>(
    input: LoadedConformanceDocument<'a>,
    expected_kind: ConformanceDocumentKind,
    loaded_digests: &mut BTreeSet<String>,
    loaded_locators: &mut BTreeSet<String>,
    logical_documents: &mut BTreeSet<(String, String, u64)>,
) -> Result<(), ConformanceClosureError> {
    validate_digest(input.raw_digest, "loaded conformance document digest")?;
    if !valid_artifact_locator(input.artifact_locator) {
        return Err(invalid(format!(
            "invalid conformance document locator {}",
            input.artifact_locator
        )));
    }
    if !loaded_digests.insert(input.raw_digest.to_owned()) {
        return Err(invalid(format!(
            "duplicate loaded document digest {}",
            input.raw_digest
        )));
    }
    if !loaded_locators.insert(input.artifact_locator.to_owned()) {
        return Err(invalid(format!(
            "duplicate loaded document locator {}",
            input.artifact_locator
        )));
    }
    let (schema, id_field) = match expected_kind {
        ConformanceDocumentKind::ConformanceBundle => (
            "https://ryuki.io/schemas/security-contracts/v1/conformance-bundle.schema.json",
            "bundle_id",
        ),
        ConformanceDocumentKind::PackageExitReceipt => (
            "https://ryuki.io/schemas/security-contracts/v1/package-exit-receipt.schema.json",
            "receipt_id",
        ),
    };
    if input.value.get("$schema").and_then(Value::as_str) != Some(schema)
        || input.value.get("contract_kind").and_then(Value::as_str) != Some(expected_kind.as_str())
    {
        return Err(invalid(format!(
            "{} has the wrong schema or contract kind",
            input.artifact_locator
        )));
    }
    let id = required_str(input.value, id_field, input.artifact_locator)?;
    let version = required_positive_u64(input.value, "document_version", id)?;
    if !logical_documents.insert((expected_kind.as_str().to_owned(), id.to_owned(), version)) {
        return Err(invalid(format!(
            "duplicate logical {} document {id} version {version}",
            expected_kind.as_str()
        )));
    }
    Ok(())
}

fn required_str<'a>(
    value: &'a Value,
    field: &str,
    context: &str,
) -> Result<&'a str, ConformanceClosureError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(format!("{context} omits valid {field}")))
}

fn required_positive_u64(
    value: &Value,
    field: &str,
    context: &str,
) -> Result<u64, ConformanceClosureError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or_else(|| invalid(format!("{context} omits valid {field}")))
}

fn required_package<'a>(
    value: &'a Value,
    field: &str,
    context: &str,
) -> Result<&'a str, ConformanceClosureError> {
    let package = required_str(value, field, context)?;
    if !PACKAGES.contains(&package) {
        return Err(invalid(format!("{context} has unknown package {package}")));
    }
    Ok(package)
}

fn required_array<'a>(
    value: &'a Value,
    field: &str,
    context: &str,
) -> Result<&'a [Value], ConformanceClosureError> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| invalid(format!("{context} omits valid {field}")))
}

fn require_equal_field(
    actual: &Value,
    expected: &Value,
    field: &str,
    context: &str,
) -> Result<(), ConformanceClosureError> {
    if actual.get(field).is_none() || actual.get(field) != expected.get(field) {
        return Err(invalid(format!("{context} has a mismatched {field}")));
    }
    Ok(())
}

fn parse_tier(value: &Value, context: &str) -> Result<TierFacts, ConformanceClosureError> {
    let name = required_str(value, "name", context)?;
    let rank = required_positive_u64(value, "rank", context)?;
    let (tier, expected_rank) = match name {
        "repository_local" => (EvidenceTier::RepositoryLocal, 1),
        "operator_environment" => (EvidenceTier::OperatorEnvironment, 2),
        "externally_attested" => (EvidenceTier::ExternallyAttested, 3),
        _ => {
            return Err(invalid(format!(
                "{context} has unknown evidence tier {name}"
            )));
        }
    };
    if rank != expected_rank {
        return Err(invalid(format!(
            "{context} has inconsistent evidence tier {name}/{rank}"
        )));
    }
    Ok(TierFacts { tier, rank })
}

fn parse_timestamp(
    value: &Value,
    field: &str,
    context: &str,
) -> Result<DateTime<Utc>, ConformanceClosureError> {
    let raw = required_str(value, field, context)?;
    DateTime::parse_from_rfc3339(raw)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|error| invalid(format!("{context} has invalid {field}: {error}")))
}

fn optional_timestamp(
    value: &Value,
    field: &str,
    context: &str,
) -> Result<Option<DateTime<Utc>>, ConformanceClosureError> {
    match value.get(field) {
        Some(Value::Null) => Ok(None),
        Some(_) => parse_timestamp(value, field, context).map(Some),
        None => Err(invalid(format!("{context} omits {field}"))),
    }
}

fn validate_bundle_timestamps(value: &Value, context: &str) -> Result<(), ConformanceClosureError> {
    let produced = parse_timestamp(value, "produced_at", context)?;
    let verified = optional_timestamp(value, "verified_at", context)?;
    let accepted = optional_timestamp(value, "accepted_at", context)?;
    let expires = parse_timestamp(value, "expires_at", context)?;
    if verified.is_some_and(|timestamp| produced > timestamp)
        || verified
            .zip(accepted)
            .is_some_and(|(left, right)| left > right)
        || accepted.is_some_and(|timestamp| timestamp >= expires)
    {
        return Err(invalid(format!(
            "{context} has inconsistent evidence timestamps"
        )));
    }
    Ok(())
}

fn validate_receipt_timestamps(
    value: &Value,
    context: &str,
) -> Result<(), ConformanceClosureError> {
    let created = parse_timestamp(value, "created_at", context)?;
    let expires = parse_timestamp(value, "expires_at", context)?;
    if created >= expires {
        return Err(invalid(format!(
            "{context} must be created before it expires"
        )));
    }
    Ok(())
}

fn validate_ledger<'a>(
    ledger: ControlTraceArtifact<'a>,
) -> Result<(LedgerFacts<'a>, BTreeMap<String, TraceFacts<'a>>), ConformanceClosureError> {
    validate_digest(ledger.raw_digest, "ControlTrace raw digest")?;
    let value = ledger.value;
    if value.get("$schema").and_then(Value::as_str) != Some(CONTROL_TRACE_SCHEMA) {
        return Err(invalid("ControlTrace declares the wrong schema"));
    }
    let facts = LedgerFacts {
        document_id: required_str(value, "document_id", "ControlTrace")?,
        document_version: required_positive_u64(value, "document_version", "ControlTrace")?,
        ledger_id: required_str(value, "ledger_id", "ControlTrace")?,
        ledger_version: required_str(value, "ledger_version", "ControlTrace")?,
    };
    if facts.document_id != CONTROL_TRACE_DOCUMENT_ID
        || facts.ledger_id != CONTROL_TRACE_LEDGER_ID
        || value.get("acceptance_status").and_then(Value::as_str) != Some("production_accepted")
        || value.get("production_accepted").and_then(Value::as_bool) != Some(true)
    {
        return Err(invalid(
            "ControlTrace is not the exact production-accepted Ryuki ledger",
        ));
    }
    let controls = required_array(value, "controls", "ControlTrace")?;
    let cases = required_array(value, "acceptance_cases", "ControlTrace")?;
    let trace_values = required_array(value, "traces", "ControlTrace")?;
    if controls.is_empty()
        || cases.is_empty()
        || trace_values.is_empty()
        || controls.len() > MAX_LEDGER_ROWS
        || cases.len() > MAX_LEDGER_ROWS
        || trace_values.len() > MAX_LEDGER_ROWS
    {
        return Err(invalid(format!(
            "ControlTrace collections must contain 1..={MAX_LEDGER_ROWS} rows"
        )));
    }

    let mut control_owners = BTreeMap::new();
    for control in controls {
        let id = required_str(control, "control_id", "ControlTrace control")?;
        let package = required_package(control, "owning_work_package", id)?;
        let team = required_str(control, "owning_team", id)?;
        if control.get("waivable").and_then(Value::as_bool).is_none() {
            return Err(invalid(format!(
                "control {id} omits an explicit waivable decision"
            )));
        }
        if control_owners
            .insert(id.to_owned(), (package.to_owned(), team.to_owned()))
            .is_some()
        {
            return Err(invalid(format!("duplicate control_id {id}")));
        }
    }
    let canonical_controls = control_owners
        .keys()
        .cloned()
        .map(Value::String)
        .collect::<Vec<_>>();
    let control_digest = digest_bytes(
        &canonical_json_bytes(&Value::Array(canonical_controls)).map_err(|error| {
            invalid(format!(
                "cannot canonicalize ControlTrace control set: {error}"
            ))
        })?,
    );
    if control_digest != CANONICAL_CONTROL_SET_DIGEST {
        return Err(invalid(
            "ControlTrace canonical control inventory is not exact",
        ));
    }

    let mut case_owners = BTreeMap::new();
    for case in cases {
        let id = required_str(case, "acceptance_case_id", "ControlTrace acceptance case")?;
        let package = required_package(case, "owning_work_package", id)?;
        let team = required_str(case, "owning_team", id)?;
        if case_owners
            .insert(id.to_owned(), (package.to_owned(), team.to_owned()))
            .is_some()
        {
            return Err(invalid(format!("duplicate acceptance_case_id {id}")));
        }
    }
    let canonical_cases = case_owners
        .keys()
        .cloned()
        .map(Value::String)
        .collect::<Vec<_>>();
    let case_digest = digest_bytes(
        &canonical_json_bytes(&Value::Array(canonical_cases)).map_err(|error| {
            invalid(format!(
                "cannot canonicalize ControlTrace case set: {error}"
            ))
        })?,
    );
    if case_digest != CANONICAL_CASE_SET_DIGEST {
        return Err(invalid(
            "ControlTrace canonical acceptance-case inventory is not exact",
        ));
    }

    let mut traces = BTreeMap::new();
    let mut mapping_tuples = BTreeSet::new();
    let mut traced_controls = BTreeSet::new();
    let mut traced_cases = BTreeSet::new();
    let mut active_controls = BTreeSet::new();
    let mut active_cases = BTreeSet::new();
    let mut active_packages = BTreeSet::new();
    let mut supersession_graph = BTreeMap::new();
    let mut superseded_trace_ids = BTreeSet::new();
    for trace in trace_values {
        let trace_id = required_str(trace, "trace_id", "ControlTrace trace")?;
        let control_id = required_str(trace, "control_id", trace_id)?;
        let case_id = required_str(trace, "acceptance_case_id", trace_id)?;
        let package_id = required_package(trace, "owning_work_package", trace_id)?;
        let team = required_str(trace, "owning_team", trace_id)?;
        let control_owner = control_owners.get(control_id).ok_or_else(|| {
            invalid(format!(
                "trace {trace_id} references unknown control {control_id}"
            ))
        })?;
        let case_owner = case_owners.get(case_id).ok_or_else(|| {
            invalid(format!(
                "trace {trace_id} references unknown acceptance case {case_id}"
            ))
        })?;
        if control_owner.0 != package_id
            || control_owner.1 != team
            || case_owner.0 != package_id
            || case_owner.1 != team
        {
            return Err(invalid(format!(
                "trace {trace_id} owner does not match its control and acceptance case"
            )));
        }
        validate_dimension_declarations(trace, trace_id)?;
        let fixture = required_str(trace, "fixture_or_probe_id", trace_id)?;
        let applicability = trace
            .get("applicability_expression")
            .ok_or_else(|| invalid(format!("trace {trace_id} omits applicability_expression")))?;
        let canonical = canonical_json_bytes(applicability).map_err(|error| {
            invalid(format!(
                "cannot canonicalize trace {trace_id} applicability: {error}"
            ))
        })?;
        let tuple = format!(
            "{control_id}\u{1f}{case_id}\u{1f}{}\u{1f}{fixture}",
            digest_bytes(&canonical)
        );
        if !mapping_tuples.insert(tuple) {
            return Err(invalid(format!(
                "duplicate static trace mapping for {control_id}/{case_id}/{fixture}"
            )));
        }
        traced_controls.insert(control_id.to_owned());
        traced_cases.insert(case_id.to_owned());
        let lifecycle = required_str(trace, "trace_lifecycle", trace_id)?;
        if lifecycle == "active" {
            active_controls.insert(control_id.to_owned());
            active_cases.insert(case_id.to_owned());
            active_packages.insert(package_id.to_owned());
        }
        let targets = match trace.get("supersedes_trace_id") {
            Some(Value::Null) | None => BTreeSet::new(),
            Some(Value::String(target)) if !target.is_empty() && target != trace_id => {
                BTreeSet::from([target.clone()])
            }
            _ => {
                return Err(invalid(format!(
                    "trace {trace_id} has invalid supersession"
                )));
            }
        };
        if let Some(target) = targets.iter().next()
            && !superseded_trace_ids.insert(target.clone())
        {
            return Err(invalid(format!("trace supersession forks at {target}")));
        }
        supersession_graph.insert(trace_id.to_owned(), targets);
        if traces
            .insert(
                trace_id.to_owned(),
                TraceFacts {
                    value: trace,
                    control_id,
                    acceptance_case_id: case_id,
                    package_id,
                },
            )
            .is_some()
        {
            return Err(invalid(format!("duplicate trace_id {trace_id}")));
        }
    }
    for (source, targets) in &supersession_graph {
        for target in targets {
            let source_trace = traces.get(source).expect("source row was indexed");
            let target_trace = traces.get(target).ok_or_else(|| {
                invalid(format!("trace {source} supersedes unknown trace {target}"))
            })?;
            if source_trace.control_id != target_trace.control_id
                || source_trace.acceptance_case_id != target_trace.acceptance_case_id
                || source_trace.package_id != target_trace.package_id
                || source_trace.value.get("owning_team") != target_trace.value.get("owning_team")
            {
                return Err(invalid(format!(
                    "trace {source} supersedes a different control/case/owner lineage"
                )));
            }
        }
    }
    for (trace_id, trace) in &traces {
        let lifecycle = required_str(trace.value, "trace_lifecycle", trace_id)?;
        match (lifecycle, superseded_trace_ids.contains(trace_id)) {
            ("active", false) | ("superseded" | "retired", true) => {}
            ("active", true) => {
                return Err(invalid(format!(
                    "active trace {trace_id} is already superseded"
                )));
            }
            ("superseded" | "retired", false) => {
                return Err(invalid(format!(
                    "non-active trace {trace_id} has no authenticated successor row"
                )));
            }
            _ => return Err(invalid(format!("trace {trace_id} has invalid lifecycle"))),
        }
    }
    reject_cycles("trace supersession", &supersession_graph)?;
    let expected_controls = control_owners.keys().cloned().collect::<BTreeSet<_>>();
    let expected_cases = case_owners.keys().cloned().collect::<BTreeSet<_>>();
    if traced_controls != expected_controls
        || active_controls != expected_controls
        || traced_cases != expected_cases
        || active_cases != expected_cases
    {
        return Err(invalid(
            "every control and acceptance case must have both a trace and an active trace",
        ));
    }
    let expected_packages = PACKAGES
        .iter()
        .map(|package| (*package).to_owned())
        .collect::<BTreeSet<_>>();
    if active_packages != expected_packages {
        return Err(invalid(format!(
            "active ControlTrace package set is not exact: {active_packages:?}"
        )));
    }
    Ok((facts, traces))
}

fn validate_dimension_declarations(
    trace: &Value,
    context: &str,
) -> Result<(), ConformanceClosureError> {
    let declarations = trace.get("evidence_instance_dimensions").ok_or_else(|| {
        invalid(format!(
            "trace {context} omits evidence_instance_dimensions"
        ))
    })?;
    for scope in ["implementation", "deployment"] {
        let values = required_array(declarations, scope, context)?;
        let mut names = BTreeSet::new();
        for value in values {
            let name = value
                .as_str()
                .filter(|name| name.starts_with(&format!("{scope}.")))
                .ok_or_else(|| {
                    invalid(format!(
                        "trace {context} has an invalid {scope} dimension declaration"
                    ))
                })?;
            if !names.insert(name) {
                return Err(invalid(format!("trace {context} repeats dimension {name}")));
            }
        }
    }
    Ok(())
}

fn validate_exact_proofs(
    bundles: &BTreeMap<&str, DocumentFacts<'_>>,
    receipts: &BTreeMap<&str, DocumentFacts<'_>>,
    loaded_digests: &BTreeSet<String>,
    proofs: &BTreeMap<String, ProofFacts>,
    context: ConformanceClosureContext<'_>,
    trusted_now: ConformanceTrustedTimeWindow,
) -> Result<(), ConformanceClosureError> {
    let proof_digests = proofs.keys().cloned().collect::<BTreeSet<_>>();
    if &proof_digests != loaded_digests {
        return Err(invalid(format!(
            "opaque proof digest set is not exact: loaded={loaded_digests:?}, proofs={proof_digests:?}"
        )));
    }
    let mut authority: Option<(&str, u64, u64, u64, &str, &str)> = None;
    let mut registry_digests = BTreeMap::new();
    let mut acceptance_ids = BTreeSet::new();
    let mut acceptance_sequences = BTreeSet::new();

    for (digest, proof) in proofs {
        let (document, expected_kind) = if let Some(document) = bundles.get(digest.as_str()) {
            (*document, ConformanceDocumentKind::ConformanceBundle)
        } else if let Some(document) = receipts.get(digest.as_str()) {
            (*document, ConformanceDocumentKind::PackageExitReceipt)
        } else {
            return Err(invalid(format!("proof {digest} has no loaded document")));
        };
        if proof.complete_document_digest != *digest
            || proof.kind != expected_kind
            || proof.document_id != document.id
            || proof.document_version != document.version
            || proof.package_id != document.package_id
            || proof.evidence_tier != document.tier.tier
            || proof.deployment_id != context.deployment_id
            || proof.trust_domain_id != context.trust_domain_id
        {
            return Err(invalid(format!(
                "opaque proof does not exactly bind loaded document {}",
                document.id
            )));
        }
        if proof.accepted_at_not_before > proof.accepted_at_not_after
            || proof.accepted_at_not_after > trusted_now.not_before
            || proof.acceptance_sequence == 0
            || proof.acceptance_sequence > proof.checkpoint_sequence
            || proof.authority_epoch == 0
            || proof.authority_revision == 0
            || proof.checkpoint_sequence == 0
            || proof.registry_version == 0
        {
            return Err(invalid(format!(
                "opaque proof for {} is stale or internally inconsistent",
                document.id
            )));
        }
        if !acceptance_ids.insert(proof.acceptance_record_id.as_str())
            || !acceptance_sequences.insert(proof.acceptance_sequence)
        {
            return Err(invalid("duplicate acceptance record identity in proof set"));
        }
        match authority {
            None => {
                authority = Some((
                    proof.authority_id.as_str(),
                    proof.authority_epoch,
                    proof.authority_revision,
                    proof.checkpoint_sequence,
                    proof.registry_id.as_str(),
                    proof.snapshot_binding_digest.as_str(),
                ));
            }
            Some((authority_id, epoch, revision, sequence, registry_id, snapshot))
                if authority_id == proof.authority_id
                    && epoch == proof.authority_epoch
                    && revision == proof.authority_revision
                    && sequence == proof.checkpoint_sequence
                    && registry_id == proof.registry_id
                    && snapshot == proof.snapshot_binding_digest => {}
            Some(_) => {
                return Err(invalid(
                    "opaque proof set crosses checkpoint snapshot boundaries",
                ));
            }
        }
        match registry_digests.insert(proof.registry_version, proof.registry_digest.as_str()) {
            Some(previous) if previous != proof.registry_digest => {
                return Err(invalid(
                    "opaque proof set gives one registry version multiple digests",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_bundle_supersession<'a>(
    evidence: &BTreeMap<&'a str, DocumentFacts<'a>>,
    proofs: &BTreeMap<String, ProofFacts>,
    context: ConformanceClosureContext<'_>,
    trusted_now: ConformanceTrustedTimeWindow,
) -> Result<SupersessionFacts, ConformanceClosureError> {
    let mut graph = BTreeMap::new();
    let mut superseded = BTreeSet::new();
    for (source_id, source) in evidence {
        let value = source.input.value;
        if !claims_production_acceptance(value)
            || value.get("normalized_result").and_then(Value::as_str) != Some("pass")
            || value.get("evidence_lifecycle").and_then(Value::as_str) != Some("accepted")
        {
            return Err(invalid(format!(
                "included evidence {source_id} is a production downgrade"
            )));
        }
        validate_bundle_context(*source, context)?;
        let produced = parse_timestamp(value, "produced_at", source.id)?;
        let accepted = optional_timestamp(value, "accepted_at", source.id)?
            .ok_or_else(|| invalid(format!("included evidence {source_id} has no accepted_at")))?;
        if produced > trusted_now.not_before || accepted > trusted_now.not_before {
            return Err(invalid(format!(
                "included evidence {source_id} is future-dated"
            )));
        }
        validate_production_observation(value, source.id, context, accepted, trusted_now)?;
        let id = value.get("supersedes_evidence_instance_id");
        let reference = value.get("supersedes_evidence_ref");
        let targets = match (id, reference) {
            (Some(Value::Null), Some(Value::Null)) => BTreeSet::new(),
            (Some(Value::String(target_id)), Some(reference))
                if !target_id.is_empty()
                    && target_id.as_str() != *source_id
                    && reference.is_object() =>
            {
                let target = evidence.get(target_id.as_str()).ok_or_else(|| {
                    invalid(format!(
                        "evidence {source_id} supersedes unknown evidence {target_id}"
                    ))
                })?;
                for field in ["trace_id", "applicability_instance_id"] {
                    require_equal_field(source.input.value, target.input.value, field, source_id)?;
                }
                if source.version <= target.version {
                    return Err(invalid(format!(
                        "superseding evidence {source_id} must have a higher document version"
                    )));
                }
                if source.tier.rank < target.tier.rank {
                    return Err(invalid(format!(
                        "superseding evidence {source_id} downgrades evidence tier"
                    )));
                }
                validate_causal_successor(source, *target, proofs, "evidence supersession")?;
                validate_superseded_evidence_reference(reference, target_id, *target)?;
                if !superseded.insert(target_id.clone()) {
                    return Err(invalid(format!(
                        "evidence supersession forks at {target_id}"
                    )));
                }
                BTreeSet::from([target_id.clone()])
            }
            _ => {
                return Err(invalid(format!(
                    "evidence {source_id} has invalid supersession"
                )));
            }
        };
        graph.insert((*source_id).to_owned(), targets);
    }
    reject_cycles("evidence supersession", &graph)?;
    Ok(SupersessionFacts { graph, superseded })
}

fn validate_receipt_supersession<'a>(
    receipts: &BTreeMap<&'a str, DocumentFacts<'a>>,
    proofs: &BTreeMap<String, ProofFacts>,
    trusted_now: ConformanceTrustedTimeWindow,
) -> Result<SupersessionFacts, ConformanceClosureError> {
    let mut graph = BTreeMap::new();
    let mut superseded = BTreeSet::new();
    for (source_id, source) in receipts {
        let value = source.input.value;
        if !claims_production_acceptance(value)
            || value.get("result").and_then(Value::as_str) != Some("pass")
            || value.get("receipt_lifecycle").and_then(Value::as_str) != Some("accepted")
            || parse_timestamp(value, "created_at", source.id)? > trusted_now.not_before
        {
            return Err(invalid(format!(
                "included receipt {source_id} is future-dated or downgraded"
            )));
        }
        let id = value.get("supersedes_receipt_id");
        let reference = value.get("supersedes_receipt_ref");
        let targets = match (id, reference) {
            (Some(Value::Null), Some(Value::Null)) => BTreeSet::new(),
            (Some(Value::String(target_id)), Some(reference))
                if !target_id.is_empty()
                    && target_id.as_str() != *source_id
                    && reference.is_object() =>
            {
                let target = receipts.get(target_id.as_str()).ok_or_else(|| {
                    invalid(format!(
                        "receipt {source_id} supersedes unknown receipt {target_id}"
                    ))
                })?;
                if source.package_id != target.package_id
                    || source.version <= target.version
                    || source.tier.rank < target.tier.rank
                {
                    return Err(invalid(format!(
                        "receipt {source_id} has an invalid supersession lineage"
                    )));
                }
                validate_causal_successor(source, *target, proofs, "receipt supersession")?;
                validate_superseded_receipt_reference(reference, target_id, *target)?;
                if !superseded.insert(target_id.clone()) {
                    return Err(invalid(format!(
                        "receipt supersession forks at {target_id}"
                    )));
                }
                BTreeSet::from([target_id.clone()])
            }
            _ => {
                return Err(invalid(format!(
                    "receipt {source_id} has invalid supersession"
                )));
            }
        };
        graph.insert((*source_id).to_owned(), targets);
    }
    reject_cycles("receipt supersession", &graph)?;
    Ok(SupersessionFacts { graph, superseded })
}

fn select_current_receipts<'a>(
    receipts: &BTreeMap<&'a str, DocumentFacts<'a>>,
    supersession: &SupersessionFacts,
    trusted_now: ConformanceTrustedTimeWindow,
) -> Result<BTreeMap<String, DocumentFacts<'a>>, ConformanceClosureError> {
    let mut selected = BTreeMap::new();
    for receipt in receipts.values() {
        let value = receipt.input.value;
        if supersession.superseded.contains(receipt.id) {
            continue;
        }
        let created = parse_timestamp(value, "created_at", receipt.id)?;
        let expires = parse_timestamp(value, "expires_at", receipt.id)?;
        if created > trusted_now.not_before || expires <= trusted_now.not_after {
            return Err(invalid(format!(
                "included receipt {} is future-dated or expired",
                receipt.id
            )));
        }
        if selected
            .insert(receipt.package_id.to_owned(), *receipt)
            .is_some()
        {
            return Err(invalid(format!(
                "package {} has multiple current receipts",
                receipt.package_id
            )));
        }
    }
    let expected = PACKAGES
        .iter()
        .map(|package| (*package).to_owned())
        .collect::<BTreeSet<_>>();
    let actual = selected.keys().cloned().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(invalid(format!(
            "current receipt package set is not exact: expected={expected:?}, actual={actual:?}"
        )));
    }
    let current_ids = selected
        .values()
        .map(|receipt| receipt.id.to_owned())
        .collect::<BTreeSet<_>>();
    let loaded_ids = receipts
        .keys()
        .map(|receipt| (*receipt).to_owned())
        .collect::<BTreeSet<_>>();
    validate_complete_history(
        "receipt supersession",
        &current_ids,
        &loaded_ids,
        &supersession.graph,
    )?;
    Ok(selected)
}

fn claims_production_acceptance(value: &Value) -> bool {
    value.get("acceptance_status").and_then(Value::as_str) == Some("production_accepted")
        && value.get("production_accepted").and_then(Value::as_bool) == Some(true)
}

fn validate_superseded_evidence_reference(
    reference: &Value,
    target_id: &str,
    target: DocumentFacts<'_>,
) -> Result<(), ConformanceClosureError> {
    if reference.get("artifact_kind").and_then(Value::as_str) != Some("conformance-bundle")
        || reference.get("bundle_id").and_then(Value::as_str) != Some(target.id)
        || reference.get("document_version").and_then(Value::as_u64) != Some(target.version)
        || reference.get("artifact_locator").and_then(Value::as_str)
            != Some(target.input.artifact_locator)
        || reference
            .get("evidence_instance_id")
            .and_then(Value::as_str)
            != Some(target_id)
        || reference.get("bundle_digest").and_then(Value::as_str) != Some(target.input.raw_digest)
    {
        return Err(invalid(format!(
            "evidence supersession reference does not exactly bind {target_id}"
        )));
    }
    Ok(())
}

fn validate_superseded_receipt_reference(
    reference: &Value,
    target_id: &str,
    target: DocumentFacts<'_>,
) -> Result<(), ConformanceClosureError> {
    if reference.get("artifact_kind").and_then(Value::as_str) != Some("package-exit-receipt")
        || reference.get("receipt_id").and_then(Value::as_str) != Some(target.id)
        || reference.get("document_version").and_then(Value::as_u64) != Some(target.version)
        || reference.get("artifact_locator").and_then(Value::as_str)
            != Some(target.input.artifact_locator)
        || reference.get("package_id").and_then(Value::as_str) != Some(target.package_id)
        || reference.get("receipt_digest").and_then(Value::as_str) != Some(target.input.raw_digest)
        || target.id != target_id
    {
        return Err(invalid(format!(
            "receipt supersession reference does not exactly bind {target_id}"
        )));
    }
    Ok(())
}

fn validate_causal_successor(
    source: &DocumentFacts<'_>,
    target: DocumentFacts<'_>,
    proofs: &BTreeMap<String, ProofFacts>,
    label: &str,
) -> Result<(), ConformanceClosureError> {
    let source_proof = proofs
        .get(source.input.raw_digest)
        .ok_or_else(|| invalid(format!("{label} source has no authenticated proof")))?;
    let target_proof = proofs
        .get(target.input.raw_digest)
        .ok_or_else(|| invalid(format!("{label} target has no authenticated proof")))?;
    if source_proof.acceptance_sequence <= target_proof.acceptance_sequence {
        return Err(invalid(format!(
            "{label} successor was not externally accepted after its predecessor"
        )));
    }
    Ok(())
}

fn validate_complete_history(
    label: &str,
    current: &BTreeSet<String>,
    loaded: &BTreeSet<String>,
    graph: &BTreeMap<String, BTreeSet<String>>,
) -> Result<(), ConformanceClosureError> {
    let graph_nodes = graph.keys().cloned().collect::<BTreeSet<_>>();
    if &graph_nodes != loaded || !current.is_subset(loaded) {
        return Err(invalid(format!(
            "{label} graph does not match loaded documents"
        )));
    }
    let mut reachable = BTreeSet::new();
    for root in current {
        let mut cursor = root.as_str();
        for depth in 0..=MAX_SUPERSESSION_DEPTH {
            if !reachable.insert(cursor.to_owned()) {
                break;
            }
            let targets = graph
                .get(cursor)
                .ok_or_else(|| invalid(format!("{label} omits node {cursor}")))?;
            let Some(target) = targets.iter().next() else {
                break;
            };
            if depth == MAX_SUPERSESSION_DEPTH {
                return Err(invalid(format!(
                    "{label} chain exceeds depth {MAX_SUPERSESSION_DEPTH}"
                )));
            }
            cursor = target;
        }
    }
    if &reachable != loaded {
        return Err(invalid(format!(
            "{label} contains orphan or unrelated history: loaded={loaded:?}, reachable={reachable:?}"
        )));
    }
    Ok(())
}

fn validate_root_receipt_reference(
    reference: &VersionedContentReference,
    receipts: &BTreeMap<String, DocumentFacts<'_>>,
) -> Result<(), ConformanceClosureError> {
    let root = receipts
        .get("SB-9")
        .expect("all ten current receipts were selected");
    if reference.artifact_kind != ArtifactKind::PackageExitReceipt
        || reference.document_id != root.id
        || reference.document_version != root.version
        || reference.content_digest != root.input.raw_digest
        || reference.artifact_locator != root.input.artifact_locator
        || root.package_id != "SB-9"
    {
        return Err(invalid(
            "deployment profile production acceptance reference does not exactly bind current SB-9 receipt",
        ));
    }
    Ok(())
}

fn validate_runtime_guard_requirements(
    profile_document: &Value,
    receipts: &BTreeMap<String, DocumentFacts<'_>>,
    traces: &BTreeMap<String, TraceFacts<'_>>,
    proofs: &BTreeMap<String, ProofFacts>,
    root_proof: &ProofFacts,
) -> Result<Vec<VerifiedRuntimeGuardRequirement>, ConformanceClosureError> {
    let profile: DeploymentSecurityProfile = serde_json::from_value(profile_document.clone())
        .map_err(|error| invalid(format!("invalid deployment security profile: {error}")))?;
    if profile.runtime_guard_evidence.mode != RuntimeGuardMode::ReceiptBound
        || !profile.runtime_guard_evidence.runtime_cross_check_required
        || profile.runtime_guard_evidence.guards.len() != 8
    {
        return Err(invalid(
            "production profile does not contain eight receipt-bound runtime guards",
        ));
    }
    if let Some(overlay) = &profile.migration_overlay {
        let receipt = receipts
            .get("SB-9")
            .ok_or_else(|| invalid("migration overlay has no current SB-9 retirement receipt"))?;
        let reference = &overlay.zero_consumer_receipt_ref;
        if reference.artifact_kind != ArtifactKind::PackageExitReceipt
            || reference.document_id != receipt.id
            || reference.document_version != receipt.version
            || reference.content_digest != receipt.input.raw_digest
            || reference.artifact_locator != receipt.input.artifact_locator
            || !receipt
                .input
                .value
                .get("retirement_closure")
                .is_some_and(Value::is_object)
        {
            return Err(invalid(
                "migration overlay does not bind the exact current SB-9 retirement closure",
            ));
        }
    }
    let mut seen_guards = BTreeSet::new();
    let mut seen_controls = BTreeSet::new();
    let mut requirements = Vec::with_capacity(8);
    for guard in profile.runtime_guard_evidence.guards {
        let guard_key = guard_key(guard.guard_id);
        if !seen_guards.insert(guard_key) {
            return Err(invalid(format!("duplicate runtime guard {guard_key}")));
        }
        let declared_control_count = guard.control_ids.len();
        let control_ids = guard.control_ids.into_iter().collect::<BTreeSet<_>>();
        if control_ids.is_empty() || control_ids.len() != declared_control_count {
            return Err(invalid(format!(
                "runtime guard {guard_key} has missing or duplicate control IDs"
            )));
        }
        for control_id in &control_ids {
            if !seen_controls.insert(control_id.clone()) {
                return Err(invalid(format!(
                    "runtime guard control {control_id} is assigned more than once"
                )));
            }
        }
        if control_ids.iter().any(|control_id| {
            !traces
                .values()
                .any(|trace| trace.control_id == control_id.as_str())
        }) {
            return Err(invalid(format!(
                "runtime guard {guard_key} references an unknown control"
            )));
        }
        let reference = guard.receipt_ref;
        let receipt = receipts
            .values()
            .find(|receipt| {
                reference.artifact_kind == ArtifactKind::PackageExitReceipt
                    && reference.document_id == receipt.id
                    && reference.document_version == receipt.version
                    && reference.content_digest == receipt.input.raw_digest
                    && reference.artifact_locator == receipt.input.artifact_locator
            })
            .ok_or_else(|| {
                invalid(format!(
                    "runtime guard {guard_key} does not exactly bind a current authenticated receipt"
                ))
            })?;
        let receipt_controls =
            exact_string_set(
                receipt.input.value.get("evaluated_sets").ok_or_else(|| {
                    invalid(format!("receipt {} omits evaluated_sets", receipt.id))
                })?,
                "control_ids",
                receipt.id,
            )?;
        if !control_ids.is_subset(&receipt_controls) {
            return Err(invalid(format!(
                "runtime guard {guard_key} is not covered by its referenced receipt"
            )));
        }
        let receipt_proof = proofs
            .get(receipt.input.raw_digest)
            .ok_or_else(|| invalid(format!("runtime guard receipt {} has no proof", receipt.id)))?;
        if receipt_proof.acceptance_sequence >= root_proof.acceptance_sequence {
            return Err(invalid(format!(
                "runtime guard receipt {} was not accepted before the SB-9 root",
                receipt.id
            )));
        }
        let requirement_digest = runtime_guard_requirement_digest(
            guard.guard_id,
            &control_ids,
            receipt.id,
            receipt.version,
            receipt.input.raw_digest,
            receipt.input.artifact_locator,
            &guard.expected_value,
        )?;
        requirements.push(VerifiedRuntimeGuardRequirement {
            guard_id: guard.guard_id,
            control_ids,
            receipt_id: receipt.id.to_owned(),
            receipt_version: receipt.version,
            receipt_digest: receipt.input.raw_digest.to_owned(),
            receipt_locator: receipt.input.artifact_locator.to_owned(),
            expected_value: guard.expected_value,
            requirement_digest,
            semantic_challenge_binding_digest: String::new(),
        });
    }
    let expected = [
        GuardId::DurablePostgresql,
        GuardId::ApprovedSecretProvider,
        GuardId::HttpsPublicUrls,
        GuardId::SecureCookies,
        GuardId::NonDevelopmentAuthenticator,
        GuardId::ExternalSigningKeyMaterial,
        GuardId::MockDependenciesDisabled,
        GuardId::FirstOwnerPathClosed,
    ]
    .into_iter()
    .map(guard_key)
    .collect::<BTreeSet<_>>();
    if seen_guards != expected {
        return Err(invalid("runtime guard identity set is not exact"));
    }
    requirements.sort_by_key(|requirement| guard_rank(requirement.guard_id));
    Ok(requirements)
}

fn guard_key(guard: GuardId) -> &'static str {
    match guard {
        GuardId::DurablePostgresql => "durable-postgresql",
        GuardId::ApprovedSecretProvider => "approved-secret-provider",
        GuardId::HttpsPublicUrls => "https-public-urls",
        GuardId::SecureCookies => "secure-cookies",
        GuardId::NonDevelopmentAuthenticator => "non-development-authenticator",
        GuardId::ExternalSigningKeyMaterial => "external-signing-key-material",
        GuardId::MockDependenciesDisabled => "mock-dependencies-disabled",
        GuardId::FirstOwnerPathClosed => "first-owner-path-closed",
    }
}

fn guard_rank(guard: GuardId) -> usize {
    match guard {
        GuardId::DurablePostgresql => 0,
        GuardId::ApprovedSecretProvider => 1,
        GuardId::HttpsPublicUrls => 2,
        GuardId::SecureCookies => 3,
        GuardId::NonDevelopmentAuthenticator => 4,
        GuardId::ExternalSigningKeyMaterial => 5,
        GuardId::MockDependenciesDisabled => 6,
        GuardId::FirstOwnerPathClosed => 7,
    }
}

fn runtime_guard_projection(requirements: &[VerifiedRuntimeGuardRequirement]) -> Value {
    Value::Array(
        requirements
            .iter()
            .map(|requirement| {
                json!({
                    "guard_id": guard_key(requirement.guard_id),
                    "control_ids": &requirement.control_ids,
                    "receipt_id": requirement.receipt_id.as_str(),
                    "receipt_version": requirement.receipt_version,
                    "receipt_digest": requirement.receipt_digest.as_str(),
                    "receipt_locator": requirement.receipt_locator.as_str(),
                    "expected_value": &requirement.expected_value,
                    "requirement_digest": requirement.requirement_digest.as_str(),
                })
            })
            .collect(),
    )
}

#[allow(clippy::too_many_arguments)]
fn runtime_guard_requirement_digest(
    guard_id: GuardId,
    control_ids: &BTreeSet<String>,
    receipt_id: &str,
    receipt_version: u64,
    receipt_digest: &str,
    receipt_locator: &str,
    expected_value: &RuntimeGuardExpectedValue,
) -> Result<String, ConformanceClosureError> {
    let projection = json!({
        "digest_contract": RUNTIME_GUARD_REQUIREMENT_BINDING_DIGEST_CONTRACT,
        "guard_id": guard_key(guard_id),
        "control_ids": control_ids,
        "receipt": {
            "artifact_kind": "package-exit-receipt",
            "document_id": receipt_id,
            "document_version": receipt_version,
            "content_digest": receipt_digest,
            "artifact_locator": receipt_locator,
        },
        "expected_value": expected_value,
    });
    canonical_projection_digest(&projection, "runtime guard requirement")
}

fn runtime_guard_semantic_challenge_binding_digest(
    closure_digest: &str,
    context_digest: &str,
    deployment_profile_raw_digest: &str,
    context: ConformanceClosureContext<'_>,
    authority: &ProofFacts,
    requirement: &VerifiedRuntimeGuardRequirement,
) -> Result<String, ConformanceClosureError> {
    let root = context.production_acceptance_receipt_ref;
    let projection = json!({
        "digest_contract": RUNTIME_GUARD_SEMANTIC_CHALLENGE_BINDING_DIGEST_CONTRACT,
        "closure_digest": closure_digest,
        "context_digest": context_digest,
        "deployment_profile_raw_digest": deployment_profile_raw_digest,
        "deployment_id": context.deployment_id,
        "trust_domain_id": context.trust_domain_id,
        "source_revision": context.source_revision,
        "artifact_digest": context.artifact_digest,
        "authority": {
            "authority_id": authority.authority_id,
            "authority_epoch": authority.authority_epoch,
            "authority_revision": authority.authority_revision,
            "checkpoint_sequence": authority.checkpoint_sequence,
            "snapshot_binding_digest": authority.snapshot_binding_digest,
        },
        "root_receipt": {
            "artifact_kind": "package-exit-receipt",
            "document_id": root.document_id,
            "document_version": root.document_version,
            "content_digest": root.content_digest,
            "artifact_locator": root.artifact_locator,
        },
        "requirement_digest": requirement.requirement_digest,
    });
    canonical_projection_digest(&projection, "runtime guard challenge")
}

fn canonical_projection_digest(
    projection: &Value,
    label: &str,
) -> Result<String, ConformanceClosureError> {
    canonical_json_bytes(projection)
        .map(|bytes| digest_bytes(&bytes))
        .map_err(|error| invalid(format!("cannot canonicalize {label} projection: {error}")))
}

#[allow(clippy::too_many_arguments)]
fn validate_current_receipt<'a>(
    package_id: &str,
    receipt: DocumentFacts<'a>,
    ledger: ControlTraceArtifact<'_>,
    ledger_facts: LedgerFacts<'_>,
    traces: &BTreeMap<String, TraceFacts<'_>>,
    evidence: &BTreeMap<&'a str, DocumentFacts<'a>>,
    superseded_evidence: &BTreeSet<String>,
    current_receipts: &BTreeMap<String, DocumentFacts<'a>>,
    used_evidence_ids: &mut BTreeSet<String>,
    context: ConformanceClosureContext<'_>,
    applicability: &DerivedProductionApplicability,
    proofs_by_digest: &BTreeMap<String, ProofFacts>,
    trusted_now: ConformanceTrustedTimeWindow,
) -> Result<BTreeSet<String>, ConformanceClosureError> {
    let value = receipt.input.value;
    validate_ledger_binding(value, receipt.id, ledger, ledger_facts)?;
    validate_closure_context(value, receipt.id, context)?;
    if !required_array(value, "waivers", receipt.id)?.is_empty() {
        return Err(invalid(format!(
            "production receipt {} may not replace exact evidence with waivers",
            receipt.id
        )));
    }

    let evaluated = value
        .get("evaluated_sets")
        .ok_or_else(|| invalid(format!("receipt {} omits evaluated_sets", receipt.id)))?;
    let trace_ids = exact_string_set(evaluated, "trace_ids", receipt.id)?;
    let control_ids = exact_string_set(evaluated, "control_ids", receipt.id)?;
    let case_ids = exact_string_set(evaluated, "acceptance_case_ids", receipt.id)?;
    let expected_traces = traces
        .iter()
        .filter(|(_, trace)| {
            trace.package_id == package_id
                && trace.value.get("trace_lifecycle").and_then(Value::as_str) == Some("active")
        })
        .map(|(id, _)| id.clone())
        .collect::<BTreeSet<_>>();
    if trace_ids != expected_traces {
        return Err(invalid(format!(
            "receipt {} trace set is not the exact active {package_id} projection",
            receipt.id
        )));
    }
    let projected_controls = trace_ids
        .iter()
        .map(|id| {
            traces
                .get(id)
                .expect("trace set was resolved")
                .control_id
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    let projected_cases = trace_ids
        .iter()
        .map(|id| {
            traces
                .get(id)
                .expect("trace set was resolved")
                .acceptance_case_id
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    if control_ids != projected_controls || case_ids != projected_cases {
        return Err(invalid(format!(
            "receipt {} control or acceptance-case set is not an exact trace projection",
            receipt.id
        )));
    }

    let instances = parse_instances(value, receipt.id)?;
    let expected_instances = applicability
        .instances
        .iter()
        .filter(|instance| instance.owning_work_package == package_id)
        .map(|instance| (instance.applicability_instance_id.as_str(), instance))
        .collect::<BTreeMap<_, _>>();
    let actual_instance_ids = instances
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_instance_ids = expected_instances.keys().copied().collect::<BTreeSet<_>>();
    if actual_instance_ids != expected_instance_ids {
        return Err(invalid(format!(
            "receipt {} applicability set is not the exact independently derived {package_id} universe",
            receipt.id
        )));
    }
    for (instance_id, actual) in &instances {
        validate_receipt_instance_projection(
            actual,
            expected_instances
                .get(instance_id.as_str())
                .expect("exact instance id set was checked"),
            receipt.id,
        )?;
    }
    let receipt_proof = proofs_by_digest
        .get(receipt.input.raw_digest)
        .ok_or_else(|| invalid(format!("receipt {} has no authenticated proof", receipt.id)))?;
    if parse_timestamp(value, "created_at", receipt.id)? > receipt_proof.accepted_at_not_after {
        return Err(invalid(format!(
            "receipt {} claims creation after its external acceptance event",
            receipt.id
        )));
    }
    let receipt_expiry = parse_timestamp(value, "expires_at", receipt.id)?;
    let mut supporting_tiers = Vec::new();
    let mut bound_pairs = BTreeSet::new();
    let mut locally_bound_evidence = BTreeSet::new();
    for binding in required_array(evaluated, "evidence_bindings", receipt.id)? {
        let evidence_id = required_str(binding, "evidence_instance_id", receipt.id)?;
        if !locally_bound_evidence.insert(evidence_id.to_owned()) {
            return Err(invalid(format!(
                "receipt {} duplicates evidence binding {evidence_id}",
                receipt.id
            )));
        }
        let bundle = evidence.get(evidence_id).ok_or_else(|| {
            invalid(format!(
                "receipt {} references unknown evidence {evidence_id}",
                receipt.id
            ))
        })?;
        validate_evidence_reference(binding, evidence_id, *bundle)?;
        let trace_id = required_str(bundle.input.value, "trace_id", bundle.id)?;
        if !trace_ids.contains(trace_id) {
            return Err(invalid(format!(
                "receipt {} binds evidence outside its exact trace set",
                receipt.id
            )));
        }
        let trace = traces
            .get(trace_id)
            .expect("receipt trace set was resolved");
        validate_bundle_context(*bundle, context)?;
        validate_authoritative_bundle(
            *bundle,
            receipt,
            trace,
            superseded_evidence,
            context,
            trusted_now,
        )?;
        if parse_timestamp(bundle.input.value, "expires_at", bundle.id)? < receipt_expiry {
            return Err(invalid(format!(
                "bundle {} expires before receipt {}",
                bundle.id, receipt.id
            )));
        }
        supporting_tiers.push(bundle.tier.rank);
        let applicability_id =
            required_str(bundle.input.value, "applicability_instance_id", bundle.id)?;
        let expected_instance = expected_instances.get(applicability_id).ok_or_else(|| {
            invalid(format!(
                "bundle {} references an instance outside the independently derived {package_id} universe",
                bundle.id
            ))
        })?;
        let pair = validate_bound_bundle_instance(*bundle, trace, expected_instance)?;
        let bundle_proof = proofs_by_digest
            .get(bundle.input.raw_digest)
            .ok_or_else(|| invalid(format!("bundle {} has no authenticated proof", bundle.id)))?;
        let claimed_bundle_acceptance =
            optional_timestamp(bundle.input.value, "accepted_at", bundle.id)?
                .ok_or_else(|| invalid(format!("bundle {} has no accepted_at", bundle.id)))?;
        if bundle_proof.acceptance_sequence >= receipt_proof.acceptance_sequence
            || claimed_bundle_acceptance > bundle_proof.accepted_at_not_after
        {
            return Err(invalid(format!(
                "bundle {} was not externally accepted before receipt {}",
                bundle.id, receipt.id
            )));
        }
        if !bound_pairs.insert(pair.clone()) {
            return Err(invalid(format!(
                "receipt {} has duplicate coverage for trace {} instance {}",
                receipt.id, pair.0, pair.1
            )));
        }
        if !used_evidence_ids.insert(evidence_id.to_owned()) {
            return Err(invalid(format!(
                "evidence {evidence_id} is bound by more than one package receipt"
            )));
        }
    }
    let required_pairs = expected_instances
        .values()
        .map(|instance| {
            (
                instance.trace_id.clone(),
                instance.applicability_instance_id.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    if bound_pairs != required_pairs {
        return Err(invalid(format!(
            "receipt {} evidence coverage is not exact: required={required_pairs:?}, bound={bound_pairs:?}",
            receipt.id
        )));
    }
    let prerequisites =
        validate_prerequisites(receipt, current_receipts, proofs_by_digest, trusted_now)?;
    for prerequisite_id in &prerequisites {
        let prerequisite = current_receipts
            .values()
            .find(|candidate| candidate.id == prerequisite_id)
            .expect("validated prerequisite resolves to a current receipt");
        supporting_tiers.push(prerequisite.tier.rank);
    }
    let weakest = supporting_tiers.into_iter().min().ok_or_else(|| {
        invalid(format!(
            "receipt {} has no direct evidence support",
            receipt.id
        ))
    })?;
    if receipt.tier.rank != weakest
        || matches!(package_id, "SB-8" | "SB-9") && receipt.tier.rank < 2
    {
        return Err(invalid(format!(
            "receipt {} tier is not the exact weakest-link production tier",
            receipt.id
        )));
    }
    validate_receipt_digest_sets(receipt, current_receipts, context)?;
    validate_retirement_closure(
        receipt,
        package_id,
        &locally_bound_evidence,
        evidence,
        superseded_evidence,
    )?;
    Ok(prerequisites)
}

fn validate_ledger_binding(
    receipt: &Value,
    receipt_id: &str,
    ledger: ControlTraceArtifact<'_>,
    facts: LedgerFacts<'_>,
) -> Result<(), ConformanceClosureError> {
    let binding = receipt
        .get("ledger_binding")
        .ok_or_else(|| invalid(format!("receipt {receipt_id} omits ledger_binding")))?;
    let exact = binding.get("artifact_kind").and_then(Value::as_str) == Some("control-trace")
        && binding.get("artifact_locator").and_then(Value::as_str) == Some(ledger.artifact_locator)
        && binding.get("document_id").and_then(Value::as_str) == Some(facts.document_id)
        && binding.get("document_version").and_then(Value::as_u64) == Some(facts.document_version)
        && binding.get("ledger_id").and_then(Value::as_str) == Some(facts.ledger_id)
        && binding.get("ledger_version").and_then(Value::as_str) == Some(facts.ledger_version)
        && binding.get("ledger_digest").and_then(Value::as_str) == Some(ledger.raw_digest);
    if !exact {
        return Err(invalid(format!(
            "receipt {receipt_id} does not exactly bind the active ControlTrace ledger"
        )));
    }
    Ok(())
}

fn validate_closure_context(
    receipt: &Value,
    receipt_id: &str,
    context: ConformanceClosureContext<'_>,
) -> Result<(), ConformanceClosureError> {
    let closure = receipt
        .get("closure_context")
        .ok_or_else(|| invalid(format!("receipt {receipt_id} omits closure_context")))?;
    let expected = [
        ("deployment_profile", context.deployment_profile),
        ("policy_versions", context.policy_versions),
        ("configuration_versions", context.configuration_versions),
        ("provider_versions", context.provider_versions),
        ("adapter_versions", context.adapter_versions),
        ("security_limit_profile", context.security_limit_profile),
    ];
    if closure.get("source_revision").and_then(Value::as_str) != Some(context.source_revision)
        || closure.get("artifact_digest").and_then(Value::as_str) != Some(context.artifact_digest)
        || expected
            .iter()
            .any(|(field, value)| closure.get(*field) != Some(*value))
    {
        return Err(invalid(format!(
            "receipt {receipt_id} has a mismatched deployment closure context"
        )));
    }
    Ok(())
}

fn exact_string_set(
    value: &Value,
    field: &str,
    context: &str,
) -> Result<BTreeSet<String>, ConformanceClosureError> {
    let mut result = BTreeSet::new();
    for item in required_array(value, field, context)? {
        let item = item
            .as_str()
            .filter(|item| !item.is_empty())
            .ok_or_else(|| invalid(format!("{context}.{field} contains a non-string")))?;
        if !result.insert(item.to_owned()) {
            return Err(invalid(format!(
                "{context}.{field} contains duplicate {item}"
            )));
        }
    }
    Ok(result)
}

fn validate_receipt_digest_sets(
    receipt: DocumentFacts<'_>,
    current_receipts: &BTreeMap<String, DocumentFacts<'_>>,
    context: ConformanceClosureContext<'_>,
) -> Result<(), ConformanceClosureError> {
    let mut expected_inputs =
        BTreeSet::from([
            required_str(
                receipt.input.value.get("ledger_binding").ok_or_else(|| {
                    invalid(format!("receipt {} omits ledger binding", receipt.id))
                })?,
                "ledger_digest",
                receipt.id,
            )?
            .to_owned(),
            context.artifact_digest.to_owned(),
            required_str(
                context.deployment_profile,
                "digest",
                "deployment profile binding",
            )?
            .to_owned(),
            required_str(
                context.security_limit_profile,
                "digest",
                "security limit binding",
            )?
            .to_owned(),
        ]);
    for (label, bindings) in [
        ("policy_versions", context.policy_versions),
        ("configuration_versions", context.configuration_versions),
        ("provider_versions", context.provider_versions),
        ("adapter_versions", context.adapter_versions),
    ] {
        let values = bindings
            .as_array()
            .ok_or_else(|| invalid(format!("expected {label} is not an array")))?;
        for binding in values {
            expected_inputs.insert(required_str(binding, "digest", label)?.to_owned());
        }
    }
    for reference in required_array(receipt.input.value, "prerequisite_receipts", receipt.id)? {
        let package = required_package(reference, "package_id", receipt.id)?;
        let target = current_receipts
            .get(package)
            .ok_or_else(|| invalid(format!("unknown prerequisite package {package}")))?;
        expected_inputs.insert(target.input.raw_digest.to_owned());
    }
    for digest in &expected_inputs {
        validate_digest(digest, "receipt input digest")?;
    }

    let expected_outputs = required_array(
        receipt
            .input
            .value
            .get("evaluated_sets")
            .ok_or_else(|| invalid(format!("receipt {} omits evaluated sets", receipt.id)))?,
        "evidence_bindings",
        receipt.id,
    )?
    .iter()
    .map(|binding| required_str(binding, "bundle_digest", receipt.id).map(ToOwned::to_owned))
    .collect::<Result<BTreeSet<_>, _>>()?;

    let actual_inputs = exact_sorted_digest_set(receipt.input.value, "input_digests", receipt.id)?;
    let actual_outputs =
        exact_sorted_digest_set(receipt.input.value, "output_digests", receipt.id)?;
    if actual_inputs != expected_inputs || actual_outputs != expected_outputs {
        return Err(invalid(format!(
            "receipt {} input/output digest projections are not exact",
            receipt.id
        )));
    }
    Ok(())
}

fn exact_sorted_digest_set(
    value: &Value,
    field: &str,
    context: &str,
) -> Result<BTreeSet<String>, ConformanceClosureError> {
    let values = required_array(value, field, context)?;
    if values.is_empty() || values.len() > MAX_CLOSURE_DOCUMENTS {
        return Err(invalid(format!(
            "{context}.{field} must contain 1..={MAX_CLOSURE_DOCUMENTS} digests"
        )));
    }
    let mut result = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for value in values {
        let digest = value
            .as_str()
            .ok_or_else(|| invalid(format!("{context}.{field} contains a non-string")))?;
        validate_digest(digest, &format!("{context}.{field}"))?;
        if previous.is_some_and(|prior| prior >= digest) || !result.insert(digest.to_owned()) {
            return Err(invalid(format!(
                "{context}.{field} is not a strictly sorted unique digest set"
            )));
        }
        previous = Some(digest);
    }
    Ok(result)
}

fn validate_retirement_closure(
    receipt: DocumentFacts<'_>,
    package_id: &str,
    bound_evidence: &BTreeSet<String>,
    evidence: &BTreeMap<&str, DocumentFacts<'_>>,
    superseded_evidence: &BTreeSet<String>,
) -> Result<(), ConformanceClosureError> {
    let retirement = receipt
        .input
        .value
        .get("retirement_closure")
        .ok_or_else(|| invalid(format!("receipt {} omits retirement_closure", receipt.id)))?;
    if package_id != "SB-9" {
        return if retirement.is_null() {
            Ok(())
        } else {
            Err(invalid(format!(
                "non-SB-9 receipt {} carries retirement authority",
                receipt.id
            )))
        };
    }
    if bound_evidence.is_empty() || !retirement.is_object() {
        return Err(invalid(
            "SB-9 retirement closure has no exact evidence inventory",
        ));
    }
    for field in [
        "zero_consumer_evidence_instance_ids",
        "zero_live_authority_evidence_instance_ids",
        "retired_bypass_evidence_instance_ids",
    ] {
        let values = required_array(retirement, field, receipt.id)?;
        let mut actual = BTreeSet::new();
        let mut previous: Option<&str> = None;
        for value in values {
            let evidence_id = value.as_str().ok_or_else(|| {
                invalid(format!(
                    "receipt {} {field} contains a non-string",
                    receipt.id
                ))
            })?;
            if previous.is_some_and(|prior| prior >= evidence_id)
                || !actual.insert(evidence_id.to_owned())
            {
                return Err(invalid(format!(
                    "receipt {} {field} is not strictly sorted and unique",
                    receipt.id
                )));
            }
            previous = Some(evidence_id);
            let bundle = evidence.get(evidence_id).ok_or_else(|| {
                invalid(format!(
                    "receipt {} {field} references unknown evidence {evidence_id}",
                    receipt.id
                ))
            })?;
            if bundle.package_id != "SB-9" || superseded_evidence.contains(evidence_id) {
                return Err(invalid(format!(
                    "receipt {} {field} references non-current or non-SB-9 evidence",
                    receipt.id
                )));
            }
        }
        // Version 1 cannot express distinct retirement roles. Until the
        // ControlTrace publishes scoped role metadata, all three categories
        // conservatively bind the complete independently derived SB-9 set.
        if actual != *bound_evidence {
            return Err(invalid(format!(
                "receipt {} {field} is not the complete SB-9 evidence set",
                receipt.id
            )));
        }
    }
    Ok(())
}

fn parse_instances<'a>(
    receipt: &'a Value,
    context: &str,
) -> Result<BTreeMap<String, &'a Value>, ConformanceClosureError> {
    let values = required_array(receipt, "applicability_instances", context)?;
    if values.is_empty() || values.len() > MAX_APPLICABILITY_INVENTORY_INSTANCES {
        return Err(invalid(format!(
            "{context} must have 1..={MAX_APPLICABILITY_INVENTORY_INSTANCES} applicability instances"
        )));
    }
    let mut instances = BTreeMap::new();
    for instance in values {
        let id = required_str(instance, "instance_id", context)?;
        dimension_map(instance, "implementation_dimensions", context)?;
        dimension_map(instance, "deployment_dimensions", context)?;
        if instances.insert(id.to_owned(), instance).is_some() {
            return Err(invalid(format!(
                "{context} duplicates applicability instance {id}"
            )));
        }
    }
    Ok(instances)
}

fn validate_evidence_reference(
    binding: &Value,
    evidence_id: &str,
    bundle: DocumentFacts<'_>,
) -> Result<(), ConformanceClosureError> {
    if binding.get("artifact_kind").and_then(Value::as_str) != Some("conformance-bundle")
        || binding.get("artifact_locator").and_then(Value::as_str)
            != Some(bundle.input.artifact_locator)
        || binding.get("bundle_id").and_then(Value::as_str) != Some(bundle.id)
        || binding.get("document_version").and_then(Value::as_u64) != Some(bundle.version)
        || binding.get("evidence_instance_id").and_then(Value::as_str) != Some(evidence_id)
        || binding.get("bundle_digest").and_then(Value::as_str) != Some(bundle.input.raw_digest)
    {
        return Err(invalid(format!(
            "evidence binding {evidence_id} does not exactly reference its loaded bundle"
        )));
    }
    Ok(())
}

fn validate_bundle_context(
    bundle: DocumentFacts<'_>,
    context: ConformanceClosureContext<'_>,
) -> Result<(), ConformanceClosureError> {
    let value = bundle.input.value;
    let bindings = value
        .get("bindings")
        .ok_or_else(|| invalid(format!("bundle {} omits bindings", bundle.id)))?;
    let expected = [
        ("deployment_profile", context.deployment_profile),
        ("policy_versions", context.policy_versions),
        ("configuration_versions", context.configuration_versions),
        ("provider_versions", context.provider_versions),
        ("adapter_versions", context.adapter_versions),
        ("security_limit_profile", context.security_limit_profile),
    ];
    if value.get("source_revision").and_then(Value::as_str) != Some(context.source_revision)
        || value.pointer("/artifact/digest").and_then(Value::as_str)
            != Some(context.artifact_digest)
        || expected
            .iter()
            .any(|(field, expected)| bindings.get(*field) != Some(*expected))
    {
        return Err(invalid(format!(
            "bundle {} has a mismatched deployment closure context",
            bundle.id
        )));
    }
    Ok(())
}

fn validate_authoritative_bundle(
    bundle: DocumentFacts<'_>,
    receipt: DocumentFacts<'_>,
    trace: &TraceFacts<'_>,
    superseded: &BTreeSet<String>,
    context: ConformanceClosureContext<'_>,
    trusted_now: ConformanceTrustedTimeWindow,
) -> Result<(), ConformanceClosureError> {
    let value = bundle.input.value;
    if !claims_production_acceptance(value)
        || value.get("normalized_result").and_then(Value::as_str) != Some("pass")
        || value.get("evidence_lifecycle").and_then(Value::as_str) != Some("accepted")
        || value.get("contains_secrets").and_then(Value::as_bool) != Some(false)
        || superseded.contains(required_str(value, "evidence_instance_id", bundle.id)?)
    {
        return Err(invalid(format!(
            "bundle {} is not current production-accepted passing evidence",
            bundle.id
        )));
    }
    let produced = parse_timestamp(value, "produced_at", bundle.id)?;
    let verified = optional_timestamp(value, "verified_at", bundle.id)?.ok_or_else(|| {
        invalid(format!(
            "production bundle {} has no verified_at",
            bundle.id
        ))
    })?;
    let accepted = optional_timestamp(value, "accepted_at", bundle.id)?.ok_or_else(|| {
        invalid(format!(
            "production bundle {} has no accepted_at",
            bundle.id
        ))
    })?;
    let expires = parse_timestamp(value, "expires_at", bundle.id)?;
    if produced > trusted_now.not_before
        || verified > trusted_now.not_before
        || accepted > trusted_now.not_before
        || expires <= trusted_now.not_after
    {
        return Err(invalid(format!(
            "production bundle {} is future-dated or expired",
            bundle.id
        )));
    }
    if bundle.tier.rank < receipt.tier.rank {
        return Err(invalid(format!(
            "bundle {} evidence tier is below receipt {}",
            bundle.id, receipt.id
        )));
    }
    for scope in ["implementation", "deployment"] {
        if let Some(minimum) = trace
            .value
            .pointer(&format!("/minimum_evidence_tier/{scope}"))
            .filter(|value| !value.is_null())
        {
            let minimum = parse_tier(
                minimum,
                trace
                    .value
                    .get("trace_id")
                    .and_then(Value::as_str)
                    .unwrap_or("trace"),
            )?;
            let applies = value
                .pointer(&format!("/evaluated_applicability/{scope}/applicable"))
                .and_then(Value::as_bool)
                .ok_or_else(|| {
                    invalid(format!("bundle {} omits {scope} applicability", bundle.id))
                })?;
            if applies && bundle.tier.rank < minimum.rank {
                return Err(invalid(format!(
                    "bundle {} evidence tier is below the trace {scope} minimum",
                    bundle.id
                )));
            }
        }
    }
    validate_production_observation(value, bundle.id, context, accepted, trusted_now)
}

fn validate_production_observation(
    bundle: &Value,
    bundle_id: &str,
    context: ConformanceClosureContext<'_>,
    accepted_at: DateTime<Utc>,
    trusted_now: ConformanceTrustedTimeWindow,
) -> Result<(), ConformanceClosureError> {
    let requirement = bundle
        .get("production_observation")
        .ok_or_else(|| invalid(format!("bundle {bundle_id} omits production_observation")))?;
    let observation = requirement
        .get("observation")
        .filter(|value| value.is_object())
        .ok_or_else(|| invalid(format!("bundle {bundle_id} has no production observation")))?;
    if requirement.get("required").and_then(Value::as_bool) != Some(true)
        || observation.get("deployment_id").and_then(Value::as_str) != Some(context.deployment_id)
        || observation.get("normalized_result").and_then(Value::as_str) != Some("pass")
    {
        return Err(invalid(format!(
            "bundle {bundle_id} is not production-observed in the expected deployment"
        )));
    }
    let observed = parse_timestamp(observation, "observed_at", bundle_id)?;
    let produced = parse_timestamp(bundle, "produced_at", bundle_id)?;
    if observed < produced || observed > accepted_at || observed > trusted_now.not_before {
        return Err(invalid(format!(
            "bundle {bundle_id} has an out-of-order or future production observation"
        )));
    }
    let hashes = required_array(observation, "artifact_hashes", bundle_id)?;
    if hashes.is_empty()
        || !hashes
            .iter()
            .any(|digest| digest.as_str() == Some(context.artifact_digest))
    {
        return Err(invalid(format!(
            "bundle {bundle_id} production observation does not bind the expected artifact"
        )));
    }
    Ok(())
}

fn dimension_map(
    value: &Value,
    field: &str,
    context: &str,
) -> Result<BTreeMap<String, Value>, ConformanceClosureError> {
    let mut dimensions = BTreeMap::new();
    for dimension in required_array(value, field, context)? {
        let name = required_str(dimension, "name", context)?;
        let selected = dimension
            .get("value")
            .filter(|value| !value.is_null())
            .ok_or_else(|| invalid(format!("{context} dimension {name} omits a value")))?;
        if dimensions
            .insert(name.to_owned(), selected.clone())
            .is_some()
        {
            return Err(invalid(format!("{context} duplicates dimension {name}")));
        }
    }
    Ok(dimensions)
}

fn validate_bound_bundle_instance(
    bundle: DocumentFacts<'_>,
    trace: &TraceFacts<'_>,
    instance: &ApplicabilityInstance,
) -> Result<(String, String), ConformanceClosureError> {
    let value = bundle.input.value;
    let trace_id = required_str(value, "trace_id", bundle.id)?;
    let instance_id = required_str(value, "applicability_instance_id", bundle.id)?;
    if trace_id != instance.trace_id
        || instance_id != instance.applicability_instance_id
        || trace.package_id != instance.owning_work_package
    {
        return Err(invalid(format!(
            "bundle {} does not bind the exact independently derived trace/instance/package tuple",
            bundle.id
        )));
    }
    for (scope, expected_scope) in [
        ("implementation", ApplicabilityScope::Implementation),
        ("deployment", ApplicabilityScope::Deployment),
    ] {
        let expected_applicable = instance.scope == expected_scope;
        let evaluation = value
            .pointer(&format!("/evaluated_applicability/{scope}"))
            .ok_or_else(|| invalid(format!("bundle {} omits {scope} applicability", bundle.id)))?;
        if evaluation.get("applicable").and_then(Value::as_bool) != Some(expected_applicable) {
            return Err(invalid(format!(
                "bundle {} has incorrect {scope} applicability",
                bundle.id
            )));
        }
        let expected_dimensions = if expected_applicable {
            applicability_dimension_map(&instance.dimensions)?
        } else {
            BTreeMap::new()
        };
        let actual_dimensions = dimension_map(evaluation, "dimensions", bundle.id)?;
        if actual_dimensions != expected_dimensions {
            return Err(invalid(format!(
                "bundle {} has incorrect {scope} dimension projection",
                bundle.id
            )));
        }
    }
    Ok((trace_id.to_owned(), instance_id.to_owned()))
}

fn validate_receipt_instance_projection(
    actual: &Value,
    expected: &ApplicabilityInstance,
    receipt_id: &str,
) -> Result<(), ConformanceClosureError> {
    let expected_dimensions = applicability_dimension_map(&expected.dimensions)?;
    let implementation = dimension_map(actual, "implementation_dimensions", receipt_id)?;
    let deployment = dimension_map(actual, "deployment_dimensions", receipt_id)?;
    let (wanted_implementation, wanted_deployment) = match expected.scope {
        ApplicabilityScope::Implementation => (expected_dimensions, BTreeMap::new()),
        ApplicabilityScope::Deployment => (BTreeMap::new(), expected_dimensions),
    };
    if implementation != wanted_implementation || deployment != wanted_deployment {
        return Err(invalid(format!(
            "receipt {receipt_id} has a mismatched legacy projection for independently derived instance {}",
            expected.applicability_instance_id
        )));
    }
    Ok(())
}

fn applicability_dimension_map(
    dimensions: &[ApplicabilityDimension],
) -> Result<BTreeMap<String, Value>, ConformanceClosureError> {
    dimensions
        .iter()
        .map(|dimension| {
            let value = match &dimension.value {
                ApplicabilityDimensionValue::String(value) => Value::String(value.clone()),
                ApplicabilityDimensionValue::Boolean(value) => Value::Bool(*value),
                ApplicabilityDimensionValue::Integer(value) => Value::Number((*value).into()),
                ApplicabilityDimensionValue::Set(values) => Value::Array(
                    values
                        .iter()
                        .map(|value| match value {
                            ApplicabilityScalar::Boolean(value) => Value::Bool(*value),
                            ApplicabilityScalar::Integer(value) => Value::Number((*value).into()),
                            ApplicabilityScalar::String(value) => Value::String(value.clone()),
                        })
                        .collect(),
                ),
            };
            Ok((dimension.name.clone(), value))
        })
        .collect()
}

fn validate_prerequisites<'a>(
    receipt: DocumentFacts<'a>,
    receipts: &BTreeMap<String, DocumentFacts<'a>>,
    proofs: &BTreeMap<String, ProofFacts>,
    trusted_now: ConformanceTrustedTimeWindow,
) -> Result<BTreeSet<String>, ConformanceClosureError> {
    let mut packages = BTreeSet::new();
    let mut receipt_ids = BTreeSet::new();
    let receipt_proof = proofs
        .get(receipt.input.raw_digest)
        .ok_or_else(|| invalid(format!("receipt {} has no authenticated proof", receipt.id)))?;
    let receipt_expiry = parse_timestamp(receipt.input.value, "expires_at", receipt.id)?;
    for reference in required_array(receipt.input.value, "prerequisite_receipts", receipt.id)? {
        let package = required_package(reference, "package_id", receipt.id)?;
        if !packages.insert(package.to_owned()) {
            return Err(invalid(format!(
                "receipt {} duplicates prerequisite package {package}",
                receipt.id
            )));
        }
        let target = receipts.get(package).ok_or_else(|| {
            invalid(format!(
                "receipt {} references unknown prerequisite package {package}",
                receipt.id
            ))
        })?;
        if reference.get("artifact_kind").and_then(Value::as_str) != Some("package-exit-receipt")
            || reference.get("artifact_locator").and_then(Value::as_str)
                != Some(target.input.artifact_locator)
            || reference.get("receipt_id").and_then(Value::as_str) != Some(target.id)
            || reference.get("document_version").and_then(Value::as_u64) != Some(target.version)
            || reference.get("receipt_digest").and_then(Value::as_str)
                != Some(target.input.raw_digest)
        {
            return Err(invalid(format!(
                "receipt {} prerequisite {package} does not exactly reference the current receipt",
                receipt.id
            )));
        }
        for field in [
            "package_id",
            "acceptance_status",
            "production_accepted",
            "evidence_tier",
            "result",
            "receipt_lifecycle",
            "expires_at",
        ] {
            require_equal_field(reference, target.input.value, field, receipt.id)?;
        }
        if target.tier.rank < receipt.tier.rank
            || !claims_production_acceptance(target.input.value)
            || target.input.value.get("result").and_then(Value::as_str) != Some("pass")
            || target
                .input
                .value
                .get("receipt_lifecycle")
                .and_then(Value::as_str)
                != Some("accepted")
            || parse_timestamp(target.input.value, "expires_at", target.id)?
                <= trusted_now.not_after
            || parse_timestamp(target.input.value, "expires_at", target.id)? < receipt_expiry
        {
            return Err(invalid(format!(
                "receipt {} prerequisite {package} is stale or downgraded",
                receipt.id
            )));
        }
        let target_proof = proofs.get(target.input.raw_digest).ok_or_else(|| {
            invalid(format!(
                "prerequisite receipt {} has no authenticated proof",
                target.id
            ))
        })?;
        if target_proof.acceptance_sequence >= receipt_proof.acceptance_sequence {
            return Err(invalid(format!(
                "prerequisite receipt {} was not externally accepted before dependent receipt {}",
                target.id, receipt.id
            )));
        }
        receipt_ids.insert(target.id.to_owned());
    }
    let required = required_prerequisite_packages(receipt.package_id);
    if packages != required {
        return Err(invalid(format!(
            "receipt {} prerequisite package set is not exact: required={required:?}, actual={packages:?}",
            receipt.id
        )));
    }
    Ok(receipt_ids)
}

fn required_prerequisite_packages(package_id: &str) -> BTreeSet<String> {
    let packages: &[&str] = match package_id {
        "SB-0" => &[],
        "SB-1" | "SB-2" | "SB-4" | "SB-5" | "SB-6" | "SB-7" => &["SB-0"],
        "SB-3" => &["SB-0", "SB-1", "SB-2"],
        "SB-8" => &[
            "SB-0", "SB-1", "SB-2", "SB-3", "SB-4", "SB-5", "SB-6", "SB-7",
        ],
        "SB-9" => &[
            "SB-0", "SB-1", "SB-2", "SB-3", "SB-4", "SB-5", "SB-6", "SB-7", "SB-8",
        ],
        _ => &[],
    };
    packages
        .iter()
        .map(|package| (*package).to_owned())
        .collect()
}

fn reject_cycles(
    label: &str,
    graph: &BTreeMap<String, BTreeSet<String>>,
) -> Result<(), ConformanceClosureError> {
    if graph.len() > MAX_CLOSURE_DOCUMENTS {
        return Err(invalid(format!(
            "{label} graph exceeds {MAX_CLOSURE_DOCUMENTS} source nodes"
        )));
    }
    let edge_count = graph
        .values()
        .try_fold(0usize, |total, targets| total.checked_add(targets.len()));
    let Some(edge_count) = edge_count else {
        return Err(invalid(format!("{label} graph edge count overflows")));
    };
    if edge_count > MAX_GRAPH_EDGES {
        return Err(invalid(format!(
            "{label} graph exceeds {MAX_GRAPH_EDGES} edges"
        )));
    }

    let mut indegree = BTreeMap::<String, usize>::new();
    for (source, targets) in graph {
        indegree.entry(source.clone()).or_default();
        for target in targets {
            let degree = indegree.entry(target.clone()).or_default();
            *degree = degree
                .checked_add(1)
                .ok_or_else(|| invalid(format!("{label} indegree overflows")))?;
        }
    }
    if indegree.len() > MAX_CLOSURE_DOCUMENTS {
        return Err(invalid(format!(
            "{label} graph exceeds {MAX_CLOSURE_DOCUMENTS} total nodes"
        )));
    }
    let mut ready = indegree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(node, _)| node.clone())
        .collect::<VecDeque<_>>();
    let mut visited = 0usize;
    while let Some(node) = ready.pop_front() {
        visited += 1;
        if let Some(targets) = graph.get(&node) {
            for target in targets {
                let degree = indegree
                    .get_mut(target)
                    .expect("all target nodes were indexed");
                *degree -= 1;
                if *degree == 0 {
                    ready.push_back(target.clone());
                }
            }
        }
    }
    if visited != indegree.len() {
        return Err(invalid(format!("{label} graph contains a cycle")));
    }
    Ok(())
}

#[cfg(any(test, feature = "security-test-support"))]
pub mod tests {
    #![cfg_attr(not(test), allow(dead_code, unused_imports))]

    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use ed25519_dalek::{Signer, SigningKey};

    use crate::conformance_applicability::{
        APPLICABILITY_IDENTITY_CONTRACT, APPLICABILITY_INVENTORY_CONTRACT,
        compare_applicability_instances, recompute_applicability_instance_id,
        recompute_applicability_inventory_binding,
    };
    use crate::conformance_trust::{
        CANONICALIZATION_PROFILE, CONFORMANCE_BUNDLE_DOMAIN, ConformanceArtifactCandidate,
        ConformanceCheckpointAuthorityAnchor, ConformanceProductionRootRef,
        ConformanceRegistryArtifact, ConformanceTrustAnchor, ConformanceTrustScope,
        ConformanceVerificationContext, PACKAGE_EXIT_RECEIPT_DOMAIN, SIGNATURE_ALGORITHM,
        SIGNATURE_VERSION, TRUST_RECONCILIATION_PROTOCOL_VERSION,
        TRUST_RECONCILIATION_RESPONSE_DOMAIN, TRUST_RECONCILIATION_RESPONSE_KIND,
        TRUST_REGISTRY_CONTRACT_KIND, TRUST_REGISTRY_SCHEMA_URI, TRUST_REGISTRY_SCHEMA_VERSION,
        ValidatedConformanceRegistryLineage, conformance_signed_subject_digest,
        conformance_signing_bytes,
    };
    use crate::production_applicability::derive_implementation_applicability;
    use crate::production_deployment_applicability::{
        ActiveProviderApplicabilityClaim, ActiveProviderRegistryApplicabilityClaim,
        DeployedArtifactApplicabilityClaim, DeploymentCheckpointApplicabilityClaim,
        ProviderMandatoryBaselineClaim, SecurityLimitApplicabilityClaim,
    };
    use crate::security_profile::ProviderLifecycleState;

    const PROFILE_JSON: &str = include_str!(
        "../../../catalog/security-contracts/v1/deployment-security-profile.implementation.json"
    );

    static PUBLIC_FIXTURE_ENTROPY_COUNTER: AtomicU64 = AtomicU64::new(1);

    fn public_fixture_entropy(label: &[u8]) -> [u8; 32] {
        let counter = PUBLIC_FIXTURE_ENTROPY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut hasher = Sha256::new();
        hasher.update(b"ryuki public closure fixture entropy");
        hasher.update(label);
        hasher.update(std::process::id().to_le_bytes());
        hasher.update(counter.to_le_bytes());
        hasher.update(elapsed.to_le_bytes());
        hasher.finalize().into()
    }

    fn test_digest(label: &str) -> String {
        digest_bytes(label.as_bytes())
    }

    const CONTROL_TRACE_JSON: &str =
        include_str!("../../../catalog/security-contracts/v1/control-trace.implementation.json");
    const SOURCE_REVISION: &str = "1111111111111111111111111111111111111111";
    const DEPLOYMENT_ID: &str = "deployment:repository-conformance-fixture";
    const TRUST_DOMAIN_ID: &str = "trust-domain:repository-fixture";
    const ARTIFACT_DIGEST: &str =
        "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    const EXPIRES_AT: &str = "2027-07-16T00:00:00Z";

    fn timestamp(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn value_digest(value: &Value) -> String {
        digest_bytes(&canonical_json_bytes(value).unwrap())
    }

    fn tier_value(rank: u64) -> Value {
        let name = match rank {
            1 => "repository_local",
            2 => "operator_environment",
            3 => "externally_attested",
            _ => panic!("unsupported fixture tier"),
        };
        json!({"name":name,"rank":rank})
    }

    fn evidence_tier(rank: u64) -> EvidenceTier {
        match rank {
            1 => EvidenceTier::RepositoryLocal,
            2 => EvidenceTier::OperatorEnvironment,
            3 => EvidenceTier::ExternallyAttested,
            _ => panic!("unsupported fixture tier"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn fixture_proof(
        kind: ConformanceDocumentKind,
        document_id: &str,
        document_version: u64,
        digest: &str,
        package_id: &str,
        tier: EvidenceTier,
        acceptance_sequence: u64,
        acceptance_record_id: String,
    ) -> ProofFacts {
        ProofFacts {
            kind,
            document_id: document_id.to_owned(),
            document_version,
            complete_document_digest: digest.to_owned(),
            accepted_at_not_before: timestamp("2026-07-15T06:00:00Z"),
            accepted_at_not_after: timestamp("2026-07-15T07:00:00Z"),
            acceptance_record_id,
            acceptance_sequence,
            authority_id: "authority:fixture".into(),
            authority_epoch: 7,
            authority_revision: 11,
            checkpoint_sequence: 1_000,
            registry_id: "registry:fixture".into(),
            registry_version: 4,
            registry_digest: test_digest("registry"),
            deployment_id: DEPLOYMENT_ID.into(),
            trust_domain_id: TRUST_DOMAIN_ID.into(),
            package_id: package_id.to_owned(),
            evidence_tier: tier,
            snapshot_binding_digest: test_digest("snapshot"),
        }
    }

    fn guard_id(index: usize) -> &'static str {
        [
            "durable-postgresql",
            "approved-secret-provider",
            "https-public-urls",
            "secure-cookies",
            "non-development-authenticator",
            "external-signing-key-material",
            "mock-dependencies-disabled",
            "first-owner-path-closed",
        ][index]
    }

    fn guard_expected_value(index: usize) -> Value {
        let provider = |provider_id: &str| {
            let provider_name = provider_id
                .strip_prefix("provider:")
                .expect("fixture provider ids are canonical");
            let adapter_kind = match provider_id {
                "provider:closure-oidc" => "auth.oidc",
                "provider:closure-secrets" => "secrets.service",
                _ => panic!("unknown guard fixture provider {provider_id}"),
            };
            json!({
                "provider_id": provider_id,
                "configuration_version": 1,
                "configuration_payload_digest": test_digest(&format!("{provider_id}-configuration")),
                "lifecycle_record_version": 1,
                "lifecycle_state": "active",
                "capability_descriptor_id": format!("capability-descriptor:{provider_name}"),
                "capability_descriptor_version": 1,
                "adapter_kind": adapter_kind,
                "adapter_version": "1.0.0",
            })
        };
        match index {
            0 => json!({
                "kind": "durable-postgresql",
                "database_provider": "cloudnativepg",
                "server_major_version": 18,
                "attestation_profile_id": "postgresql-infrastructure-attestation-profile:closure-fixture",
                "attestation_profile_version": 1,
                "attestation_profile_digest": test_digest("guard-postgresql-infrastructure-profile"),
                "provider_route_binding_digest": test_digest("guard-postgresql-provider-route"),
                "database_identity_digest": test_digest("guard-database-identity"),
                "storage_binding_digest": test_digest("guard-storage-binding"),
                "migration_inventory_digest": test_digest("guard-migration-inventory"),
                "application_role": "ryuki_application",
                "migration_role": "ryuki_migrator",
            }),
            1 => json!({
                "kind": "approved-secret-provider",
                // Independent golden for this exact provider/capability
                // projection; never derive an authority expectation from the
                // rows it is meant to constrain.
                "provider_inventory_digest": "sha256:2ffee450df4ff1c6d7bc351ca8f742c2f62d6992cd12bf37eb1cb03ab4f91a2a",
                "providers": [{
                    "provider": provider("provider:closure-secrets"),
                    "runtime_binding_digest": test_digest("guard-secret-provider-runtime-binding"),
                }],
                "required_capability_ids": ["secret-read", "secret-renew"],
            }),
            2 => json!({
                "kind": "https-public-urls",
                // Independent goldens for the deterministic, genuinely signed
                // ingress composition fixture. These intentionally do not
                // call the fixture's digest constructor.
                "public_origin_set_digest": "sha256:bbecce0b5f74832b9e6cd285a60e3d0df2edd97f4aab88da09cd0300398589b5",
                "ingress_binding_digest": "sha256:2982c5fad2f24909662f88025ee5049f1a4d4c0a9d21109b9a216c7dba688064",
                "attestation_profile_id": "ingress-attestation-profile:closure-fixture",
                "attestation_profile_version": 1,
                "attestation_profile_digest": test_digest("guard-ingress-profile"),
            }),
            3 => json!({
                "kind": "secure-cookies",
                "policies": [{
                    "policy_id": "cookie-policy:api-entra-login-binding",
                    "cookie_name": "__Host-entra_login_csrf",
                    "secure": true,
                    "http_only": true,
                    "path": "/",
                    "domain": null,
                    "same_site": "lax",
                    "policy_digest": "sha256:dd2524c0de18cc5e6af3f6f917b3d9084d5ee8e0348a9197bad15d8c4f35aa70",
                }, {
                    "policy_id": "cookie-policy:api-oidc-login-binding",
                    "cookie_name": "__Host-oidc_login_csrf",
                    "secure": true,
                    "http_only": true,
                    "path": "/",
                    "domain": null,
                    "same_site": "lax",
                    "policy_digest": "sha256:58daba94f8a546b3ecb66ef47d68d373d031a9aeb86a5b3a3a60c722917dbbb9",
                }, {
                    "policy_id": "cookie-policy:api-session",
                    "cookie_name": "__Host-ryuki_session",
                    "secure": true,
                    "http_only": true,
                    "path": "/",
                    "domain": null,
                    "same_site": "lax",
                    "policy_digest": "sha256:f64e6fef4fa12a22a0e15fb87ca3f10bb9d1212b76d129dd1cfb91f00ac043e1",
                }],
                "policy_inventory_digest": "sha256:5d41f46cb07894ac33d14824daeccdc7e466577383fc0a463f9a919949a0bbc7",
            }),
            4 => {
                let authenticators = json!([{
                    "provider": provider("provider:closure-oidc"),
                    "authenticator_kind": "oidc",
                    "runtime_binding_digest": test_digest("guard-oidc-runtime-binding"),
                }]);
                json!({
                    "kind": "non-development-authenticator",
                    // Independent golden for the exact canonical positive
                    // fixture above; never derive an authority expectation
                    // from the rows it is meant to constrain.
                    "authenticator_inventory_digest": "sha256:9ca77367549f69dc70b33d1cce114c5834d23527439cd47b1b6105755e31a280",
                    "authenticators": authenticators,
                })
            }
            5 => json!({
                "kind": "external-signing-key-material",
                "signing_inventory_digest": test_digest("guard-signing-inventory"),
                "purposes": [{
                    "purpose_id": "signing-purpose:control-plane-grants",
                    "algorithm": "ed25519",
                    "custody_kind": "kms",
                    "key_identity_digest": test_digest("guard-control-plane-key"),
                }, {
                    "purpose_id": "signing-purpose:session-credentials",
                    "algorithm": "hmac-sha256",
                    "custody_kind": "hsm",
                    "key_identity_digest": test_digest("guard-session-key"),
                }],
            }),
            6 => json!({
                "kind": "mock-dependencies-disabled",
                "dependency_inventory_digest": test_digest("guard-dependency-inventory"),
                "required_component_ids": [
                    "runtime-component:database",
                    "runtime-component:secret-provider",
                ],
            }),
            7 => json!({
                "kind": "first-owner-path-closed",
                "deployment_id": DEPLOYMENT_ID,
                "state_contract_version": 1,
                "authority_namespace_digest": test_digest("guard-authority-namespace"),
                "closure_record_digest": test_digest("guard-first-owner-closure"),
            }),
            _ => unreachable!("there are exactly eight guards"),
        }
    }

    fn refresh_authenticator_inventory_digest(profile: &mut Value) {
        let authenticators =
            profile["runtime_guard_evidence"]["guards"][4]["expected_value"]["authenticators"]
                .clone();
        let typed: Vec<ExpectedAuthenticatorBinding> =
            serde_json::from_value(authenticators).unwrap();
        profile["runtime_guard_evidence"]["guards"][4]["expected_value"]["authenticator_inventory_digest"] = json!(
            authenticator_inventory_digest(&typed)
                .expect("fixture authenticator inventory must canonicalize")
        );
    }

    fn refresh_secret_provider_inventory_digest(profile: &mut Value) {
        let expected_value = &profile["runtime_guard_evidence"]["guards"][1]["expected_value"];
        let providers: Vec<ExpectedSecretProviderBinding> =
            serde_json::from_value(expected_value["providers"].clone()).unwrap();
        let required_capability_ids: Vec<String> =
            serde_json::from_value(expected_value["required_capability_ids"].clone()).unwrap();
        profile["runtime_guard_evidence"]["guards"][1]["expected_value"]["provider_inventory_digest"] = json!(
            secret_provider_inventory_digest(&providers, &required_capability_ids)
                .expect("fixture secret-provider inventory must canonicalize")
        );
    }

    fn receipt_id(package_id: &str) -> String {
        format!("package-exit-receipt:{}", package_id.to_ascii_lowercase())
    }

    fn receipt_locator(package_id: &str) -> String {
        format!("fixtures/receipts/{}.json", package_id.to_ascii_lowercase())
    }

    #[derive(Clone)]
    struct SyntheticClosure {
        ledger: Value,
        ledger_digest: String,
        ledger_locator: String,
        applicability: DerivedProductionApplicability,
        profile: Value,
        root_ref: VersionedContentReference,
        deployment_profile: Value,
        policy_versions: Value,
        configuration_versions: Value,
        provider_versions: Value,
        adapter_versions: Value,
        security_limit_profile: Value,
        bundles: Vec<Value>,
        bundle_digests: Vec<String>,
        bundle_locators: Vec<String>,
        receipts: Vec<Value>,
        receipt_digests: Vec<String>,
        receipt_locators: Vec<String>,
        proofs: BTreeMap<String, ProofFacts>,
        trusted_now: ConformanceTrustedTimeWindow,
        current_root_acceptance_record_id: String,
    }

    impl SyntheticClosure {
        fn complete() -> Self {
            let mut ledger: Value = serde_json::from_str(CONTROL_TRACE_JSON).unwrap();
            ledger["acceptance_status"] = json!("production_accepted");
            ledger["production_accepted"] = json!(true);
            let ledger_digest = value_digest(&ledger);
            let ledger_locator =
                "catalog/security-contracts/v1/control-trace.implementation.json".to_owned();

            let traces = ledger["traces"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|trace| trace["trace_lifecycle"] == "active")
                .map(|trace| {
                    (
                        trace["trace_id"].as_str().unwrap().to_owned(),
                        trace.clone(),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            assert_eq!(traces.len(), 141);

            let mut first_control_by_package = BTreeMap::new();
            for trace in traces.values() {
                first_control_by_package
                    .entry(trace["owning_work_package"].as_str().unwrap().to_owned())
                    .or_insert_with(|| trace["control_id"].as_str().unwrap().to_owned());
            }

            let mut profile: Value = serde_json::from_str(PROFILE_JSON).unwrap();
            profile["security_profile"] = json!("production");
            profile["applicability"]["security_profiles"] = json!(["production"]);
            profile["lifecycle"]["state"] = json!("active");
            profile["control_trace_ref"]["content_digest"] = json!(ledger_digest.clone());
            let root_ref = VersionedContentReference {
                artifact_kind: ArtifactKind::PackageExitReceipt,
                document_id: receipt_id("SB-9"),
                document_version: 1,
                content_digest: test_digest("placeholder-root"),
                artifact_locator: receipt_locator("SB-9"),
            };
            profile["production_acceptance_receipt_ref"] = serde_json::to_value(&root_ref).unwrap();
            let guard_packages = &PACKAGES[..8];
            profile["runtime_guard_evidence"] = json!({
                "mode":"receipt_bound",
                "runtime_cross_check_required":true,
                "guards":guard_packages.iter().enumerate().map(|(index, package_id)| json!({
                    "guard_id":guard_id(index),
                    "control_ids":[first_control_by_package[*package_id].clone()],
                    "receipt_ref":{
                        "artifact_kind":"package-exit-receipt",
                        "document_id":receipt_id(package_id),
                        "document_version":1,
                        "content_digest":test_digest(&format!("placeholder-{package_id}")),
                        "artifact_locator":receipt_locator(package_id),
                    },
                    "expected_value":guard_expected_value(index),
                })).collect::<Vec<_>>()
            });

            let typed_profile: DeploymentSecurityProfile =
                serde_json::from_value(profile.clone()).unwrap();
            let policy_versions = Value::Array(profile_policy_version_bindings(&typed_profile));
            let configuration_versions =
                Value::Array(profile_configuration_version_bindings(&typed_profile));
            let provider_versions =
                json!([{"id":"provider","version":"1","digest":test_digest("provider")}]);
            let adapter_versions =
                json!([{"id":"adapter","version":"1","digest":test_digest("adapter")}]);
            let security_limit_profile =
                json!({"id":"limits","version":"1","digest":test_digest("limits")});
            let deployment_profile = json!({
                "id":profile["document_id"].clone(),
                "version":profile["document_version"].as_u64().unwrap().to_string(),
                "deployment_id":DEPLOYMENT_ID,
                "digest_contract":DEPLOYMENT_PROFILE_CONFORMANCE_BINDING_DIGEST_CONTRACT,
                "digest":deployment_profile_conformance_binding_digest(&profile).unwrap(),
            });

            let trace_binding =
                crate::conformance_applicability::ApplicabilityControlTraceBinding {
                    document_id: typed_profile.control_trace_ref.document_id.clone(),
                    document_version: typed_profile.control_trace_ref.document_version,
                    content_digest: typed_profile.control_trace_ref.content_digest.clone(),
                };
            let mut instances = Vec::with_capacity(traces.len());
            for trace in traces.values() {
                let mut dimension_names = trace
                    .pointer("/evidence_instance_dimensions/implementation")
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|name| name.as_str().unwrap())
                    .collect::<Vec<_>>();
                dimension_names.sort_unstable();
                let dimensions = dimension_names
                    .into_iter()
                    .map(|name| {
                        let value = match name {
                            "implementation.source_revision" => SOURCE_REVISION,
                            "implementation.artifact_digest" => ARTIFACT_DIGEST,
                            "implementation.fixture_or_probe_id" => {
                                trace["fixture_or_probe_id"].as_str().unwrap()
                            }
                            _ => panic!("unexpected checked-in implementation dimension {name}"),
                        };
                        ApplicabilityDimension {
                            name: name.to_owned(),
                            value: ApplicabilityDimensionValue::String(value.to_owned()),
                        }
                    })
                    .collect::<Vec<_>>();
                let mut instance = ApplicabilityInstance {
                    applicability_instance_id: String::new(),
                    trace_id: trace["trace_id"].as_str().unwrap().to_owned(),
                    owning_work_package: trace["owning_work_package"].as_str().unwrap().to_owned(),
                    scope: ApplicabilityScope::Implementation,
                    subject: crate::conformance_applicability::ApplicabilitySubject::Component {
                        component_id: "component:ryuki-api".into(),
                        component_version: "1.0.0".into(),
                    },
                    dimensions,
                };
                instance.applicability_instance_id =
                    recompute_applicability_instance_id(&trace_binding, &instance).unwrap();
                instances.push(instance);
            }
            instances.sort_by(compare_applicability_instances);
            let binding =
                recompute_applicability_inventory_binding(&trace_binding, &instances).unwrap();
            assert_eq!(binding.identity_contract, APPLICABILITY_IDENTITY_CONTRACT);
            assert_eq!(binding.inventory_contract, APPLICABILITY_INVENTORY_CONTRACT);
            let applicability = DerivedProductionApplicability { binding, instances };

            let mut proofs = BTreeMap::new();
            let mut bundles = Vec::with_capacity(applicability.instances.len());
            let mut bundle_digests = Vec::with_capacity(applicability.instances.len());
            let mut bundle_locators = Vec::with_capacity(applicability.instances.len());
            let mut bundle_index_by_instance = BTreeMap::new();
            for (index, instance) in applicability.instances.iter().enumerate() {
                let trace = &traces[&instance.trace_id];
                let evidence_id = format!("evidence:{index:03}");
                let bundle_id = format!("conformance-bundle:{index:03}");
                let locator = format!("fixtures/bundles/{index:03}.json");
                let dimensions = serde_json::to_value(&instance.dimensions).unwrap();
                let bundle = json!({
                    "$schema":"https://ryuki.io/schemas/security-contracts/v1/conformance-bundle.schema.json",
                    "contract_kind":"conformance-bundle",
                    "document_version":1,
                    "bundle_id":bundle_id,
                    "acceptance_status":"production_accepted",
                    "production_accepted":true,
                    "trace_id":instance.trace_id,
                    "evidence_instance_id":evidence_id,
                    "applicability_instance_id":instance.applicability_instance_id,
                    "control_id":trace["control_id"].clone(),
                    "acceptance_case_id":trace["acceptance_case_id"].clone(),
                    "evaluated_applicability":{
                        "implementation":{"applicable":true,"dimensions":dimensions},
                        "deployment":{"applicable":false,"dimensions":[]}
                    },
                    "source_revision":SOURCE_REVISION,
                    "artifact":{"digest":ARTIFACT_DIGEST},
                    "bindings":{
                        "deployment_profile":deployment_profile.clone(),
                        "policy_versions":policy_versions.clone(),
                        "configuration_versions":configuration_versions.clone(),
                        "provider_versions":provider_versions.clone(),
                        "adapter_versions":adapter_versions.clone(),
                        "security_limit_profile":security_limit_profile.clone(),
                    },
                    "normalized_result":"pass",
                    "contains_secrets":false,
                    "provenance":{"evidence_tier":tier_value(2)},
                    "production_observation":{
                        "required":true,
                        "observation":{
                            "deployment_id":DEPLOYMENT_ID,
                            "normalized_result":"pass",
                            "observed_at":"2026-07-15T01:00:00Z",
                            "artifact_hashes":[ARTIFACT_DIGEST]
                        }
                    },
                    "evidence_lifecycle":"accepted",
                    "produced_at":"2026-07-15T00:00:00Z",
                    "verified_at":"2026-07-15T02:00:00Z",
                    "accepted_at":"2026-07-15T03:00:00Z",
                    "expires_at":EXPIRES_AT,
                    "supersedes_evidence_instance_id":null,
                    "supersedes_evidence_ref":null,
                });
                let digest = value_digest(&bundle);
                proofs.insert(
                    digest.clone(),
                    fixture_proof(
                        ConformanceDocumentKind::ConformanceBundle,
                        bundle["bundle_id"].as_str().unwrap(),
                        1,
                        &digest,
                        &instance.owning_work_package,
                        EvidenceTier::OperatorEnvironment,
                        u64::try_from(index).unwrap() + 1,
                        format!("acceptance:bundle:{index:03}"),
                    ),
                );
                bundle_index_by_instance.insert(instance.applicability_instance_id.clone(), index);
                bundles.push(bundle);
                bundle_digests.push(digest);
                bundle_locators.push(locator);
            }

            let mut receipts: Vec<Value> = Vec::with_capacity(PACKAGES.len());
            let mut receipt_digests: Vec<String> = Vec::with_capacity(PACKAGES.len());
            let mut receipt_locators: Vec<String> = Vec::with_capacity(PACKAGES.len());
            let mut receipt_index_by_package: BTreeMap<String, usize> = BTreeMap::new();
            for (package_index, package_id) in PACKAGES.iter().enumerate() {
                let trace_ids = traces
                    .iter()
                    .filter(|(_, trace)| trace["owning_work_package"] == *package_id)
                    .map(|(trace_id, _)| trace_id.clone())
                    .collect::<BTreeSet<_>>();
                let control_ids = trace_ids
                    .iter()
                    .map(|trace_id| traces[trace_id]["control_id"].as_str().unwrap().to_owned())
                    .collect::<BTreeSet<_>>();
                let acceptance_case_ids = trace_ids
                    .iter()
                    .map(|trace_id| {
                        traces[trace_id]["acceptance_case_id"]
                            .as_str()
                            .unwrap()
                            .to_owned()
                    })
                    .collect::<BTreeSet<_>>();
                let package_instances = applicability
                    .instances
                    .iter()
                    .filter(|instance| instance.owning_work_package == *package_id)
                    .collect::<Vec<_>>();
                let applicability_instances = package_instances
                    .iter()
                    .map(|instance| json!({
                        "instance_id":instance.applicability_instance_id,
                        "implementation_dimensions":serde_json::to_value(&instance.dimensions).unwrap(),
                        "deployment_dimensions":[],
                    }))
                    .collect::<Vec<_>>();
                let evidence_bindings = package_instances
                    .iter()
                    .map(|instance| {
                        let index = bundle_index_by_instance[&instance.applicability_instance_id];
                        json!({
                            "artifact_kind":"conformance-bundle",
                            "artifact_locator":bundle_locators[index],
                            "bundle_id":bundles[index]["bundle_id"].clone(),
                            "document_version":1,
                            "evidence_instance_id":bundles[index]["evidence_instance_id"].clone(),
                            "bundle_digest":bundle_digests[index],
                        })
                    })
                    .collect::<Vec<_>>();
                let prerequisite_receipts = required_prerequisite_packages(package_id)
                    .into_iter()
                    .map(|prerequisite_package| {
                        let index = receipt_index_by_package[&prerequisite_package];
                        let prerequisite = &receipts[index];
                        json!({
                            "artifact_kind":"package-exit-receipt",
                            "artifact_locator":receipt_locators[index],
                            "receipt_id":prerequisite["receipt_id"].clone(),
                            "document_version":1,
                            "receipt_digest":receipt_digests[index],
                            "package_id":prerequisite["package_id"].clone(),
                            "acceptance_status":prerequisite["acceptance_status"].clone(),
                            "production_accepted":prerequisite["production_accepted"].clone(),
                            "evidence_tier":prerequisite["evidence_tier"].clone(),
                            "result":prerequisite["result"].clone(),
                            "receipt_lifecycle":prerequisite["receipt_lifecycle"].clone(),
                            "expires_at":prerequisite["expires_at"].clone(),
                        })
                    })
                    .collect::<Vec<_>>();
                let mut input_digests = BTreeSet::from([
                    ledger_digest.clone(),
                    ARTIFACT_DIGEST.to_owned(),
                    deployment_profile["digest"].as_str().unwrap().to_owned(),
                    security_limit_profile["digest"]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                ]);
                for bindings in [
                    &policy_versions,
                    &configuration_versions,
                    &provider_versions,
                    &adapter_versions,
                ] {
                    for binding in bindings.as_array().unwrap() {
                        input_digests.insert(binding["digest"].as_str().unwrap().to_owned());
                    }
                }
                for prerequisite in &prerequisite_receipts {
                    input_digests
                        .insert(prerequisite["receipt_digest"].as_str().unwrap().to_owned());
                }
                let output_digests = evidence_bindings
                    .iter()
                    .map(|binding| binding["bundle_digest"].as_str().unwrap().to_owned())
                    .collect::<BTreeSet<_>>();
                let retirement_closure = if *package_id == "SB-9" {
                    let evidence_ids = evidence_bindings
                        .iter()
                        .map(|binding| binding["evidence_instance_id"].as_str().unwrap().to_owned())
                        .collect::<BTreeSet<_>>();
                    json!({
                        "zero_consumer_evidence_instance_ids":evidence_ids,
                        "zero_live_authority_evidence_instance_ids":evidence_ids,
                        "retired_bypass_evidence_instance_ids":evidence_ids,
                    })
                } else {
                    Value::Null
                };
                let id = receipt_id(package_id);
                let locator = receipt_locator(package_id);
                let receipt = json!({
                    "$schema":"https://ryuki.io/schemas/security-contracts/v1/package-exit-receipt.schema.json",
                    "contract_kind":"package-exit-receipt",
                    "document_version":1,
                    "receipt_id":id,
                    "package_id":package_id,
                    "acceptance_status":"production_accepted",
                    "production_accepted":true,
                    "ledger_binding":{
                        "artifact_kind":"control-trace",
                        "artifact_locator":ledger_locator,
                        "document_id":ledger["document_id"].clone(),
                        "document_version":ledger["document_version"].clone(),
                        "ledger_id":ledger["ledger_id"].clone(),
                        "ledger_version":ledger["ledger_version"].clone(),
                        "ledger_digest":ledger_digest,
                    },
                    "evaluated_sets":{
                        "trace_ids":trace_ids,
                        "control_ids":control_ids,
                        "acceptance_case_ids":acceptance_case_ids,
                        "evidence_bindings":evidence_bindings,
                    },
                    "applicability_instances":applicability_instances,
                    "closure_context":{
                        "source_revision":SOURCE_REVISION,
                        "artifact_digest":ARTIFACT_DIGEST,
                        "deployment_profile":deployment_profile.clone(),
                        "policy_versions":policy_versions.clone(),
                        "configuration_versions":configuration_versions.clone(),
                        "provider_versions":provider_versions.clone(),
                        "adapter_versions":adapter_versions.clone(),
                        "security_limit_profile":security_limit_profile.clone(),
                    },
                    "prerequisite_receipts":prerequisite_receipts,
                    "input_digests":input_digests,
                    "output_digests":output_digests,
                    "evidence_tier":tier_value(2),
                    "result":"pass",
                    "receipt_lifecycle":"accepted",
                    "waivers":[],
                    "retirement_closure":retirement_closure,
                    "created_at":"2026-07-15T05:00:00Z",
                    "expires_at":EXPIRES_AT,
                    "supersedes_receipt_id":null,
                    "supersedes_receipt_ref":null,
                });
                let digest = value_digest(&receipt);
                proofs.insert(
                    digest.clone(),
                    fixture_proof(
                        ConformanceDocumentKind::PackageExitReceipt,
                        receipt["receipt_id"].as_str().unwrap(),
                        1,
                        &digest,
                        package_id,
                        EvidenceTier::OperatorEnvironment,
                        200 + u64::try_from(package_index).unwrap(),
                        format!("acceptance:receipt:{package_id}"),
                    ),
                );
                receipt_index_by_package.insert((*package_id).to_owned(), package_index);
                receipts.push(receipt);
                receipt_digests.push(digest);
                receipt_locators.push(locator);
            }

            let root_index = receipt_index_by_package["SB-9"];
            let mut root_ref = root_ref;
            root_ref.content_digest = receipt_digests[root_index].clone();
            profile["production_acceptance_receipt_ref"] = serde_json::to_value(&root_ref).unwrap();
            for (guard_index, package_id) in guard_packages.iter().enumerate() {
                let receipt_index = receipt_index_by_package[*package_id];
                profile["runtime_guard_evidence"]["guards"][guard_index]["receipt_ref"]["content_digest"] =
                    json!(receipt_digests[receipt_index].clone());
            }
            assert_eq!(
                deployment_profile["digest"].as_str().unwrap(),
                deployment_profile_conformance_binding_digest(&profile).unwrap()
            );
            let current_root_acceptance_record_id = proofs[&root_ref.content_digest]
                .acceptance_record_id
                .clone();

            Self {
                ledger,
                ledger_digest,
                ledger_locator,
                applicability,
                profile,
                root_ref,
                deployment_profile,
                policy_versions,
                configuration_versions,
                provider_versions,
                adapter_versions,
                security_limit_profile,
                bundles,
                bundle_digests,
                bundle_locators,
                receipts,
                receipt_digests,
                receipt_locators,
                proofs,
                trusted_now: ConformanceTrustedTimeWindow {
                    not_before: timestamp("2026-07-16T12:00:00Z"),
                    not_after: timestamp("2026-07-16T12:01:00Z"),
                },
                current_root_acceptance_record_id,
            }
        }

        fn context(&self) -> ConformanceClosureContext<'_> {
            ConformanceClosureContext {
                deployment_id: DEPLOYMENT_ID,
                trust_domain_id: TRUST_DOMAIN_ID,
                source_revision: SOURCE_REVISION,
                artifact_digest: ARTIFACT_DIGEST,
                deployment_profile: &self.deployment_profile,
                policy_versions: &self.policy_versions,
                configuration_versions: &self.configuration_versions,
                provider_versions: &self.provider_versions,
                adapter_versions: &self.adapter_versions,
                security_limit_profile: &self.security_limit_profile,
                deployment_profile_document: &self.profile,
                production_acceptance_receipt_ref: &self.root_ref,
            }
        }

        fn verify(&self) -> Result<ClosureProjection, ConformanceClosureError> {
            let bundles = self
                .bundles
                .iter()
                .zip(&self.bundle_digests)
                .zip(&self.bundle_locators)
                .map(
                    |((value, raw_digest), artifact_locator)| LoadedConformanceDocument {
                        artifact_locator,
                        raw_digest,
                        value,
                    },
                )
                .collect::<Vec<_>>();
            let receipts = self
                .receipts
                .iter()
                .zip(&self.receipt_digests)
                .zip(&self.receipt_locators)
                .map(
                    |((value, raw_digest), artifact_locator)| LoadedConformanceDocument {
                        artifact_locator,
                        raw_digest,
                        value,
                    },
                )
                .collect::<Vec<_>>();
            verify_with_proof_facts(
                ControlTraceArtifact {
                    value: &self.ledger,
                    raw_digest: &self.ledger_digest,
                    artifact_locator: &self.ledger_locator,
                },
                &bundles,
                &receipts,
                &self.proofs,
                self.context(),
                &self.applicability,
                self.trusted_now,
                None,
                &digest_bytes(&canonical_json_bytes(&self.profile).unwrap()),
                &self.root_ref.content_digest,
                &self.current_root_acceptance_record_id,
            )
        }

        fn receipt_index(&self, package_id: &str) -> usize {
            self.receipts
                .iter()
                .position(|receipt| receipt["package_id"] == package_id)
                .unwrap()
        }

        fn propagate_profile_binding(&mut self) {
            let old_digest = self.deployment_profile["digest"]
                .as_str()
                .unwrap()
                .to_owned();
            let new_digest = deployment_profile_conformance_binding_digest(&self.profile).unwrap();
            self.deployment_profile["digest"] = json!(new_digest.clone());
            for bundle in &mut self.bundles {
                bundle["bindings"]["deployment_profile"] = self.deployment_profile.clone();
            }
            for receipt in &mut self.receipts {
                receipt["closure_context"]["deployment_profile"] = self.deployment_profile.clone();
                let values = receipt["input_digests"].as_array_mut().unwrap();
                for value in values.iter_mut() {
                    if value.as_str() == Some(old_digest.as_str()) {
                        *value = json!(new_digest.clone());
                    }
                }
                values.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
            }
        }

        fn add_bundle_successor(&mut self) -> (String, String) {
            let target_index = self
                .bundle_digests
                .iter()
                .position(|digest| self.proofs[digest].package_id == "SB-5")
                .unwrap();
            let target = self.bundles[target_index].clone();
            let target_digest = self.bundle_digests[target_index].clone();
            let target_locator = self.bundle_locators[target_index].clone();
            let target_evidence_id = target["evidence_instance_id"].as_str().unwrap().to_owned();
            let successor_evidence_id = format!("{target_evidence_id}:successor");
            let successor_bundle_id =
                format!("{}:successor", target["bundle_id"].as_str().unwrap());
            let successor_locator = "fixtures/bundles/successor.json".to_owned();
            let mut successor = target.clone();
            successor["document_version"] = json!(2);
            successor["bundle_id"] = json!(successor_bundle_id);
            successor["evidence_instance_id"] = json!(successor_evidence_id);
            successor["supersedes_evidence_instance_id"] = json!(target_evidence_id);
            successor["supersedes_evidence_ref"] = json!({
                "artifact_kind":"conformance-bundle",
                "bundle_id":target["bundle_id"].clone(),
                "document_version":1,
                "artifact_locator":target_locator,
                "evidence_instance_id":target["evidence_instance_id"].clone(),
                "bundle_digest":target_digest,
            });
            let successor_digest = value_digest(&successor);
            let mut proof = self.proofs[&target_digest].clone();
            proof.document_id = successor["bundle_id"].as_str().unwrap().to_owned();
            proof.document_version = 2;
            proof.complete_document_digest = successor_digest.clone();
            proof.acceptance_record_id = "acceptance:bundle:successor".into();
            proof.acceptance_sequence = 150;
            self.proofs.insert(successor_digest.clone(), proof);
            self.bundles.push(successor);
            self.bundle_digests.push(successor_digest.clone());
            self.bundle_locators.push(successor_locator.clone());

            let package_id = self.proofs[&successor_digest].package_id.clone();
            let receipt_index = self.receipt_index(&package_id);
            let bindings = self.receipts[receipt_index]["evaluated_sets"]["evidence_bindings"]
                .as_array_mut()
                .unwrap();
            let binding = bindings
                .iter_mut()
                .find(|binding| {
                    binding["evidence_instance_id"].as_str() == Some(target_evidence_id.as_str())
                })
                .unwrap();
            binding["artifact_locator"] = json!(successor_locator);
            binding["bundle_id"] = self.bundles.last().unwrap()["bundle_id"].clone();
            binding["document_version"] = json!(2);
            binding["evidence_instance_id"] = json!(successor_evidence_id);
            binding["bundle_digest"] = json!(successor_digest.clone());
            let outputs = self.receipts[receipt_index]["output_digests"]
                .as_array_mut()
                .unwrap();
            for digest in outputs.iter_mut() {
                if digest.as_str() == Some(target_digest.as_str()) {
                    *digest = json!(successor_digest.clone());
                }
            }
            outputs.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
            (target_digest, successor_digest)
        }
    }

    const FIXTURE_REGISTRY_ID: &str = "conformance-trust-root-registry:closure-fixture";
    const FIXTURE_REGISTRY_LOCATOR: &str = "fixtures/trust/conformance-registry.json";
    const FIXTURE_SIGNER_ID: &str = "signer:closure-fixture";
    const FIXTURE_SIGNING_KEY_ID: &str = "conformance-key:closure-fixture";
    const FIXTURE_AUTHORITY_ID: &str = "conformance-trust-checkpoint-authority:closure-fixture";
    const FIXTURE_AUTHORITY_KEY_ID: &str = "conformance-trust-checkpoint-key:closure-fixture";
    const FIXTURE_AUTHORITY_EPOCH: u64 = 7;
    const FIXTURE_AUTHORITY_REVISION: u64 = 11;
    const FIXTURE_CHECKPOINT_SEQUENCE: u64 = 1_000;

    #[derive(Debug)]
    struct SignedFixtureDocument {
        kind: ConformanceDocumentKind,
        package_id: String,
        artifact_locator: String,
        value: Value,
        raw_bytes: Vec<u8>,
        raw_digest: String,
        acceptance_record_id: String,
        acceptance_sequence: u64,
    }

    fn fixture_registry(signing_key: &SigningKey) -> (Vec<u8>, String, String) {
        let public_key = signing_key.verifying_key().to_bytes();
        let fingerprint = digest_bytes(&public_key);
        let registry = json!({
            "$schema": TRUST_REGISTRY_SCHEMA_URI,
            "schema_version": TRUST_REGISTRY_SCHEMA_VERSION,
            "contract_kind": TRUST_REGISTRY_CONTRACT_KIND,
            "document_id": FIXTURE_REGISTRY_ID,
            "document_version": 1,
            "predecessor_registry_ref": null,
            "acceptance_status": "production_accepted",
            "production_accepted": true,
            "lifecycle": {
                "state": "active",
                "effective_at": "2026-01-01T00:00:00Z"
            },
            "applicability": {
                "evaluation_scope": "deployment",
                "security_profiles": ["production"],
                "deployment_ids": [DEPLOYMENT_ID],
                "trust_domain_ids": [TRUST_DOMAIN_ID]
            },
            "trust_policy_version": 1,
            "canonicalization_profiles": [CANONICALIZATION_PROFILE],
            "signature_algorithms": [SIGNATURE_ALGORITHM],
            "keys": [{
                "key_id": FIXTURE_SIGNING_KEY_ID,
                "signer_identity": FIXTURE_SIGNER_ID,
                "algorithm": SIGNATURE_ALGORITHM,
                "public_key_base64": BASE64_STANDARD.encode(public_key),
                "public_key_fingerprint": fingerprint,
                "allowed_purposes": ["conformance_bundle", "package_exit_receipt"],
                "allowed_evidence_tiers": ["externally_attested"],
                "allowed_package_ids": PACKAGES,
                "deployment_ids": [DEPLOYMENT_ID],
                "trust_domain_ids": [TRUST_DOMAIN_ID],
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2028-01-01T00:00:00Z",
                "lifecycle": "active",
                "supersedes_key_id": null
            }],
            "key_tombstones": []
        });
        let raw_bytes = canonical_json_bytes(&registry).unwrap();
        let raw_digest = digest_bytes(&raw_bytes);
        (raw_bytes, raw_digest, fingerprint)
    }

    fn sign_fixture_document(
        mut value: Value,
        kind: ConformanceDocumentKind,
        package_id: &str,
        artifact_locator: String,
        acceptance_sequence: u64,
        signing_key: &SigningKey,
        registry_digest: &str,
    ) -> SignedFixtureDocument {
        let (purpose, domain) = match kind {
            ConformanceDocumentKind::ConformanceBundle => {
                ("conformance_bundle", CONFORMANCE_BUNDLE_DOMAIN)
            }
            ConformanceDocumentKind::PackageExitReceipt => {
                ("package_exit_receipt", PACKAGE_EXIT_RECEIPT_DOMAIN)
            }
        };
        value["schema_version"] = json!(TRUST_REGISTRY_SCHEMA_VERSION);
        value["signer"] = json!({
            "signature_version": SIGNATURE_VERSION,
            "identity": FIXTURE_SIGNER_ID,
            "key_id": FIXTURE_SIGNING_KEY_ID,
            "algorithm": SIGNATURE_ALGORITHM,
            "canonicalization": CANONICALIZATION_PROFILE,
            "purpose": purpose,
            "domain": domain,
            "trust_registry_id": FIXTURE_REGISTRY_ID,
            "trust_registry_version": 1,
            "trust_registry_digest": registry_digest,
            "signed_at": "2026-07-15T05:30:00Z",
            "signed_subject_digest": test_digest("placeholder-signed-subject"),
            "signature_base64": BASE64_STANDARD.encode([0_u8; 64]),
        });
        let subject_digest = conformance_signed_subject_digest(&value).unwrap();
        value["signer"]["signed_subject_digest"] = json!(subject_digest);
        let signature = signing_key.sign(&conformance_signing_bytes(&value).unwrap());
        value["signer"]["signature_base64"] = json!(BASE64_STANDARD.encode(signature.to_bytes()));
        let raw_bytes = canonical_json_bytes(&value).unwrap();
        let raw_digest = digest_bytes(&raw_bytes);
        SignedFixtureDocument {
            kind,
            package_id: package_id.to_owned(),
            artifact_locator,
            value,
            raw_bytes,
            raw_digest,
            acceptance_record_id: format!(
                "conformance-acceptance:closure-fixture-{acceptance_sequence:04}"
            ),
            acceptance_sequence,
        }
    }

    fn fixture_acceptance_record(
        document: &SignedFixtureDocument,
        signing_key_fingerprint: &str,
        registry_digest: &str,
    ) -> Value {
        let (document_id_field, purpose) = match document.kind {
            ConformanceDocumentKind::ConformanceBundle => ("bundle_id", "conformance_bundle"),
            ConformanceDocumentKind::PackageExitReceipt => ("receipt_id", "package_exit_receipt"),
        };
        let signature = BASE64_STANDARD
            .decode(
                document.value["signer"]["signature_base64"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        json!({
            "acceptance_record_id": document.acceptance_record_id,
            "document": {
                "contract_kind": document.kind.as_str(),
                "document_id": document.value[document_id_field].clone(),
                "document_version": document.value["document_version"].clone(),
                "complete_document_digest": document.raw_digest,
                "signature_digest": digest_bytes(&signature),
                "signed_subject_digest": document.value["signer"]["signed_subject_digest"].clone(),
            },
            "signer": {
                "key_id": FIXTURE_SIGNING_KEY_ID,
                "public_key_fingerprint": signing_key_fingerprint,
            },
            "registry": {
                "registry_id": FIXTURE_REGISTRY_ID,
                "registry_version": 1,
                "registry_digest": registry_digest,
                "artifact_locator": FIXTURE_REGISTRY_LOCATOR,
                "head_sequence": 1,
                "head_authority_revision": 1,
            },
            "deployment_id": DEPLOYMENT_ID,
            "trust_domain_id": TRUST_DOMAIN_ID,
            "work_package_id": document.package_id,
            "purpose": purpose,
            "evidence_tier": "externally_attested",
            "authority_sequence": document.acceptance_sequence,
            "authority_epoch": FIXTURE_AUTHORITY_EPOCH,
            "accepted_at": {
                "not_before": "2026-07-15T06:00:00Z",
                "not_after": "2026-07-15T07:00:00Z",
            },
            "lifecycle": "accepted",
        })
    }

    fn write_fixture_frame(output: &mut Vec<u8>, bytes: &[u8]) {
        output.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        output.extend_from_slice(bytes);
    }

    fn signed_fixture_response(
        request: &crate::conformance_trust::ConformanceCheckpointRequest,
        acceptance_records: Vec<Value>,
        root_acceptance_record_id: &str,
        authority_key: &SigningKey,
        authority_fingerprint: &str,
    ) -> Vec<u8> {
        let request_value: Value = serde_json::from_slice(request.as_bytes()).unwrap();
        let mut response = json!({
            "schema_version": TRUST_RECONCILIATION_PROTOCOL_VERSION,
            "contract_kind": TRUST_RECONCILIATION_RESPONSE_KIND,
            "canonicalization": CANONICALIZATION_PROFILE,
            "signature_algorithm": SIGNATURE_ALGORITHM,
            "authority": {
                "authority_id": FIXTURE_AUTHORITY_ID,
                "key_id": FIXTURE_AUTHORITY_KEY_ID,
                "public_key_fingerprint": authority_fingerprint,
            },
            "request_nonce": request_value["request_nonce"].clone(),
            "request_digest": request.digest(),
            "namespace": request_value["namespace"].clone(),
            "candidate_head": request_value["candidate_head"].clone(),
            "current_head": request_value["candidate_head"].clone(),
            "candidate_production_root": request_value["candidate_production_root"].clone(),
            "current_production_root": {
                "receipt_ref": request_value["candidate_production_root"].clone(),
                "acceptance_record_id": root_acceptance_record_id,
            },
            "validated_lineage_digest": request_value["validated_lineage_digest"].clone(),
            "state": "external_strongly_consistent",
            "outcome": "matched",
            "reconciliation": {
                "candidate_matches_current": true,
                "candidate_production_root_matches_current": true,
                "restored_state_reconciled": true,
                "no_auto_advance": true,
            },
            "checkpoint": {
                "sequence": FIXTURE_CHECKPOINT_SEQUENCE,
                "authority_epoch": FIXTURE_AUTHORITY_EPOCH,
                "authority_revision": FIXTURE_AUTHORITY_REVISION,
                "observed_at": {
                    "not_before": "2026-07-16T11:59:58Z",
                    "not_after": "2026-07-16T11:59:59Z",
                },
                "valid_until": "2026-07-16T12:04:00Z",
            },
            "acceptance_records": acceptance_records,
            "signature_base64": BASE64_STANDARD.encode([0_u8; 64]),
        });
        let mut subject = response.clone();
        subject.as_object_mut().unwrap().remove("signature_base64");
        let canonical = canonical_json_bytes(&subject).unwrap();
        let mut signing_bytes = Vec::new();
        write_fixture_frame(
            &mut signing_bytes,
            TRUST_RECONCILIATION_RESPONSE_DOMAIN.as_bytes(),
        );
        write_fixture_frame(&mut signing_bytes, &canonical);
        let signature = authority_key.sign(&signing_bytes);
        response["signature_base64"] = json!(BASE64_STANDARD.encode(signature.to_bytes()));
        canonical_json_bytes(&response).unwrap()
    }

    fn fixture_manifest(
        ledger: &Value,
        control_trace_ref: &VersionedContentReference,
    ) -> ProductionBuildManifest {
        let oidc_baseline_digest = test_digest("fixture-oidc-adapter-baseline");
        let secret_baseline_digest = test_digest("fixture-secret-adapter-baseline");
        let mut manifest: ProductionBuildManifest = serde_json::from_value(json!({
            "$schema": crate::production_build::PRODUCTION_BUILD_MANIFEST_SCHEMA_URI,
            "schema_version": crate::production_build::PRODUCTION_BUILD_MANIFEST_SCHEMA_VERSION,
            "contract_kind": crate::production_build::PRODUCTION_BUILD_MANIFEST_CONTRACT_KIND,
            "document_id": "production-build-manifest:closure-fixture",
            "document_version": 1,
            "component": {
                "component_id": "component:ryuki-api",
                "component_version": "1.0.0",
                "executable_name": "ryuki-api",
                "target": {
                    "architecture": "x86_64",
                    "operating_system": "linux",
                    "family": "unix",
                    "pointer_width_bits": 64,
                    "endian": "little",
                },
            },
            "source": {
                "revision_algorithm": "git_sha1",
                "revision": SOURCE_REVISION,
            },
            "runtime_executable": {
                "content_digest": test_digest("fixture-runtime-executable"),
                "byte_length": 42,
            },
            "oci_subject": {
                "subject_kind": "oci_image_manifest",
                "repository": "ghcr.io/ryuki/ryuki-api",
                "content_digest": ARTIFACT_DIGEST,
            },
            "control_trace_ref": control_trace_ref,
            "shipped_adapters": [
                {
                    "adapter_kind": "auth.oidc",
                    "adapter_version": "1.0.0",
                    "production_eligible": true,
                    "capability_ids": ["authenticate"],
                    "mandatory_baseline": {
                        "document_id": "provider-capability-baseline:closure-oidc",
                        "document_version": 1,
                        "content_digest": oidc_baseline_digest,
                        "artifact_locator": "fixtures/providers/closure-oidc-baseline.json",
                        "required_trace_ids": ["TRACE-SB-CONF-05-AC-055"],
                    },
                },
                {
                    "adapter_kind": "secrets.service",
                    "adapter_version": "1.0.0",
                    "production_eligible": true,
                    "capability_ids": ["secret-read", "secret-renew"],
                    "mandatory_baseline": {
                        "document_id": "provider-capability-baseline:closure-secrets",
                        "document_version": 1,
                        "content_digest": secret_baseline_digest,
                        "artifact_locator": "fixtures/providers/closure-secrets-baseline.json",
                        "required_trace_ids": ["TRACE-SB-CONF-05-AC-055"],
                    },
                }
            ],
            "selector_dispositions": [{
                "selector_domain": "auth_mode",
                "selector": "fixture",
                "disposition": "implemented",
                "adapter_kind": "auth.oidc",
            }],
            "implementation_applicability": {
                "identity_contract": APPLICABILITY_IDENTITY_CONTRACT,
                "inventory_contract": APPLICABILITY_INVENTORY_CONTRACT,
                "instance_count": 1,
                "content_digest": test_digest("placeholder-implementation-applicability"),
            },
            "implementation_applicability_instances": [],
        }))
        .unwrap();
        let implementation = derive_implementation_applicability(ledger, &manifest).unwrap();
        manifest.implementation_applicability = implementation.binding;
        manifest.implementation_applicability_instances = implementation.instances;
        manifest
    }

    fn fixture_deployment_claims(
        profile: &DeploymentSecurityProfile,
        manifest: &ProductionBuildManifest,
    ) -> ProductionDeploymentApplicabilityClaims {
        let provider_claim =
            |provider_id: &str,
             provider_kind: &str,
             adapter: &crate::production_build::ShippedAdapter| {
                let provider_name = provider_id
                    .strip_prefix("provider:")
                    .expect("fixture provider ids are canonical");
                ActiveProviderApplicabilityClaim {
                    provider_id: provider_id.into(),
                    provider_kind: provider_kind.into(),
                    configuration_version: 1,
                    configuration_payload_digest: test_digest(&format!(
                        "{provider_id}-configuration"
                    )),
                    lifecycle_record_version: 1,
                    lifecycle_state: ProviderLifecycleState::Active,
                    trust_domain_id: TRUST_DOMAIN_ID.into(),
                    descriptor_id: format!("capability-descriptor:{provider_name}"),
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
                }
            };
        let oidc_adapter = manifest
            .shipped_adapters
            .iter()
            .find(|adapter| adapter.adapter_kind == "auth.oidc")
            .expect("fixture manifest contains the OIDC adapter");
        let secret_adapter = manifest
            .shipped_adapters
            .iter()
            .find(|adapter| adapter.adapter_kind == "secrets.service")
            .expect("fixture manifest contains the secret-service adapter");
        ProductionDeploymentApplicabilityClaims {
            checkpoints: vec![DeploymentCheckpointApplicabilityClaim {
                trust_domain_id: TRUST_DOMAIN_ID.into(),
                authority_id: FIXTURE_AUTHORITY_ID.into(),
                authority_epoch: FIXTURE_AUTHORITY_EPOCH,
                sequence: FIXTURE_CHECKPOINT_SEQUENCE,
                trust_registry_digest: profile
                    .conformance_trust_root_registry_ref
                    .content_digest
                    .clone(),
                trust_registry_locator: profile
                    .conformance_trust_root_registry_ref
                    .artifact_locator
                    .clone(),
            }],
            provider_registry: ActiveProviderRegistryApplicabilityClaim {
                document_id: profile.provider_registry_ref.document_id.clone(),
                document_version: profile.provider_registry_ref.document_version,
                content_digest: profile.provider_registry_ref.content_digest.clone(),
                artifact_locator: profile.provider_registry_ref.artifact_locator.clone(),
                registry_version: 1,
                active_providers: vec![
                    provider_claim("provider:closure-oidc", "oidc", oidc_adapter),
                    provider_claim("provider:closure-secrets", "secret-service", secret_adapter),
                ],
            },
            security_limit_profile: SecurityLimitApplicabilityClaim {
                document_id: profile.security_limit_profile_ref.document_id.clone(),
                document_version: profile.security_limit_profile_ref.document_version,
                content_digest: profile.security_limit_profile_ref.content_digest.clone(),
                artifact_locator: profile.security_limit_profile_ref.artifact_locator.clone(),
                profile_version: 1,
            },
            deployed_artifact: DeployedArtifactApplicabilityClaim {
                subject_kind: manifest.oci_subject.subject_kind,
                repository: manifest.oci_subject.repository.clone(),
                subject_digest: manifest.oci_subject.content_digest.clone(),
            },
        }
    }

    fn focused_authenticator_binding(
        provider_id: &str,
        authenticator_kind: ProductionAuthenticatorKind,
    ) -> ExpectedAuthenticatorBinding {
        let provider_name = provider_id
            .strip_prefix("provider:")
            .expect("focused fixture provider id is canonical");
        ExpectedAuthenticatorBinding {
            provider: ExpectedProviderBinding {
                provider_id: provider_id.into(),
                configuration_version: 1,
                configuration_payload_digest: test_digest(&format!("{provider_id}-configuration")),
                lifecycle_record_version: 1,
                lifecycle_state: ProviderLifecycleState::Active,
                capability_descriptor_id: format!("capability-descriptor:{provider_name}"),
                capability_descriptor_version: 1,
                adapter_kind: format!("auth.{provider_name}"),
                adapter_version: "1.0.0".into(),
            },
            authenticator_kind,
            runtime_binding_digest: test_digest(&format!("{provider_id}-runtime-binding")),
        }
    }

    fn focused_authenticator_claim(
        binding: &ExpectedAuthenticatorBinding,
        provider_kind: &str,
    ) -> ActiveProviderApplicabilityClaim {
        ActiveProviderApplicabilityClaim {
            provider_id: binding.provider.provider_id.clone(),
            provider_kind: provider_kind.into(),
            configuration_version: binding.provider.configuration_version,
            configuration_payload_digest: binding.provider.configuration_payload_digest.clone(),
            lifecycle_record_version: binding.provider.lifecycle_record_version,
            lifecycle_state: binding.provider.lifecycle_state,
            trust_domain_id: TRUST_DOMAIN_ID.into(),
            descriptor_id: binding.provider.capability_descriptor_id.clone(),
            descriptor_version: binding.provider.capability_descriptor_version,
            adapter_kind: binding.provider.adapter_kind.clone(),
            adapter_version: binding.provider.adapter_version.clone(),
            advertised_capability_ids: vec!["authenticate".into()],
            production_eligible: true,
            mandatory_baseline_ref: ProviderMandatoryBaselineClaim {
                document_id: format!(
                    "provider-capability-baseline:{}",
                    binding
                        .provider
                        .provider_id
                        .strip_prefix("provider:")
                        .unwrap()
                ),
                document_version: 1,
                content_digest: test_digest(&format!("{}-baseline", binding.provider.provider_id)),
                artifact_locator: format!(
                    "fixtures/providers/{}-baseline.json",
                    binding
                        .provider
                        .provider_id
                        .strip_prefix("provider:")
                        .unwrap()
                ),
            },
        }
    }

    fn focused_all_authenticator_classes() -> (
        Vec<ExpectedAuthenticatorBinding>,
        Vec<ActiveProviderApplicabilityClaim>,
    ) {
        let classes = [
            (
                "provider:focused-api-token",
                "api-token",
                ProductionAuthenticatorKind::ApiToken,
            ),
            (
                "provider:focused-local-webauthn",
                "local-webauthn",
                ProductionAuthenticatorKind::Passkey,
            ),
            (
                "provider:focused-oauth-service",
                "oauth-service",
                ProductionAuthenticatorKind::OauthService,
            ),
            (
                "provider:focused-oidc",
                "oidc",
                ProductionAuthenticatorKind::Oidc,
            ),
            (
                "provider:focused-oidc-broker",
                "oidc-broker",
                ProductionAuthenticatorKind::OidcBroker,
            ),
            (
                "provider:focused-workload",
                "workload",
                ProductionAuthenticatorKind::Workload,
            ),
        ];
        let authenticators = classes
            .iter()
            .map(|(provider_id, _, authenticator_kind)| {
                focused_authenticator_binding(provider_id, *authenticator_kind)
            })
            .collect::<Vec<_>>();
        let claims = authenticators
            .iter()
            .zip(classes)
            .map(|(binding, (_, provider_kind, _))| {
                focused_authenticator_claim(binding, provider_kind)
            })
            .collect();
        (authenticators, claims)
    }

    fn validate_focused_authenticator_inventory(
        authenticators: &[ExpectedAuthenticatorBinding],
        active_providers: &[ActiveProviderApplicabilityClaim],
        inventory_digest: &str,
    ) -> Result<(), ConformanceClosureError> {
        let claims_by_id = active_providers
            .iter()
            .map(|claim| (claim.provider_id.as_str(), claim))
            .collect::<BTreeMap<_, _>>();
        validate_authenticator_provider_bindings(
            inventory_digest,
            authenticators,
            active_providers,
            &claims_by_id,
            TRUST_DOMAIN_ID,
        )
    }

    fn focused_secret_binding(provider_id: &str) -> ExpectedSecretProviderBinding {
        let provider_name = provider_id
            .strip_prefix("provider:")
            .expect("focused fixture provider id is canonical");
        ExpectedSecretProviderBinding {
            provider: ExpectedProviderBinding {
                provider_id: provider_id.into(),
                configuration_version: 1,
                configuration_payload_digest: test_digest(&format!("{provider_id}-configuration")),
                lifecycle_record_version: 1,
                lifecycle_state: ProviderLifecycleState::Active,
                capability_descriptor_id: format!("capability-descriptor:{provider_name}"),
                capability_descriptor_version: 1,
                adapter_kind: "secrets.service".into(),
                adapter_version: "1.0.0".into(),
            },
            runtime_binding_digest: test_digest(&format!("{provider_id}-runtime-binding")),
        }
    }

    fn focused_secret_claim(
        binding: &ExpectedSecretProviderBinding,
    ) -> ActiveProviderApplicabilityClaim {
        let provider = &binding.provider;
        ActiveProviderApplicabilityClaim {
            provider_id: provider.provider_id.clone(),
            provider_kind: "secret-service".into(),
            configuration_version: provider.configuration_version,
            configuration_payload_digest: provider.configuration_payload_digest.clone(),
            lifecycle_record_version: provider.lifecycle_record_version,
            lifecycle_state: provider.lifecycle_state,
            trust_domain_id: TRUST_DOMAIN_ID.into(),
            descriptor_id: provider.capability_descriptor_id.clone(),
            descriptor_version: provider.capability_descriptor_version,
            adapter_kind: provider.adapter_kind.clone(),
            adapter_version: provider.adapter_version.clone(),
            advertised_capability_ids: vec!["secret-read".into(), "secret-renew".into()],
            production_eligible: true,
            mandatory_baseline_ref: ProviderMandatoryBaselineClaim {
                document_id: format!(
                    "provider-capability-baseline:{}",
                    provider.provider_id.strip_prefix("provider:").unwrap()
                ),
                document_version: 1,
                content_digest: test_digest(&format!("{}-baseline", provider.provider_id)),
                artifact_locator: format!(
                    "fixtures/providers/{}-baseline.json",
                    provider.provider_id.strip_prefix("provider:").unwrap()
                ),
            },
        }
    }

    fn validate_focused_secret_inventory(
        providers: &[ExpectedSecretProviderBinding],
        required_capability_ids: &[String],
        active_providers: &[ActiveProviderApplicabilityClaim],
        inventory_digest: &str,
    ) -> Result<(), ConformanceClosureError> {
        let claims_by_id = active_providers
            .iter()
            .map(|claim| (claim.provider_id.as_str(), claim))
            .collect::<BTreeMap<_, _>>();
        validate_secret_provider_bindings(
            inventory_digest,
            providers,
            required_capability_ids,
            active_providers,
            &claims_by_id,
            TRUST_DOMAIN_ID,
        )
    }

    fn fixture_version_context(
        profile: &DeploymentSecurityProfile,
        manifest: &ProductionBuildManifest,
        claims: &ProductionDeploymentApplicabilityClaims,
        profile_document: &Value,
    ) -> (Value, Value, Value, Value, Value, Value) {
        let deployment_profile = json!({
            "id": profile.document_id,
            "version": profile.document_version.to_string(),
            "deployment_id": profile.deployment_id,
            "digest_contract": DEPLOYMENT_PROFILE_CONFORMANCE_BINDING_DIGEST_CONTRACT,
            "digest": deployment_profile_conformance_binding_digest(profile_document).unwrap(),
        });
        let policy_versions = Value::Array(profile_policy_version_bindings(profile));
        let configuration_versions = Value::Array(profile_configuration_version_bindings(profile));
        let mut provider_versions = claims
            .provider_registry
            .active_providers
            .iter()
            .map(|provider| {
                json!({
                    "id": provider.provider_id,
                    "version": provider.configuration_version.to_string(),
                    "digest": provider.configuration_payload_digest,
                })
            })
            .collect::<Vec<_>>();
        provider_versions.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
        let mut adapter_versions = manifest
            .shipped_adapters
            .iter()
            .map(|adapter| {
                json!({
                    "id": adapter.adapter_kind,
                    "version": adapter.adapter_version,
                    "digest": adapter.mandatory_baseline.content_digest,
                })
            })
            .collect::<Vec<_>>();
        adapter_versions.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
        let limit = &claims.security_limit_profile;
        let security_limit_profile = json!({
            "id": limit.document_id,
            "version": limit.profile_version.to_string(),
            "digest": limit.content_digest,
        });
        (
            deployment_profile,
            policy_versions,
            configuration_versions,
            Value::Array(provider_versions),
            Value::Array(adapter_versions),
            security_limit_profile,
        )
    }

    #[derive(Debug, Clone, Copy)]
    enum PublicFixtureMutation {
        None,
        OverlayRetiresWithinVerificationWindow,
        OverlayWithEarlierSemanticExpiry,
        WrongDerivedProfile,
        WrongTypedProfile,
        WrongGuardExpectedValue,
        UnknownGuardProvider,
        MismatchedGuardProviderProjection,
        MissingSecretCapability,
        AuthenticatorProviderKindMismatch,
        DevelopmentProviderClaim,
    }

    fn verify_public_fixture(
        mutation: PublicFixtureMutation,
    ) -> Result<VerifiedConformanceClosure, String> {
        let signing_key = SigningKey::from_bytes(&public_fixture_entropy(b"document signer"));
        let authority_key = SigningKey::from_bytes(&public_fixture_entropy(b"authority signer"));
        let (registry_raw, registry_digest, signing_key_fingerprint) =
            fixture_registry(&signing_key);

        let mut ledger: Value = serde_json::from_str(CONTROL_TRACE_JSON).unwrap();
        ledger["acceptance_status"] = json!("production_accepted");
        ledger["production_accepted"] = json!(true);
        let ledger_raw = canonical_json_bytes(&ledger).unwrap();
        let ledger_digest = digest_bytes(&ledger_raw);
        let ledger_locator =
            "catalog/security-contracts/v1/control-trace.implementation.json".to_owned();
        let traces = ledger["traces"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|trace| trace["trace_lifecycle"] == "active")
            .map(|trace| {
                (
                    trace["trace_id"].as_str().unwrap().to_owned(),
                    trace.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();

        let mut first_control_by_package = BTreeMap::new();
        for trace in traces.values() {
            first_control_by_package
                .entry(trace["owning_work_package"].as_str().unwrap().to_owned())
                .or_insert_with(|| trace["control_id"].as_str().unwrap().to_owned());
        }

        let mut profile: Value = serde_json::from_str(PROFILE_JSON).unwrap();
        profile["security_profile"] = json!("production");
        profile["deployment_id"] = json!(DEPLOYMENT_ID);
        profile["tenancy_mode"] = json!("single_tenant");
        profile["applicability"]["security_profiles"] = json!(["production"]);
        profile["applicability"]["deployment_ids"] = json!([DEPLOYMENT_ID]);
        profile["lifecycle"]["state"] = json!("active");
        profile["lifecycle"]["effective_at"] = json!("2026-07-15T00:00:00Z");
        profile["trust_topology"]["trust_domain_ids"] = json!([TRUST_DOMAIN_ID]);
        profile["control_trace_ref"] = json!({
            "artifact_kind": "control-trace",
            "document_id": ledger["document_id"].clone(),
            "document_version": ledger["document_version"].clone(),
            "content_digest": ledger_digest,
            "artifact_locator": ledger_locator,
        });
        profile["conformance_trust_root_registry_ref"] = json!({
            "artifact_kind": "conformance-trust-root-registry",
            "document_id": FIXTURE_REGISTRY_ID,
            "document_version": 1,
            "content_digest": registry_digest,
            "artifact_locator": FIXTURE_REGISTRY_LOCATOR,
        });
        let mut root_ref = VersionedContentReference {
            artifact_kind: ArtifactKind::PackageExitReceipt,
            document_id: receipt_id("SB-9"),
            document_version: 1,
            content_digest: test_digest("placeholder-public-root"),
            artifact_locator: receipt_locator("SB-9"),
        };
        profile["production_acceptance_receipt_ref"] = serde_json::to_value(&root_ref).unwrap();
        if matches!(
            mutation,
            PublicFixtureMutation::OverlayRetiresWithinVerificationWindow
                | PublicFixtureMutation::OverlayWithEarlierSemanticExpiry
        ) {
            let retirement_deadline = match mutation {
                PublicFixtureMutation::OverlayRetiresWithinVerificationWindow => {
                    "2026-07-16T12:00:03Z"
                }
                PublicFixtureMutation::OverlayWithEarlierSemanticExpiry => "2026-07-16T12:00:10Z",
                _ => unreachable!(),
            };
            profile["migration_overlay"] = json!({
                "overlay_id": "migration-overlay:public-closure-fixture",
                "overlay_version": 1,
                "security_profile": "production",
                "authority_source": "provider_registry",
                "legacy_selector_present": true,
                "provider_registry_present": true,
                "retirement_deadline": retirement_deadline,
                "conflict_telemetry_name": "security_migration_conflicts_total",
                "grants_authority": false,
                "live_execution_allowed": false,
                "zero_consumer_receipt_ref": root_ref.clone(),
            });
        }
        let guard_packages = &PACKAGES[..8];
        profile["runtime_guard_evidence"] = json!({
            "mode": "receipt_bound",
            "runtime_cross_check_required": true,
            "guards": guard_packages
                .iter()
                .enumerate()
                .map(|(index, package_id)| json!({
                    "guard_id": guard_id(index),
                    "control_ids": [first_control_by_package[*package_id].clone()],
                    "receipt_ref": {
                        "artifact_kind": "package-exit-receipt",
                        "document_id": receipt_id(package_id),
                        "document_version": 1,
                        "content_digest": test_digest(&format!("placeholder-public-{package_id}")),
                        "artifact_locator": receipt_locator(package_id),
                    },
                    "expected_value": guard_expected_value(index),
                }))
                .collect::<Vec<_>>(),
        });
        match mutation {
            PublicFixtureMutation::UnknownGuardProvider => {
                profile["runtime_guard_evidence"]["guards"][1]["expected_value"]["providers"][0]
                    ["provider"]["provider_id"] = json!("provider:closure-unknown");
                refresh_secret_provider_inventory_digest(&mut profile);
            }
            PublicFixtureMutation::MissingSecretCapability => {
                profile["runtime_guard_evidence"]["guards"][1]["expected_value"]["required_capability_ids"] =
                    json!(["secret-admin"]);
                refresh_secret_provider_inventory_digest(&mut profile);
            }
            PublicFixtureMutation::MismatchedGuardProviderProjection => {
                profile["runtime_guard_evidence"]["guards"][1]["expected_value"]["providers"][0]
                    ["provider"]["configuration_payload_digest"] =
                    json!(test_digest("cross-wired-secret-provider-configuration"));
                refresh_secret_provider_inventory_digest(&mut profile);
            }
            PublicFixtureMutation::AuthenticatorProviderKindMismatch => {
                profile["runtime_guard_evidence"]["guards"][4]["expected_value"]["authenticators"]
                    [0]["authenticator_kind"] = json!("passkey");
                refresh_authenticator_inventory_digest(&mut profile);
            }
            _ => {}
        }

        let preliminary_profile: DeploymentSecurityProfile =
            serde_json::from_value(profile.clone()).unwrap();
        let mut manifest = fixture_manifest(&ledger, &preliminary_profile.control_trace_ref);
        let mut claims = fixture_deployment_claims(&preliminary_profile, &manifest);
        if matches!(mutation, PublicFixtureMutation::DevelopmentProviderClaim) {
            claims.provider_registry.active_providers[0].provider_kind =
                "development-fixture".into();
        }
        let applicability = derive_complete_production_applicability(
            &ledger,
            &manifest,
            &preliminary_profile,
            &claims,
        )
        .map_err(|error| error.to_string())?;
        assert_eq!(applicability.instances.len(), 288);
        let implementation_count = applicability
            .instances
            .iter()
            .filter(|instance| instance.scope == ApplicabilityScope::Implementation)
            .count();
        assert_eq!(implementation_count, 144);
        manifest.implementation_applicability = recompute_applicability_inventory_binding(
            &crate::conformance_applicability::ApplicabilityControlTraceBinding {
                document_id: preliminary_profile.control_trace_ref.document_id.clone(),
                document_version: preliminary_profile.control_trace_ref.document_version,
                content_digest: preliminary_profile.control_trace_ref.content_digest.clone(),
            },
            &manifest.implementation_applicability_instances,
        )
        .unwrap();
        let (
            deployment_profile,
            policy_versions,
            configuration_versions,
            provider_versions,
            adapter_versions,
            security_limit_profile,
        ) = fixture_version_context(&preliminary_profile, &manifest, &claims, &profile);

        let mut bundles = Vec::with_capacity(applicability.instances.len());
        let mut bundle_index_by_instance = BTreeMap::new();
        for (index, instance) in applicability.instances.iter().enumerate() {
            let trace = &traces[&instance.trace_id];
            let evidence_id = format!("evidence:{index:03}");
            let bundle_id = format!("conformance-bundle:{index:03}");
            let dimensions = serde_json::to_value(&instance.dimensions).unwrap();
            let (implementation_applicable, implementation_dimensions) =
                if instance.scope == ApplicabilityScope::Implementation {
                    (true, dimensions.clone())
                } else {
                    (false, json!([]))
                };
            let (deployment_applicable, deployment_dimensions) =
                if instance.scope == ApplicabilityScope::Deployment {
                    (true, dimensions)
                } else {
                    (false, json!([]))
                };
            let value = json!({
                "$schema": "https://ryuki.io/schemas/security-contracts/v1/conformance-bundle.schema.json",
                "contract_kind": "conformance-bundle",
                "document_version": 1,
                "bundle_id": bundle_id,
                "acceptance_status": "production_accepted",
                "production_accepted": true,
                "trace_id": instance.trace_id,
                "evidence_instance_id": evidence_id,
                "applicability_instance_id": instance.applicability_instance_id,
                "control_id": trace["control_id"].clone(),
                "acceptance_case_id": trace["acceptance_case_id"].clone(),
                "evaluated_applicability": {
                    "implementation": {
                        "applicable": implementation_applicable,
                        "dimensions": implementation_dimensions,
                    },
                    "deployment": {
                        "applicable": deployment_applicable,
                        "dimensions": deployment_dimensions,
                    },
                },
                "source_revision": SOURCE_REVISION,
                "artifact": {"digest": ARTIFACT_DIGEST},
                "bindings": {
                    "deployment_profile": deployment_profile.clone(),
                    "policy_versions": policy_versions.clone(),
                    "configuration_versions": configuration_versions.clone(),
                    "provider_versions": provider_versions.clone(),
                    "adapter_versions": adapter_versions.clone(),
                    "security_limit_profile": security_limit_profile.clone(),
                },
                "normalized_result": "pass",
                "contains_secrets": false,
                "provenance": {"evidence_tier": tier_value(3)},
                "production_observation": {
                    "required": true,
                    "observation": {
                        "deployment_id": DEPLOYMENT_ID,
                        "normalized_result": "pass",
                        "observed_at": "2026-07-15T01:00:00Z",
                        "artifact_hashes": [ARTIFACT_DIGEST],
                    },
                },
                "evidence_lifecycle": "accepted",
                "produced_at": "2026-07-15T00:00:00Z",
                "verified_at": "2026-07-15T02:00:00Z",
                "accepted_at": "2026-07-15T03:00:00Z",
                "expires_at": EXPIRES_AT,
                "supersedes_evidence_instance_id": null,
                "supersedes_evidence_ref": null,
            });
            let signed = sign_fixture_document(
                value,
                ConformanceDocumentKind::ConformanceBundle,
                &instance.owning_work_package,
                format!("fixtures/bundles/{index:03}.json"),
                u64::try_from(index).unwrap() + 1,
                &signing_key,
                &registry_digest,
            );
            bundle_index_by_instance
                .insert(instance.applicability_instance_id.clone(), bundles.len());
            bundles.push(signed);
        }

        let mut receipts: Vec<SignedFixtureDocument> = Vec::with_capacity(PACKAGES.len());
        let mut receipt_index_by_package: BTreeMap<String, usize> = BTreeMap::new();
        for (package_index, package_id) in PACKAGES.iter().enumerate() {
            let trace_ids = traces
                .iter()
                .filter(|(_, trace)| trace["owning_work_package"] == *package_id)
                .map(|(trace_id, _)| trace_id.clone())
                .collect::<BTreeSet<_>>();
            let control_ids = trace_ids
                .iter()
                .map(|trace_id| traces[trace_id]["control_id"].as_str().unwrap().to_owned())
                .collect::<BTreeSet<_>>();
            let acceptance_case_ids = trace_ids
                .iter()
                .map(|trace_id| {
                    traces[trace_id]["acceptance_case_id"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                })
                .collect::<BTreeSet<_>>();
            let package_instances = applicability
                .instances
                .iter()
                .filter(|instance| instance.owning_work_package == *package_id)
                .collect::<Vec<_>>();
            let applicability_instances = package_instances
                .iter()
                .map(|instance| {
                    let dimensions = serde_json::to_value(&instance.dimensions).unwrap();
                    let (implementation_dimensions, deployment_dimensions) = match instance.scope {
                        ApplicabilityScope::Implementation => (dimensions, json!([])),
                        ApplicabilityScope::Deployment => (json!([]), dimensions),
                    };
                    json!({
                        "instance_id": instance.applicability_instance_id,
                        "implementation_dimensions": implementation_dimensions,
                        "deployment_dimensions": deployment_dimensions,
                    })
                })
                .collect::<Vec<_>>();
            let evidence_bindings = package_instances
                .iter()
                .map(|instance| {
                    let bundle =
                        &bundles[bundle_index_by_instance[&instance.applicability_instance_id]];
                    json!({
                        "artifact_kind": "conformance-bundle",
                        "artifact_locator": bundle.artifact_locator,
                        "bundle_id": bundle.value["bundle_id"].clone(),
                        "document_version": 1,
                        "evidence_instance_id": bundle.value["evidence_instance_id"].clone(),
                        "bundle_digest": bundle.raw_digest,
                    })
                })
                .collect::<Vec<_>>();
            let prerequisite_receipts = required_prerequisite_packages(package_id)
                .into_iter()
                .map(|prerequisite_package| {
                    let prerequisite = &receipts[receipt_index_by_package[&prerequisite_package]];
                    json!({
                        "artifact_kind": "package-exit-receipt",
                        "artifact_locator": prerequisite.artifact_locator,
                        "receipt_id": prerequisite.value["receipt_id"].clone(),
                        "document_version": 1,
                        "receipt_digest": prerequisite.raw_digest,
                        "package_id": prerequisite.value["package_id"].clone(),
                        "acceptance_status": prerequisite.value["acceptance_status"].clone(),
                        "production_accepted": prerequisite.value["production_accepted"].clone(),
                        "evidence_tier": prerequisite.value["evidence_tier"].clone(),
                        "result": prerequisite.value["result"].clone(),
                        "receipt_lifecycle": prerequisite.value["receipt_lifecycle"].clone(),
                        "expires_at": prerequisite.value["expires_at"].clone(),
                    })
                })
                .collect::<Vec<_>>();
            let mut input_digests = BTreeSet::from([
                ledger_digest.clone(),
                ARTIFACT_DIGEST.to_owned(),
                deployment_profile["digest"].as_str().unwrap().to_owned(),
                security_limit_profile["digest"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            ]);
            for bindings in [
                &policy_versions,
                &configuration_versions,
                &provider_versions,
                &adapter_versions,
            ] {
                for binding in bindings.as_array().unwrap() {
                    input_digests.insert(binding["digest"].as_str().unwrap().to_owned());
                }
            }
            for prerequisite in &prerequisite_receipts {
                input_digests.insert(prerequisite["receipt_digest"].as_str().unwrap().to_owned());
            }
            let output_digests = evidence_bindings
                .iter()
                .map(|binding| binding["bundle_digest"].as_str().unwrap().to_owned())
                .collect::<BTreeSet<_>>();
            let retirement_closure = if *package_id == "SB-9" {
                let evidence_ids = evidence_bindings
                    .iter()
                    .map(|binding| binding["evidence_instance_id"].as_str().unwrap().to_owned())
                    .collect::<BTreeSet<_>>();
                json!({
                    "zero_consumer_evidence_instance_ids": evidence_ids,
                    "zero_live_authority_evidence_instance_ids": evidence_ids,
                    "retired_bypass_evidence_instance_ids": evidence_ids,
                })
            } else {
                Value::Null
            };
            let value = json!({
                "$schema": "https://ryuki.io/schemas/security-contracts/v1/package-exit-receipt.schema.json",
                "contract_kind": "package-exit-receipt",
                "document_version": 1,
                "receipt_id": receipt_id(package_id),
                "package_id": package_id,
                "acceptance_status": "production_accepted",
                "production_accepted": true,
                "ledger_binding": {
                    "artifact_kind": "control-trace",
                    "artifact_locator": ledger_locator,
                    "document_id": ledger["document_id"].clone(),
                    "document_version": ledger["document_version"].clone(),
                    "ledger_id": ledger["ledger_id"].clone(),
                    "ledger_version": ledger["ledger_version"].clone(),
                    "ledger_digest": ledger_digest,
                },
                "evaluated_sets": {
                    "trace_ids": trace_ids,
                    "control_ids": control_ids,
                    "acceptance_case_ids": acceptance_case_ids,
                    "evidence_bindings": evidence_bindings,
                },
                "applicability_instances": applicability_instances,
                "closure_context": {
                    "source_revision": SOURCE_REVISION,
                    "artifact_digest": ARTIFACT_DIGEST,
                    "deployment_profile": deployment_profile.clone(),
                    "policy_versions": policy_versions.clone(),
                    "configuration_versions": configuration_versions.clone(),
                    "provider_versions": provider_versions.clone(),
                    "adapter_versions": adapter_versions.clone(),
                    "security_limit_profile": security_limit_profile.clone(),
                },
                "prerequisite_receipts": prerequisite_receipts,
                "input_digests": input_digests,
                "output_digests": output_digests,
                "evidence_tier": tier_value(3),
                "result": "pass",
                "receipt_lifecycle": "accepted",
                "waivers": [],
                "retirement_closure": retirement_closure,
                "created_at": "2026-07-15T05:00:00Z",
                "expires_at": EXPIRES_AT,
                "supersedes_receipt_id": null,
                "supersedes_receipt_ref": null,
            });
            let signed = sign_fixture_document(
                value,
                ConformanceDocumentKind::PackageExitReceipt,
                package_id,
                receipt_locator(package_id),
                u64::try_from(bundles.len() + package_index + 1).unwrap(),
                &signing_key,
                &registry_digest,
            );
            receipt_index_by_package.insert((*package_id).to_owned(), receipts.len());
            receipts.push(signed);
        }

        let root_index = receipt_index_by_package["SB-9"];
        root_ref.content_digest = receipts[root_index].raw_digest.clone();
        profile["production_acceptance_receipt_ref"] = serde_json::to_value(&root_ref).unwrap();
        if profile["migration_overlay"].is_object() {
            profile["migration_overlay"]["zero_consumer_receipt_ref"] =
                serde_json::to_value(&root_ref).unwrap();
        }
        for (guard_index, package_id) in guard_packages.iter().enumerate() {
            let receipt_index = receipt_index_by_package[*package_id];
            profile["runtime_guard_evidence"]["guards"][guard_index]["receipt_ref"]["content_digest"] =
                json!(receipts[receipt_index].raw_digest);
        }
        assert_eq!(
            deployment_profile["digest"].as_str().unwrap(),
            deployment_profile_conformance_binding_digest(&profile).unwrap()
        );
        let exact_profile: DeploymentSecurityProfile =
            serde_json::from_value(profile.clone()).unwrap();
        assert!(
            exact_profile
                .validate_structure_at(timestamp("2026-07-16T12:00:02Z"))
                .is_empty()
        );

        let lineage = ValidatedConformanceRegistryLineage::from_registry_chain(
            &[ConformanceRegistryArtifact {
                artifact_locator: FIXTURE_REGISTRY_LOCATOR,
                raw_bytes: &registry_raw,
            }],
            ConformanceTrustAnchor {
                artifact_locator: FIXTURE_REGISTRY_LOCATOR,
                document_id: FIXTURE_REGISTRY_ID,
                document_version: 1,
                content_digest: &registry_digest,
            },
            timestamp("2026-07-16T11:59:56Z"),
        )
        .map_err(|error| error.to_string())?;
        let authority_public_key = authority_key.verifying_key().to_bytes();
        let authority_fingerprint = digest_bytes(&authority_public_key);
        let authority_anchor = ConformanceCheckpointAuthorityAnchor {
            authority_id: FIXTURE_AUTHORITY_ID,
            key_id: FIXTURE_AUTHORITY_KEY_ID,
            public_key: &authority_public_key,
            public_key_fingerprint: &authority_fingerprint,
            minimum_authority_epoch: FIXTURE_AUTHORITY_EPOCH,
        };
        let mut requested_document_digests = bundles
            .iter()
            .chain(&receipts)
            .map(|document| document.raw_digest.clone())
            .collect::<Vec<_>>();
        requested_document_digests.sort();
        assert!(
            requested_document_digests
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
        let request = lineage
            .reconciliation_request(
                ConformanceTrustScope {
                    deployment_id: DEPLOYMENT_ID,
                    trust_domain_id: TRUST_DOMAIN_ID,
                },
                ConformanceProductionRootRef {
                    document_id: &root_ref.document_id,
                    document_version: root_ref.document_version,
                    content_digest: &root_ref.content_digest,
                    artifact_locator: &root_ref.artifact_locator,
                },
                authority_anchor,
                public_fixture_entropy(b"reconciliation nonce"),
                timestamp("2026-07-16T11:59:57Z"),
                &requested_document_digests,
            )
            .map_err(|error| error.to_string())?;
        let acceptance_records = bundles
            .iter()
            .chain(&receipts)
            .map(|document| {
                fixture_acceptance_record(document, &signing_key_fingerprint, &registry_digest)
            })
            .collect::<Vec<_>>();
        let raw_response = signed_fixture_response(
            &request,
            acceptance_records,
            &receipts[root_index].acceptance_record_id,
            &authority_key,
            &authority_fingerprint,
        );
        let trusted_now = ConformanceTrustedTimeWindow {
            not_before: timestamp("2026-07-16T12:00:02Z"),
            not_after: timestamp("2026-07-16T12:00:03Z"),
        };
        let checkpoint = lineage
            .verify_reconciliation_response(&request, &raw_response, authority_anchor, trusted_now)
            .map_err(|error| error.to_string())?;

        let mut root_artifact = None;
        let mut artifacts = Vec::with_capacity(bundles.len() + receipts.len() - 1);
        for document in bundles.iter().chain(&receipts) {
            let artifact = checkpoint
                .verify_artifact(
                    ConformanceArtifactCandidate::new(
                        document.artifact_locator.clone(),
                        document.raw_digest.clone(),
                        document.raw_bytes.clone(),
                    ),
                    ConformanceVerificationContext {
                        deployment_id: DEPLOYMENT_ID,
                        trust_domain_id: TRUST_DOMAIN_ID,
                        package_id: &document.package_id,
                        evidence_tier: EvidenceTier::ExternallyAttested,
                    },
                    trusted_now,
                )
                .map_err(|error| error.to_string())?;
            if document.kind == ConformanceDocumentKind::PackageExitReceipt
                && document.package_id == "SB-9"
            {
                root_artifact = Some(artifact);
            } else {
                artifacts.push(artifact);
            }
        }
        let current_root = checkpoint
            .verify_current_production_root(root_artifact.unwrap())
            .map_err(|error| error.to_string())?;
        let control_trace =
            verify_control_trace_artifact(&exact_profile.control_trace_ref, ledger_raw)
                .map_err(|error| error.to_string())?;
        let mut supplied_profile = exact_profile.clone();
        if matches!(
            mutation,
            PublicFixtureMutation::WrongDerivedProfile | PublicFixtureMutation::WrongTypedProfile
        ) {
            supplied_profile.policy_version += 1;
        }
        if matches!(mutation, PublicFixtureMutation::WrongGuardExpectedValue) {
            let durable_postgresql = supplied_profile
                .runtime_guard_evidence
                .guards
                .iter_mut()
                .find(|guard| guard.guard_id == GuardId::DurablePostgresql)
                .expect("the genuine fixture must contain the durable PostgreSQL guard");
            let RuntimeGuardExpectedValue::DurablePostgresql {
                storage_binding_digest,
                ..
            } = &mut durable_postgresql.expected_value
            else {
                unreachable!("the guard identifier and expected-value kind are fixture-bound")
            };
            *storage_binding_digest = test_digest("cross-wired-storage-binding");
        }
        let context_profile = if matches!(mutation, PublicFixtureMutation::WrongDerivedProfile) {
            &supplied_profile
        } else {
            &exact_profile
        };
        let profile_raw_bytes = canonical_json_bytes(&profile).unwrap();
        let derived_context = derive_production_conformance_closure_context(
            &manifest,
            context_profile,
            &claims,
            &profile_raw_bytes,
        )
        .map_err(|error| error.to_string())?;
        verify_production_conformance_closure(
            checkpoint,
            current_root,
            artifacts,
            control_trace,
            ProductionConformanceClosureInputs {
                manifest: &manifest,
                profile: &supplied_profile,
                deployment_claims: &claims,
                context: &derived_context,
            },
            trusted_now,
        )
        .map_err(|error| error.to_string())
    }

    /// Builds the same genuinely signed 288-instance closure used by the core
    /// acceptance test and returns its exact bound profile representation.
    ///
    /// This is feature-gated test support so downstream startup-composition
    /// tests can exercise opaque production capabilities without adding a
    /// production constructor or fabricating proof facts.
    #[cfg(feature = "security-test-support")]
    pub fn genuine_production_closure_fixture()
    -> Result<(VerifiedConformanceClosure, Box<[u8]>), String> {
        let closure = verify_public_fixture(PublicFixtureMutation::None)?;
        let profile_raw_bytes = closure._profile_raw_bytes.clone();
        Ok((closure, profile_raw_bytes))
    }

    #[test]
    fn public_entrypoint_accepts_one_genuine_opaque_288_instance_closure() {
        let closure = verify_public_fixture(PublicFixtureMutation::None)
            .expect("the public closure boundary must accept one exact authenticated fixture");
        assert_eq!(closure.package_count(), 10);
        assert_eq!(closure.evidence_count(), 288);
        assert_eq!(closure.applicability_instances().len(), 288);
        assert_eq!(closure.runtime_guard_requirements().len(), 8);
        for requirement in closure.runtime_guard_requirements() {
            assert_eq!(
                requirement.guard_id(),
                requirement.expected_value().guard_id()
            );
            assert!(requirement.requirement_digest().starts_with("sha256:"));
            assert!(
                requirement
                    .semantic_challenge_binding_digest()
                    .starts_with("sha256:")
            );
            assert_ne!(
                requirement.requirement_digest(),
                requirement.semantic_challenge_binding_digest()
            );
        }
        assert_eq!(
            closure.production_build_manifest().source.revision,
            SOURCE_REVISION
        );
        assert_eq!(closure.deployment_profile().deployment_id, DEPLOYMENT_ID);
        closure
            .ensure_fresh(ConformanceTrustedTimeWindow {
                not_before: timestamp("2026-07-16T12:00:04Z"),
                not_after: timestamp("2026-07-16T12:00:05Z"),
            })
            .unwrap();
    }

    #[test]
    fn runtime_guard_challenges_cannot_replay_across_verified_closures() {
        let first = verify_public_fixture(PublicFixtureMutation::None).unwrap();
        let second = verify_public_fixture(PublicFixtureMutation::None).unwrap();
        for (first_requirement, second_requirement) in first
            .runtime_guard_requirements()
            .iter()
            .zip(second.runtime_guard_requirements())
        {
            assert_eq!(first_requirement.guard_id(), second_requirement.guard_id());
            assert_ne!(
                first_requirement.semantic_challenge_binding_digest(),
                second_requirement.semantic_challenge_binding_digest()
            );
        }
    }

    #[test]
    fn public_entrypoint_rejects_typed_profile_different_from_exact_document() {
        let error = verify_public_fixture(PublicFixtureMutation::WrongTypedProfile).unwrap_err();
        assert!(
            error
                .contains("typed deployment profile differs from the exact bound profile document")
        );
    }

    #[test]
    fn public_entrypoint_rejects_guard_expectation_different_from_authenticated_profile() {
        let error =
            verify_public_fixture(PublicFixtureMutation::WrongGuardExpectedValue).unwrap_err();
        assert!(
            error
                .contains("typed deployment profile differs from the exact bound profile document")
        );
    }

    #[test]
    fn public_entrypoint_rejects_guard_provider_absent_from_active_inventory() {
        let error = verify_public_fixture(PublicFixtureMutation::UnknownGuardProvider).unwrap_err();
        assert!(error.contains(
            "approved-secret-provider expectation is not the exact active secret-service provider inventory"
        ));
    }

    #[test]
    fn public_entrypoint_rejects_guard_provider_projection_mismatch() {
        let error = verify_public_fixture(PublicFixtureMutation::MismatchedGuardProviderProjection)
            .unwrap_err();
        assert!(
            error.contains("does not exactly match its production-eligible active provider claim")
        );
    }

    #[test]
    fn public_entrypoint_rejects_secret_provider_without_required_capability() {
        let error =
            verify_public_fixture(PublicFixtureMutation::MissingSecretCapability).unwrap_err();
        assert!(error.contains("advertising every required capability"));
    }

    #[test]
    fn secret_provider_guard_requires_exact_sorted_runtime_bound_inventory() {
        let providers = vec![
            focused_secret_binding("provider:focused-secrets-primary"),
            focused_secret_binding("provider:focused-secrets-secondary"),
        ];
        let active_providers = providers
            .iter()
            .map(focused_secret_claim)
            .collect::<Vec<_>>();
        let capabilities = vec!["secret-read".into(), "secret-renew".into()];
        let inventory_digest = secret_provider_inventory_digest(&providers, &capabilities).unwrap();
        validate_focused_secret_inventory(
            &providers,
            &capabilities,
            &active_providers,
            &inventory_digest,
        )
        .expect("the exact runtime-bound secret-provider inventory must close");

        let omitted = vec![providers[1].clone()];
        let omitted_digest = secret_provider_inventory_digest(&omitted, &capabilities).unwrap();
        let error = validate_focused_secret_inventory(
            &omitted,
            &capabilities,
            &active_providers,
            &omitted_digest,
        )
        .unwrap_err();
        assert!(error.to_string().contains("exact active secret-service"));

        let mut extra = providers.clone();
        extra.push(focused_secret_binding("provider:focused-secrets-tertiary"));
        let extra_digest = secret_provider_inventory_digest(&extra, &capabilities).unwrap();
        let error = validate_focused_secret_inventory(
            &extra,
            &capabilities,
            &active_providers,
            &extra_digest,
        )
        .unwrap_err();
        assert!(error.to_string().contains("exact active secret-service"));

        let mut reordered = providers.clone();
        reordered.swap(0, 1);
        let reordered_digest = secret_provider_inventory_digest(&reordered, &capabilities).unwrap();
        let error = validate_focused_secret_inventory(
            &reordered,
            &capabilities,
            &active_providers,
            &reordered_digest,
        )
        .unwrap_err();
        assert!(error.to_string().contains("strictly sorted"));

        let mut duplicate = providers.clone();
        duplicate[1].provider = duplicate[0].provider.clone();
        let duplicate_digest = secret_provider_inventory_digest(&duplicate, &capabilities).unwrap();
        let error = validate_focused_secret_inventory(
            &duplicate,
            &capabilities,
            &active_providers,
            &duplicate_digest,
        )
        .unwrap_err();
        assert!(error.to_string().contains("strictly sorted"));

        let mut runtime_drift = providers.clone();
        runtime_drift[0].runtime_binding_digest = test_digest("runtime-substitution");
        let error = validate_focused_secret_inventory(
            &runtime_drift,
            &capabilities,
            &active_providers,
            &inventory_digest,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("canonical binding and capability")
        );

        let error = validate_focused_secret_inventory(
            &providers,
            &capabilities,
            &active_providers,
            &test_digest("inventory-substitution"),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("canonical binding and capability")
        );
    }

    #[test]
    fn secret_provider_guard_rejects_capability_and_provider_binding_substitution() {
        let providers = vec![focused_secret_binding("provider:focused-secrets-primary")];
        let active_providers = vec![focused_secret_claim(&providers[0])];
        let capabilities = vec!["secret-read".into(), "secret-renew".into()];

        let substituted_capabilities = vec!["secret-admin".into(), "secret-read".into()];
        let digest =
            secret_provider_inventory_digest(&providers, &substituted_capabilities).unwrap();
        let error = validate_focused_secret_inventory(
            &providers,
            &substituted_capabilities,
            &active_providers,
            &digest,
        )
        .unwrap_err();
        assert!(error.to_string().contains("advertising every required"));

        let mut unsorted_capabilities = capabilities.clone();
        unsorted_capabilities.swap(0, 1);
        let digest = secret_provider_inventory_digest(&providers, &unsorted_capabilities).unwrap();
        let error = validate_focused_secret_inventory(
            &providers,
            &unsorted_capabilities,
            &active_providers,
            &digest,
        )
        .unwrap_err();
        assert!(error.to_string().contains("strictly sorted"));

        let mut substituted_provider = providers;
        substituted_provider[0]
            .provider
            .configuration_payload_digest = test_digest("provider-binding-substitution");
        let digest =
            secret_provider_inventory_digest(&substituted_provider, &capabilities).unwrap();
        let error = validate_focused_secret_inventory(
            &substituted_provider,
            &capabilities,
            &active_providers,
            &digest,
        )
        .unwrap_err();
        assert!(error.to_string().contains("does not exactly match"));
    }

    #[test]
    fn authenticator_guard_covers_all_six_provider_classes_exactly() {
        let (authenticators, active_providers) = focused_all_authenticator_classes();
        let inventory_digest = authenticator_inventory_digest(&authenticators).unwrap();

        validate_focused_authenticator_inventory(
            &authenticators,
            &active_providers,
            &inventory_digest,
        )
        .expect("all six exact production authenticator provider classes must close");

        let mut omitted_api_token = authenticators.clone();
        omitted_api_token.remove(0);
        let omitted_digest = authenticator_inventory_digest(&omitted_api_token).unwrap();
        let error = validate_focused_authenticator_inventory(
            &omitted_api_token,
            &active_providers,
            &omitted_digest,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("exact active authenticator provider inventory")
        );
    }

    #[test]
    fn authenticator_guard_requires_a_human_provider_and_exact_family() {
        let (authenticators, active_providers) = focused_all_authenticator_classes();
        let machine_authenticators = vec![
            authenticators[0].clone(),
            authenticators[2].clone(),
            authenticators[5].clone(),
        ];
        let machine_providers = vec![
            active_providers[0].clone(),
            active_providers[2].clone(),
            active_providers[5].clone(),
        ];
        let machine_digest = authenticator_inventory_digest(&machine_authenticators).unwrap();
        let error = validate_focused_authenticator_inventory(
            &machine_authenticators,
            &machine_providers,
            &machine_digest,
        )
        .unwrap_err();
        assert!(error.to_string().contains("has no active human"));

        let mut wrong_family = authenticators.clone();
        wrong_family[0].authenticator_kind = ProductionAuthenticatorKind::Workload;
        let wrong_family_digest = authenticator_inventory_digest(&wrong_family).unwrap();
        let error = validate_focused_authenticator_inventory(
            &wrong_family,
            &active_providers,
            &wrong_family_digest,
        )
        .unwrap_err();
        assert!(error.to_string().contains("typed authenticator kind"));
    }

    #[test]
    fn authenticator_guard_rejects_inventory_digest_substitution() {
        let (authenticators, active_providers) = focused_all_authenticator_classes();
        let substituted = test_digest("substituted-authenticator-inventory");

        let error = validate_focused_authenticator_inventory(
            &authenticators,
            &active_providers,
            &substituted,
        )
        .unwrap_err();
        assert!(error.to_string().contains("canonical binding inventory"));
    }

    #[test]
    fn public_entrypoint_rejects_authenticator_provider_kind_mismatch() {
        let error = verify_public_fixture(PublicFixtureMutation::AuthenticatorProviderKindMismatch)
            .unwrap_err();
        assert!(error.contains("provider kind does not match its typed authenticator kind"));
    }

    #[test]
    fn public_entrypoint_rejects_development_provider_claims() {
        let error =
            verify_public_fixture(PublicFixtureMutation::DevelopmentProviderClaim).unwrap_err();
        assert!(error.contains("closed production provider kind"));
    }

    #[test]
    fn public_entrypoint_rejects_overlay_retirement_inside_the_verification_window() {
        let error =
            verify_public_fixture(PublicFixtureMutation::OverlayRetiresWithinVerificationWindow)
                .unwrap_err();
        assert!(error.contains(
            "migration overlay retirement_deadline does not remain valid through the trusted-time verification window"
        ));
    }

    #[test]
    fn overlay_retirement_deadline_bounds_the_verified_closure_lifetime() {
        let closure =
            verify_public_fixture(PublicFixtureMutation::OverlayWithEarlierSemanticExpiry)
                .expect("a live overlay should verify before its retirement deadline");
        assert_eq!(
            closure.semantic_valid_until(),
            timestamp("2026-07-16T12:00:10Z")
        );
        closure
            .ensure_fresh(ConformanceTrustedTimeWindow {
                not_before: timestamp("2026-07-16T12:00:08Z"),
                not_after: timestamp("2026-07-16T12:00:09Z"),
            })
            .unwrap();
        assert!(
            closure
                .ensure_fresh(ConformanceTrustedTimeWindow {
                    not_before: timestamp("2026-07-16T12:00:09Z"),
                    not_after: timestamp("2026-07-16T12:00:10Z"),
                })
                .is_err()
        );
    }

    #[test]
    fn derived_context_rejects_typed_profile_different_from_exact_document() {
        let error = verify_public_fixture(PublicFixtureMutation::WrongDerivedProfile).unwrap_err();
        assert!(error.contains(
            "typed deployment profile differs from the exact production profile document"
        ));
    }

    #[test]
    fn derived_context_retains_the_exact_raw_profile_representation() {
        let mut profile_value: Value = serde_json::from_str(PROFILE_JSON).unwrap();
        profile_value["security_profile"] = json!("production");
        profile_value["deployment_id"] = json!(DEPLOYMENT_ID);
        profile_value["applicability"]["security_profiles"] = json!(["production"]);
        profile_value["applicability"]["deployment_ids"] = json!([DEPLOYMENT_ID]);
        profile_value["trust_topology"]["trust_domain_ids"] = json!([TRUST_DOMAIN_ID]);
        profile_value["production_acceptance_receipt_ref"] = json!({
            "artifact_kind": "package-exit-receipt",
            "document_id": "package-exit-receipt:raw-profile-test",
            "document_version": 1,
            "content_digest": test_digest("raw-profile-test-root"),
            "artifact_locator": "receipts/raw-profile-test.json",
        });
        profile_value["migration_overlay"] = Value::Null;
        let profile: DeploymentSecurityProfile =
            serde_json::from_value(profile_value.clone()).unwrap();
        let ledger: Value = serde_json::from_str(CONTROL_TRACE_JSON).unwrap();
        let manifest = fixture_manifest(&ledger, &profile.control_trace_ref);
        let claims = fixture_deployment_claims(&profile, &manifest);
        let explicit_null_raw = canonical_json_bytes(&profile_value).unwrap();
        let explicit_null = derive_production_conformance_closure_context(
            &manifest,
            &profile,
            &claims,
            &explicit_null_raw,
        )
        .unwrap();

        profile_value
            .as_object_mut()
            .unwrap()
            .remove("migration_overlay");
        let omitted_raw = canonical_json_bytes(&profile_value).unwrap();
        let omitted_profile: DeploymentSecurityProfile =
            serde_json::from_value(profile_value).unwrap();
        assert_eq!(omitted_profile, profile);
        let omitted = derive_production_conformance_closure_context(
            &manifest,
            &omitted_profile,
            &claims,
            &omitted_raw,
        )
        .unwrap();

        assert_ne!(
            explicit_null.deployment_profile_raw_digest(),
            omitted.deployment_profile_raw_digest()
        );
        assert_eq!(
            explicit_null.deployment_profile_raw_digest(),
            digest_bytes(&explicit_null_raw)
        );
        assert_eq!(
            omitted.deployment_profile_raw_digest(),
            digest_bytes(&omitted_raw)
        );
    }

    fn assert_rejected(fixture: &SyntheticClosure) {
        assert!(fixture.verify().is_err());
    }

    #[test]
    fn profile_binding_projection_breaks_root_cycle_but_binds_everything_else() {
        let profile: Value = serde_json::from_str(PROFILE_JSON).unwrap();
        let baseline = deployment_profile_conformance_binding_digest(&profile).unwrap();

        let mut changed_root = profile.clone();
        changed_root["production_acceptance_receipt_ref"] = json!({
            "artifact_kind": "package-exit-receipt",
            "document_id": "package-exit-receipt:sb-9-current",
            "document_version": 7,
            "content_digest": test_digest("root"),
            "artifact_locator": "catalog/security-contracts/v1/package-exit-receipts/sb-9.json"
        });
        assert_eq!(
            baseline,
            deployment_profile_conformance_binding_digest(&changed_root).unwrap()
        );

        let mut guarded = profile.clone();
        guarded["runtime_guard_evidence"] = json!({
            "mode":"receipt_bound",
            "runtime_cross_check_required":true,
            "guards":[{
                "guard_id":"durable-postgresql",
                "control_ids":["SB-DATA-01"],
                "receipt_ref":{
                    "artifact_kind":"package-exit-receipt",
                    "document_id":"package-exit-receipt:guard",
                    "document_version":4,
                    "content_digest":test_digest("guard-a"),
                    "artifact_locator":"catalog/security-contracts/v1/package-exit-receipts/guard.json"
                },
                "expected_value":guard_expected_value(0)
            }]
        });
        let guarded_digest = deployment_profile_conformance_binding_digest(&guarded).unwrap();
        let mut changed_guard_digest = guarded.clone();
        changed_guard_digest["runtime_guard_evidence"]["guards"][0]["receipt_ref"]["content_digest"] =
            json!(test_digest("guard-b"));
        assert_eq!(
            guarded_digest,
            deployment_profile_conformance_binding_digest(&changed_guard_digest).unwrap()
        );
        let mut changed_guard_expected_value = guarded.clone();
        changed_guard_expected_value["runtime_guard_evidence"]["guards"][0]["expected_value"]["storage_binding_digest"] =
            json!(test_digest("changed-guard-storage-binding"));
        assert_ne!(
            guarded_digest,
            deployment_profile_conformance_binding_digest(&changed_guard_expected_value).unwrap()
        );
        let mut changed_guard_identity = guarded;
        changed_guard_identity["runtime_guard_evidence"]["guards"][0]["receipt_ref"]["document_version"] =
            json!(5);
        assert_ne!(
            guarded_digest,
            deployment_profile_conformance_binding_digest(&changed_guard_identity).unwrap()
        );

        let mut overlaid = profile.clone();
        overlaid["migration_overlay"] = json!({
            "overlay_id":"migration-overlay:test",
            "overlay_version":1,
            "security_profile":"test",
            "authority_source":"provider_registry",
            "legacy_selector_present":false,
            "provider_registry_present":true,
            "retirement_deadline":"2027-01-01T00:00:00Z",
            "conflict_telemetry_name":"migration_conflicts",
            "grants_authority":false,
            "live_execution_allowed":false,
            "zero_consumer_receipt_ref":{
                "artifact_kind":"package-exit-receipt",
                "document_id":"package-exit-receipt:zero-consumer",
                "document_version":2,
                "content_digest":test_digest("overlay-a"),
                "artifact_locator":"catalog/security-contracts/v1/package-exit-receipts/zero-consumer.json"
            }
        });
        let overlay_digest = deployment_profile_conformance_binding_digest(&overlaid).unwrap();
        let mut changed_overlay_digest = overlaid.clone();
        changed_overlay_digest["migration_overlay"]["zero_consumer_receipt_ref"]["content_digest"] =
            json!(test_digest("overlay-b"));
        assert_eq!(
            overlay_digest,
            deployment_profile_conformance_binding_digest(&changed_overlay_digest).unwrap()
        );
        let mut changed_overlay_identity = overlaid;
        changed_overlay_identity["migration_overlay"]["zero_consumer_receipt_ref"]["document_id"] =
            json!("package-exit-receipt:other");
        assert_ne!(
            overlay_digest,
            deployment_profile_conformance_binding_digest(&changed_overlay_identity).unwrap()
        );

        for pointer in [
            "/document_version",
            "/deployment_profile_version",
            "/platform_configuration_version",
            "/policy_version",
        ] {
            let mut changed = profile.clone();
            let next = changed
                .pointer(pointer)
                .and_then(Value::as_u64)
                .expect("profile version is an unsigned integer")
                .checked_add(1)
                .expect("fixture version can advance");
            *changed.pointer_mut(pointer).unwrap() = json!(next);
            assert_ne!(
                baseline,
                deployment_profile_conformance_binding_digest(&changed).unwrap(),
                "projection failed to bind {pointer}"
            );
        }
        let full_digest = digest_bytes(&canonical_json_bytes(&profile).unwrap());
        assert_ne!(
            baseline, full_digest,
            "full raw profile pin stays independent"
        );

        let mut unknown = profile.clone();
        unknown["unknown_security_field"] = json!(true);
        assert!(deployment_profile_conformance_binding_digest(&unknown).is_err());
        let mut missing = profile.clone();
        missing.as_object_mut().unwrap().remove("deployment_id");
        assert!(deployment_profile_conformance_binding_digest(&missing).is_err());
        assert!(deployment_profile_conformance_binding_digest(&json!([])).is_err());
    }

    #[test]
    fn closure_context_digest_binds_every_semantic_dimension() {
        let profile: Value = serde_json::from_str(PROFILE_JSON).unwrap();
        let deployment_profile = json!({
            "id": "deployment-security-profile:repository-implementation-v1",
            "version": "1",
            "deployment_id": "deployment:repository-conformance-fixture",
            "digest_contract": DEPLOYMENT_PROFILE_CONFORMANCE_BINDING_DIGEST_CONTRACT,
            "digest": deployment_profile_conformance_binding_digest(&profile).unwrap(),
        });
        let policy = json!([{"id":"policy","version":"1","digest":test_digest("policy")}]);
        let configuration = json!([{"id":"config","version":"1","digest":test_digest("config")}]);
        let providers = json!([{"id":"provider","version":"1","digest":test_digest("provider")}]);
        let adapters = json!([{"id":"adapter","version":"1","digest":test_digest("adapter")}]);
        let limits = json!({"id":"limits","version":"1","digest":test_digest("limits")});
        let root = VersionedContentReference {
            artifact_kind: ArtifactKind::PackageExitReceipt,
            document_id: "package-exit-receipt:sb-9".into(),
            document_version: 1,
            content_digest: test_digest("receipt"),
            artifact_locator: "catalog/security-contracts/v1/package-exit-receipts/sb-9.json"
                .into(),
        };
        let base = ConformanceClosureContext {
            deployment_id: "deployment:repository-conformance-fixture",
            trust_domain_id: "trust-domain:repository-fixture",
            source_revision: "1111111111111111111111111111111111111111",
            artifact_digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            deployment_profile: &deployment_profile,
            policy_versions: &policy,
            configuration_versions: &configuration,
            provider_versions: &providers,
            adapter_versions: &adapters,
            security_limit_profile: &limits,
            deployment_profile_document: &profile,
            production_acceptance_receipt_ref: &root,
        };
        let baseline = conformance_closure_context_digest(base).unwrap();
        let changed_policy = json!([]);
        let changed = ConformanceClosureContext {
            policy_versions: &changed_policy,
            ..base
        };
        assert_ne!(
            baseline,
            conformance_closure_context_digest(changed).unwrap()
        );
        let changed_artifact = ConformanceClosureContext {
            artifact_digest: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            ..base
        };
        assert_ne!(
            baseline,
            conformance_closure_context_digest(changed_artifact).unwrap()
        );
    }

    #[test]
    fn deployment_profile_binding_uses_top_level_document_version() {
        let mut profile: Value = serde_json::from_str(PROFILE_JSON).unwrap();
        profile["document_version"] = json!(3);
        profile["deployment_profile_version"] = json!(99);
        profile["security_profile"] = json!("production");
        let root = VersionedContentReference {
            artifact_kind: ArtifactKind::PackageExitReceipt,
            document_id: "package-exit-receipt:sb-9".into(),
            document_version: 1,
            content_digest: test_digest("root-receipt"),
            artifact_locator: "catalog/security-contracts/v1/package-exit-receipts/sb-9.json"
                .into(),
        };
        profile["production_acceptance_receipt_ref"] = serde_json::to_value(&root).unwrap();
        let binding = json!({
            "id":"deployment-security-profile:repository-implementation-v1",
            "version":"3",
            "deployment_id":"deployment:repository-conformance-fixture",
            "digest_contract":DEPLOYMENT_PROFILE_CONFORMANCE_BINDING_DIGEST_CONTRACT,
            "digest":deployment_profile_conformance_binding_digest(&profile).unwrap(),
        });
        let empty = json!([]);
        let typed_profile: DeploymentSecurityProfile =
            serde_json::from_value(profile.clone()).unwrap();
        let policy_versions = Value::Array(profile_policy_version_bindings(&typed_profile));
        let configuration_versions =
            Value::Array(profile_configuration_version_bindings(&typed_profile));
        let limit = json!({"id":"limits","version":"1","digest":test_digest("limits")});
        let context = ConformanceClosureContext {
            deployment_id: "deployment:repository-conformance-fixture",
            trust_domain_id: "trust-domain:repository-fixture",
            source_revision: "1111111111111111111111111111111111111111",
            artifact_digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            deployment_profile: &binding,
            policy_versions: &policy_versions,
            configuration_versions: &configuration_versions,
            provider_versions: &empty,
            adapter_versions: &empty,
            security_limit_profile: &limit,
            deployment_profile_document: &profile,
            production_acceptance_receipt_ref: &root,
        };
        validate_context(context).unwrap();

        let mut shrunk_policy = policy_versions.clone();
        shrunk_policy.as_array_mut().unwrap().pop();
        assert!(
            validate_context(ConformanceClosureContext {
                policy_versions: &shrunk_policy,
                ..context
            })
            .is_err()
        );

        let mut shrunk_configuration = configuration_versions.clone();
        shrunk_configuration.as_array_mut().unwrap().pop();
        assert!(
            validate_context(ConformanceClosureContext {
                configuration_versions: &shrunk_configuration,
                ..context
            })
            .is_err()
        );

        let mut wrong_binding = binding.clone();
        wrong_binding["version"] = json!("99");
        let wrong = ConformanceClosureContext {
            deployment_profile: &wrong_binding,
            ..context
        };
        assert!(validate_context(wrong).is_err());
    }

    #[test]
    fn oversized_control_trace_is_rejected_before_json_parsing() {
        let reference = VersionedContentReference {
            artifact_kind: ArtifactKind::ControlTrace,
            document_id: CONTROL_TRACE_DOCUMENT_ID.into(),
            document_version: 1,
            content_digest: test_digest("oversized-control-trace"),
            artifact_locator: "fixtures/control-trace.json".into(),
        };
        assert!(
            verify_control_trace_artifact(&reference, vec![b' '; MAX_CONTROL_TRACE_BYTES + 1])
                .is_err()
        );
    }

    #[test]
    fn complete_semantic_closure_accepts_all_141_checked_in_trace_instances() {
        let fixture = SyntheticClosure::complete();
        let closure = fixture.verify().unwrap();
        assert_eq!(fixture.applicability.instances.len(), 141);
        assert_eq!(closure.evidence_digests.len(), 141);
        assert_eq!(closure.receipt_digests.len(), 10);
        assert_eq!(closure.runtime_guard_requirements.len(), 8);
    }

    #[test]
    fn self_shrunk_and_mixed_applicability_are_rejected() {
        let mut shrunk = SyntheticClosure::complete();
        let index = shrunk.receipt_index("SB-0");
        shrunk.receipts[index]["applicability_instances"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert_rejected(&shrunk);

        let mut mixed = SyntheticClosure::complete();
        let index = mixed.receipt_index("SB-0");
        mixed.receipts[index]["applicability_instances"][0]["implementation_dimensions"][0]["value"] =
            json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_rejected(&mixed);
    }

    #[test]
    fn detached_snapshot_and_root_acceptance_proofs_are_rejected() {
        let mut mixed_snapshot = SyntheticClosure::complete();
        mixed_snapshot
            .proofs
            .values_mut()
            .next()
            .unwrap()
            .snapshot_binding_digest = test_digest("other-snapshot");
        assert_rejected(&mixed_snapshot);

        let mut detached_root = SyntheticClosure::complete();
        detached_root
            .proofs
            .get_mut(&detached_root.root_ref.content_digest)
            .unwrap()
            .acceptance_record_id = "acceptance:detached-root".into();
        assert_rejected(&detached_root);
    }

    #[test]
    fn supersession_forks_cycles_and_sequence_inversions_are_rejected() {
        let mut inverted = SyntheticClosure::complete();
        let (target_digest, _) = inverted.add_bundle_successor();
        inverted
            .proofs
            .get_mut(&target_digest)
            .unwrap()
            .acceptance_sequence = 160;
        assert_rejected(&inverted);

        let mut forked = SyntheticClosure::complete();
        let (target_digest, successor_digest) = forked.add_bundle_successor();
        let successor_index = forked
            .bundle_digests
            .iter()
            .position(|digest| digest == &successor_digest)
            .unwrap();
        let mut fork = forked.bundles[successor_index].clone();
        fork["document_version"] = json!(3);
        fork["bundle_id"] = json!("conformance-bundle:fork");
        fork["evidence_instance_id"] = json!("evidence:fork");
        let fork_digest = value_digest(&fork);
        let mut proof = forked.proofs[&successor_digest].clone();
        proof.document_id = "conformance-bundle:fork".into();
        proof.document_version = 3;
        proof.complete_document_digest = fork_digest.clone();
        proof.acceptance_record_id = "acceptance:bundle:fork".into();
        proof.acceptance_sequence = 160;
        forked.proofs.insert(fork_digest.clone(), proof);
        forked.bundles.push(fork);
        forked.bundle_digests.push(fork_digest);
        forked
            .bundle_locators
            .push("fixtures/bundles/fork.json".into());
        assert_rejected(&forked);

        let cycle = BTreeMap::from([
            ("a".into(), BTreeSet::from(["b".into()])),
            ("b".into(), BTreeSet::from(["a".into()])),
        ]);
        assert!(reject_cycles("supersession", &cycle).is_err());
        assert!(forked.proofs.contains_key(&target_digest));
    }

    #[test]
    fn prerequisite_omission_tier_downgrade_and_expiry_are_rejected() {
        let mut omitted = SyntheticClosure::complete();
        let index = omitted.receipt_index("SB-8");
        omitted.receipts[index]["prerequisite_receipts"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert_rejected(&omitted);

        let mut downgraded = SyntheticClosure::complete();
        let receipt_index = downgraded.receipt_index("SB-3");
        let receipt_digest = downgraded.receipt_digests[receipt_index].clone();
        downgraded.receipts[receipt_index]["evidence_tier"] = tier_value(1);
        downgraded
            .proofs
            .get_mut(&receipt_digest)
            .unwrap()
            .evidence_tier = evidence_tier(1);
        for (bundle, digest) in downgraded
            .bundles
            .iter_mut()
            .zip(downgraded.bundle_digests.iter())
        {
            if downgraded.proofs[digest].package_id == "SB-3" {
                bundle["provenance"]["evidence_tier"] = tier_value(1);
                downgraded.proofs.get_mut(digest).unwrap().evidence_tier = evidence_tier(1);
            }
        }
        assert_rejected(&downgraded);

        let mut expired = SyntheticClosure::complete();
        let target_index = expired.receipt_index("SB-3");
        expired.receipts[target_index]["expires_at"] = json!("2027-01-01T00:00:00Z");
        for receipt in &mut expired.receipts {
            for prerequisite in receipt["prerequisite_receipts"].as_array_mut().unwrap() {
                if prerequisite["package_id"] == "SB-3" {
                    prerequisite["expires_at"] = json!("2027-01-01T00:00:00Z");
                }
            }
        }
        assert_rejected(&expired);
    }

    #[test]
    fn sb9_retirement_closure_omission_and_wrong_ids_are_rejected() {
        let mut omitted = SyntheticClosure::complete();
        let index = omitted.receipt_index("SB-9");
        omitted.receipts[index]["retirement_closure"] = Value::Null;
        assert_rejected(&omitted);

        let mut wrong = SyntheticClosure::complete();
        let index = wrong.receipt_index("SB-9");
        wrong.receipts[index]["retirement_closure"]["zero_consumer_evidence_instance_ids"][0] =
            json!("evidence:unknown");
        assert_rejected(&wrong);
    }

    #[test]
    fn duplicate_cross_guard_control_is_rejected_after_exact_profile_rebinding() {
        let mut fixture = SyntheticClosure::complete();
        fixture.profile["runtime_guard_evidence"]["guards"][1]["control_ids"] =
            fixture.profile["runtime_guard_evidence"]["guards"][0]["control_ids"].clone();
        fixture.propagate_profile_binding();
        assert_rejected(&fixture);
    }

    #[test]
    fn receipt_input_and_output_digest_sets_are_exact() {
        let mut missing_input = SyntheticClosure::complete();
        let index = missing_input.receipt_index("SB-4");
        missing_input.receipts[index]["input_digests"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert_rejected(&missing_input);

        let mut missing_output = SyntheticClosure::complete();
        let index = missing_output.receipt_index("SB-4");
        missing_output.receipts[index]["output_digests"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert_rejected(&missing_output);
    }

    #[test]
    fn trusted_time_window_cannot_extend_expired_semantic_evidence() {
        let mut fixture = SyntheticClosure::complete();
        fixture.trusted_now = ConformanceTrustedTimeWindow {
            not_before: timestamp("2027-08-01T00:00:00Z"),
            not_after: timestamp("2027-08-01T00:01:00Z"),
        };
        assert_rejected(&fixture);
    }
}
