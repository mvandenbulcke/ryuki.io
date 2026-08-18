//! Live measurement for the permanent first-owner closure guard.
//!
//! Migration 193 stores an authority-verified closure certificate and its
//! initial privileged-domain assignments.  This module does not create or
//! repair that evidence.  It measures the exact deployment row through the
//! already-attested, unpublished PostgreSQL runtime and requires the stored
//! canonical bytes, duplicated columns, core projections, deployment profile,
//! and receipt-bound expected value to agree.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use ryuki_core::conformance_trust::canonical_json_bytes;
use ryuki_core::conformance_trust::ConformanceTrustedTimeWindow;
use ryuki_core::postgresql_infrastructure::PostgresqlSessionBinding;
use ryuki_core::security_profile::{
    first_owner_closure_certificate_canonical_bytes,
    first_owner_closure_certificate_is_installable_at,
    first_owner_closure_certificate_signature_digest, first_owner_closure_record_digest,
    first_owner_closure_record_from_certificate, parse_first_owner_closure_certificate,
    verify_first_owner_closure_certificate, DeploymentSecurityProfile,
    FirstOwnerCertificateAuthorityAnchor, FirstOwnerClosureCertificate,
    FirstOwnerClosureCertificateError, RuntimeGuardExpectedValue, TenancyMode,
    VerifiedFirstOwnerClosureCertificate, FIRST_OWNER_MAX_EXACT_JSON_INTEGER,
    FIRST_OWNER_PRIVILEGED_DOMAINS,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use thiserror::Error;

use crate::database::{PostgresqlRuntimeObservation, RetainedPostgresqlRuntime};

const LIVE_MEASUREMENT_TIMEOUT: Duration = Duration::from_secs(15);
const FIRST_OWNER_INSTALLATION_BINDING_DIGEST_CONTRACT: &str =
    "ryuki-first-owner-installation-binding-v1";
const FIRST_OWNER_RECONCILIATION_BINDING_DIGEST_CONTRACT: &str =
    "ryuki-first-owner-reconciliation-binding-v1";

/// Redacted failure categories for the live first-owner closure boundary.
///
/// No variant retains a database error, certificate byte, principal ID, or
/// authority identifier, so startup logs cannot accidentally disclose the
/// measured control-plane identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum FirstOwnerRuntimeError {
    #[error("first-owner closure verification received the wrong runtime-guard expectation")]
    WrongExpectedGuard,
    #[error("first-owner closure expectation differs from the deployment security profile")]
    ProfileExpectationMismatch,
    #[error("first-owner closure database measurement timed out")]
    MeasurementTimedOut,
    #[error("first-owner closure database measurement failed")]
    DatabaseReadFailed,
    #[error("the deployment has no permanent first-owner closure record")]
    ClosureRecordMissing,
    #[error("the first-owner closure certificate is not exact canonical JSON")]
    CertificateNotCanonical,
    #[error("the first-owner closure certificate has an invalid closed schema")]
    CertificateSchemaInvalid,
    #[error("the first-owner closure certificate digest is invalid")]
    CertificateDigestInvalid,
    #[error("the detached first-owner closure certificate digest differs from its deployment pin")]
    CertificateFileDigestMismatch,
    #[error("the first-owner closure certificate signature representation is invalid")]
    SignatureRepresentationInvalid,
    #[error("the independently pinned first-owner authority binding is invalid")]
    AuthorityBindingInvalid,
    #[error("the first-owner closure certificate signature is invalid")]
    SignatureVerificationFailed,
    #[error("the first-owner closure database columns differ from the certificate")]
    StoredFactsMismatch,
    #[error("the first-owner privileged-domain assignment set is invalid")]
    AssignmentSetInvalid,
    #[error("the first-owner closure atomic audit or domain-event evidence is invalid")]
    AtomicEvidenceInvalid,
    #[error("the first-owner closure core projection is invalid")]
    ProjectionInvalid,
    #[error("the live first-owner closure differs from the receipt-bound expectation")]
    ExpectedValueMismatch,
    #[error("the retained PostgreSQL runtime identity was substituted")]
    RuntimeIdentityInvalid,
    #[error("the retained PostgreSQL channel is inactive or changed")]
    RuntimeChannelInvalid,
    #[error("the live first-owner closure changed after it was sealed")]
    LiveMeasurementChanged,
    #[error("the first-owner installation receipt binding is invalid")]
    ReceiptBindingInvalid,
    #[error("the trusted first-owner installation interval is invalid")]
    InvalidTrustedTimeWindow,
    #[error(
        "the first-owner installation capability is not active for the complete trusted interval"
    )]
    InstallationCapabilityInactive,
}

impl From<FirstOwnerClosureCertificateError> for FirstOwnerRuntimeError {
    fn from(error: FirstOwnerClosureCertificateError) -> Self {
        match error {
            FirstOwnerClosureCertificateError::InvalidCertificate => Self::CertificateSchemaInvalid,
            FirstOwnerClosureCertificateError::NonCanonicalCertificate => {
                Self::CertificateNotCanonical
            }
            FirstOwnerClosureCertificateError::InvalidSignatureRepresentation => {
                Self::SignatureRepresentationInvalid
            }
            FirstOwnerClosureCertificateError::InvalidAuthorityBinding => {
                Self::AuthorityBindingInvalid
            }
            FirstOwnerClosureCertificateError::SignatureVerificationFailed => {
                Self::SignatureVerificationFailed
            }
        }
    }
}

impl FirstOwnerRuntimeError {
    /// Payload-free category suitable for operator-facing migration errors.
    pub(crate) const fn redacted_category(&self) -> &'static str {
        match self {
            Self::DatabaseReadFailed => "database-read-failed",
            Self::MeasurementTimedOut => "measurement-timed-out",
            Self::ClosureRecordMissing => "closure-record-missing",
            Self::RuntimeChannelInvalid => "runtime-channel-invalid",
            _ => "evidence-integrity-or-admission-failed",
        }
    }
}

/// Independently provisioned first-owner authority trust anchor.
///
/// These values must come from the workload/deployment trust channel, never
/// from the closure row or the rollbackable security-contract root.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct FirstOwnerAuthorityAnchor {
    authority_id: String,
    key_id: String,
    public_key_fingerprint: String,
    minimum_authority_epoch: u64,
    public_key_bytes: [u8; 32],
}

impl fmt::Debug for FirstOwnerAuthorityAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirstOwnerAuthorityAnchor")
            .field("authority_id", &"[PINNED]")
            .field("key_id", &"[PINNED]")
            .field("public_key_fingerprint", &"[PINNED]")
            .field("minimum_authority_epoch", &self.minimum_authority_epoch)
            .field("public_key", &"[PINNED-ED25519-PUBLIC-KEY]")
            .finish()
    }
}

impl FirstOwnerAuthorityAnchor {
    pub(crate) fn new(
        authority_id: String,
        key_id: String,
        public_key_fingerprint: String,
        minimum_authority_epoch: u64,
        public_key_bytes: [u8; 32],
    ) -> Result<Self, FirstOwnerRuntimeError> {
        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|_| FirstOwnerRuntimeError::AuthorityBindingInvalid)?;
        if minimum_authority_epoch == 0
            || minimum_authority_epoch > FIRST_OWNER_MAX_EXACT_JSON_INTEGER
            || verifying_key.is_weak()
            || sha256_digest(&public_key_bytes) != public_key_fingerprint
        {
            return Err(FirstOwnerRuntimeError::AuthorityBindingInvalid);
        }
        Ok(Self {
            authority_id,
            key_id,
            public_key_fingerprint,
            minimum_authority_epoch,
            public_key_bytes,
        })
    }

    fn as_core_anchor(&self) -> FirstOwnerCertificateAuthorityAnchor<'_> {
        FirstOwnerCertificateAuthorityAnchor {
            authority_id: &self.authority_id,
            authority_key_id: &self.key_id,
            public_key: &self.public_key_bytes,
            public_key_fingerprint: &self.public_key_fingerprint,
            minimum_authority_epoch: self.minimum_authority_epoch,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeploymentScope {
    deployment_id: String,
    trust_domain_ids: Vec<String>,
    tenancy_mode: TenancyMode,
}

impl DeploymentScope {
    fn from_profile(
        profile: &DeploymentSecurityProfile,
        expected: &RuntimeGuardExpectedValue,
    ) -> Result<Self, FirstOwnerRuntimeError> {
        let RuntimeGuardExpectedValue::FirstOwnerPathClosed { deployment_id, .. } = expected else {
            return Err(FirstOwnerRuntimeError::WrongExpectedGuard);
        };
        if profile.deployment_id.as_str() != deployment_id.as_str() {
            return Err(FirstOwnerRuntimeError::ProfileExpectationMismatch);
        }
        Ok(Self {
            deployment_id: profile.deployment_id.clone(),
            trust_domain_ids: profile.trust_topology.trust_domain_ids.clone(),
            tenancy_mode: profile.tenancy_mode,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
struct FirstOwnerClosureRow {
    deployment_id: String,
    schema_version: String,
    contract_kind: String,
    canonicalization: String,
    signature_algorithm: String,
    state_contract_version: i64,
    trust_domain_ids: Vec<String>,
    tenancy_mode: String,
    tenant_id: Option<String>,
    authority_id: String,
    authority_key_id: String,
    authority_public_key_fingerprint: String,
    authority_epoch: i64,
    namespace_id: String,
    authority_namespace_digest: String,
    closure_status: String,
    closure_event_id: String,
    authority_sequence: i64,
    first_owner_principal_id: String,
    claim_request_digest: String,
    capability_id: String,
    capability_expires_at_text: String,
    capability_expires_at: DateTime<Utc>,
    closed_at_not_before_text: String,
    closed_at_not_before: DateTime<Utc>,
    closed_at_not_after_text: String,
    closed_at_not_after: DateTime<Utc>,
    certificate_document: Value,
    certificate_bytes: Vec<u8>,
    closure_certificate_digest: String,
    authority_signature: Vec<u8>,
    authority_signature_digest: String,
    closure_record_digest: String,
    audit_log_id: i64,
    domain_event_id: i64,
    recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
struct FirstOwnerAssignmentRow {
    deployment_id: String,
    domain_id: String,
    assignment_event_id: String,
    principal_id: String,
    first_owner_principal_id: String,
    closure_event_id: String,
    closure_certificate_digest: String,
    assigned_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
struct FirstOwnerAuditRow {
    id: i64,
    occurred_at: DateTime<Utc>,
    request_id: Option<String>,
    actor_principal: String,
    actor_display: Option<String>,
    actor_roles: Vec<String>,
    provider_mode: String,
    action: String,
    from_stage: Option<String>,
    to_stage: String,
    from_status: Option<String>,
    to_status: String,
    detail: Value,
    outcome: String,
    prev_hash: String,
    entry_hash: String,
    has_predecessor: bool,
    predecessor_entry_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
struct FirstOwnerDomainEventRow {
    id: i64,
    event_type: String,
    aggregate_type: String,
    aggregate_id: String,
    site: Option<String>,
    environment: Option<String>,
    actor: String,
    payload: Value,
    occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FirstOwnerClosureSnapshot {
    closure: FirstOwnerClosureRow,
    assignments: Vec<FirstOwnerAssignmentRow>,
    audit: FirstOwnerAuditRow,
    domain_event: FirstOwnerDomainEventRow,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct FirstOwnerInstallationBinding {
    deployment_id: String,
    certificate_digest: String,
    authority_namespace_digest: String,
    closure_record_digest: String,
    requirement_digest: String,
    challenge_binding_digest: String,
    installation_valid_until: DateTime<Utc>,
    reconciliation_binding_digest: String,
    installation_binding_digest: String,
}

impl fmt::Debug for FirstOwnerInstallationBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirstOwnerInstallationBinding")
            .field(
                "contract",
                &FIRST_OWNER_INSTALLATION_BINDING_DIGEST_CONTRACT,
            )
            .field("deployment", &"[RECEIPT-BOUND]")
            .field("certificate_digest", &self.certificate_digest)
            .field(
                "reconciliation_binding_digest",
                &self.reconciliation_binding_digest,
            )
            .field(
                "installation_binding_digest",
                &self.installation_binding_digest,
            )
            .finish()
    }
}

impl FirstOwnerInstallationBinding {
    pub(crate) fn deployment_id(&self) -> &str {
        &self.deployment_id
    }

    #[cfg(test)]
    pub(crate) fn certificate_digest(&self) -> &str {
        &self.certificate_digest
    }

    pub(crate) fn authority_namespace_digest(&self) -> &str {
        &self.authority_namespace_digest
    }

    pub(crate) fn closure_record_digest(&self) -> &str {
        &self.closure_record_digest
    }

    pub(crate) fn requirement_digest(&self) -> &str {
        &self.requirement_digest
    }

    pub(crate) fn challenge_binding_digest(&self) -> &str {
        &self.challenge_binding_digest
    }

    /// Exclusive end of fresh installation authority. Readback validation is
    /// intentionally timeless and never rejects merely because this passed.
    pub(crate) fn installation_valid_until(&self) -> DateTime<Utc> {
        self.installation_valid_until.to_owned()
    }

    pub(crate) fn digest(&self) -> &str {
        &self.installation_binding_digest
    }

    /// Stable identity for a committed first-owner installation. Unlike the
    /// fresh authority digest, this excludes transient receipt/challenge and
    /// workload-instance facts so a newly attested one-shot pod can reconcile
    /// an unknown COMMIT outcome without gaining a second write capability.
    pub(crate) fn reconciliation_digest(&self) -> &str {
        &self.reconciliation_binding_digest
    }
}

#[derive(Serialize)]
struct FirstOwnerInstallationBindingProjection<'a> {
    digest_contract: &'static str,
    deployment_id: &'a str,
    state_contract_version: u64,
    certificate_digest: &'a str,
    authority_namespace_digest: &'a str,
    closure_record_digest: &'a str,
    authority_id: &'a str,
    authority_key_id: &'a str,
    authority_epoch: u64,
    capability_expires_at: &'a str,
    requirement_digest: &'a str,
    challenge_binding_digest: &'a str,
}

#[derive(Serialize)]
struct FirstOwnerReconciliationBindingProjection<'a> {
    digest_contract: &'static str,
    deployment_id: &'a str,
    state_contract_version: u64,
    certificate_digest: &'a str,
    authority_namespace_digest: &'a str,
    closure_record_digest: &'a str,
    authority_id: &'a str,
    authority_key_id: &'a str,
    authority_epoch: u64,
    capability_id: &'a str,
    capability_expires_at: &'a str,
}

/// Timeless, non-cloneable proof for one detached first-owner certificate.
///
/// It is not installation authority. The exact bytes, parsed closed type,
/// signature proof, independent authority identity, receipt-bound state, and
/// operation binding remain inseparable until a trusted interval is supplied.
pub(crate) struct VerifiedFirstOwnerInstallCertificate {
    certificate_bytes: Box<[u8]>,
    certificate: FirstOwnerClosureCertificate,
    proof: VerifiedFirstOwnerClosureCertificate,
    authority: FirstOwnerAuthorityAnchor,
    authority_id: String,
    authority_key_id: String,
    authority_epoch: u64,
    scope: DeploymentScope,
    expected: RuntimeGuardExpectedValue,
    binding: FirstOwnerInstallationBinding,
}

impl fmt::Debug for VerifiedFirstOwnerInstallCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedFirstOwnerInstallCertificate")
            .field("contract", &"first-owner-install-certificate-v1")
            .field("certificate", &"[TIMELESS-SIGNATURE-VERIFIED]")
            .field("authority", &"[INDEPENDENTLY-PINNED]")
            .field("binding", &self.binding)
            .finish()
    }
}

impl VerifiedFirstOwnerInstallCertificate {
    #[cfg(test)]
    pub(crate) fn expected_value(&self) -> &RuntimeGuardExpectedValue {
        &self.expected
    }

    pub(crate) fn installation_binding(&self) -> &FirstOwnerInstallationBinding {
        &self.binding
    }

    /// Build another non-cloneable readback expectation without minting write
    /// authority. Lost-COMMIT reconciliation can therefore repeat exact reads
    /// while the one-shot installation path remains unavailable.
    pub(crate) fn readback_expectation(
        &self,
    ) -> Result<FirstOwnerInstallationReadbackExpectation, FirstOwnerRuntimeError> {
        validate_retained_install_certificate(self)?;
        Ok(FirstOwnerInstallationReadbackExpectation {
            scope: self.scope.clone(),
            expected: self.expected.clone(),
            authority: self.authority.clone(),
            binding: self.binding.clone(),
        })
    }

    /// Consume the timeless proof and mint one installation authority only
    /// when the entire conservative trusted interval is inside the capability
    /// window. Expiry is exclusive; permanent serving validation is timeless.
    pub(crate) fn authorize_installation(
        self,
        trusted_now: ConformanceTrustedTimeWindow,
    ) -> Result<VerifiedFirstOwnerInstallationAuthority, FirstOwnerRuntimeError> {
        validate_retained_install_certificate(&self)?;
        if trusted_now.not_before > trusted_now.not_after {
            return Err(FirstOwnerRuntimeError::InvalidTrustedTimeWindow);
        }
        let active_at_start = first_owner_closure_certificate_is_installable_at(
            &self.certificate,
            trusted_now.not_before,
        )?;
        let active_at_end = first_owner_closure_certificate_is_installable_at(
            &self.certificate,
            trusted_now.not_after,
        )?;
        if !active_at_start || !active_at_end {
            return Err(FirstOwnerRuntimeError::InstallationCapabilityInactive);
        }
        Ok(VerifiedFirstOwnerInstallationAuthority { certificate: self })
    }
}

/// Non-cloneable, one-shot database write authority.
pub(crate) struct VerifiedFirstOwnerInstallationAuthority {
    certificate: VerifiedFirstOwnerInstallCertificate,
}

impl fmt::Debug for VerifiedFirstOwnerInstallationAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedFirstOwnerInstallationAuthority")
            .field("contract", &"first-owner-installation-authority-v1")
            .field("binding", &self.certificate.binding)
            .finish()
    }
}

impl VerifiedFirstOwnerInstallationAuthority {
    #[cfg(test)]
    pub(crate) fn installation_binding(&self) -> &FirstOwnerInstallationBinding {
        &self.certificate.binding
    }

    /// The exact certificate bytes are exposed only by consuming the one-shot
    /// authority. The paired expectation survives the SQL call for same-
    /// transaction readback and lost-COMMIT reconciliation.
    pub(crate) fn into_database_storage_parts(
        self,
    ) -> (Box<[u8]>, FirstOwnerInstallationReadbackExpectation) {
        let VerifiedFirstOwnerInstallCertificate {
            certificate_bytes,
            authority,
            scope,
            expected,
            binding,
            ..
        } = self.certificate;
        (
            certificate_bytes,
            FirstOwnerInstallationReadbackExpectation {
                scope,
                expected,
                authority,
                binding,
            },
        )
    }
}

/// Exact state retained across a storage call and usable on an existing SQLx
/// transaction connection. It deliberately has no `Clone` implementation.
pub(crate) struct FirstOwnerInstallationReadbackExpectation {
    scope: DeploymentScope,
    expected: RuntimeGuardExpectedValue,
    authority: FirstOwnerAuthorityAnchor,
    binding: FirstOwnerInstallationBinding,
}

impl fmt::Debug for FirstOwnerInstallationReadbackExpectation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirstOwnerInstallationReadbackExpectation")
            .field("contract", &"first-owner-installation-readback-v1")
            .field("binding", &self.binding)
            .finish()
    }
}

impl FirstOwnerInstallationReadbackExpectation {
    #[cfg(test)]
    pub(crate) fn expected_value(&self) -> &RuntimeGuardExpectedValue {
        &self.expected
    }

    #[cfg(test)]
    pub(crate) fn installation_binding(&self) -> &FirstOwnerInstallationBinding {
        &self.binding
    }
}

/// Verify a detached, digest-pinned certificate against the deployment
/// profile and the exact `FirstOwnerPathClosed` receipt challenge.
pub(crate) fn verify_first_owner_install_certificate(
    certificate_bytes: Vec<u8>,
    expected_file_digest: &str,
    profile: &DeploymentSecurityProfile,
    expected: &RuntimeGuardExpectedValue,
    requirement_digest: &str,
    challenge_binding_digest: &str,
    authority: FirstOwnerAuthorityAnchor,
) -> Result<VerifiedFirstOwnerInstallCertificate, FirstOwnerRuntimeError> {
    let scope = DeploymentScope::from_profile(profile, expected)?;
    verify_first_owner_install_certificate_for_scope(
        certificate_bytes,
        expected_file_digest,
        scope,
        expected,
        requirement_digest,
        challenge_binding_digest,
        authority,
    )
}

fn verify_first_owner_install_certificate_for_scope(
    certificate_bytes: Vec<u8>,
    expected_file_digest: &str,
    scope: DeploymentScope,
    expected: &RuntimeGuardExpectedValue,
    requirement_digest: &str,
    challenge_binding_digest: &str,
    authority: FirstOwnerAuthorityAnchor,
) -> Result<VerifiedFirstOwnerInstallCertificate, FirstOwnerRuntimeError> {
    if !valid_sha256_digest(expected_file_digest)
        || sha256_digest(&certificate_bytes) != expected_file_digest
    {
        return Err(FirstOwnerRuntimeError::CertificateFileDigestMismatch);
    }
    let certificate = parse_first_owner_closure_certificate(&certificate_bytes)?;
    if first_owner_closure_certificate_canonical_bytes(&certificate)? != certificate_bytes {
        return Err(FirstOwnerRuntimeError::CertificateNotCanonical);
    }
    let proof = verify_first_owner_closure_certificate(&certificate, authority.as_core_anchor())?;
    if proof.certificate_digest() != expected_file_digest {
        return Err(FirstOwnerRuntimeError::CertificateFileDigestMismatch);
    }
    validate_certificate_receipt_scope(&certificate, &proof, &scope, expected)?;
    let binding = first_owner_installation_binding(
        &certificate,
        &proof,
        expected,
        requirement_digest,
        challenge_binding_digest,
    )?;
    let authority_id = certificate.authority_namespace.authority_id.clone();
    let authority_key_id = certificate.authority_namespace.authority_key_id.clone();
    let authority_epoch = certificate.authority_namespace.authority_epoch;
    Ok(VerifiedFirstOwnerInstallCertificate {
        certificate_bytes: certificate_bytes.into_boxed_slice(),
        certificate,
        proof,
        authority,
        authority_id,
        authority_key_id,
        authority_epoch,
        scope,
        expected: expected.clone(),
        binding,
    })
}

fn validate_certificate_receipt_scope(
    certificate: &FirstOwnerClosureCertificate,
    proof: &VerifiedFirstOwnerClosureCertificate,
    scope: &DeploymentScope,
    expected: &RuntimeGuardExpectedValue,
) -> Result<(), FirstOwnerRuntimeError> {
    let RuntimeGuardExpectedValue::FirstOwnerPathClosed {
        deployment_id,
        state_contract_version,
        authority_namespace_digest,
        closure_record_digest,
    } = expected
    else {
        return Err(FirstOwnerRuntimeError::WrongExpectedGuard);
    };
    if deployment_id != &scope.deployment_id
        || certificate.authority_namespace.deployment_id != scope.deployment_id
        || certificate.authority_namespace.trust_domain_ids != scope.trust_domain_ids
        || certificate.authority_namespace.tenancy_mode != scope.tenancy_mode
        || certificate.closure.deployment_id != scope.deployment_id
    {
        return Err(FirstOwnerRuntimeError::ProfileExpectationMismatch);
    }
    if *state_contract_version != certificate.closure.state_contract_version
        || authority_namespace_digest != proof.authority_namespace_digest()
        || closure_record_digest != proof.closure_record_digest()
    {
        return Err(FirstOwnerRuntimeError::ExpectedValueMismatch);
    }
    Ok(())
}

fn first_owner_installation_binding(
    certificate: &FirstOwnerClosureCertificate,
    proof: &VerifiedFirstOwnerClosureCertificate,
    expected: &RuntimeGuardExpectedValue,
    requirement_digest: &str,
    challenge_binding_digest: &str,
) -> Result<FirstOwnerInstallationBinding, FirstOwnerRuntimeError> {
    let RuntimeGuardExpectedValue::FirstOwnerPathClosed {
        deployment_id,
        state_contract_version,
        authority_namespace_digest,
        closure_record_digest,
    } = expected
    else {
        return Err(FirstOwnerRuntimeError::WrongExpectedGuard);
    };
    let bound_digests = [
        proof.certificate_digest(),
        proof.authority_namespace_digest(),
        proof.closure_record_digest(),
        proof.signature_digest(),
        requirement_digest,
        challenge_binding_digest,
    ];
    if bound_digests
        .iter()
        .any(|digest| !valid_sha256_digest(digest))
        || bound_digests
            .iter()
            .enumerate()
            .any(|(index, digest)| bound_digests[index + 1..].contains(digest))
        || authority_namespace_digest != proof.authority_namespace_digest()
        || closure_record_digest != proof.closure_record_digest()
    {
        return Err(FirstOwnerRuntimeError::ReceiptBindingInvalid);
    }
    let projection = FirstOwnerInstallationBindingProjection {
        digest_contract: FIRST_OWNER_INSTALLATION_BINDING_DIGEST_CONTRACT,
        deployment_id,
        state_contract_version: *state_contract_version,
        certificate_digest: proof.certificate_digest(),
        authority_namespace_digest,
        closure_record_digest,
        authority_id: &certificate.authority_namespace.authority_id,
        authority_key_id: &certificate.authority_namespace.authority_key_id,
        authority_epoch: certificate.authority_namespace.authority_epoch,
        capability_expires_at: &certificate.closure.capability_expires_at,
        requirement_digest,
        challenge_binding_digest,
    };
    let reconciliation_projection = FirstOwnerReconciliationBindingProjection {
        digest_contract: FIRST_OWNER_RECONCILIATION_BINDING_DIGEST_CONTRACT,
        deployment_id,
        state_contract_version: *state_contract_version,
        certificate_digest: proof.certificate_digest(),
        authority_namespace_digest,
        closure_record_digest,
        authority_id: &certificate.authority_namespace.authority_id,
        authority_key_id: &certificate.authority_namespace.authority_key_id,
        authority_epoch: certificate.authority_namespace.authority_epoch,
        capability_id: &certificate.closure.capability_id,
        capability_expires_at: &certificate.closure.capability_expires_at,
    };
    let canonical = canonical_json_bytes(
        &serde_json::to_value(projection)
            .map_err(|_| FirstOwnerRuntimeError::ReceiptBindingInvalid)?,
    )
    .map_err(|_| FirstOwnerRuntimeError::ReceiptBindingInvalid)?;
    let reconciliation_canonical = canonical_json_bytes(
        &serde_json::to_value(reconciliation_projection)
            .map_err(|_| FirstOwnerRuntimeError::ReceiptBindingInvalid)?,
    )
    .map_err(|_| FirstOwnerRuntimeError::ReceiptBindingInvalid)?;
    Ok(FirstOwnerInstallationBinding {
        deployment_id: deployment_id.clone(),
        certificate_digest: proof.certificate_digest().to_owned(),
        authority_namespace_digest: authority_namespace_digest.clone(),
        closure_record_digest: closure_record_digest.clone(),
        requirement_digest: requirement_digest.to_owned(),
        challenge_binding_digest: challenge_binding_digest.to_owned(),
        installation_valid_until: parse_exact_timestamp(
            &certificate.closure.capability_expires_at,
        )?,
        reconciliation_binding_digest: sha256_digest(&reconciliation_canonical),
        installation_binding_digest: sha256_digest(&canonical),
    })
}

fn validate_retained_install_certificate(
    verified: &VerifiedFirstOwnerInstallCertificate,
) -> Result<(), FirstOwnerRuntimeError> {
    if sha256_digest(&verified.certificate_bytes) != verified.proof.certificate_digest()
        || first_owner_closure_certificate_canonical_bytes(&verified.certificate)?
            != verified.certificate_bytes.as_ref()
        || parse_first_owner_closure_certificate(&verified.certificate_bytes)?
            != verified.certificate
    {
        return Err(FirstOwnerRuntimeError::CertificateDigestInvalid);
    }
    let reverified = verify_first_owner_closure_certificate(
        &verified.certificate,
        verified.authority.as_core_anchor(),
    )?;
    if reverified != verified.proof
        || verified.authority_id != verified.certificate.authority_namespace.authority_id
        || verified.authority_key_id != verified.certificate.authority_namespace.authority_key_id
        || verified.authority_epoch != verified.certificate.authority_namespace.authority_epoch
    {
        return Err(FirstOwnerRuntimeError::AuthorityBindingInvalid);
    }
    validate_certificate_receipt_scope(
        &verified.certificate,
        &verified.proof,
        &verified.scope,
        &verified.expected,
    )?;
    let rebound = first_owner_installation_binding(
        &verified.certificate,
        &verified.proof,
        &verified.expected,
        verified.binding.requirement_digest(),
        verified.binding.challenge_binding_digest(),
    )?;
    if rebound != verified.binding {
        return Err(FirstOwnerRuntimeError::ReceiptBindingInvalid);
    }
    Ok(())
}

/// The verified local half of `FirstOwnerPathClosed`.
///
/// This handle intentionally retains the exact `RetainedPostgresqlRuntime`
/// allocation and separate pointers to its pool, session binding, and runtime
/// observation.  The nominal runtime-guard witness remains responsible for
/// challenge binding and freshness.
pub(crate) struct VerifiedFirstOwnerClosureRuntime {
    runtime: Arc<RetainedPostgresqlRuntime>,
    exact_pool: Arc<PgPool>,
    exact_session_binding: Arc<PostgresqlSessionBinding>,
    exact_runtime_observation: Arc<PostgresqlRuntimeObservation>,
    authority: FirstOwnerAuthorityAnchor,
    scope: DeploymentScope,
    expected: RuntimeGuardExpectedValue,
    observed: RuntimeGuardExpectedValue,
    snapshot: FirstOwnerClosureSnapshot,
}

impl fmt::Debug for VerifiedFirstOwnerClosureRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedFirstOwnerClosureRuntime")
            .field("contract", &"first-owner-path-closed-live-v1")
            .field("deployment", &"[RECEIPT-BOUND]")
            .field("closure", &"[VERIFIED]")
            .field("privileged_domain_assignments", &"[VERIFIED-SET]")
            .field("postgresql_channel", &"[RETAINED]")
            .finish()
    }
}

impl VerifiedFirstOwnerClosureRuntime {
    pub(crate) fn runtime(&self) -> &Arc<RetainedPostgresqlRuntime> {
        &self.runtime
    }

    pub(crate) fn observed_value(&self) -> &RuntimeGuardExpectedValue {
        &self.observed
    }

    /// Confirm that `candidate` is the same complete retained PostgreSQL
    /// runtime, not merely a pool that reaches the same database.
    pub(crate) fn same_runtime(&self, candidate: &RetainedPostgresqlRuntime) -> bool {
        self.runtime.same_runtime(candidate)
            && candidate.pool_ptr_eq(&self.exact_pool)
            && candidate.observation_ptr_eq(&self.exact_runtime_observation)
            && Arc::ptr_eq(candidate.session_binding(), &self.exact_session_binding)
    }

    /// Synchronous integrity fence.  Channel liveness is repeated by
    /// `remeasure_exact`; this fence proves that all locally retained channel,
    /// pool, session, observation, profile, and closure projections are still
    /// the exact allocations and values sealed by the initial measurement.
    pub(crate) fn verify_integrity(&self) -> Result<(), FirstOwnerRuntimeError> {
        if !self.same_runtime(self.runtime.as_ref()) {
            return Err(FirstOwnerRuntimeError::RuntimeIdentityInvalid);
        }
        let revalidated =
            validate_snapshot(&self.snapshot, &self.scope, &self.expected, &self.authority)?;
        if revalidated != self.observed {
            return Err(FirstOwnerRuntimeError::RuntimeIdentityInvalid);
        }
        Ok(())
    }

    /// Repeat the closure query through the exact retained PostgreSQL channel.
    ///
    /// Synchronous fences run on both sides of the asynchronous query.  The
    /// retained DurablePostgresql measurement also runs on both sides, which
    /// proves the single TLS channel remains active and unchanged.
    pub(crate) async fn remeasure_exact(
        &self,
        profile: &DeploymentSecurityProfile,
        expected: &RuntimeGuardExpectedValue,
    ) -> Result<(), FirstOwnerRuntimeError> {
        let scope = DeploymentScope::from_profile(profile, expected)?;
        if scope != self.scope || expected != &self.expected {
            return Err(FirstOwnerRuntimeError::ProfileExpectationMismatch);
        }
        self.verify_integrity()?;
        let snapshot = bounded_live_snapshot(self.runtime.as_ref(), &scope.deployment_id).await?;
        let observed = validate_snapshot(&snapshot, &scope, expected, &self.authority)?;
        if snapshot != self.snapshot || observed != self.observed {
            return Err(FirstOwnerRuntimeError::LiveMeasurementChanged);
        }
        self.verify_integrity()
    }
}

/// Measure and verify the deployment's permanent first-owner closure through
/// the exact unpublished DurablePostgresql runtime.
pub(crate) async fn verify_first_owner_path_closed(
    runtime: Arc<RetainedPostgresqlRuntime>,
    profile: &DeploymentSecurityProfile,
    expected: &RuntimeGuardExpectedValue,
    authority: FirstOwnerAuthorityAnchor,
) -> Result<VerifiedFirstOwnerClosureRuntime, FirstOwnerRuntimeError> {
    let scope = DeploymentScope::from_profile(profile, expected)?;
    let snapshot = bounded_live_snapshot(runtime.as_ref(), &scope.deployment_id).await?;
    let observed = validate_snapshot(&snapshot, &scope, expected, &authority)?;
    let verified = VerifiedFirstOwnerClosureRuntime {
        exact_pool: Arc::clone(runtime.pool()),
        exact_session_binding: Arc::clone(runtime.session_binding()),
        exact_runtime_observation: Arc::clone(runtime.observation()),
        runtime,
        authority,
        scope,
        expected: expected.clone(),
        observed,
        snapshot,
    };
    verified.verify_integrity()?;
    Ok(verified)
}

async fn bounded_live_snapshot(
    runtime: &RetainedPostgresqlRuntime,
    deployment_id: &str,
) -> Result<FirstOwnerClosureSnapshot, FirstOwnerRuntimeError> {
    tokio::time::timeout(LIVE_MEASUREMENT_TIMEOUT, async {
        runtime
            .remeasure_exact()
            .await
            .map_err(|_| FirstOwnerRuntimeError::RuntimeChannelInvalid)?;
        let snapshot = read_snapshot(runtime.pool(), deployment_id).await?;
        runtime
            .remeasure_exact()
            .await
            .map_err(|_| FirstOwnerRuntimeError::RuntimeChannelInvalid)?;
        Ok(snapshot)
    })
    .await
    .map_err(|_| FirstOwnerRuntimeError::MeasurementTimedOut)?
}

async fn configure_read_only_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), FirstOwnerRuntimeError> {
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut **transaction)
        .await
        .map_err(|_| FirstOwnerRuntimeError::DatabaseReadFailed)?;
    sqlx::query("SET LOCAL statement_timeout = '5s'")
        .execute(&mut **transaction)
        .await
        .map_err(|_| FirstOwnerRuntimeError::DatabaseReadFailed)?;
    sqlx::query("SET LOCAL lock_timeout = '2s'")
        .execute(&mut **transaction)
        .await
        .map_err(|_| FirstOwnerRuntimeError::DatabaseReadFailed)?;
    sqlx::query("SET LOCAL idle_in_transaction_session_timeout = '5s'")
        .execute(&mut **transaction)
        .await
        .map_err(|_| FirstOwnerRuntimeError::DatabaseReadFailed)?;
    Ok(())
}

async fn read_snapshot(
    pool: &PgPool,
    deployment_id: &str,
) -> Result<FirstOwnerClosureSnapshot, FirstOwnerRuntimeError> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| FirstOwnerRuntimeError::DatabaseReadFailed)?;
    configure_read_only_snapshot(&mut transaction).await?;
    let snapshot = read_snapshot_from_connection(&mut transaction, deployment_id).await?;
    transaction
        .commit()
        .await
        .map_err(|_| FirstOwnerRuntimeError::DatabaseReadFailed)?;
    Ok(snapshot)
}

async fn read_snapshot_from_connection(
    connection: &mut PgConnection,
    deployment_id: &str,
) -> Result<FirstOwnerClosureSnapshot, FirstOwnerRuntimeError> {
    let mut closures = sqlx::query_as::<_, FirstOwnerClosureRow>(
        r#"
        SELECT
            deployment_id,
            schema_version,
            contract_kind,
            canonicalization,
            signature_algorithm,
            state_contract_version,
            trust_domain_ids,
            tenancy_mode,
            tenant_id,
            authority_id,
            authority_key_id,
            authority_public_key_fingerprint,
            authority_epoch,
            namespace_id,
            authority_namespace_digest,
            closure_status,
            closure_event_id,
            authority_sequence,
            first_owner_principal_id,
            claim_request_digest,
            capability_id,
            capability_expires_at_text,
            capability_expires_at,
            closed_at_not_before_text,
            closed_at_not_before,
            closed_at_not_after_text,
            closed_at_not_after,
            certificate_document,
            certificate_bytes,
            closure_certificate_digest,
            authority_signature,
            authority_signature_digest,
            closure_record_digest,
            audit_log_id,
            domain_event_id,
            recorded_at
        FROM public.first_owner_closure_records
        WHERE deployment_id = $1
        LIMIT 2
        "#,
    )
    .bind(deployment_id)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| FirstOwnerRuntimeError::DatabaseReadFailed)?;
    if closures.is_empty() {
        return Err(FirstOwnerRuntimeError::ClosureRecordMissing);
    }
    if closures.len() != 1 {
        return Err(FirstOwnerRuntimeError::AtomicEvidenceInvalid);
    }
    let closure = closures
        .pop()
        .ok_or(FirstOwnerRuntimeError::ClosureRecordMissing)?;
    let assignments = sqlx::query_as::<_, FirstOwnerAssignmentRow>(
        r#"
        SELECT
            deployment_id,
            domain_id,
            assignment_event_id,
            principal_id,
            first_owner_principal_id,
            closure_event_id,
            closure_certificate_digest,
            assigned_at
        FROM public.first_owner_privileged_domain_assignments
        WHERE deployment_id = $1
        ORDER BY domain_id COLLATE "C"
        LIMIT 6
        "#,
    )
    .bind(deployment_id)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| FirstOwnerRuntimeError::DatabaseReadFailed)?;
    let mut audits = sqlx::query_as::<_, FirstOwnerAuditRow>(
        r#"
        SELECT
            audit.id,
            audit.occurred_at,
            audit.request_id::TEXT AS request_id,
            audit.actor_principal,
            audit.actor_display,
            audit.actor_roles,
            audit.provider_mode,
            audit.action,
            audit.from_stage,
            audit.to_stage,
            audit.from_status,
            audit.to_status,
            audit.detail,
            audit.outcome,
            audit.prev_hash,
            audit.entry_hash,
            EXISTS (
                SELECT 1
                FROM public.audit_log AS predecessor
                WHERE predecessor.id < audit.id
            ) AS has_predecessor,
            (
                SELECT predecessor.entry_hash
                FROM public.audit_log AS predecessor
                WHERE predecessor.id < audit.id
                ORDER BY predecessor.id DESC
                LIMIT 1
            ) AS predecessor_entry_hash
        FROM public.audit_log AS audit
        WHERE audit.id = $1
        LIMIT 2
        "#,
    )
    .bind(closure.audit_log_id)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| FirstOwnerRuntimeError::DatabaseReadFailed)?;
    if audits.len() != 1 {
        return Err(FirstOwnerRuntimeError::AtomicEvidenceInvalid);
    }
    let audit = audits
        .pop()
        .ok_or(FirstOwnerRuntimeError::AtomicEvidenceInvalid)?;
    let mut domain_events = sqlx::query_as::<_, FirstOwnerDomainEventRow>(
        r#"
        SELECT
            id,
            event_type,
            aggregate_type,
            aggregate_id,
            site,
            environment,
            actor,
            payload,
            occurred_at
        FROM public.domain_events
        WHERE id = $1
        LIMIT 2
        "#,
    )
    .bind(closure.domain_event_id)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| FirstOwnerRuntimeError::DatabaseReadFailed)?;
    if domain_events.len() != 1 {
        return Err(FirstOwnerRuntimeError::AtomicEvidenceInvalid);
    }
    let domain_event = domain_events
        .pop()
        .ok_or(FirstOwnerRuntimeError::AtomicEvidenceInvalid)?;
    Ok(FirstOwnerClosureSnapshot {
        closure,
        assignments,
        audit,
        domain_event,
    })
}

/// Validate an installation readback on the caller's existing PostgreSQL
/// connection. Passing `&mut *transaction` keeps the write and all exact-row,
/// assignment, audit, and domain-event checks in one outer transaction.
pub(crate) async fn validate_first_owner_installation_readback(
    connection: &mut PgConnection,
    expectation: &FirstOwnerInstallationReadbackExpectation,
) -> Result<(), FirstOwnerRuntimeError> {
    let snapshot =
        read_snapshot_from_connection(connection, &expectation.scope.deployment_id).await?;
    let observed = validate_snapshot(
        &snapshot,
        &expectation.scope,
        &expectation.expected,
        &expectation.authority,
    )?;
    if observed != expectation.expected
        || snapshot.closure.closure_certificate_digest != expectation.binding.certificate_digest
    {
        return Err(FirstOwnerRuntimeError::LiveMeasurementChanged);
    }
    Ok(())
}

fn validate_snapshot(
    snapshot: &FirstOwnerClosureSnapshot,
    scope: &DeploymentScope,
    expected: &RuntimeGuardExpectedValue,
    authority: &FirstOwnerAuthorityAnchor,
) -> Result<RuntimeGuardExpectedValue, FirstOwnerRuntimeError> {
    let RuntimeGuardExpectedValue::FirstOwnerPathClosed {
        deployment_id: expected_deployment_id,
        ..
    } = expected
    else {
        return Err(FirstOwnerRuntimeError::WrongExpectedGuard);
    };
    if expected_deployment_id != &scope.deployment_id {
        return Err(FirstOwnerRuntimeError::ProfileExpectationMismatch);
    }

    let row = &snapshot.closure;
    if row.deployment_id != scope.deployment_id
        || row.trust_domain_ids != scope.trust_domain_ids
        || tenancy_mode_label(scope.tenancy_mode) != row.tenancy_mode
    {
        return Err(FirstOwnerRuntimeError::ProfileExpectationMismatch);
    }

    let certificate = parse_first_owner_closure_certificate(&row.certificate_bytes)?;
    let certificate_document = serde_json::to_value(&certificate)
        .map_err(|_| FirstOwnerRuntimeError::CertificateSchemaInvalid)?;
    if first_owner_closure_certificate_canonical_bytes(&certificate)? != row.certificate_bytes
        || certificate_document != row.certificate_document
    {
        return Err(FirstOwnerRuntimeError::CertificateNotCanonical);
    }
    let proof = verify_first_owner_closure_certificate(&certificate, authority.as_core_anchor())?;
    let certificate_digest = proof.certificate_digest();
    if certificate_digest != row.closure_certificate_digest {
        return Err(FirstOwnerRuntimeError::CertificateDigestInvalid);
    }
    let signature_digest = first_owner_closure_certificate_signature_digest(&certificate)?;
    let certificate_signature = BASE64_STANDARD
        .decode(certificate.signature_base64.as_bytes())
        .map_err(|_| FirstOwnerRuntimeError::SignatureRepresentationInvalid)?;
    if certificate_signature.len() != 64
        || BASE64_STANDARD.encode(&certificate_signature) != certificate.signature_base64
        || certificate_signature != row.authority_signature
        || signature_digest != proof.signature_digest()
        || signature_digest != row.authority_signature_digest
        || sha256_digest(&row.authority_signature) != signature_digest
    {
        return Err(FirstOwnerRuntimeError::SignatureRepresentationInvalid);
    }

    let namespace_digest = proof.authority_namespace_digest();
    let state_contract_version =
        i64::try_from(certificate.authority_namespace.state_contract_version)
            .map_err(|_| FirstOwnerRuntimeError::StoredFactsMismatch)?;
    let authority_epoch = i64::try_from(certificate.authority_namespace.authority_epoch)
        .map_err(|_| FirstOwnerRuntimeError::StoredFactsMismatch)?;
    let authority_sequence = i64::try_from(certificate.closure.authority_sequence)
        .map_err(|_| FirstOwnerRuntimeError::StoredFactsMismatch)?;
    if row.schema_version != certificate.schema_version
        || row.contract_kind != certificate.contract_kind
        || row.canonicalization != certificate.canonicalization
        || row.signature_algorithm != certificate.signature_algorithm
        || row.state_contract_version != state_contract_version
        || row.trust_domain_ids != certificate.authority_namespace.trust_domain_ids
        || row.tenancy_mode != tenancy_mode_label(certificate.authority_namespace.tenancy_mode)
        || row.tenant_id != certificate.authority_namespace.tenant_id
        || row.deployment_id != certificate.authority_namespace.deployment_id
        || row.authority_id != certificate.authority_namespace.authority_id
        || row.authority_key_id != certificate.authority_namespace.authority_key_id
        || row.authority_public_key_fingerprint
            != certificate
                .authority_namespace
                .authority_public_key_fingerprint
        || row.authority_epoch != authority_epoch
        || row.namespace_id != certificate.authority_namespace.namespace_id
        || row.authority_namespace_digest != namespace_digest
        || row.state_contract_version
            != i64::try_from(certificate.closure.state_contract_version)
                .map_err(|_| FirstOwnerRuntimeError::StoredFactsMismatch)?
        || row.deployment_id != certificate.closure.deployment_id
        || row.authority_namespace_digest != certificate.closure.authority_namespace_digest
        || row.closure_status != "closed"
        || row.closure_event_id != certificate.closure.closure_event_id
        || row.authority_sequence != authority_sequence
        || row.first_owner_principal_id != certificate.closure.first_owner_principal_id
        || row.claim_request_digest != certificate.closure.claim_request_digest
        || row.capability_id != certificate.closure.capability_id
        || row.capability_expires_at_text != certificate.closure.capability_expires_at
        || row.closed_at_not_before_text != certificate.closure.closed_at_not_before
        || row.closed_at_not_after_text != certificate.closure.closed_at_not_after
    {
        return Err(FirstOwnerRuntimeError::StoredFactsMismatch);
    }

    let capability_expires_at = parse_exact_timestamp(&certificate.closure.capability_expires_at)?;
    let closed_at_not_before = parse_exact_timestamp(&certificate.closure.closed_at_not_before)?;
    let closed_at_not_after = parse_exact_timestamp(&certificate.closure.closed_at_not_after)?;
    if row.capability_expires_at != capability_expires_at
        || row.closed_at_not_before != closed_at_not_before
        || row.closed_at_not_after != closed_at_not_after
        || row.audit_log_id <= 0
        || row.domain_event_id <= 0
        || row.recorded_at < row.closed_at_not_after
        || row.recorded_at >= row.capability_expires_at
    {
        return Err(FirstOwnerRuntimeError::StoredFactsMismatch);
    }

    validate_assignments(snapshot, &certificate, certificate_digest)?;
    validate_atomic_evidence(snapshot, &certificate, certificate_digest)?;

    let closure_record = first_owner_closure_record_from_certificate(&certificate)?;
    let closure_record_digest = first_owner_closure_record_digest(&closure_record)
        .map_err(|_| FirstOwnerRuntimeError::ProjectionInvalid)?;
    if row.closure_record_digest != closure_record_digest
        || closure_record_digest != proof.closure_record_digest()
    {
        return Err(FirstOwnerRuntimeError::StoredFactsMismatch);
    }

    let observed = RuntimeGuardExpectedValue::FirstOwnerPathClosed {
        deployment_id: row.deployment_id.clone(),
        state_contract_version: u64::try_from(row.state_contract_version)
            .map_err(|_| FirstOwnerRuntimeError::ProjectionInvalid)?,
        authority_namespace_digest: namespace_digest.to_owned(),
        closure_record_digest,
    };
    if &observed != expected {
        return Err(FirstOwnerRuntimeError::ExpectedValueMismatch);
    }
    Ok(observed)
}

fn validate_assignments(
    snapshot: &FirstOwnerClosureSnapshot,
    certificate: &FirstOwnerClosureCertificate,
    certificate_digest: &str,
) -> Result<(), FirstOwnerRuntimeError> {
    let signed = &certificate.privileged_domain_assignments;
    if signed.len() != FIRST_OWNER_PRIVILEGED_DOMAINS.len()
        || snapshot.assignments.len() != FIRST_OWNER_PRIVILEGED_DOMAINS.len()
        || !signed
            .iter()
            .map(|assignment| assignment.domain_id.as_str())
            .eq(FIRST_OWNER_PRIVILEGED_DOMAINS)
    {
        return Err(FirstOwnerRuntimeError::AssignmentSetInvalid);
    }
    for (stored, certified) in snapshot.assignments.iter().zip(signed) {
        if stored.deployment_id != snapshot.closure.deployment_id
            || stored.domain_id != certified.domain_id
            || stored.assignment_event_id != certified.assignment_event_id
            || stored.principal_id != certified.principal_id
            || stored.first_owner_principal_id != snapshot.closure.first_owner_principal_id
            || stored.closure_event_id != snapshot.closure.closure_event_id
            || stored.closure_certificate_digest != certificate_digest
            || stored.assigned_at != snapshot.closure.closed_at_not_after
        {
            return Err(FirstOwnerRuntimeError::AssignmentSetInvalid);
        }
    }
    Ok(())
}

fn validate_atomic_evidence(
    snapshot: &FirstOwnerClosureSnapshot,
    certificate: &FirstOwnerClosureCertificate,
    certificate_digest: &str,
) -> Result<(), FirstOwnerRuntimeError> {
    let row = &snapshot.closure;
    let audit = &snapshot.audit;
    let expected_audit_detail = serde_json::json!({
        "authority_namespace_digest": row.authority_namespace_digest,
        "closure_certificate_digest": certificate_digest,
        "closure_event_id": row.closure_event_id,
        "deployment_id": row.deployment_id,
    });
    let expected_prev_hash = match (
        audit.has_predecessor,
        audit.predecessor_entry_hash.as_deref(),
    ) {
        (false, None) => crate::audit::AUDIT_CHAIN_GENESIS,
        (true, Some(predecessor_entry_hash)) => predecessor_entry_hash,
        _ => return Err(FirstOwnerRuntimeError::AtomicEvidenceInvalid),
    };
    let audit_payload = crate::audit::audit_canonical_payload(
        audit.request_id.as_deref(),
        &audit.actor_principal,
        audit.actor_display.as_deref().unwrap_or(""),
        &audit.actor_roles,
        &audit.provider_mode,
        &audit.action,
        audit.from_stage.as_deref(),
        &audit.to_stage,
        audit.from_status.as_deref(),
        &audit.to_status,
        &audit.detail,
        &audit.outcome,
    );
    let expected_entry_hash = crate::audit::chain_hash(expected_prev_hash, &audit_payload);
    if audit.id != row.audit_log_id
        || audit.request_id.is_some()
        || audit.actor_principal != certificate.closure.first_owner_principal_id
        || audit.actor_display.is_some()
        || !audit.actor_roles.is_empty()
        || audit.provider_mode != "first-owner-authority"
        || audit.action != "platform.first-owner.close"
        || audit.from_stage.is_some()
        || audit.to_stage != "bootstrap-closed"
        || audit.from_status.is_some()
        || audit.to_status != "closed"
        || audit.detail != expected_audit_detail
        || audit.outcome != "applied"
        || audit.occurred_at > row.recorded_at
        || audit.prev_hash != expected_prev_hash
        || audit.entry_hash != expected_entry_hash
    {
        return Err(FirstOwnerRuntimeError::AtomicEvidenceInvalid);
    }

    let event = &snapshot.domain_event;
    let expected_event_payload = serde_json::json!({
        "authority_namespace_digest": row.authority_namespace_digest,
        "closure_certificate_digest": certificate_digest,
        "closure_event_id": row.closure_event_id,
    });
    if event.id != row.domain_event_id
        || event.event_type != "platform.first-owner-closed"
        || event.aggregate_type != "deployment"
        || event.aggregate_id != row.deployment_id
        || event.site.is_some()
        || event.environment.is_some()
        || event.actor != certificate.closure.first_owner_principal_id
        || event.payload != expected_event_payload
        || event.occurred_at != row.closed_at_not_after
    {
        return Err(FirstOwnerRuntimeError::AtomicEvidenceInvalid);
    }
    Ok(())
}

fn parse_exact_timestamp(value: &str) -> Result<DateTime<Utc>, FirstOwnerRuntimeError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| FirstOwnerRuntimeError::CertificateSchemaInvalid)
}

fn tenancy_mode_label(mode: TenancyMode) -> &'static str {
    match mode {
        TenancyMode::SingleTenant => "single_tenant",
        TenancyMode::MultiTenant => "multi_tenant",
    }
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn valid_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && hex.bytes().any(|byte| byte != b'0')
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use rand::rngs::OsRng;
    use ryuki_core::security_profile::{
        first_owner_authority_namespace_digest, first_owner_closure_certificate_signing_bytes,
        FirstOwnerAuthorityNamespace, FirstOwnerClosureStatus, SignedFirstOwnerClosure,
        SignedPrivilegedDomainAssignment,
    };
    use serde_json::json;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn timestamp(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn fixture() -> (
        FirstOwnerClosureSnapshot,
        DeploymentScope,
        RuntimeGuardExpectedValue,
        FirstOwnerAuthorityAnchor,
    ) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key_bytes = signing_key.verifying_key().to_bytes();
        let public_key_fingerprint = sha256_digest(&public_key_bytes);
        let authority = FirstOwnerAuthorityAnchor::new(
            "first-owner-authority:fixture".into(),
            "first-owner-authority-key:fixture".into(),
            public_key_fingerprint.clone(),
            1,
            public_key_bytes,
        )
        .unwrap();
        let namespace = FirstOwnerAuthorityNamespace {
            state_contract_version: 1,
            deployment_id: "deployment:fixture".into(),
            trust_domain_ids: vec!["trust-domain:fixture".into()],
            tenancy_mode: TenancyMode::SingleTenant,
            tenant_id: None,
            authority_id: "first-owner-authority:fixture".into(),
            authority_key_id: "first-owner-authority-key:fixture".into(),
            authority_public_key_fingerprint: public_key_fingerprint.clone(),
            authority_epoch: 1,
            namespace_id: "first-owner-namespace:fixture".into(),
        };
        let namespace_digest = first_owner_authority_namespace_digest(&namespace).unwrap();
        let closure = SignedFirstOwnerClosure {
            state_contract_version: 1,
            deployment_id: "deployment:fixture".into(),
            authority_namespace_digest: namespace_digest.clone(),
            status: FirstOwnerClosureStatus::Closed,
            closure_event_id: "first-owner-closure-event:fixture".into(),
            authority_sequence: 1,
            first_owner_principal_id: "principal:fixture-owner".into(),
            claim_request_digest: digest('2'),
            capability_id: "first-owner-capability:fixture".into(),
            capability_expires_at: "2026-01-01T00:05:00Z".into(),
            closed_at_not_before: "2026-01-01T00:00:00Z".into(),
            closed_at_not_after: "2026-01-01T00:00:01Z".into(),
        };
        let signed_assignments = FIRST_OWNER_PRIVILEGED_DOMAINS
            .iter()
            .enumerate()
            .map(|(index, domain)| SignedPrivilegedDomainAssignment {
                assignment_event_id: format!("first-owner-assignment-event:fixture-{index}"),
                domain_id: (*domain).into(),
                principal_id: "principal:fixture-owner".into(),
            })
            .collect::<Vec<_>>();
        let mut certificate = FirstOwnerClosureCertificate {
            schema_version: "1.0.0".into(),
            contract_kind: "first-owner-closure-certificate".into(),
            canonicalization: "ryuki-canonical-json-v1".into(),
            signature_algorithm: "ed25519".into(),
            authority_namespace: namespace,
            closure,
            privileged_domain_assignments: signed_assignments,
            signature_base64: BASE64_STANDARD.encode(
                signing_key
                    .sign(b"first-owner certificate fixture placeholder")
                    .to_bytes(),
            ),
        };
        let signature = signing_key
            .sign(&first_owner_closure_certificate_signing_bytes(&certificate).unwrap())
            .to_bytes()
            .to_vec();
        certificate.signature_base64 = BASE64_STANDARD.encode(&signature);
        let certificate_document = serde_json::to_value(&certificate).unwrap();
        let certificate_bytes = canonical_json_bytes(&certificate_document).unwrap();
        let certificate_digest = sha256_digest(&certificate_bytes);
        let closure_record = first_owner_closure_record_from_certificate(&certificate).unwrap();
        let closure_record_digest = first_owner_closure_record_digest(&closure_record).unwrap();
        let closed_at_not_after = timestamp("2026-01-01T00:00:01Z");
        let assignments = certificate
            .privileged_domain_assignments
            .iter()
            .map(|assignment| FirstOwnerAssignmentRow {
                deployment_id: "deployment:fixture".into(),
                domain_id: assignment.domain_id.clone(),
                assignment_event_id: assignment.assignment_event_id.clone(),
                principal_id: assignment.principal_id.clone(),
                first_owner_principal_id: "principal:fixture-owner".into(),
                closure_event_id: "first-owner-closure-event:fixture".into(),
                closure_certificate_digest: certificate_digest.clone(),
                assigned_at: closed_at_not_after,
            })
            .collect();
        let audit_detail = json!({
            "authority_namespace_digest": namespace_digest.clone(),
            "closure_certificate_digest": certificate_digest.clone(),
            "closure_event_id": "first-owner-closure-event:fixture",
            "deployment_id": "deployment:fixture",
        });
        let audit_payload = crate::audit::audit_canonical_payload(
            None,
            "principal:fixture-owner",
            "",
            &[],
            "first-owner-authority",
            "platform.first-owner.close",
            None,
            "bootstrap-closed",
            None,
            "closed",
            &audit_detail,
            "applied",
        );
        let audit_entry_hash =
            crate::audit::chain_hash(crate::audit::AUDIT_CHAIN_GENESIS, &audit_payload);
        let snapshot = FirstOwnerClosureSnapshot {
            closure: FirstOwnerClosureRow {
                deployment_id: "deployment:fixture".into(),
                schema_version: "1.0.0".into(),
                contract_kind: "first-owner-closure-certificate".into(),
                canonicalization: "ryuki-canonical-json-v1".into(),
                signature_algorithm: "ed25519".into(),
                state_contract_version: 1,
                trust_domain_ids: vec!["trust-domain:fixture".into()],
                tenancy_mode: "single_tenant".into(),
                tenant_id: None,
                authority_id: "first-owner-authority:fixture".into(),
                authority_key_id: "first-owner-authority-key:fixture".into(),
                authority_public_key_fingerprint: public_key_fingerprint,
                authority_epoch: 1,
                namespace_id: "first-owner-namespace:fixture".into(),
                authority_namespace_digest: namespace_digest.clone(),
                closure_status: "closed".into(),
                closure_event_id: "first-owner-closure-event:fixture".into(),
                authority_sequence: 1,
                first_owner_principal_id: "principal:fixture-owner".into(),
                claim_request_digest: digest('2'),
                capability_id: "first-owner-capability:fixture".into(),
                capability_expires_at_text: "2026-01-01T00:05:00Z".into(),
                capability_expires_at: timestamp("2026-01-01T00:05:00Z"),
                closed_at_not_before_text: "2026-01-01T00:00:00Z".into(),
                closed_at_not_before: timestamp("2026-01-01T00:00:00Z"),
                closed_at_not_after_text: "2026-01-01T00:00:01Z".into(),
                closed_at_not_after,
                certificate_document,
                certificate_bytes,
                closure_certificate_digest: certificate_digest.clone(),
                authority_signature: signature.clone(),
                authority_signature_digest: sha256_digest(&signature),
                closure_record_digest: closure_record_digest.clone(),
                audit_log_id: 1,
                domain_event_id: 1,
                recorded_at: timestamp("2026-01-01T00:00:02Z"),
            },
            assignments,
            audit: FirstOwnerAuditRow {
                id: 1,
                occurred_at: timestamp("2026-01-01T00:00:00Z"),
                request_id: None,
                actor_principal: "principal:fixture-owner".into(),
                actor_display: None,
                actor_roles: Vec::new(),
                provider_mode: "first-owner-authority".into(),
                action: "platform.first-owner.close".into(),
                from_stage: None,
                to_stage: "bootstrap-closed".into(),
                from_status: None,
                to_status: "closed".into(),
                detail: audit_detail,
                outcome: "applied".into(),
                prev_hash: crate::audit::AUDIT_CHAIN_GENESIS.into(),
                entry_hash: audit_entry_hash,
                has_predecessor: false,
                predecessor_entry_hash: None,
            },
            domain_event: FirstOwnerDomainEventRow {
                id: 1,
                event_type: "platform.first-owner-closed".into(),
                aggregate_type: "deployment".into(),
                aggregate_id: "deployment:fixture".into(),
                site: None,
                environment: None,
                actor: "principal:fixture-owner".into(),
                payload: json!({
                    "authority_namespace_digest": namespace_digest.clone(),
                    "closure_certificate_digest": certificate_digest.clone(),
                    "closure_event_id": "first-owner-closure-event:fixture",
                }),
                occurred_at: closed_at_not_after,
            },
        };
        let scope = DeploymentScope {
            deployment_id: "deployment:fixture".into(),
            trust_domain_ids: vec!["trust-domain:fixture".into()],
            tenancy_mode: TenancyMode::SingleTenant,
        };
        let expected = RuntimeGuardExpectedValue::FirstOwnerPathClosed {
            deployment_id: "deployment:fixture".into(),
            state_contract_version: 1,
            authority_namespace_digest: namespace_digest,
            closure_record_digest,
        };
        (snapshot, scope, expected, authority)
    }

    fn install_fixture() -> (
        Vec<u8>,
        String,
        DeploymentScope,
        RuntimeGuardExpectedValue,
        FirstOwnerAuthorityAnchor,
    ) {
        let (snapshot, scope, expected, authority) = fixture();
        (
            snapshot.closure.certificate_bytes,
            snapshot.closure.closure_certificate_digest,
            scope,
            expected,
            authority,
        )
    }

    fn verify_install_fixture(
        bytes: Vec<u8>,
        file_digest: &str,
        scope: DeploymentScope,
        expected: &RuntimeGuardExpectedValue,
        requirement_digest: &str,
        challenge_binding_digest: &str,
        authority: FirstOwnerAuthorityAnchor,
    ) -> Result<VerifiedFirstOwnerInstallCertificate, FirstOwnerRuntimeError> {
        verify_first_owner_install_certificate_for_scope(
            bytes,
            file_digest,
            scope,
            expected,
            requirement_digest,
            challenge_binding_digest,
            authority,
        )
    }

    #[test]
    fn detached_certificate_retains_exact_receipt_and_repeatable_readback_binding() {
        let (bytes, file_digest, scope, expected, authority) = install_fixture();
        let verified = verify_install_fixture(
            bytes.clone(),
            &file_digest,
            scope,
            &expected,
            &digest('8'),
            &digest('9'),
            authority,
        )
        .unwrap();
        assert_eq!(verified.expected_value(), &expected);
        assert_eq!(
            verified.installation_binding().certificate_digest(),
            file_digest
        );
        let installation_valid_until = timestamp("2026-01-01T00:05:00Z");
        assert_eq!(
            verified.installation_binding().installation_valid_until(),
            installation_valid_until
        );
        let first = verified.readback_expectation().unwrap();
        let second = verified.readback_expectation().unwrap();
        assert_eq!(first.expected_value(), &expected);
        assert_eq!(first.installation_binding(), second.installation_binding());

        let authority = verified
            .authorize_installation(ConformanceTrustedTimeWindow {
                not_before: timestamp("2026-01-01T00:00:01Z"),
                not_after: timestamp("2026-01-01T00:04:59Z"),
            })
            .unwrap();
        let marker_digest = authority.installation_binding().digest().to_owned();
        assert_eq!(
            authority.installation_binding().installation_valid_until(),
            installation_valid_until
        );
        let (storage_bytes, readback) = authority.into_database_storage_parts();
        assert_eq!(storage_bytes.as_ref(), bytes);
        assert_eq!(readback.installation_binding().digest(), marker_digest);
        assert_eq!(
            readback.installation_binding().installation_valid_until(),
            installation_valid_until
        );
    }

    #[test]
    fn deployment_scope_substitutions_are_rejected() {
        for mutate in [0_u8, 1, 2] {
            let (bytes, file_digest, mut scope, expected, authority) = install_fixture();
            match mutate {
                0 => scope.deployment_id = "deployment:substituted".into(),
                1 => scope.trust_domain_ids = vec!["trust-domain:substituted".into()],
                2 => scope.tenancy_mode = TenancyMode::MultiTenant,
                _ => unreachable!(),
            }
            assert!(matches!(
                verify_install_fixture(
                    bytes,
                    &file_digest,
                    scope,
                    &expected,
                    &digest('8'),
                    &digest('9'),
                    authority,
                ),
                Err(FirstOwnerRuntimeError::ProfileExpectationMismatch)
            ));
        }
    }

    #[test]
    fn expected_state_and_projection_digest_substitutions_are_rejected() {
        for mutate in [0_u8, 1, 2] {
            let (bytes, file_digest, scope, mut expected, authority) = install_fixture();
            let RuntimeGuardExpectedValue::FirstOwnerPathClosed {
                state_contract_version,
                authority_namespace_digest,
                closure_record_digest,
                ..
            } = &mut expected
            else {
                unreachable!();
            };
            match mutate {
                0 => *state_contract_version = 2,
                1 => *authority_namespace_digest = digest('a'),
                2 => *closure_record_digest = digest('b'),
                _ => unreachable!(),
            }
            assert!(matches!(
                verify_install_fixture(
                    bytes,
                    &file_digest,
                    scope,
                    &expected,
                    &digest('8'),
                    &digest('9'),
                    authority,
                ),
                Err(FirstOwnerRuntimeError::ExpectedValueMismatch)
            ));
        }
    }

    #[test]
    fn detached_file_and_authority_substitutions_are_rejected() {
        let (bytes, _, scope, expected, authority) = install_fixture();
        assert!(matches!(
            verify_install_fixture(
                bytes,
                &digest('c'),
                scope,
                &expected,
                &digest('8'),
                &digest('9'),
                authority,
            ),
            Err(FirstOwnerRuntimeError::CertificateFileDigestMismatch)
        ));

        let (bytes, file_digest, scope, expected, mut authority) = install_fixture();
        authority.minimum_authority_epoch = 2;
        assert!(matches!(
            verify_install_fixture(
                bytes,
                &file_digest,
                scope,
                &expected,
                &digest('8'),
                &digest('9'),
                authority,
            ),
            Err(FirstOwnerRuntimeError::AuthorityBindingInvalid)
        ));
    }

    #[test]
    fn receipt_digest_substitution_changes_only_fresh_installation_identity() {
        let (bytes, file_digest, scope, expected, authority) = install_fixture();
        let exact = verify_install_fixture(
            bytes.clone(),
            &file_digest,
            scope.clone(),
            &expected,
            &digest('8'),
            &digest('9'),
            authority.clone(),
        )
        .unwrap();
        let exact_digest = exact.installation_binding().digest().to_owned();
        let exact_reconciliation_digest = exact
            .installation_binding()
            .reconciliation_digest()
            .to_owned();

        let substituted = verify_install_fixture(
            bytes,
            &file_digest,
            scope,
            &expected,
            &digest('a'),
            &digest('b'),
            authority,
        )
        .unwrap();
        assert_ne!(exact_digest, substituted.installation_binding().digest());
        assert_eq!(
            exact_reconciliation_digest,
            substituted.installation_binding().reconciliation_digest()
        );
        assert_eq!(
            substituted.installation_binding().requirement_digest(),
            digest('a')
        );
        assert_eq!(
            substituted
                .installation_binding()
                .challenge_binding_digest(),
            digest('b')
        );

        let (other_bytes, other_file_digest, other_scope, other_expected, other_authority) =
            install_fixture();
        let other = verify_install_fixture(
            other_bytes,
            &other_file_digest,
            other_scope,
            &other_expected,
            &digest('8'),
            &digest('9'),
            other_authority,
        )
        .unwrap();
        assert_ne!(
            exact_reconciliation_digest,
            other.installation_binding().reconciliation_digest()
        );
    }

    #[test]
    fn installation_trusted_interval_uses_inclusive_close_and_exclusive_expiry() {
        let verify = || {
            let (bytes, file_digest, scope, expected, authority) = install_fixture();
            verify_install_fixture(
                bytes,
                &file_digest,
                scope,
                &expected,
                &digest('8'),
                &digest('9'),
                authority,
            )
            .unwrap()
        };
        assert!(verify()
            .authorize_installation(ConformanceTrustedTimeWindow {
                not_before: timestamp("2026-01-01T00:00:01Z"),
                not_after: timestamp("2026-01-01T00:00:01Z"),
            })
            .is_ok());
        assert!(matches!(
            verify().authorize_installation(ConformanceTrustedTimeWindow {
                not_before: timestamp("2026-01-01T00:00:00Z"),
                not_after: timestamp("2026-01-01T00:00:01Z"),
            }),
            Err(FirstOwnerRuntimeError::InstallationCapabilityInactive)
        ));
        assert!(matches!(
            verify().authorize_installation(ConformanceTrustedTimeWindow {
                not_before: timestamp("2026-01-01T00:04:59Z"),
                not_after: timestamp("2026-01-01T00:05:00Z"),
            }),
            Err(FirstOwnerRuntimeError::InstallationCapabilityInactive)
        ));
        assert!(matches!(
            verify().authorize_installation(ConformanceTrustedTimeWindow {
                not_before: timestamp("2026-01-01T00:00:02Z"),
                not_after: timestamp("2026-01-01T00:00:01Z"),
            }),
            Err(FirstOwnerRuntimeError::InvalidTrustedTimeWindow)
        ));
    }

    #[test]
    fn exact_snapshot_matches_receipt_bound_value() {
        let (snapshot, scope, expected, authority) = fixture();
        assert_eq!(
            validate_snapshot(&snapshot, &scope, &expected, &authority),
            Ok(expected)
        );
    }

    #[test]
    fn duplicated_row_tamper_is_rejected() {
        let (mut snapshot, scope, expected, authority) = fixture();
        snapshot.closure.authority_key_id = "first-owner-key:substituted".into();
        assert_eq!(
            validate_snapshot(&snapshot, &scope, &expected, &authority),
            Err(FirstOwnerRuntimeError::StoredFactsMismatch)
        );
    }

    #[test]
    fn canonical_certificate_tamper_is_rejected() {
        let (mut snapshot, scope, expected, authority) = fixture();
        snapshot.closure.certificate_bytes.push(b' ');
        assert_eq!(
            validate_snapshot(&snapshot, &scope, &expected, &authority),
            Err(FirstOwnerRuntimeError::CertificateNotCanonical)
        );
    }

    #[test]
    fn missing_nullable_namespace_key_is_rejected() {
        let (mut snapshot, scope, expected, authority) = fixture();
        snapshot
            .closure
            .certificate_document
            .get_mut("authority_namespace")
            .and_then(Value::as_object_mut)
            .unwrap()
            .remove("tenant_id");
        snapshot.closure.certificate_bytes =
            canonical_json_bytes(&snapshot.closure.certificate_document).unwrap();
        assert_eq!(
            validate_snapshot(&snapshot, &scope, &expected, &authority),
            Err(FirstOwnerRuntimeError::CertificateNotCanonical)
        );
    }

    #[test]
    fn arbitrary_well_formed_signature_is_rejected() {
        let (mut snapshot, scope, expected, authority) = fixture();
        let substituted_signature = SigningKey::generate(&mut OsRng)
            .sign(b"substituted first-owner certificate signature")
            .to_bytes()
            .to_vec();
        snapshot
            .closure
            .certificate_document
            .as_object_mut()
            .unwrap()
            .insert(
                "signature_base64".into(),
                Value::String(BASE64_STANDARD.encode(&substituted_signature)),
            );
        snapshot.closure.certificate_bytes =
            canonical_json_bytes(&snapshot.closure.certificate_document).unwrap();
        snapshot.closure.authority_signature = substituted_signature.clone();
        snapshot.closure.authority_signature_digest = sha256_digest(&substituted_signature);
        snapshot.closure.closure_certificate_digest =
            sha256_digest(&snapshot.closure.certificate_bytes);
        assert_eq!(
            validate_snapshot(&snapshot, &scope, &expected, &authority),
            Err(FirstOwnerRuntimeError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn stored_signature_byte_substitution_is_rejected_even_with_matching_row_digest() {
        let (mut snapshot, scope, expected, authority) = fixture();
        snapshot.closure.authority_signature[0] ^= 0x01;
        snapshot.closure.authority_signature_digest =
            sha256_digest(&snapshot.closure.authority_signature);
        assert_eq!(
            validate_snapshot(&snapshot, &scope, &expected, &authority),
            Err(FirstOwnerRuntimeError::SignatureRepresentationInvalid)
        );
    }

    #[test]
    fn privileged_domain_assignment_tamper_is_rejected() {
        let (mut snapshot, scope, expected, authority) = fixture();
        snapshot.assignments[0].principal_id = "principal:substituted-owner".into();
        assert_eq!(
            validate_snapshot(&snapshot, &scope, &expected, &authority),
            Err(FirstOwnerRuntimeError::AssignmentSetInvalid)
        );
    }

    #[test]
    fn linked_atomic_evidence_tamper_is_rejected() {
        let (mut snapshot, scope, expected, authority) = fixture();
        snapshot.domain_event.actor = "principal:substituted-owner".into();
        assert_eq!(
            validate_snapshot(&snapshot, &scope, &expected, &authority),
            Err(FirstOwnerRuntimeError::AtomicEvidenceInvalid)
        );
    }

    #[test]
    fn linked_audit_chain_witness_tamper_is_rejected() {
        for mutation in 0_u8..3 {
            let (mut snapshot, scope, expected, authority) = fixture();
            match mutation {
                0 => snapshot.audit.prev_hash = digest('a'),
                1 => snapshot.audit.entry_hash = digest('b'),
                2 => snapshot.audit.has_predecessor = true,
                _ => unreachable!(),
            }
            assert_eq!(
                validate_snapshot(&snapshot, &scope, &expected, &authority),
                Err(FirstOwnerRuntimeError::AtomicEvidenceInvalid)
            );
        }
    }

    #[test]
    fn receipt_bound_expected_value_mismatch_is_rejected() {
        let (snapshot, scope, mut expected, authority) = fixture();
        let RuntimeGuardExpectedValue::FirstOwnerPathClosed {
            closure_record_digest,
            ..
        } = &mut expected
        else {
            unreachable!();
        };
        *closure_record_digest = digest('f');
        assert_eq!(
            validate_snapshot(&snapshot, &scope, &expected, &authority),
            Err(FirstOwnerRuntimeError::ExpectedValueMismatch)
        );
    }

    #[test]
    fn debug_output_redacts_measured_identity() {
        let error = FirstOwnerRuntimeError::StoredFactsMismatch;
        let rendered = format!("{error:?}");
        assert!(!rendered.contains("principal:"));
        assert!(!rendered.contains("deployment:"));
        assert!(!rendered.contains("sha256:"));
        let _ = json!({ "category": rendered });
    }
}
