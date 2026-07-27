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
use ed25519_dalek::{Signature, VerifyingKey};
use ryuki_core::conformance_trust::canonical_json_bytes;
use ryuki_core::postgresql_infrastructure::PostgresqlSessionBinding;
use ryuki_core::security_profile::{
    first_owner_authority_namespace_digest, first_owner_closure_record_digest,
    DeploymentSecurityProfile, FirstOwnerAuthorityNamespace, FirstOwnerClosureRecord,
    FirstOwnerClosureStatus, RuntimeGuardExpectedValue, TenancyMode,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use thiserror::Error;

use crate::database::{PostgresqlRuntimeObservation, RetainedPostgresqlRuntime};

const LIVE_MEASUREMENT_TIMEOUT: Duration = Duration::from_secs(15);
const FIRST_OWNER_CERTIFICATE_SIGNATURE_DOMAIN: &[u8] = b"ryuki-v1/first-owner-closure-certificate";
const PRIVILEGED_DOMAINS: [&str; 5] = [
    "audit-administration",
    "identity-administration",
    "live-execution-administration",
    "policy-administration",
    "secret-key-custody",
];

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
    verifying_key: VerifyingKey,
}

impl fmt::Debug for FirstOwnerAuthorityAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirstOwnerAuthorityAnchor")
            .field("authority_id", &"[PINNED]")
            .field("key_id", &"[PINNED]")
            .field("public_key_fingerprint", &"[PINNED]")
            .field("minimum_authority_epoch", &self.minimum_authority_epoch)
            .field("verifying_key", &"[PINNED-ED25519-PUBLIC-KEY]")
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
            verifying_key,
        })
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SignedFirstOwnerClosure {
    state_contract_version: u64,
    deployment_id: String,
    authority_namespace_digest: String,
    status: FirstOwnerClosureStatus,
    closure_event_id: String,
    authority_sequence: u64,
    first_owner_principal_id: String,
    claim_request_digest: String,
    capability_id: String,
    capability_expires_at: String,
    closed_at_not_before: String,
    closed_at_not_after: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SignedPrivilegedDomainAssignment {
    assignment_event_id: String,
    domain_id: String,
    principal_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FirstOwnerClosureCertificate {
    schema_version: String,
    contract_kind: String,
    canonicalization: String,
    signature_algorithm: String,
    authority_namespace: FirstOwnerAuthorityNamespace,
    closure: SignedFirstOwnerClosure,
    privileged_domain_assignments: Vec<SignedPrivilegedDomainAssignment>,
    signature_base64: String,
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
    let closure = sqlx::query_as::<_, FirstOwnerClosureRow>(
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
        "#,
    )
    .bind(deployment_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| FirstOwnerRuntimeError::DatabaseReadFailed)?
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
        "#,
    )
    .bind(deployment_id)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| FirstOwnerRuntimeError::DatabaseReadFailed)?;
    let audit = sqlx::query_as::<_, FirstOwnerAuditRow>(
        r#"
        SELECT
            id,
            occurred_at,
            request_id::TEXT AS request_id,
            actor_principal,
            actor_display,
            actor_roles,
            provider_mode,
            action,
            from_stage,
            to_stage,
            from_status,
            to_status,
            detail,
            outcome
        FROM public.audit_log
        WHERE id = $1
        "#,
    )
    .bind(closure.audit_log_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| FirstOwnerRuntimeError::DatabaseReadFailed)?
    .ok_or(FirstOwnerRuntimeError::AtomicEvidenceInvalid)?;
    let domain_event = sqlx::query_as::<_, FirstOwnerDomainEventRow>(
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
        "#,
    )
    .bind(closure.domain_event_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| FirstOwnerRuntimeError::DatabaseReadFailed)?
    .ok_or(FirstOwnerRuntimeError::AtomicEvidenceInvalid)?;
    transaction
        .commit()
        .await
        .map_err(|_| FirstOwnerRuntimeError::DatabaseReadFailed)?;
    Ok(FirstOwnerClosureSnapshot {
        closure,
        assignments,
        audit,
        domain_event,
    })
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

    let value_from_bytes: Value = serde_json::from_slice(&row.certificate_bytes)
        .map_err(|_| FirstOwnerRuntimeError::CertificateNotCanonical)?;
    let canonical = canonical_json_bytes(&value_from_bytes)
        .map_err(|_| FirstOwnerRuntimeError::CertificateNotCanonical)?;
    if canonical != row.certificate_bytes || value_from_bytes != row.certificate_document {
        return Err(FirstOwnerRuntimeError::CertificateNotCanonical);
    }
    validate_certificate_shape(&value_from_bytes)?;
    let certificate: FirstOwnerClosureCertificate = serde_json::from_value(value_from_bytes)
        .map_err(|_| FirstOwnerRuntimeError::CertificateSchemaInvalid)?;
    if certificate.schema_version != "1.0.0"
        || certificate.contract_kind != "first-owner-closure-certificate"
        || certificate.canonicalization != "ryuki-canonical-json-v1"
        || certificate.signature_algorithm != "ed25519"
    {
        return Err(FirstOwnerRuntimeError::CertificateSchemaInvalid);
    }

    let certificate_digest = sha256_digest(&row.certificate_bytes);
    if certificate_digest != row.closure_certificate_digest {
        return Err(FirstOwnerRuntimeError::CertificateDigestInvalid);
    }
    validate_signature(&certificate, row, authority)?;

    let namespace_digest = first_owner_authority_namespace_digest(&certificate.authority_namespace)
        .map_err(|_| FirstOwnerRuntimeError::ProjectionInvalid)?;
    let state_contract_version =
        i64::try_from(certificate.authority_namespace.state_contract_version)
            .map_err(|_| FirstOwnerRuntimeError::StoredFactsMismatch)?;
    let authority_epoch = i64::try_from(certificate.authority_namespace.authority_epoch)
        .map_err(|_| FirstOwnerRuntimeError::StoredFactsMismatch)?;
    let authority_sequence = i64::try_from(certificate.closure.authority_sequence)
        .map_err(|_| FirstOwnerRuntimeError::StoredFactsMismatch)?;
    let closure_status = match certificate.closure.status {
        FirstOwnerClosureStatus::Closed => "closed",
    };
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
        || row.closure_status != closure_status
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

    validate_assignments(snapshot, &certificate, &certificate_digest)?;
    validate_atomic_evidence(snapshot, &certificate, &certificate_digest)?;

    let closure_record = FirstOwnerClosureRecord {
        state_contract_version: certificate.closure.state_contract_version,
        deployment_id: certificate.closure.deployment_id,
        authority_namespace_digest: certificate.closure.authority_namespace_digest,
        status: certificate.closure.status,
        closure_event_id: certificate.closure.closure_event_id,
        authority_sequence: certificate.closure.authority_sequence,
        first_owner_principal_id: certificate.closure.first_owner_principal_id,
        claim_request_digest: certificate.closure.claim_request_digest,
        capability_id: certificate.closure.capability_id,
        capability_expires_at: certificate.closure.capability_expires_at,
        closed_at_not_before: certificate.closure.closed_at_not_before,
        closed_at_not_after: certificate.closure.closed_at_not_after,
        closure_certificate_digest: certificate_digest,
    };
    let closure_record_digest = first_owner_closure_record_digest(&closure_record)
        .map_err(|_| FirstOwnerRuntimeError::ProjectionInvalid)?;
    if row.closure_record_digest != closure_record_digest {
        return Err(FirstOwnerRuntimeError::StoredFactsMismatch);
    }

    let observed = RuntimeGuardExpectedValue::FirstOwnerPathClosed {
        deployment_id: row.deployment_id.clone(),
        state_contract_version: u64::try_from(row.state_contract_version)
            .map_err(|_| FirstOwnerRuntimeError::ProjectionInvalid)?,
        authority_namespace_digest: namespace_digest,
        closure_record_digest,
    };
    if &observed != expected {
        return Err(FirstOwnerRuntimeError::ExpectedValueMismatch);
    }
    Ok(observed)
}

fn validate_certificate_shape(document: &Value) -> Result<(), FirstOwnerRuntimeError> {
    const TOP_LEVEL_KEYS: [&str; 8] = [
        "authority_namespace",
        "canonicalization",
        "closure",
        "contract_kind",
        "privileged_domain_assignments",
        "schema_version",
        "signature_algorithm",
        "signature_base64",
    ];
    const NAMESPACE_KEYS: [&str; 10] = [
        "authority_epoch",
        "authority_id",
        "authority_key_id",
        "authority_public_key_fingerprint",
        "deployment_id",
        "namespace_id",
        "state_contract_version",
        "tenancy_mode",
        "tenant_id",
        "trust_domain_ids",
    ];
    const CLOSURE_KEYS: [&str; 12] = [
        "authority_namespace_digest",
        "authority_sequence",
        "capability_expires_at",
        "capability_id",
        "claim_request_digest",
        "closed_at_not_after",
        "closed_at_not_before",
        "closure_event_id",
        "deployment_id",
        "first_owner_principal_id",
        "state_contract_version",
        "status",
    ];
    const ASSIGNMENT_KEYS: [&str; 3] = ["assignment_event_id", "domain_id", "principal_id"];

    let namespace = document.get("authority_namespace");
    let closure = document.get("closure");
    let assignments = document
        .get("privileged_domain_assignments")
        .and_then(Value::as_array);
    if !has_exact_object_keys(document, &TOP_LEVEL_KEYS)
        || !namespace.is_some_and(|value| has_exact_object_keys(value, &NAMESPACE_KEYS))
        || !closure.is_some_and(|value| has_exact_object_keys(value, &CLOSURE_KEYS))
        || !assignments.is_some_and(|values| {
            values.len() == PRIVILEGED_DOMAINS.len()
                && values
                    .iter()
                    .all(|value| has_exact_object_keys(value, &ASSIGNMENT_KEYS))
        })
    {
        return Err(FirstOwnerRuntimeError::CertificateSchemaInvalid);
    }
    Ok(())
}

fn has_exact_object_keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
    })
}

fn certificate_signing_bytes(document: &Value) -> Result<Vec<u8>, FirstOwnerRuntimeError> {
    let mut unsigned = document.clone();
    let object = unsigned
        .as_object_mut()
        .ok_or(FirstOwnerRuntimeError::CertificateSchemaInvalid)?;
    if object.remove("signature_base64").is_none() {
        return Err(FirstOwnerRuntimeError::CertificateSchemaInvalid);
    }
    let canonical = canonical_json_bytes(&unsigned)
        .map_err(|_| FirstOwnerRuntimeError::CertificateNotCanonical)?;
    let domain_length = u64::try_from(FIRST_OWNER_CERTIFICATE_SIGNATURE_DOMAIN.len())
        .map_err(|_| FirstOwnerRuntimeError::CertificateSchemaInvalid)?;
    let canonical_length = u64::try_from(canonical.len())
        .map_err(|_| FirstOwnerRuntimeError::CertificateSchemaInvalid)?;
    let mut signing_bytes =
        Vec::with_capacity(16 + FIRST_OWNER_CERTIFICATE_SIGNATURE_DOMAIN.len() + canonical.len());
    signing_bytes.extend_from_slice(&domain_length.to_le_bytes());
    signing_bytes.extend_from_slice(FIRST_OWNER_CERTIFICATE_SIGNATURE_DOMAIN);
    signing_bytes.extend_from_slice(&canonical_length.to_le_bytes());
    signing_bytes.extend_from_slice(&canonical);
    Ok(signing_bytes)
}

fn validate_signature(
    certificate: &FirstOwnerClosureCertificate,
    row: &FirstOwnerClosureRow,
    authority: &FirstOwnerAuthorityAnchor,
) -> Result<(), FirstOwnerRuntimeError> {
    let signature_bytes = BASE64_STANDARD
        .decode(certificate.signature_base64.as_bytes())
        .map_err(|_| FirstOwnerRuntimeError::SignatureRepresentationInvalid)?;
    if signature_bytes.len() != 64
        || BASE64_STANDARD.encode(&signature_bytes) != certificate.signature_base64
        || signature_bytes != row.authority_signature
        || sha256_digest(&signature_bytes) != row.authority_signature_digest
    {
        return Err(FirstOwnerRuntimeError::SignatureRepresentationInvalid);
    }
    if certificate.authority_namespace.authority_id != authority.authority_id
        || certificate.authority_namespace.authority_key_id != authority.key_id
        || certificate
            .authority_namespace
            .authority_public_key_fingerprint
            != authority.public_key_fingerprint
        || certificate.authority_namespace.authority_epoch < authority.minimum_authority_epoch
    {
        return Err(FirstOwnerRuntimeError::AuthorityBindingInvalid);
    }
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| FirstOwnerRuntimeError::SignatureRepresentationInvalid)?;
    let signing_bytes = certificate_signing_bytes(&row.certificate_document)?;
    authority
        .verifying_key
        .verify_strict(&signing_bytes, &signature)
        .map_err(|_| FirstOwnerRuntimeError::SignatureVerificationFailed)?;
    Ok(())
}

fn validate_assignments(
    snapshot: &FirstOwnerClosureSnapshot,
    certificate: &FirstOwnerClosureCertificate,
    certificate_digest: &str,
) -> Result<(), FirstOwnerRuntimeError> {
    let signed = &certificate.privileged_domain_assignments;
    if signed.len() != PRIVILEGED_DOMAINS.len()
        || snapshot.assignments.len() != PRIVILEGED_DOMAINS.len()
        || !signed
            .iter()
            .map(|assignment| assignment.domain_id.as_str())
            .eq(PRIVILEGED_DOMAINS)
        || signed.iter().any(|assignment| {
            !valid_runtime_identifier(&assignment.assignment_event_id)
                || !valid_runtime_identifier(&assignment.principal_id)
        })
        || signed.iter().enumerate().any(|(index, assignment)| {
            signed[index + 1..]
                .iter()
                .any(|candidate| candidate.assignment_event_id == assignment.assignment_event_id)
        })
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

fn valid_runtime_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    (3..=255).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(*byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
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
        let signing_key = SigningKey::from_bytes(&[0x17; 32]);
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
            closure_event_id: "first-owner-event:fixture".into(),
            authority_sequence: 1,
            first_owner_principal_id: "principal:fixture-owner".into(),
            claim_request_digest: digest('2'),
            capability_id: "first-owner-capability:fixture".into(),
            capability_expires_at: "2026-01-01T00:05:00Z".into(),
            closed_at_not_before: "2026-01-01T00:00:00Z".into(),
            closed_at_not_after: "2026-01-01T00:00:01Z".into(),
        };
        let signed_assignments = PRIVILEGED_DOMAINS
            .iter()
            .enumerate()
            .map(|(index, domain)| SignedPrivilegedDomainAssignment {
                assignment_event_id: format!("first-owner-assignment:event-{index}"),
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
            signature_base64: String::new(),
        };
        let unsigned_document = serde_json::to_value(&certificate).unwrap();
        let signature = signing_key
            .sign(&certificate_signing_bytes(&unsigned_document).unwrap())
            .to_bytes()
            .to_vec();
        certificate.signature_base64 = BASE64_STANDARD.encode(&signature);
        let certificate_document = serde_json::to_value(&certificate).unwrap();
        let certificate_bytes = canonical_json_bytes(&certificate_document).unwrap();
        let certificate_digest = sha256_digest(&certificate_bytes);
        let closure_record = FirstOwnerClosureRecord {
            state_contract_version: 1,
            deployment_id: certificate.closure.deployment_id.clone(),
            authority_namespace_digest: namespace_digest.clone(),
            status: FirstOwnerClosureStatus::Closed,
            closure_event_id: certificate.closure.closure_event_id.clone(),
            authority_sequence: 1,
            first_owner_principal_id: certificate.closure.first_owner_principal_id.clone(),
            claim_request_digest: certificate.closure.claim_request_digest.clone(),
            capability_id: certificate.closure.capability_id.clone(),
            capability_expires_at: certificate.closure.capability_expires_at.clone(),
            closed_at_not_before: certificate.closure.closed_at_not_before.clone(),
            closed_at_not_after: certificate.closure.closed_at_not_after.clone(),
            closure_certificate_digest: certificate_digest.clone(),
        };
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
                closure_event_id: "first-owner-event:fixture".into(),
                closure_certificate_digest: certificate_digest.clone(),
                assigned_at: closed_at_not_after,
            })
            .collect();
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
                closure_event_id: "first-owner-event:fixture".into(),
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
                detail: json!({
                    "authority_namespace_digest": namespace_digest.clone(),
                    "closure_certificate_digest": certificate_digest.clone(),
                    "closure_event_id": "first-owner-event:fixture",
                    "deployment_id": "deployment:fixture",
                }),
                outcome: "applied".into(),
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
                    "closure_event_id": "first-owner-event:fixture",
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
            Err(FirstOwnerRuntimeError::CertificateSchemaInvalid)
        );
    }

    #[test]
    fn arbitrary_well_formed_signature_is_rejected() {
        let (mut snapshot, scope, expected, authority) = fixture();
        let substituted_signature = vec![0x42; 64];
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
