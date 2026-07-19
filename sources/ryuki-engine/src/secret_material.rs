//! Provider-qualified, value-free secret references and zeroizing material.
//!
//! Administrative secret records are intentionally not represented here. A
//! [`SecretRef`] is the immutable runtime projection admitted for one use; a
//! [`SecretMaterial`] is the short-lived value returned by a resolver.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use thiserror::Error;
use zeroize::Zeroizing;

pub const SECRET_REF_SCHEMA_VERSION: u32 = 1;
pub const SECRET_LEASE_METADATA_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SecretBoundaryError {
    #[error("secret boundary field '{field}' is invalid ({reason})")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("secret reference does not match the admitted resolution context")]
    ScopeMismatch,
    #[error("resolved secret version does not match the pinned reference version")]
    VersionMismatch,
    #[error("secret lease transition does not match the current authority fence")]
    FenceMismatch,
    #[error("secret lease transition is not permitted")]
    InvalidLeaseTransition,
    #[error("secret lease lifecycle fields are inconsistent")]
    InvalidLeaseLifecycle,
}

fn invalid(field: &'static str, reason: &'static str) -> SecretBoundaryError {
    SecretBoundaryError::InvalidField { field, reason }
}

fn validate_identifier(
    field: &'static str,
    value: &str,
    prefix: Option<&str>,
) -> Result<(), SecretBoundaryError> {
    if value.is_empty() || value.len() > 256 || value.trim() != value {
        return Err(invalid(field, "must be non-empty and bounded"));
    }
    if let Some(prefix) = prefix {
        let Some(suffix) = value.strip_prefix(prefix) else {
            return Err(invalid(field, "has the wrong namespace"));
        };
        if suffix.is_empty() {
            return Err(invalid(field, "must have a non-empty namespace suffix"));
        }
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'.' | b'_' | b'-' | b'/')
    }) {
        return Err(invalid(field, "contains a non-canonical character"));
    }
    Ok(())
}

/// Decode an optional wire field only when it is present and non-null.
///
/// JSON Schema treats an omitted optional property differently from a present
/// property whose value is `null`. Serde's ordinary `Option<T>` decoder merges
/// those states, so security-contract optionals use this helper to keep the
/// Rust decoder exactly aligned with the closed canonical schemas.
fn deserialize_present_non_null<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

fn validate_optional_identifier(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), SecretBoundaryError> {
    if let Some(value) = value {
        validate_identifier(field, value, None)?;
    }
    Ok(())
}

fn validate_fingerprint(value: &str) -> Result<(), SecretBoundaryError> {
    let Some(hex) = value.strip_prefix("hmac-sha256:") else {
        return Err(invalid(
            "referenceFingerprint",
            "must use the hmac-sha256 digest domain",
        ));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(
            "referenceFingerprint",
            "must contain 64 lowercase hexadecimal digits",
        ));
    }
    Ok(())
}

fn validate_opaque_locator(value: &str) -> Result<(), SecretBoundaryError> {
    if value.is_empty()
        || value.len() > 4096
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(invalid(
            "opaqueLocator",
            "must be a non-empty bounded opaque string",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SecretVersionSelector {
    Pinned {
        #[serde(rename = "secretVersion")]
        secret_version: String,
    },
    LatestAtResolve,
}

impl SecretVersionSelector {
    pub fn pinned(secret_version: impl Into<String>) -> Result<Self, SecretBoundaryError> {
        let secret_version = secret_version.into();
        validate_identifier("secretVersion", &secret_version, None)?;
        Ok(Self::Pinned { secret_version })
    }

    pub fn latest_at_resolve() -> Self {
        Self::LatestAtResolve
    }

    pub fn pinned_version(&self) -> Option<&str> {
        match self {
            Self::Pinned { secret_version } => Some(secret_version),
            Self::LatestAtResolve => None,
        }
    }

    fn validate(&self) -> Result<(), SecretBoundaryError> {
        if let Self::Pinned { secret_version } = self {
            validate_identifier("secretVersion", secret_version, None)?;
        }
        Ok(())
    }
}

/// Serializable, value-free runtime selection handle.
///
/// Debug output intentionally excludes the opaque locator and field selector.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretRef {
    schema_version: u32,
    provider_id: String,
    provider_config_version: u64,
    deployment_id: String,
    trust_domain_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_id: Option<String>,
    reference_fingerprint: String,
    fingerprint_key_id: String,
    opaque_locator: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    field_selector: Option<String>,
    purpose: String,
    version_selector: SecretVersionSelector,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SecretRefWire {
    schema_version: u32,
    provider_id: String,
    provider_config_version: u64,
    deployment_id: String,
    trust_domain_id: String,
    #[serde(default, deserialize_with = "deserialize_present_non_null")]
    tenant_id: Option<String>,
    reference_fingerprint: String,
    fingerprint_key_id: String,
    opaque_locator: String,
    #[serde(default, deserialize_with = "deserialize_present_non_null")]
    field_selector: Option<String>,
    purpose: String,
    version_selector: SecretVersionSelector,
}

impl TryFrom<SecretRefWire> for SecretRef {
    type Error = SecretBoundaryError;

    fn try_from(wire: SecretRefWire) -> Result<Self, Self::Error> {
        let value = Self {
            schema_version: wire.schema_version,
            provider_id: wire.provider_id,
            provider_config_version: wire.provider_config_version,
            deployment_id: wire.deployment_id,
            trust_domain_id: wire.trust_domain_id,
            tenant_id: wire.tenant_id,
            reference_fingerprint: wire.reference_fingerprint,
            fingerprint_key_id: wire.fingerprint_key_id,
            opaque_locator: wire.opaque_locator,
            field_selector: wire.field_selector,
            purpose: wire.purpose,
            version_selector: wire.version_selector,
        };
        value.validate()?;
        Ok(value)
    }
}

impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        SecretRefWire::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretRef")
            .field("schema_version", &self.schema_version)
            .field("provider_id", &self.provider_id)
            .field("provider_config_version", &self.provider_config_version)
            .field("deployment_id", &self.deployment_id)
            .field("trust_domain_id", &self.trust_domain_id)
            .field("tenant_id", &self.tenant_id)
            .field("reference_fingerprint", &self.reference_fingerprint)
            .field("fingerprint_key_id", &self.fingerprint_key_id)
            .field("opaque_locator", &"[REDACTED]")
            .field(
                "field_selector",
                &self.field_selector.as_ref().map(|_| "[REDACTED]"),
            )
            .field("purpose", &self.purpose)
            .field("version_selector", &self.version_selector)
            .finish()
    }
}

impl SecretRef {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        provider_id: impl Into<String>,
        provider_config_version: u64,
        deployment_id: impl Into<String>,
        trust_domain_id: impl Into<String>,
        tenant_id: Option<String>,
        reference_fingerprint: impl Into<String>,
        fingerprint_key_id: impl Into<String>,
        opaque_locator: impl Into<String>,
        field_selector: Option<String>,
        purpose: impl Into<String>,
        version_selector: SecretVersionSelector,
    ) -> Result<Self, SecretBoundaryError> {
        let value = Self {
            schema_version: SECRET_REF_SCHEMA_VERSION,
            provider_id: provider_id.into(),
            provider_config_version,
            deployment_id: deployment_id.into(),
            trust_domain_id: trust_domain_id.into(),
            tenant_id,
            reference_fingerprint: reference_fingerprint.into(),
            fingerprint_key_id: fingerprint_key_id.into(),
            opaque_locator: opaque_locator.into(),
            field_selector,
            purpose: purpose.into(),
            version_selector,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), SecretBoundaryError> {
        if self.schema_version != SECRET_REF_SCHEMA_VERSION {
            return Err(invalid("schemaVersion", "is unsupported"));
        }
        validate_identifier("providerId", &self.provider_id, Some("provider:"))?;
        if self.provider_config_version == 0 {
            return Err(invalid("providerConfigVersion", "must be positive"));
        }
        validate_identifier("deploymentId", &self.deployment_id, Some("deployment:"))?;
        validate_identifier(
            "trustDomainId",
            &self.trust_domain_id,
            Some("trust-domain:"),
        )?;
        validate_optional_identifier("tenantId", self.tenant_id.as_deref())?;
        validate_fingerprint(&self.reference_fingerprint)?;
        validate_identifier("fingerprintKeyId", &self.fingerprint_key_id, Some("key:"))?;
        validate_opaque_locator(&self.opaque_locator)?;
        if let Some(selector) = self.field_selector.as_deref()
            && (selector.is_empty()
                || selector.len() > 256
                || selector.trim() != selector
                || selector.chars().any(char::is_control))
        {
            return Err(invalid("fieldSelector", "must be a bounded selector"));
        }
        validate_identifier("purpose", &self.purpose, Some("purpose:"))?;
        self.version_selector.validate()
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }
    pub fn provider_config_version(&self) -> u64 {
        self.provider_config_version
    }
    pub fn deployment_id(&self) -> &str {
        &self.deployment_id
    }
    pub fn trust_domain_id(&self) -> &str {
        &self.trust_domain_id
    }
    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }
    pub fn reference_fingerprint(&self) -> &str {
        &self.reference_fingerprint
    }
    pub fn fingerprint_key_id(&self) -> &str {
        &self.fingerprint_key_id
    }
    pub fn opaque_locator(&self) -> &str {
        &self.opaque_locator
    }
    pub fn field_selector(&self) -> Option<&str> {
        self.field_selector.as_deref()
    }
    pub fn purpose(&self) -> &str {
        &self.purpose
    }
    pub fn version_selector(&self) -> &SecretVersionSelector {
        &self.version_selector
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretResolutionContext {
    deployment_id: String,
    trust_domain_id: String,
    tenant_id: Option<String>,
    purpose: String,
    workload_id: String,
    request_id: Option<String>,
    job_id: Option<String>,
    authority_epoch: u64,
    fencing_token: u64,
}

impl SecretResolutionContext {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        deployment_id: impl Into<String>,
        trust_domain_id: impl Into<String>,
        tenant_id: Option<String>,
        purpose: impl Into<String>,
        workload_id: impl Into<String>,
        request_id: Option<String>,
        job_id: Option<String>,
        authority_epoch: u64,
        fencing_token: u64,
    ) -> Result<Self, SecretBoundaryError> {
        let value = Self {
            deployment_id: deployment_id.into(),
            trust_domain_id: trust_domain_id.into(),
            tenant_id,
            purpose: purpose.into(),
            workload_id: workload_id.into(),
            request_id,
            job_id,
            authority_epoch,
            fencing_token,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), SecretBoundaryError> {
        validate_identifier("deploymentId", &self.deployment_id, Some("deployment:"))?;
        validate_identifier(
            "trustDomainId",
            &self.trust_domain_id,
            Some("trust-domain:"),
        )?;
        validate_optional_identifier("tenantId", self.tenant_id.as_deref())?;
        validate_identifier("purpose", &self.purpose, Some("purpose:"))?;
        validate_identifier("workloadId", &self.workload_id, Some("workload:"))?;
        validate_optional_identifier("requestId", self.request_id.as_deref())?;
        validate_optional_identifier("jobId", self.job_id.as_deref())?;
        if self.request_id.is_none() && self.job_id.is_none() {
            return Err(invalid("requestId/jobId", "at least one is required"));
        }
        if self.authority_epoch == 0 || self.fencing_token == 0 {
            return Err(invalid("authorityEpoch/fencingToken", "must be positive"));
        }
        Ok(())
    }

    pub fn admits(&self, secret_ref: &SecretRef) -> Result<(), SecretBoundaryError> {
        if secret_ref.deployment_id != self.deployment_id
            || secret_ref.trust_domain_id != self.trust_domain_id
            || secret_ref.tenant_id != self.tenant_id
            || secret_ref.purpose != self.purpose
        {
            return Err(SecretBoundaryError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn workload_id(&self) -> &str {
        &self.workload_id
    }
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }
    pub fn job_id(&self) -> Option<&str> {
        self.job_id.as_deref()
    }
    pub fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }
    pub fn fencing_token(&self) -> u64 {
        self.fencing_token
    }
}

/// Scope-bound secret bytes. This type intentionally implements neither
/// `Debug`, `Clone`, `Serialize`, nor `Deserialize`.
///
/// ```compile_fail
/// use ryuki_engine::secret_material::SecretMaterial;
/// fn requires_debug<T: std::fmt::Debug>() {}
/// requires_debug::<SecretMaterial>();
/// ```
///
/// ```compile_fail
/// use ryuki_engine::secret_material::SecretMaterial;
/// fn requires_serialize<T: serde::Serialize>() {}
/// requires_serialize::<SecretMaterial>();
/// ```
pub struct SecretMaterial(Zeroizing<Vec<u8>>);

impl SecretMaterial {
    pub fn new(bytes: Vec<u8>) -> Result<Self, SecretBoundaryError> {
        if bytes.is_empty() {
            return Err(invalid("secretMaterial", "must not be empty"));
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn with_bytes<T>(&self, use_material: impl FnOnce(&[u8]) -> T) -> T {
        use_material(self.0.as_slice())
    }
}

/// Exact version-selection semantics used for this resolution. This remains
/// distinct from `resolved_version`: a latest-at-resolve request may resolve to
/// the same concrete version as a pinned request without becoming equivalent
/// cache or audit authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretResolutionMode {
    Pinned,
    LatestAtResolve,
}

/// Party responsible for terminating the material scope represented by the
/// lease metadata. Static KV reads use the workload runtime's bounded local
/// lease; provider-issued dynamic credentials use provider revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretLeaseRevocationOwner {
    Provider,
    WorkloadRuntime,
}

/// Optimistic authority fence captured before a lifecycle transition. A
/// transition is admitted only when this value still equals the current lease
/// and the successor advances the fencing token without changing authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretLeaseFence {
    authority_epoch: u64,
    fencing_token: u64,
}

impl SecretLeaseFence {
    pub fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }

    pub fn fencing_token(self) -> u64 {
        self.fencing_token
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretLeaseLifecycleState {
    Requested,
    Issued,
    Active,
    Renewing,
    Draining,
    Revoked,
    Expired,
    Failed,
}

#[derive(Clone, PartialEq, Eq)]
struct IssuedLeaseFields {
    lease_id: String,
    resolved_version: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// Value-free issuance fields supplied by a resolver after provider response
/// validation. The lease identifier is intentionally omitted from Debug and
/// from every public projection other than serialized lease metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuedSecretLease {
    lease_id: String,
    resolved_version: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl IssuedSecretLease {
    pub fn try_new(
        lease_id: impl Into<String>,
        resolved_version: impl Into<String>,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, SecretBoundaryError> {
        let lease_id = lease_id.into();
        let resolved_version = resolved_version.into();
        validate_identifier("leaseId", &lease_id, None)?;
        validate_identifier("resolvedVersion", &resolved_version, None)?;
        if issued_at >= expires_at {
            return Err(SecretBoundaryError::InvalidLeaseLifecycle);
        }
        Ok(Self {
            lease_id,
            resolved_version,
            issued_at,
            expires_at,
        })
    }
}

pub enum SecretLeaseLifecycleInput {
    Requested,
    Issued(IssuedSecretLease),
    Active(IssuedSecretLease),
    Renewing(IssuedSecretLease),
    Draining(IssuedSecretLease),
    Revoked {
        issued: IssuedSecretLease,
        terminal_at: DateTime<Utc>,
    },
    Expired {
        issued: IssuedSecretLease,
        terminal_at: DateTime<Utc>,
    },
    Failed {
        issued: Option<IssuedSecretLease>,
        terminal_at: DateTime<Utc>,
    },
}

#[derive(Clone, PartialEq, Eq)]
enum SecretLeaseLifecycle {
    Requested,
    Issued(IssuedLeaseFields),
    Active(IssuedLeaseFields),
    Renewing(IssuedLeaseFields),
    Draining(IssuedLeaseFields),
    Revoked(IssuedLeaseFields, DateTime<Utc>),
    Expired(IssuedLeaseFields, DateTime<Utc>),
    Failed {
        issued: Option<IssuedLeaseFields>,
        terminal_at: DateTime<Utc>,
    },
}

#[derive(Clone, PartialEq, Eq)]
pub struct SecretLeaseMetadata {
    schema_version: u32,
    reference_fingerprint: String,
    fingerprint_key_id: String,
    provider_id: String,
    provider_config_version: u64,
    adapter_capability_version: String,
    deployment_id: String,
    trust_domain_id: String,
    tenant_id: Option<String>,
    workload_id: String,
    purpose: String,
    resolution_mode: SecretResolutionMode,
    requested_version: Option<String>,
    revocation_owner: SecretLeaseRevocationOwner,
    request_id: Option<String>,
    job_id: Option<String>,
    authority_epoch: u64,
    fencing_token: u64,
    lifecycle: SecretLeaseLifecycle,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SecretLeaseWire {
    schema_version: u32,
    reference_fingerprint: String,
    fingerprint_key_id: String,
    provider_id: String,
    provider_config_version: u64,
    adapter_capability_version: String,
    deployment_id: String,
    trust_domain_id: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_non_null"
    )]
    tenant_id: Option<String>,
    workload_id: String,
    purpose: String,
    resolution_mode: SecretResolutionMode,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_non_null"
    )]
    requested_version: Option<String>,
    revocation_owner: SecretLeaseRevocationOwner,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_non_null"
    )]
    request_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_non_null"
    )]
    job_id: Option<String>,
    authority_epoch: u64,
    fencing_token: u64,
    lifecycle_state: SecretLeaseLifecycleState,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_non_null"
    )]
    lease_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_non_null"
    )]
    resolved_version: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_non_null"
    )]
    issued_at: Option<DateTime<Utc>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_non_null"
    )]
    expires_at: Option<DateTime<Utc>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_non_null"
    )]
    terminal_at: Option<DateTime<Utc>>,
}

impl SecretLeaseWire {
    fn into_metadata(self) -> Result<SecretLeaseMetadata, SecretBoundaryError> {
        match (self.resolution_mode, self.requested_version.as_deref()) {
            (SecretResolutionMode::Pinned, Some(version)) => {
                validate_identifier("requestedVersion", version, None)?;
            }
            (SecretResolutionMode::LatestAtResolve, None) => {}
            _ => return Err(SecretBoundaryError::InvalidLeaseLifecycle),
        }
        let issued = match (
            self.lease_id,
            self.resolved_version,
            self.issued_at,
            self.expires_at,
        ) {
            (None, None, None, None) => None,
            (Some(lease_id), Some(resolved_version), Some(issued_at), Some(expires_at)) => {
                if issued_at >= expires_at {
                    return Err(SecretBoundaryError::InvalidLeaseLifecycle);
                }
                validate_identifier("leaseId", &lease_id, None)?;
                validate_identifier("resolvedVersion", &resolved_version, None)?;
                if self.resolution_mode == SecretResolutionMode::Pinned
                    && self.requested_version.as_deref() != Some(resolved_version.as_str())
                {
                    return Err(SecretBoundaryError::VersionMismatch);
                }
                Some(IssuedLeaseFields {
                    lease_id,
                    resolved_version,
                    issued_at,
                    expires_at,
                })
            }
            _ => return Err(SecretBoundaryError::InvalidLeaseLifecycle),
        };
        let lifecycle = match (self.lifecycle_state, issued, self.terminal_at) {
            (SecretLeaseLifecycleState::Requested, None, None) => SecretLeaseLifecycle::Requested,
            (SecretLeaseLifecycleState::Issued, Some(fields), None) => {
                SecretLeaseLifecycle::Issued(fields)
            }
            (SecretLeaseLifecycleState::Active, Some(fields), None) => {
                SecretLeaseLifecycle::Active(fields)
            }
            (SecretLeaseLifecycleState::Renewing, Some(fields), None) => {
                SecretLeaseLifecycle::Renewing(fields)
            }
            (SecretLeaseLifecycleState::Draining, Some(fields), None) => {
                SecretLeaseLifecycle::Draining(fields)
            }
            (SecretLeaseLifecycleState::Revoked, Some(fields), Some(terminal_at))
                if terminal_at >= fields.issued_at =>
            {
                SecretLeaseLifecycle::Revoked(fields, terminal_at)
            }
            (SecretLeaseLifecycleState::Expired, Some(fields), Some(terminal_at))
                if terminal_at >= fields.expires_at =>
            {
                SecretLeaseLifecycle::Expired(fields, terminal_at)
            }
            (SecretLeaseLifecycleState::Failed, fields, Some(terminal_at)) => {
                if fields
                    .as_ref()
                    .is_some_and(|fields| terminal_at < fields.issued_at)
                {
                    return Err(SecretBoundaryError::InvalidLeaseLifecycle);
                }
                SecretLeaseLifecycle::Failed {
                    issued: fields,
                    terminal_at,
                }
            }
            _ => return Err(SecretBoundaryError::InvalidLeaseLifecycle),
        };
        let metadata = SecretLeaseMetadata {
            schema_version: self.schema_version,
            reference_fingerprint: self.reference_fingerprint,
            fingerprint_key_id: self.fingerprint_key_id,
            provider_id: self.provider_id,
            provider_config_version: self.provider_config_version,
            adapter_capability_version: self.adapter_capability_version,
            deployment_id: self.deployment_id,
            trust_domain_id: self.trust_domain_id,
            tenant_id: self.tenant_id,
            workload_id: self.workload_id,
            purpose: self.purpose,
            resolution_mode: self.resolution_mode,
            requested_version: self.requested_version,
            revocation_owner: self.revocation_owner,
            request_id: self.request_id,
            job_id: self.job_id,
            authority_epoch: self.authority_epoch,
            fencing_token: self.fencing_token,
            lifecycle,
        };
        metadata.validate_common()?;
        Ok(metadata)
    }
}

impl SecretLeaseMetadata {
    pub fn try_new(
        secret_ref: &SecretRef,
        context: &SecretResolutionContext,
        adapter_capability_version: impl Into<String>,
        revocation_owner: SecretLeaseRevocationOwner,
        lifecycle: SecretLeaseLifecycleInput,
    ) -> Result<Self, SecretBoundaryError> {
        context.admits(secret_ref)?;
        let (resolution_mode, requested_version) = match secret_ref.version_selector() {
            SecretVersionSelector::Pinned { secret_version } => {
                (SecretResolutionMode::Pinned, Some(secret_version.clone()))
            }
            SecretVersionSelector::LatestAtResolve => (SecretResolutionMode::LatestAtResolve, None),
        };
        let issued_for_version_check = match &lifecycle {
            SecretLeaseLifecycleInput::Requested => None,
            SecretLeaseLifecycleInput::Issued(issued)
            | SecretLeaseLifecycleInput::Active(issued)
            | SecretLeaseLifecycleInput::Renewing(issued)
            | SecretLeaseLifecycleInput::Draining(issued)
            | SecretLeaseLifecycleInput::Revoked { issued, .. }
            | SecretLeaseLifecycleInput::Expired { issued, .. } => Some(issued),
            SecretLeaseLifecycleInput::Failed { issued, .. } => issued.as_ref(),
        };
        if resolution_mode == SecretResolutionMode::Pinned
            && issued_for_version_check.is_some_and(|issued| {
                requested_version.as_deref() != Some(issued.resolved_version.as_str())
            })
        {
            return Err(SecretBoundaryError::VersionMismatch);
        }
        let lifecycle = match lifecycle {
            SecretLeaseLifecycleInput::Requested => SecretLeaseLifecycle::Requested,
            SecretLeaseLifecycleInput::Issued(fields) => {
                SecretLeaseLifecycle::Issued(fields.into())
            }
            SecretLeaseLifecycleInput::Active(fields) => {
                SecretLeaseLifecycle::Active(fields.into())
            }
            SecretLeaseLifecycleInput::Renewing(fields) => {
                SecretLeaseLifecycle::Renewing(fields.into())
            }
            SecretLeaseLifecycleInput::Draining(fields) => {
                SecretLeaseLifecycle::Draining(fields.into())
            }
            SecretLeaseLifecycleInput::Revoked {
                issued,
                terminal_at,
            } if terminal_at >= issued.issued_at => {
                SecretLeaseLifecycle::Revoked(issued.into(), terminal_at)
            }
            SecretLeaseLifecycleInput::Expired {
                issued,
                terminal_at,
            } if terminal_at >= issued.expires_at => {
                SecretLeaseLifecycle::Expired(issued.into(), terminal_at)
            }
            SecretLeaseLifecycleInput::Failed {
                issued,
                terminal_at,
            } if issued
                .as_ref()
                .is_none_or(|issued| terminal_at >= issued.issued_at) =>
            {
                SecretLeaseLifecycle::Failed {
                    issued: issued.map(Into::into),
                    terminal_at,
                }
            }
            _ => return Err(SecretBoundaryError::InvalidLeaseLifecycle),
        };
        let metadata = Self {
            schema_version: SECRET_LEASE_METADATA_SCHEMA_VERSION,
            reference_fingerprint: secret_ref.reference_fingerprint.clone(),
            fingerprint_key_id: secret_ref.fingerprint_key_id.clone(),
            provider_id: secret_ref.provider_id.clone(),
            provider_config_version: secret_ref.provider_config_version,
            adapter_capability_version: adapter_capability_version.into(),
            deployment_id: context.deployment_id.clone(),
            trust_domain_id: context.trust_domain_id.clone(),
            tenant_id: context.tenant_id.clone(),
            workload_id: context.workload_id.clone(),
            purpose: context.purpose.clone(),
            resolution_mode,
            requested_version,
            revocation_owner,
            request_id: context.request_id.clone(),
            job_id: context.job_id.clone(),
            authority_epoch: context.authority_epoch,
            fencing_token: context.fencing_token,
            lifecycle,
        };
        metadata.validate_common()?;
        Ok(metadata)
    }

    fn validate_common(&self) -> Result<(), SecretBoundaryError> {
        if self.schema_version != SECRET_LEASE_METADATA_SCHEMA_VERSION {
            return Err(invalid("schemaVersion", "is unsupported"));
        }
        validate_fingerprint(&self.reference_fingerprint)?;
        validate_identifier("fingerprintKeyId", &self.fingerprint_key_id, Some("key:"))?;
        validate_identifier("providerId", &self.provider_id, Some("provider:"))?;
        if self.provider_config_version == 0 {
            return Err(invalid("providerConfigVersion", "must be positive"));
        }
        validate_identifier(
            "adapterCapabilityVersion",
            &self.adapter_capability_version,
            None,
        )?;
        validate_identifier("deploymentId", &self.deployment_id, Some("deployment:"))?;
        validate_identifier(
            "trustDomainId",
            &self.trust_domain_id,
            Some("trust-domain:"),
        )?;
        validate_optional_identifier("tenantId", self.tenant_id.as_deref())?;
        validate_identifier("workloadId", &self.workload_id, Some("workload:"))?;
        validate_identifier("purpose", &self.purpose, Some("purpose:"))?;
        match (self.resolution_mode, self.requested_version.as_deref()) {
            (SecretResolutionMode::Pinned, Some(version)) => {
                validate_identifier("requestedVersion", version, None)?;
                if self
                    .issued_fields()
                    .is_some_and(|issued| issued.resolved_version != version)
                {
                    return Err(SecretBoundaryError::VersionMismatch);
                }
            }
            (SecretResolutionMode::LatestAtResolve, None) => {}
            _ => return Err(SecretBoundaryError::InvalidLeaseLifecycle),
        }
        validate_optional_identifier("requestId", self.request_id.as_deref())?;
        validate_optional_identifier("jobId", self.job_id.as_deref())?;
        if self.request_id.is_none() && self.job_id.is_none() {
            return Err(invalid("requestId/jobId", "at least one is required"));
        }
        if self.authority_epoch == 0 || self.fencing_token == 0 {
            return Err(invalid("authorityEpoch/fencingToken", "must be positive"));
        }
        Ok(())
    }

    pub fn lifecycle_state(&self) -> SecretLeaseLifecycleState {
        match self.lifecycle {
            SecretLeaseLifecycle::Requested => SecretLeaseLifecycleState::Requested,
            SecretLeaseLifecycle::Issued(_) => SecretLeaseLifecycleState::Issued,
            SecretLeaseLifecycle::Active(_) => SecretLeaseLifecycleState::Active,
            SecretLeaseLifecycle::Renewing(_) => SecretLeaseLifecycleState::Renewing,
            SecretLeaseLifecycle::Draining(_) => SecretLeaseLifecycleState::Draining,
            SecretLeaseLifecycle::Revoked(_, _) => SecretLeaseLifecycleState::Revoked,
            SecretLeaseLifecycle::Expired(_, _) => SecretLeaseLifecycleState::Expired,
            SecretLeaseLifecycle::Failed { .. } => SecretLeaseLifecycleState::Failed,
        }
    }

    pub fn reference_fingerprint(&self) -> &str {
        &self.reference_fingerprint
    }
    pub fn resolution_mode(&self) -> SecretResolutionMode {
        self.resolution_mode
    }
    pub fn requested_version(&self) -> Option<&str> {
        self.requested_version.as_deref()
    }
    pub fn revocation_owner(&self) -> SecretLeaseRevocationOwner {
        self.revocation_owner
    }
    pub fn fence(&self) -> SecretLeaseFence {
        SecretLeaseFence {
            authority_epoch: self.authority_epoch,
            fencing_token: self.fencing_token,
        }
    }

    /// Validate one lifecycle successor against the fence read with the
    /// current value. Persistence must apply the same `authority_epoch` and
    /// `fencing_token` as compare-and-set predicates; this method prevents a
    /// stale caller from manufacturing a syntactically valid successor first.
    pub fn validate_transition_to(
        &self,
        expected_current: SecretLeaseFence,
        next: &Self,
    ) -> Result<(), SecretBoundaryError> {
        if self.fence() != expected_current
            || next.authority_epoch != self.authority_epoch
            || next.fencing_token <= self.fencing_token
        {
            return Err(SecretBoundaryError::FenceMismatch);
        }
        if self.schema_version != next.schema_version
            || self.reference_fingerprint != next.reference_fingerprint
            || self.fingerprint_key_id != next.fingerprint_key_id
            || self.provider_id != next.provider_id
            || self.provider_config_version != next.provider_config_version
            || self.adapter_capability_version != next.adapter_capability_version
            || self.deployment_id != next.deployment_id
            || self.trust_domain_id != next.trust_domain_id
            || self.tenant_id != next.tenant_id
            || self.workload_id != next.workload_id
            || self.purpose != next.purpose
            || self.resolution_mode != next.resolution_mode
            || self.requested_version != next.requested_version
            || self.revocation_owner != next.revocation_owner
            || self.request_id != next.request_id
            || self.job_id != next.job_id
        {
            return Err(SecretBoundaryError::InvalidLeaseTransition);
        }

        let current_state = self.lifecycle_state();
        let next_state = next.lifecycle_state();
        let permitted = matches!(
            (current_state, next_state),
            (
                SecretLeaseLifecycleState::Requested,
                SecretLeaseLifecycleState::Issued | SecretLeaseLifecycleState::Failed
            ) | (
                SecretLeaseLifecycleState::Issued,
                SecretLeaseLifecycleState::Active
                    | SecretLeaseLifecycleState::Draining
                    | SecretLeaseLifecycleState::Revoked
                    | SecretLeaseLifecycleState::Expired
                    | SecretLeaseLifecycleState::Failed
            ) | (
                SecretLeaseLifecycleState::Active,
                SecretLeaseLifecycleState::Renewing
                    | SecretLeaseLifecycleState::Draining
                    | SecretLeaseLifecycleState::Revoked
                    | SecretLeaseLifecycleState::Expired
                    | SecretLeaseLifecycleState::Failed
            ) | (
                SecretLeaseLifecycleState::Renewing,
                SecretLeaseLifecycleState::Active
                    | SecretLeaseLifecycleState::Draining
                    | SecretLeaseLifecycleState::Revoked
                    | SecretLeaseLifecycleState::Expired
                    | SecretLeaseLifecycleState::Failed
            ) | (
                SecretLeaseLifecycleState::Draining,
                SecretLeaseLifecycleState::Revoked
                    | SecretLeaseLifecycleState::Expired
                    | SecretLeaseLifecycleState::Failed
            )
        );
        if !permitted {
            return Err(SecretBoundaryError::InvalidLeaseTransition);
        }

        if let Some(current_issued) = self.issued_fields() {
            let Some(next_issued) = next.issued_fields() else {
                return Err(SecretBoundaryError::InvalidLeaseTransition);
            };
            if current_issued != next_issued {
                return Err(SecretBoundaryError::InvalidLeaseTransition);
            }
        }
        next.validate_common()
    }
    pub fn resolved_version(&self) -> Option<&str> {
        self.issued_fields()
            .map(|fields| fields.resolved_version.as_str())
    }
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.issued_fields().map(|fields| fields.expires_at)
    }

    fn issued_fields(&self) -> Option<&IssuedLeaseFields> {
        match &self.lifecycle {
            SecretLeaseLifecycle::Requested => None,
            SecretLeaseLifecycle::Issued(fields)
            | SecretLeaseLifecycle::Active(fields)
            | SecretLeaseLifecycle::Renewing(fields)
            | SecretLeaseLifecycle::Draining(fields)
            | SecretLeaseLifecycle::Revoked(fields, _)
            | SecretLeaseLifecycle::Expired(fields, _) => Some(fields),
            SecretLeaseLifecycle::Failed { issued, .. } => issued.as_ref(),
        }
    }

    fn terminal_at(&self) -> Option<DateTime<Utc>> {
        match &self.lifecycle {
            SecretLeaseLifecycle::Revoked(_, terminal_at)
            | SecretLeaseLifecycle::Expired(_, terminal_at)
            | SecretLeaseLifecycle::Failed { terminal_at, .. } => Some(*terminal_at),
            _ => None,
        }
    }
}

impl From<IssuedSecretLease> for IssuedLeaseFields {
    fn from(value: IssuedSecretLease) -> Self {
        Self {
            lease_id: value.lease_id,
            resolved_version: value.resolved_version,
            issued_at: value.issued_at,
            expires_at: value.expires_at,
        }
    }
}

impl fmt::Debug for SecretLeaseMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretLeaseMetadata")
            .field("provider_id", &self.provider_id)
            .field("provider_config_version", &self.provider_config_version)
            .field("reference_fingerprint", &self.reference_fingerprint)
            .field("lifecycle_state", &self.lifecycle_state())
            .field("lease_id", &self.issued_fields().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl Serialize for SecretLeaseMetadata {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let issued = self.issued_fields();
        SecretLeaseWire {
            schema_version: self.schema_version,
            reference_fingerprint: self.reference_fingerprint.clone(),
            fingerprint_key_id: self.fingerprint_key_id.clone(),
            provider_id: self.provider_id.clone(),
            provider_config_version: self.provider_config_version,
            adapter_capability_version: self.adapter_capability_version.clone(),
            deployment_id: self.deployment_id.clone(),
            trust_domain_id: self.trust_domain_id.clone(),
            tenant_id: self.tenant_id.clone(),
            workload_id: self.workload_id.clone(),
            purpose: self.purpose.clone(),
            resolution_mode: self.resolution_mode,
            requested_version: self.requested_version.clone(),
            revocation_owner: self.revocation_owner,
            request_id: self.request_id.clone(),
            job_id: self.job_id.clone(),
            authority_epoch: self.authority_epoch,
            fencing_token: self.fencing_token,
            lifecycle_state: self.lifecycle_state(),
            lease_id: issued.map(|fields| fields.lease_id.clone()),
            resolved_version: issued.map(|fields| fields.resolved_version.clone()),
            issued_at: issued.map(|fields| fields.issued_at),
            expires_at: issued.map(|fields| fields.expires_at),
            terminal_at: self.terminal_at(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SecretLeaseMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        SecretLeaseWire::deserialize(deserializer)?
            .into_metadata()
            .map_err(serde::de::Error::custom)
    }
}

pub struct ResolvedSecret {
    pub material: SecretMaterial,
    pub metadata: SecretLeaseMetadata,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret_ref() -> SecretRef {
        SecretRef::try_new(
            "provider:vault-primary",
            7,
            "deployment:prod-eu",
            "trust-domain:prod-eu",
            Some("tenant:one".to_string()),
            format!("hmac-sha256:{}", "a".repeat(64)),
            "key:secret-ref-fingerprint-v2",
            "secret/ryuki/vendor",
            Some("password".to_string()),
            "purpose:integration-authentication",
            SecretVersionSelector::pinned("42").unwrap(),
        )
        .unwrap()
    }

    fn resolution_context(fencing_token: u64) -> SecretResolutionContext {
        SecretResolutionContext::try_new(
            "deployment:prod-eu",
            "trust-domain:prod-eu",
            Some("tenant:one".to_string()),
            "purpose:integration-authentication",
            "workload:platform-api",
            Some("request:123".to_string()),
            None,
            9,
            fencing_token,
        )
        .unwrap()
    }

    #[test]
    fn secret_ref_round_trips_without_material_and_debug_redacts_selectors() {
        let reference = secret_ref();
        let json = serde_json::to_string(&reference).unwrap();
        assert!(!json.contains("material"));
        let decoded: SecretRef = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, reference);

        let debug = format!("{reference:?}");
        assert!(!debug.contains("secret/ryuki/vendor"));
        assert!(!debug.contains("password"));
        assert_eq!(debug.matches("[REDACTED]").count(), 2);
    }

    #[test]
    fn secret_ref_rejects_unknown_fields_and_invalid_versions() {
        let mut value = serde_json::to_value(secret_ref()).unwrap();
        value["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SecretRef>(value).is_err());

        let mut value = serde_json::to_value(secret_ref()).unwrap();
        value["schemaVersion"] = serde_json::json!(2);
        assert!(serde_json::from_value::<SecretRef>(value).is_err());

        let mut value = serde_json::to_value(secret_ref()).unwrap();
        value["referenceFingerprint"] = serde_json::json!(format!("sha256:{}", "a".repeat(64)));
        assert!(serde_json::from_value::<SecretRef>(value).is_err());
    }

    #[test]
    fn optional_wire_fields_reject_explicit_null() {
        for field in ["tenantId", "fieldSelector"] {
            let mut value = serde_json::to_value(secret_ref()).unwrap();
            value[field] = serde_json::Value::Null;
            assert!(
                serde_json::from_value::<SecretRef>(value).is_err(),
                "{field} must be omitted rather than null"
            );
        }

        let mut requested = serde_json::json!({
            "schemaVersion": 1,
            "referenceFingerprint": format!("hmac-sha256:{}", "a".repeat(64)),
            "fingerprintKeyId": "key:secret-ref-fingerprint-v2",
            "providerId": "provider:vault-primary",
            "providerConfigVersion": 7,
            "adapterCapabilityVersion": "1.0.0",
            "deploymentId": "deployment:prod-eu",
            "trustDomainId": "trust-domain:prod-eu",
            "workloadId": "workload:platform-api",
            "purpose": "purpose:integration-authentication",
            "resolutionMode": "pinned",
            "requestedVersion": "42",
            "revocationOwner": "workload-runtime",
            "requestId": "request:123",
            "authorityEpoch": 9,
            "fencingToken": 11,
            "lifecycleState": "requested"
        });
        for field in [
            "leaseId",
            "resolvedVersion",
            "issuedAt",
            "expiresAt",
            "terminalAt",
        ] {
            requested[field] = serde_json::Value::Null;
            assert!(
                serde_json::from_value::<SecretLeaseMetadata>(requested.clone()).is_err(),
                "{field} must be absent rather than null"
            );
            requested.as_object_mut().unwrap().remove(field);
        }
    }

    #[test]
    fn namespaced_identifiers_require_a_nonempty_suffix() {
        for (field, value) in [
            ("providerId", "provider:"),
            ("deploymentId", "deployment:"),
            ("trustDomainId", "trust-domain:"),
            ("fingerprintKeyId", "key:"),
            ("purpose", "purpose:"),
        ] {
            let mut wire = serde_json::to_value(secret_ref()).unwrap();
            wire[field] = serde_json::json!(value);
            assert!(
                serde_json::from_value::<SecretRef>(wire).is_err(),
                "{field} accepted an empty namespace suffix"
            );
        }
        assert!(
            SecretResolutionContext::try_new(
                "deployment:prod-eu",
                "trust-domain:prod-eu",
                Some("tenant:one".to_string()),
                "purpose:integration-authentication",
                "workload:",
                Some("request:123".to_string()),
                None,
                9,
                11,
            )
            .is_err()
        );
    }

    #[test]
    fn resolution_context_rejects_cross_scope_substitution() {
        let context = resolution_context(11);
        assert!(context.admits(&secret_ref()).is_ok());

        let mut value = serde_json::to_value(secret_ref()).unwrap();
        value["tenantId"] = serde_json::json!("tenant:two");
        let substituted: SecretRef = serde_json::from_value(value).unwrap();
        assert_eq!(
            context.admits(&substituted),
            Err(SecretBoundaryError::ScopeMismatch)
        );
    }

    #[test]
    fn lease_state_wire_shape_rejects_fabricated_or_incomplete_fields() {
        let base = serde_json::json!({
            "schemaVersion": 1,
            "referenceFingerprint": format!("hmac-sha256:{}", "a".repeat(64)),
            "fingerprintKeyId": "key:secret-ref-fingerprint-v2",
            "providerId": "provider:vault-primary",
            "providerConfigVersion": 7,
            "adapterCapabilityVersion": "1.0.0",
            "deploymentId": "deployment:prod-eu",
            "trustDomainId": "trust-domain:prod-eu",
            "workloadId": "workload:platform-api",
            "purpose": "purpose:integration-authentication",
            "resolutionMode": "pinned",
            "requestedVersion": "42",
            "revocationOwner": "workload-runtime",
            "requestId": "request:123",
            "authorityEpoch": 9,
            "fencingToken": 11,
            "lifecycleState": "requested"
        });
        let requested: SecretLeaseMetadata = serde_json::from_value(base.clone()).unwrap();
        assert_eq!(
            requested.lifecycle_state(),
            SecretLeaseLifecycleState::Requested
        );
        assert_eq!(
            serde_json::from_value::<SecretLeaseMetadata>(serde_json::json!({
                "schemaVersion": 1,
                "referenceFingerprint": format!("hmac-sha256:{}", "a".repeat(64)),
                "fingerprintKeyId": "key:secret-ref-fingerprint-v2",
                "providerId": "provider:vault-primary",
                "providerConfigVersion": 7,
                "adapterCapabilityVersion": "1.0.0",
                "deploymentId": "deployment:prod-eu",
                "trustDomainId": "trust-domain:prod-eu",
                "workloadId": "workload:platform-api",
                "purpose": "purpose:integration-authentication",
                "resolutionMode": "pinned",
                "requestedVersion": "42",
                "revocationOwner": "workload-runtime",
                "requestId": "request:123",
                "authorityEpoch": 9,
                "fencingToken": 11,
                "lifecycleState": "active"
            }))
            .unwrap_err()
            .to_string(),
            "secret lease lifecycle fields are inconsistent"
        );

        let mut fabricated = base;
        fabricated["leaseId"] = serde_json::json!("lease:forged");
        assert!(serde_json::from_value::<SecretLeaseMetadata>(fabricated).is_err());
    }

    #[test]
    fn secret_material_is_nonempty_and_only_exposed_through_a_scoped_callback() {
        assert!(SecretMaterial::new(Vec::new()).is_err());
        let material = SecretMaterial::new(b"value".to_vec()).unwrap();
        assert_eq!(material.with_bytes(|bytes| bytes.len()), 5);
    }

    #[test]
    fn pinned_resolution_rejects_a_substituted_provider_version() {
        let now = Utc::now();
        let issued =
            IssuedSecretLease::try_new("lease:one", "43", now, now + chrono::Duration::seconds(30))
                .unwrap();
        assert_eq!(
            SecretLeaseMetadata::try_new(
                &secret_ref(),
                &resolution_context(11),
                "vault-kv-v2.v1",
                SecretLeaseRevocationOwner::WorkloadRuntime,
                SecretLeaseLifecycleInput::Active(issued),
            ),
            Err(SecretBoundaryError::VersionMismatch)
        );

        let latest = SecretRef::try_new(
            "provider:vault-primary",
            7,
            "deployment:prod-eu",
            "trust-domain:prod-eu",
            Some("tenant:one".to_string()),
            format!("hmac-sha256:{}", "b".repeat(64)),
            "key:secret-ref-fingerprint-v2",
            "secret/ryuki/vendor",
            Some("password".to_string()),
            "purpose:integration-authentication",
            SecretVersionSelector::latest_at_resolve(),
        )
        .unwrap();
        let issued =
            IssuedSecretLease::try_new("lease:two", "43", now, now + chrono::Duration::seconds(30))
                .unwrap();
        assert!(
            SecretLeaseMetadata::try_new(
                &latest,
                &resolution_context(11),
                "vault-kv-v2.v1",
                SecretLeaseRevocationOwner::WorkloadRuntime,
                SecretLeaseLifecycleInput::Active(issued),
            )
            .is_ok()
        );
    }

    #[test]
    fn expiration_cannot_precede_the_issued_expiry_deadline() {
        let now = Utc::now();
        let expiry = now + chrono::Duration::seconds(30);
        let issued = IssuedSecretLease::try_new("lease:one", "42", now, expiry).unwrap();
        assert_eq!(
            SecretLeaseMetadata::try_new(
                &secret_ref(),
                &resolution_context(11),
                "vault-kv-v2.v1",
                SecretLeaseRevocationOwner::WorkloadRuntime,
                SecretLeaseLifecycleInput::Expired {
                    issued,
                    terminal_at: expiry - chrono::Duration::milliseconds(1),
                },
            ),
            Err(SecretBoundaryError::InvalidLeaseLifecycle)
        );
    }

    #[test]
    fn lifecycle_transition_requires_the_current_fence_and_advances_it() {
        let requested = SecretLeaseMetadata::try_new(
            &secret_ref(),
            &resolution_context(11),
            "vault-kv-v2.v1",
            SecretLeaseRevocationOwner::WorkloadRuntime,
            SecretLeaseLifecycleInput::Requested,
        )
        .unwrap();
        let now = Utc::now();
        let issued = SecretLeaseMetadata::try_new(
            &secret_ref(),
            &resolution_context(12),
            "vault-kv-v2.v1",
            SecretLeaseRevocationOwner::WorkloadRuntime,
            SecretLeaseLifecycleInput::Issued(
                IssuedSecretLease::try_new(
                    "lease:one",
                    "42",
                    now,
                    now + chrono::Duration::seconds(30),
                )
                .unwrap(),
            ),
        )
        .unwrap();
        assert!(
            requested
                .validate_transition_to(requested.fence(), &issued)
                .is_ok()
        );
        assert_eq!(
            requested.validate_transition_to(
                SecretLeaseFence {
                    authority_epoch: 9,
                    fencing_token: 10,
                },
                &issued,
            ),
            Err(SecretBoundaryError::FenceMismatch)
        );
    }
}
