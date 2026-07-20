//! Typed, fail-closed authorization capabilities.
//!
//! This module deliberately does not adapt `AuthSession` into a principal. A
//! [`VerifiedPrincipal`] and [`ResolvedResource`] have no public constructors;
//! the future credential-admission and canonical-resource resolvers must own
//! those construction seams. Likewise, an implementation-only action registry
//! can evaluate only to denial. This lets repositories adopt the permit types
//! without turning transitional catalog data or caller-provided strings into
//! production authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::num::NonZeroU64;

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::{Digest as ShaDigest, Sha256};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const PERMIT_KEY_DOMAIN: &[u8] = b"ryuki-authorization-kernel-key-v1";
const DECISION_DIGEST_DOMAIN: &[u8] = b"ryuki-authorization-decision-v1";
const QUERY_PREDICATE_DOMAIN: &[u8] = b"ryuki-authorization-query-predicate-v1";
const INSTANCE_PERMIT_DOMAIN: &[u8] = b"ryuki-authorization-instance-permit-v1";
const QUERY_PERMIT_DOMAIN: &[u8] = b"ryuki-authorization-query-permit-v1";
const OBLIGATION_RECEIPT_DOMAIN: &[u8] = b"ryuki-authorization-obligation-receipt-v1";
const OBLIGATION_RECEIPT_DIGEST_DOMAIN: &[u8] = b"ryuki-authorization-obligation-receipt-digest-v1";
const MAX_PERMIT_LIFETIME_SECONDS: i64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeploymentProfile {
    Development,
    Test,
    Production,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    RequestRead,
    RequestApprove,
    AuditRead,
    PlatformSettingsUpdate,
    AgentHeartbeat,
}

impl Action {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequestRead => "request.read",
            Self::RequestApprove => "request.approve",
            Self::AuditRead => "audit.read",
            Self::PlatformSettingsUpdate => "platform.settings.update",
            Self::AgentHeartbeat => "agent.heartbeat",
        }
    }

    const fn resource_kind(self) -> ResourceKind {
        match self {
            Self::RequestRead | Self::RequestApprove => ResourceKind::Request,
            Self::AuditRead => ResourceKind::AuditLog,
            Self::PlatformSettingsUpdate => ResourceKind::PlatformConfig,
            Self::AgentHeartbeat => ResourceKind::Agent,
        }
    }

    const fn semantics(self) -> AuthorizationSemantics {
        match self {
            Self::AuditRead => AuthorizationSemantics::Query,
            Self::PlatformSettingsUpdate => AuthorizationSemantics::Global,
            Self::RequestRead | Self::RequestApprove | Self::AgentHeartbeat => {
                AuthorizationSemantics::Instance
            }
        }
    }

    fn required_obligations(self) -> BTreeSet<ObligationKind> {
        match self {
            Self::RequestApprove | Self::PlatformSettingsUpdate => BTreeSet::from([
                ObligationKind::Audit,
                ObligationKind::MakerChecker,
                ObligationKind::StepUp,
            ]),
            Self::RequestRead | Self::AuditRead | Self::AgentHeartbeat => {
                BTreeSet::from([ObligationKind::Audit])
            }
        }
    }

    const fn actor_is_registered(self, actor: ActorKind) -> bool {
        match self {
            Self::RequestRead | Self::AuditRead => {
                matches!(actor, ActorKind::VerifiedHuman | ActorKind::Service)
            }
            Self::RequestApprove | Self::PlatformSettingsUpdate => {
                matches!(actor, ActorKind::VerifiedHuman)
            }
            Self::AgentHeartbeat => matches!(actor, ActorKind::Agent),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceKind {
    Request,
    AuditLog,
    PlatformConfig,
    Agent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActorKind {
    Anonymous,
    VerifiedHuman,
    Service,
    Workload,
    Agent,
    System,
    Webhook,
    /// An explicit local identity. It is never treated as a human, service,
    /// workload, or system actor and is rejected by a production kernel.
    DevelopmentFixture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceSensitivity {
    Internal,
    Confidential,
    Restricted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssuranceLevel {
    SingleFactor,
    MultiFactor,
    PhishingResistant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyRole {
    Requester,
    Auditor,
    PlatformAdministrator,
    ServiceReader,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceLifecycle {
    Active,
    Terminal,
    Quarantined,
    Revoked,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObligationKind {
    Audit,
    StepUp,
    MakerChecker,
    Quorum,
    Idempotency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
enum AuthorizationSemantics {
    Instance,
    Query,
    Global,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct BindingVersion(NonZeroU64);

impl BindingVersion {
    pub fn new(value: u64) -> Result<Self, AuthorizationError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(AuthorizationError::InvalidBinding(
                "version must be positive",
            ))
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct BindingDigest([u8; 32]);

impl BindingDigest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn sha256(domain: &'static [u8], value: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update((domain.len() as u64).to_be_bytes());
        hasher.update(domain);
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
        Self(hasher.finalize().into())
    }
}

impl fmt::Debug for BindingDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BindingDigest(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
enum ScopeDisposition {
    Global,
    Scoped(BTreeSet<String>),
}

/// An explicit scope axis. An empty set can never mean global authority.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ExplicitScope(ScopeDisposition);

impl ExplicitScope {
    pub const fn global() -> Self {
        Self(ScopeDisposition::Global)
    }

    pub fn scoped(values: BTreeSet<String>) -> Result<Self, AuthorizationError> {
        if values.is_empty() || values.iter().any(|value| !valid_identifier(value)) {
            return Err(AuthorizationError::InvalidBinding(
                "scoped authority must contain canonical values",
            ));
        }
        Ok(Self(ScopeDisposition::Scoped(values)))
    }

    pub fn permits(&self, value: Option<&str>) -> bool {
        match (&self.0, value) {
            (ScopeDisposition::Global, _) => true,
            (ScopeDisposition::Scoped(values), Some(value)) => values.contains(value),
            (ScopeDisposition::Scoped(_), None) => false,
        }
    }

    pub const fn is_global(&self) -> bool {
        matches!(self.0, ScopeDisposition::Global)
    }

    pub fn values(&self) -> Option<&BTreeSet<String>> {
        match &self.0 {
            ScopeDisposition::Global => None,
            ScopeDisposition::Scoped(values) => Some(values),
        }
    }
}

impl fmt::Debug for ExplicitScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            ScopeDisposition::Global => formatter.write_str("ExplicitScope::Global"),
            ScopeDisposition::Scoped(values) => formatter
                .debug_tuple("ExplicitScope::Scoped")
                .field(&format_args!("{} value(s)", values.len()))
                .finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct PrincipalVersionBinding {
    principal_id: String,
    lifecycle_version: BindingVersion,
    authority_version: BindingVersion,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct CredentialBinding {
    credential_id: String,
    credential_version: BindingVersion,
    provider_id: String,
    provider_configuration_version: BindingVersion,
    provider_lifecycle_version: BindingVersion,
    expires_at: DateTime<Utc>,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct AssuranceBinding {
    level: AssuranceLevel,
    audience_digest: BindingDigest,
    key_id_digest: BindingDigest,
    authenticated_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum DelegationBinding {
    Disabled,
    Chain {
        chain_digest: BindingDigest,
        authority_version: BindingVersion,
        expires_at: DateTime<Utc>,
    },
}

/// Provider-neutral identity accepted by the central admission boundary.
///
/// Fields are intentionally private and there is no public constructor. An
/// `AuthSession`, role list, provider subject, or handler cannot promote itself
/// into this type.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedPrincipal {
    actor_kind: ActorKind,
    actor: PrincipalVersionBinding,
    effective_subject: PrincipalVersionBinding,
    deployment_id: String,
    trust_domain_id: String,
    tenant_id: Option<String>,
    credential: CredentialBinding,
    assurance: AssuranceBinding,
    delegation: DelegationBinding,
    site_scope: ExplicitScope,
    environment_scope: ExplicitScope,
    policy_roles: BTreeSet<PolicyRole>,
    expires_at: DateTime<Utc>,
}

impl fmt::Debug for VerifiedPrincipal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedPrincipal")
            .field("actor_kind", &self.actor_kind)
            .field("binding", &"<redacted>")
            .finish()
    }
}

/// A canonical resource resolved before policy evaluation.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedResource {
    kind: ResourceKind,
    canonical_id: String,
    deployment_id: String,
    trust_domain_id: String,
    tenant_id: Option<String>,
    site_id: Option<String>,
    environment_id: Option<String>,
    owner_principal_id: Option<String>,
    resource_version: BindingVersion,
    sensitivity: ResourceSensitivity,
    lifecycle_state: ResourceLifecycle,
}

impl fmt::Debug for ResolvedResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedResource")
            .field("kind", &self.kind)
            .field("binding", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DecisionStatus {
    Deny,
    AllowPending,
    AllowSatisfied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
enum DenialReason {
    RegistryNotReady,
    Expired,
    WrongResourceKind,
    WrongActorKind,
    DevelopmentIdentityInProduction,
    NamespaceMismatch,
    ScopeMismatch,
    OwnerMismatch,
    ActionNotGranted,
    InsufficientAssurance,
    ResourceUnavailable,
    EffectiveSubjectMismatch,
    DelegationDisabled,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct KernelAuthorityBinding {
    kernel_instance_id: Uuid,
    policy_version: BindingVersion,
    policy_digest: BindingDigest,
    action_registry_version: BindingVersion,
    action_registry_digest: BindingDigest,
    maximum_authority_version: BindingVersion,
    maximum_authority_digest: BindingDigest,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct DecisionBinding {
    decision_id: Uuid,
    kernel: KernelAuthorityBinding,
    action: Action,
    semantics: AuthorizationSemantics,
    principal: VerifiedPrincipal,
    resource: ResolvedResource,
    required_obligations: BTreeSet<ObligationKind>,
    expires_at: DateTime<Utc>,
}

pub struct AuthorizationDecision {
    status: DecisionStatus,
    denial_reason: Option<DenialReason>,
    binding: DecisionBinding,
    decision_digest: BindingDigest,
}

impl AuthorizationDecision {
    pub const fn status(&self) -> DecisionStatus {
        self.status
    }

    pub fn required_obligations(&self) -> impl Iterator<Item = ObligationKind> + '_ {
        self.binding.required_obligations.iter().copied()
    }
}

impl fmt::Debug for AuthorizationDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationDecision")
            .field("status", &self.status)
            .field("denial_reason", &self.denial_reason)
            .field("binding", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[allow(dead_code)] // Production issuer constructors land with their transactional repositories.
enum ObligationIssuerKind {
    AuditRepository,
    StepUpVerifier,
    ApprovalRepository,
    QuorumRepository,
    IdempotencyRepository,
}

impl ObligationIssuerKind {
    const fn satisfies(self, kind: ObligationKind) -> bool {
        matches!(
            (self, kind),
            (Self::AuditRepository, ObligationKind::Audit)
                | (Self::StepUpVerifier, ObligationKind::StepUp)
                | (Self::ApprovalRepository, ObligationKind::MakerChecker)
                | (Self::QuorumRepository, ObligationKind::Quorum)
                | (Self::IdempotencyRepository, ObligationKind::Idempotency)
        )
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct ObligationIssuerBinding {
    kind: ObligationIssuerKind,
    issuer_id: String,
    configuration_version: BindingVersion,
}

/// Proof material is typed by the service that owns the obligation. No generic
/// boolean or caller-selected digest can stand in for completion.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[allow(dead_code)] // Variants remain sealed until their owning evidence services are wired.
enum ObligationEvidence {
    AuditReservation {
        audit_event_id: Uuid,
        reservation_version: BindingVersion,
    },
    StepUp {
        ceremony_id: Uuid,
        assurance: AssuranceLevel,
    },
    MakerChecker {
        checker_principal_id: String,
        approval_version: BindingVersion,
    },
    Quorum {
        approval_set_digest: BindingDigest,
        member_count: NonZeroU64,
    },
    Idempotency {
        key_digest: BindingDigest,
        record_version: BindingVersion,
    },
}

impl ObligationEvidence {
    const fn kind(&self) -> ObligationKind {
        match self {
            Self::AuditReservation { .. } => ObligationKind::Audit,
            Self::StepUp { .. } => ObligationKind::StepUp,
            Self::MakerChecker { .. } => ObligationKind::MakerChecker,
            Self::Quorum { .. } => ObligationKind::Quorum,
            Self::Idempotency { .. } => ObligationKind::Idempotency,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct ObligationReceiptBinding {
    receipt_id: Uuid,
    kind: ObligationKind,
    issuer: ObligationIssuerBinding,
    evidence: ObligationEvidence,
    decision_digest: BindingDigest,
    actor_lifecycle_version: BindingVersion,
    actor_authority_version: BindingVersion,
    effective_subject_lifecycle_version: BindingVersion,
    effective_subject_authority_version: BindingVersion,
    credential_version: BindingVersion,
    provider_configuration_version: BindingVersion,
    provider_lifecycle_version: BindingVersion,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct ObligationReceiptPayload<'a> {
    binding: &'a ObligationReceiptBinding,
    receipt_digest: BindingDigest,
}

/// A receipt is produced by the service that actually satisfied an obligation.
/// Its binding, evidence, digest, seal, and all constructors are private; a
/// boolean or caller assertion cannot become a receipt. Production issuers are
/// intentionally absent until their repositories are transactionally wired.
#[derive(Clone, PartialEq, Eq)]
pub struct ObligationReceipt {
    binding: ObligationReceiptBinding,
    receipt_digest: BindingDigest,
    seal: [u8; 32],
}

impl fmt::Debug for ObligationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObligationReceipt")
            .field("kind", &self.binding.kind)
            .field("binding", &"<redacted>")
            .finish()
    }
}

pub struct SatisfiedDecision {
    binding: DecisionBinding,
    decision_digest: BindingDigest,
    receipt_digests: BTreeSet<BindingDigest>,
    expires_at: DateTime<Utc>,
}

impl fmt::Debug for SatisfiedDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SatisfiedDecision")
            .field("status", &DecisionStatus::AllowSatisfied)
            .field("binding", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct PermitBinding {
    decision: DecisionBinding,
    decision_digest: BindingDigest,
    receipt_digests: BTreeSet<BindingDigest>,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct TransactionBinding {
    nonce: Uuid,
    expires_at: DateTime<Utc>,
}

/// A transaction identity must be owned by the database transaction wrapper.
/// There is intentionally no public constructor while that producer is absent.
pub struct TransactionContext(TransactionBinding);

impl TransactionContext {
    #[cfg(test)]
    fn for_test(expires_at: DateTime<Utc>) -> Self {
        Self(TransactionBinding {
            nonce: Uuid::new_v4(),
            expires_at,
        })
    }
}

impl fmt::Debug for TransactionContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TransactionContext(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct SnapshotBinding {
    nonce: Uuid,
    authority_version: BindingVersion,
    expires_at: DateTime<Utc>,
}

pub struct SnapshotContext(SnapshotBinding);

impl SnapshotContext {
    #[cfg(test)]
    fn for_test(authority_version: BindingVersion, expires_at: DateTime<Utc>) -> Self {
        Self(SnapshotBinding {
            nonce: Uuid::new_v4(),
            authority_version,
            expires_at,
        })
    }
}

impl fmt::Debug for SnapshotContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SnapshotContext(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct RequestedQuery {
    filters: BTreeMap<String, String>,
    limit: u32,
    offset: u64,
}

impl RequestedQuery {
    pub fn new(
        filters: BTreeMap<String, String>,
        limit: u32,
        offset: u64,
    ) -> Result<Self, AuthorizationError> {
        if limit == 0
            || filters.len() > 8
            || filters.iter().any(|(key, value)| {
                !matches!(key.as_str(), "site_id" | "environment_id") || !valid_identifier(value)
            })
        {
            return Err(AuthorizationError::InvalidQuery);
        }
        Ok(Self {
            filters,
            limit,
            offset,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct CanonicalQueryScope {
    site_scope: ExplicitScope,
    environment_scope: ExplicitScope,
}

impl CanonicalQueryScope {
    pub const fn site_scope(&self) -> &ExplicitScope {
        &self.site_scope
    }

    pub const fn environment_scope(&self) -> &ExplicitScope {
        &self.environment_scope
    }
}

impl fmt::Debug for CanonicalQueryScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalQueryScope")
            .field("site_scope", &self.site_scope)
            .field("environment_scope", &self.environment_scope)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct AuthorizedQueryPlan {
    predicate_digest: BindingDigest,
    scope: CanonicalQueryScope,
    filters: BTreeMap<String, String>,
    limit: u32,
    offset: u64,
    maximum_limit: u32,
    maximum_offset: u64,
}

#[derive(Serialize)]
struct InstancePermitPayload<'a> {
    binding: &'a PermitBinding,
    transaction: &'a TransactionBinding,
    expires_at: DateTime<Utc>,
}

/// Unforgeable instance/global authorization capability.
///
/// Deliberately not `Clone`, `Serialize`, or `Deserialize`.
pub struct AuthorizationPermit {
    binding: PermitBinding,
    transaction: TransactionBinding,
    expires_at: DateTime<Utc>,
    seal: [u8; 32],
}

impl AuthorizationPermit {
    pub const fn action(&self) -> Action {
        self.binding.decision.action
    }

    pub const fn resource_kind(&self) -> ResourceKind {
        self.binding.decision.resource.kind
    }

    pub fn resource_id(&self) -> &str {
        &self.binding.decision.resource.canonical_id
    }

    pub const fn resource_version(&self) -> BindingVersion {
        self.binding.decision.resource.resource_version
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

impl fmt::Debug for AuthorizationPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizationPermit(<redacted>)")
    }
}

#[derive(Serialize)]
struct QueryPermitPayload<'a> {
    binding: &'a PermitBinding,
    snapshot: &'a SnapshotBinding,
    plan: &'a AuthorizedQueryPlan,
    expires_at: DateTime<Utc>,
}

/// Unforgeable collection-read capability.
///
/// Deliberately not `Clone`, `Serialize`, or `Deserialize`. A repository must
/// derive its predicate and page ceiling from this object rather than accept a
/// second raw predicate alongside it.
pub struct QueryPermit {
    binding: PermitBinding,
    snapshot: SnapshotBinding,
    plan: AuthorizedQueryPlan,
    expires_at: DateTime<Utc>,
    seal: [u8; 32],
}

impl QueryPermit {
    pub const fn action(&self) -> Action {
        self.binding.decision.action
    }

    pub fn filters(&self) -> &BTreeMap<String, String> {
        &self.plan.filters
    }

    pub const fn scope(&self) -> &CanonicalQueryScope {
        &self.plan.scope
    }

    pub const fn limit(&self) -> u32 {
        self.plan.limit
    }

    pub const fn offset(&self) -> u64 {
        self.plan.offset
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

impl fmt::Debug for QueryPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("QueryPermit(<redacted>)")
    }
}

enum ClockSource {
    System,
    #[cfg(test)]
    Fixed(DateTime<Utc>),
}

/// Owns the only permit constructors and one process-local sealing key.
pub struct AuthorizationKernel {
    profile: DeploymentProfile,
    /// Populated only by a validated route+resolver+repository registry loader.
    /// The public implementation-only constructor always leaves this empty.
    active_actions: BTreeSet<Action>,
    authority: KernelAuthorityBinding,
    permit_key: [u8; 32],
    query_maximum_limit: u32,
    query_maximum_offset: u64,
    delegation_enabled: bool,
    clock: ClockSource,
}

impl fmt::Debug for AuthorizationKernel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationKernel")
            .field("profile", &self.profile)
            .field("active_action_count", &self.active_actions.len())
            .field("sealing_key", &"<redacted>")
            .finish()
    }
}

impl AuthorizationKernel {
    /// Construct a fail-closed kernel for the current transitional registry.
    /// There is intentionally no public constructor that asserts production
    /// readiness; a later verified registry loader must own that seam.
    pub fn implementation_only(
        profile: DeploymentProfile,
        policy_version: BindingVersion,
        policy_digest: BindingDigest,
        action_registry_version: BindingVersion,
        action_registry_digest: BindingDigest,
        maximum_authority_version: BindingVersion,
        maximum_authority_digest: BindingDigest,
    ) -> Self {
        Self::new(
            profile,
            BTreeSet::new(),
            policy_version,
            policy_digest,
            action_registry_version,
            action_registry_digest,
            maximum_authority_version,
            maximum_authority_digest,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        profile: DeploymentProfile,
        active_actions: BTreeSet<Action>,
        policy_version: BindingVersion,
        policy_digest: BindingDigest,
        action_registry_version: BindingVersion,
        action_registry_digest: BindingDigest,
        maximum_authority_version: BindingVersion,
        maximum_authority_digest: BindingDigest,
    ) -> Self {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let mut hasher = Sha256::new();
        hasher.update(PERMIT_KEY_DOMAIN);
        hasher.update(first.as_bytes());
        hasher.update(second.as_bytes());
        let permit_key = hasher.finalize().into();
        let kernel_instance_id = Uuid::new_v4();
        Self {
            profile,
            active_actions,
            authority: KernelAuthorityBinding {
                kernel_instance_id,
                policy_version,
                policy_digest,
                action_registry_version,
                action_registry_digest,
                maximum_authority_version,
                maximum_authority_digest,
            },
            permit_key,
            query_maximum_limit: 200,
            query_maximum_offset: 100_000,
            delegation_enabled: false,
            clock: ClockSource::System,
        }
    }

    fn now(&self) -> DateTime<Utc> {
        match &self.clock {
            ClockSource::System => Utc::now(),
            #[cfg(test)]
            ClockSource::Fixed(now) => *now,
        }
    }

    pub fn decide(
        &self,
        principal: &VerifiedPrincipal,
        action: Action,
        resource: &ResolvedResource,
    ) -> AuthorizationDecision {
        let now = self.now();
        let expires_at = [
            principal.expires_at,
            principal.credential.expires_at,
            principal.assurance.expires_at,
        ]
        .into_iter()
        .min()
        .unwrap_or(now);

        let denial_reason = if !self.active_actions.contains(&action) {
            Some(DenialReason::RegistryNotReady)
        } else if expires_at <= now {
            Some(DenialReason::Expired)
        } else if resource.kind != action.resource_kind() {
            Some(DenialReason::WrongResourceKind)
        } else if principal.actor_kind == ActorKind::DevelopmentFixture
            && self.profile == DeploymentProfile::Production
        {
            Some(DenialReason::DevelopmentIdentityInProduction)
        } else if !action.actor_is_registered(principal.actor_kind) {
            Some(DenialReason::WrongActorKind)
        } else if principal.deployment_id != resource.deployment_id
            || principal.trust_domain_id != resource.trust_domain_id
            || principal.tenant_id != resource.tenant_id
        {
            Some(DenialReason::NamespaceMismatch)
        } else if !principal.site_scope.permits(resource.site_id.as_deref())
            || !principal
                .environment_scope
                .permits(resource.environment_id.as_deref())
        {
            Some(DenialReason::ScopeMismatch)
        } else if !resource_lifecycle_permits(action, resource.lifecycle_state) {
            Some(DenialReason::ResourceUnavailable)
        } else if !assurance_permits(action, resource.sensitivity, principal.assurance.level) {
            Some(DenialReason::InsufficientAssurance)
        } else if !policy_entitles(principal, action) {
            Some(DenialReason::ActionNotGranted)
        } else if matches!(principal.delegation, DelegationBinding::Disabled)
            && principal.actor != principal.effective_subject
        {
            Some(DenialReason::EffectiveSubjectMismatch)
        } else if action == Action::RequestRead
            && !policy_can_read_any(principal)
            && resource.owner_principal_id.as_deref()
                != Some(principal.effective_subject.principal_id.as_str())
        {
            Some(DenialReason::OwnerMismatch)
        } else if !self.delegation_enabled
            && !matches!(principal.delegation, DelegationBinding::Disabled)
        {
            Some(DenialReason::DelegationDisabled)
        } else {
            None
        };

        let required_obligations = action.required_obligations();
        let binding = DecisionBinding {
            decision_id: Uuid::new_v4(),
            kernel: self.authority.clone(),
            action,
            semantics: action.semantics(),
            principal: principal.clone(),
            resource: resource.clone(),
            required_obligations,
            expires_at,
        };
        let status = if denial_reason.is_some() {
            DecisionStatus::Deny
        } else if binding.required_obligations.is_empty() {
            DecisionStatus::AllowSatisfied
        } else {
            DecisionStatus::AllowPending
        };
        let decision_digest = authorization_decision_digest(status, denial_reason, &binding);
        AuthorizationDecision {
            status,
            denial_reason,
            binding,
            decision_digest,
        }
    }

    pub fn satisfy_obligations(
        &self,
        decision: &AuthorizationDecision,
        receipts: &[ObligationReceipt],
    ) -> Result<SatisfiedDecision, AuthorizationError> {
        let now = self.now();
        if decision.binding.kernel.kernel_instance_id != self.authority.kernel_instance_id {
            return Err(AuthorizationError::ForeignKernel);
        }
        if authorization_decision_digest(decision.status, decision.denial_reason, &decision.binding)
            != decision.decision_digest
        {
            return Err(AuthorizationError::InvalidDecision);
        }
        if decision.status == DecisionStatus::Deny || decision.denial_reason.is_some() {
            return Err(AuthorizationError::Denied);
        }
        if decision.status != DecisionStatus::AllowPending
            && !(decision.status == DecisionStatus::AllowSatisfied
                && decision.binding.required_obligations.is_empty())
        {
            return Err(AuthorizationError::InvalidDecision);
        }
        if decision.binding.expires_at <= now {
            return Err(AuthorizationError::Expired);
        }

        let mut seen = BTreeSet::new();
        let mut receipt_digests = BTreeSet::new();
        let mut expires_at = decision.binding.expires_at;
        for receipt in receipts {
            self.verify_seal(
                OBLIGATION_RECEIPT_DOMAIN,
                &ObligationReceiptPayload {
                    binding: &receipt.binding,
                    receipt_digest: receipt.receipt_digest,
                },
                &receipt.seal,
                AuthorizationError::InvalidObligationReceipt,
            )?;
            let expected_digest =
                digest_serializable(OBLIGATION_RECEIPT_DIGEST_DOMAIN, &receipt.binding);
            if !decision
                .binding
                .required_obligations
                .contains(&receipt.binding.kind)
                || receipt.receipt_digest != expected_digest
                || !receipt_digests.insert(receipt.receipt_digest)
                || !seen.insert(receipt.binding.kind)
                || receipt.binding.evidence.kind() != receipt.binding.kind
                || !receipt.binding.issuer.kind.satisfies(receipt.binding.kind)
                || !valid_identifier(&receipt.binding.issuer.issuer_id)
                || receipt.binding.receipt_id.is_nil()
                || receipt.binding.decision_digest != decision.decision_digest
                || receipt.binding.actor_lifecycle_version
                    != decision.binding.principal.actor.lifecycle_version
                || receipt.binding.actor_authority_version
                    != decision.binding.principal.actor.authority_version
                || receipt.binding.effective_subject_lifecycle_version
                    != decision
                        .binding
                        .principal
                        .effective_subject
                        .lifecycle_version
                || receipt.binding.effective_subject_authority_version
                    != decision
                        .binding
                        .principal
                        .effective_subject
                        .authority_version
                || receipt.binding.credential_version
                    != decision.binding.principal.credential.credential_version
                || receipt.binding.provider_configuration_version
                    != decision
                        .binding
                        .principal
                        .credential
                        .provider_configuration_version
                || receipt.binding.provider_lifecycle_version
                    != decision
                        .binding
                        .principal
                        .credential
                        .provider_lifecycle_version
                || receipt.binding.issued_at > now
                || receipt.binding.expires_at <= now
                || receipt.binding.expires_at > decision.binding.expires_at
                || !obligation_evidence_is_valid(
                    &receipt.binding.evidence,
                    &decision.binding.principal,
                )
            {
                return Err(AuthorizationError::InvalidObligationReceipt);
            }
            expires_at = expires_at.min(receipt.binding.expires_at);
        }
        if seen != decision.binding.required_obligations {
            return Err(AuthorizationError::UnsatisfiedObligations);
        }

        Ok(SatisfiedDecision {
            binding: decision.binding.clone(),
            decision_digest: decision.decision_digest,
            receipt_digests,
            expires_at,
        })
    }

    pub fn authorize_instance(
        &self,
        decision: SatisfiedDecision,
        transaction: &TransactionContext,
    ) -> Result<AuthorizationPermit, AuthorizationError> {
        let now = self.now();
        if decision.binding.kernel.kernel_instance_id != self.authority.kernel_instance_id {
            return Err(AuthorizationError::ForeignKernel);
        }
        if decision.binding.semantics == AuthorizationSemantics::Query {
            return Err(AuthorizationError::WrongPermitKind);
        }
        let expires_at = decision
            .expires_at
            .min(transaction.0.expires_at)
            .min(decision.binding.principal.expires_at)
            .min(now + chrono::Duration::seconds(MAX_PERMIT_LIFETIME_SECONDS));
        if expires_at <= now {
            return Err(AuthorizationError::Expired);
        }
        let binding = PermitBinding {
            decision: decision.binding,
            decision_digest: decision.decision_digest,
            receipt_digests: decision.receipt_digests,
        };
        let seal = self.seal(
            INSTANCE_PERMIT_DOMAIN,
            &InstancePermitPayload {
                binding: &binding,
                transaction: &transaction.0,
                expires_at,
            },
        );
        Ok(AuthorizationPermit {
            binding,
            transaction: transaction.0.clone(),
            expires_at,
            seal,
        })
    }

    pub fn authorize_query(
        &self,
        decision: SatisfiedDecision,
        requested: RequestedQuery,
        snapshot: &SnapshotContext,
    ) -> Result<QueryPermit, AuthorizationError> {
        let now = self.now();
        if decision.binding.kernel.kernel_instance_id != self.authority.kernel_instance_id {
            return Err(AuthorizationError::ForeignKernel);
        }
        if decision.binding.semantics != AuthorizationSemantics::Query {
            return Err(AuthorizationError::WrongPermitKind);
        }
        if requested.limit > self.query_maximum_limit
            || requested.offset > self.query_maximum_offset
            || !query_filters_within_scope(&decision.binding.principal, &requested.filters)
        {
            return Err(AuthorizationError::QueryWouldWidenAuthority);
        }
        let expires_at = decision
            .expires_at
            .min(snapshot.0.expires_at)
            .min(now + chrono::Duration::seconds(MAX_PERMIT_LIFETIME_SECONDS));
        if expires_at <= now {
            return Err(AuthorizationError::Expired);
        }
        let predicate_digest = digest_serializable(
            QUERY_PREDICATE_DOMAIN,
            &(
                &decision.binding.principal.site_scope,
                &decision.binding.principal.environment_scope,
                &requested.filters,
            ),
        );
        let scope = CanonicalQueryScope {
            site_scope: decision.binding.principal.site_scope.clone(),
            environment_scope: decision.binding.principal.environment_scope.clone(),
        };
        let plan = AuthorizedQueryPlan {
            predicate_digest,
            scope,
            filters: requested.filters,
            limit: requested.limit,
            offset: requested.offset,
            maximum_limit: self.query_maximum_limit,
            maximum_offset: self.query_maximum_offset,
        };
        let binding = PermitBinding {
            decision: decision.binding,
            decision_digest: decision.decision_digest,
            receipt_digests: decision.receipt_digests,
        };
        let seal = self.seal(
            QUERY_PERMIT_DOMAIN,
            &QueryPermitPayload {
                binding: &binding,
                snapshot: &snapshot.0,
                plan: &plan,
                expires_at,
            },
        );
        Ok(QueryPermit {
            binding,
            snapshot: snapshot.0.clone(),
            plan,
            expires_at,
            seal,
        })
    }

    pub fn ensure_instance_current(
        &self,
        permit: &AuthorizationPermit,
        current_principal: &VerifiedPrincipal,
        current_resource: &ResolvedResource,
        transaction: &TransactionContext,
    ) -> Result<(), AuthorizationError> {
        let now = self.now();
        self.verify_seal(
            INSTANCE_PERMIT_DOMAIN,
            &InstancePermitPayload {
                binding: &permit.binding,
                transaction: &permit.transaction,
                expires_at: permit.expires_at,
            },
            &permit.seal,
            AuthorizationError::InvalidPermit,
        )?;
        if permit.binding.decision.kernel != self.authority {
            return Err(AuthorizationError::ForeignKernel);
        }
        if permit.expires_at <= now {
            return Err(AuthorizationError::Expired);
        }
        if permit.transaction != transaction.0 {
            return Err(AuthorizationError::TransactionMismatch);
        }
        if &permit.binding.decision.principal != current_principal
            || &permit.binding.decision.resource != current_resource
        {
            return Err(AuthorizationError::StaleBinding);
        }
        Ok(())
    }

    pub fn ensure_query_current(
        &self,
        permit: &QueryPermit,
        current_principal: &VerifiedPrincipal,
        current_resource: &ResolvedResource,
        snapshot: &SnapshotContext,
    ) -> Result<(), AuthorizationError> {
        let now = self.now();
        self.verify_seal(
            QUERY_PERMIT_DOMAIN,
            &QueryPermitPayload {
                binding: &permit.binding,
                snapshot: &permit.snapshot,
                plan: &permit.plan,
                expires_at: permit.expires_at,
            },
            &permit.seal,
            AuthorizationError::InvalidPermit,
        )?;
        if permit.binding.decision.kernel != self.authority {
            return Err(AuthorizationError::ForeignKernel);
        }
        if permit.expires_at <= now {
            return Err(AuthorizationError::Expired);
        }
        if permit.snapshot != snapshot.0 {
            return Err(AuthorizationError::SnapshotMismatch);
        }
        if &permit.binding.decision.principal != current_principal
            || &permit.binding.decision.resource != current_resource
        {
            return Err(AuthorizationError::StaleBinding);
        }
        if permit.plan.limit > permit.plan.maximum_limit
            || permit.plan.offset > permit.plan.maximum_offset
            || permit.plan.scope.site_scope != current_principal.site_scope
            || permit.plan.scope.environment_scope != current_principal.environment_scope
            || !query_filters_within_scope(current_principal, &permit.plan.filters)
        {
            return Err(AuthorizationError::QueryWouldWidenAuthority);
        }
        Ok(())
    }

    /// Test-only stand-in for the future transactionally bound obligation
    /// services. Keeping this producer behind `cfg(test)` prevents production
    /// code from manufacturing evidence before those services exist.
    #[cfg(test)]
    fn issue_test_receipt(
        &self,
        decision: &AuthorizationDecision,
        kind: ObligationKind,
    ) -> ObligationReceipt {
        let now = self.now();
        let (issuer_kind, issuer_id, evidence) = match kind {
            ObligationKind::Audit => (
                ObligationIssuerKind::AuditRepository,
                "issuer:audit:test",
                ObligationEvidence::AuditReservation {
                    audit_event_id: Uuid::new_v4(),
                    reservation_version: BindingVersion::new(1).expect("positive test version"),
                },
            ),
            ObligationKind::StepUp => (
                ObligationIssuerKind::StepUpVerifier,
                "issuer:step-up:test",
                ObligationEvidence::StepUp {
                    ceremony_id: Uuid::new_v4(),
                    assurance: AssuranceLevel::PhishingResistant,
                },
            ),
            ObligationKind::MakerChecker => (
                ObligationIssuerKind::ApprovalRepository,
                "issuer:approval:test",
                ObligationEvidence::MakerChecker {
                    checker_principal_id: "principal:checker".into(),
                    approval_version: BindingVersion::new(1).expect("positive test version"),
                },
            ),
            ObligationKind::Quorum => (
                ObligationIssuerKind::QuorumRepository,
                "issuer:quorum:test",
                ObligationEvidence::Quorum {
                    approval_set_digest: BindingDigest::sha256(
                        b"ryuki-test-quorum-v1",
                        decision.binding.decision_id.as_bytes(),
                    ),
                    member_count: NonZeroU64::new(2).expect("positive quorum"),
                },
            ),
            ObligationKind::Idempotency => (
                ObligationIssuerKind::IdempotencyRepository,
                "issuer:idempotency:test",
                ObligationEvidence::Idempotency {
                    key_digest: BindingDigest::sha256(
                        b"ryuki-test-idempotency-v1",
                        decision.binding.decision_id.as_bytes(),
                    ),
                    record_version: BindingVersion::new(1).expect("positive test version"),
                },
            ),
        };
        let binding = ObligationReceiptBinding {
            receipt_id: Uuid::new_v4(),
            kind,
            issuer: ObligationIssuerBinding {
                kind: issuer_kind,
                issuer_id: issuer_id.into(),
                configuration_version: BindingVersion::new(1).expect("positive test version"),
            },
            evidence,
            decision_digest: decision.decision_digest,
            actor_lifecycle_version: decision.binding.principal.actor.lifecycle_version,
            actor_authority_version: decision.binding.principal.actor.authority_version,
            effective_subject_lifecycle_version: decision
                .binding
                .principal
                .effective_subject
                .lifecycle_version,
            effective_subject_authority_version: decision
                .binding
                .principal
                .effective_subject
                .authority_version,
            credential_version: decision.binding.principal.credential.credential_version,
            provider_configuration_version: decision
                .binding
                .principal
                .credential
                .provider_configuration_version,
            provider_lifecycle_version: decision
                .binding
                .principal
                .credential
                .provider_lifecycle_version,
            issued_at: now,
            expires_at: decision
                .binding
                .expires_at
                .min(now + chrono::Duration::seconds(MAX_PERMIT_LIFETIME_SECONDS)),
        };
        let receipt_digest = digest_serializable(OBLIGATION_RECEIPT_DIGEST_DOMAIN, &binding);
        let seal = self.seal(
            OBLIGATION_RECEIPT_DOMAIN,
            &ObligationReceiptPayload {
                binding: &binding,
                receipt_digest,
            },
        );
        ObligationReceipt {
            binding,
            receipt_digest,
            seal,
        }
    }

    fn seal<T: Serialize>(&self, domain: &'static [u8], value: &T) -> [u8; 32] {
        let bytes = serde_json::to_vec(value).expect("permit payload is serializable");
        let mut mac = HmacSha256::new_from_slice(&self.permit_key)
            .expect("HMAC-SHA256 accepts a 32-byte key");
        mac.update(&(domain.len() as u64).to_be_bytes());
        mac.update(domain);
        mac.update(&(bytes.len() as u64).to_be_bytes());
        mac.update(&bytes);
        mac.finalize().into_bytes().into()
    }

    fn verify_seal<T: Serialize>(
        &self,
        domain: &'static [u8],
        value: &T,
        seal: &[u8; 32],
        invalid: AuthorizationError,
    ) -> Result<(), AuthorizationError> {
        let bytes = serde_json::to_vec(value).map_err(|_| invalid)?;
        let mut mac = HmacSha256::new_from_slice(&self.permit_key).map_err(|_| invalid)?;
        mac.update(&(domain.len() as u64).to_be_bytes());
        mac.update(domain);
        mac.update(&(bytes.len() as u64).to_be_bytes());
        mac.update(&bytes);
        mac.verify_slice(seal).map_err(|_| invalid)
    }
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationError {
    #[error("invalid authorization binding: {0}")]
    InvalidBinding(&'static str),
    #[error("authorization decision denied")]
    Denied,
    #[error("authorization decision binding is invalid")]
    InvalidDecision,
    #[error("authorization obligations are not satisfied")]
    UnsatisfiedObligations,
    #[error("authorization obligation receipt is invalid")]
    InvalidObligationReceipt,
    #[error("authorization binding has expired")]
    Expired,
    #[error("authorization object belongs to another kernel")]
    ForeignKernel,
    #[error("authorization permit is invalid")]
    InvalidPermit,
    #[error("authorization permit kind does not match the operation")]
    WrongPermitKind,
    #[error("authorization transaction does not match")]
    TransactionMismatch,
    #[error("authorization snapshot does not match")]
    SnapshotMismatch,
    #[error("authorization binding is stale")]
    StaleBinding,
    #[error("query is invalid")]
    InvalidQuery,
    #[error("query would widen authorized scope")]
    QueryWouldWidenAuthority,
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn digest_serializable<T: Serialize>(domain: &'static [u8], value: &T) -> BindingDigest {
    let bytes = serde_json::to_vec(value).expect("authorization binding is serializable");
    BindingDigest::sha256(domain, &bytes)
}

fn authorization_decision_digest(
    status: DecisionStatus,
    denial_reason: Option<DenialReason>,
    binding: &DecisionBinding,
) -> BindingDigest {
    digest_serializable(DECISION_DIGEST_DOMAIN, &(status, denial_reason, binding))
}

fn obligation_evidence_is_valid(
    evidence: &ObligationEvidence,
    principal: &VerifiedPrincipal,
) -> bool {
    match evidence {
        ObligationEvidence::AuditReservation { audit_event_id, .. } => !audit_event_id.is_nil(),
        ObligationEvidence::StepUp {
            ceremony_id,
            assurance,
        } => !ceremony_id.is_nil() && *assurance >= AssuranceLevel::PhishingResistant,
        ObligationEvidence::MakerChecker {
            checker_principal_id,
            ..
        } => {
            valid_identifier(checker_principal_id)
                && checker_principal_id != &principal.actor.principal_id
                && checker_principal_id != &principal.effective_subject.principal_id
        }
        ObligationEvidence::Quorum {
            approval_set_digest,
            member_count,
        } => approval_set_digest.0 != [0; 32] && member_count.get() >= 2,
        ObligationEvidence::Idempotency { key_digest, .. } => key_digest.0 != [0; 32],
    }
}

fn query_filters_within_scope(
    principal: &VerifiedPrincipal,
    filters: &BTreeMap<String, String>,
) -> bool {
    filters.iter().all(|(key, value)| match key.as_str() {
        "site_id" => principal.site_scope.permits(Some(value)),
        "environment_id" => principal.environment_scope.permits(Some(value)),
        _ => false,
    })
}

fn policy_entitles(principal: &VerifiedPrincipal, action: Action) -> bool {
    match (principal.actor_kind, action) {
        (ActorKind::VerifiedHuman, Action::RequestRead) => {
            principal.policy_roles.iter().any(|role| {
                matches!(
                    role,
                    PolicyRole::Requester | PolicyRole::Auditor | PolicyRole::PlatformAdministrator
                )
            })
        }
        (ActorKind::VerifiedHuman, Action::AuditRead) => {
            principal.policy_roles.iter().any(|role| {
                matches!(
                    role,
                    PolicyRole::Auditor | PolicyRole::PlatformAdministrator
                )
            })
        }
        (ActorKind::Service, Action::RequestRead | Action::AuditRead) => {
            principal.policy_roles.contains(&PolicyRole::ServiceReader)
        }
        // These actions stay inactive until their complete policy and receipt
        // producers are registry-verified. Encoding the intended role floor
        // here prevents a later activation from inheriting read-tier policy.
        (ActorKind::VerifiedHuman, Action::RequestApprove) => principal
            .policy_roles
            .contains(&PolicyRole::PlatformAdministrator),
        (ActorKind::VerifiedHuman, Action::PlatformSettingsUpdate) => principal
            .policy_roles
            .contains(&PolicyRole::PlatformAdministrator),
        (ActorKind::Agent, Action::AgentHeartbeat) => true,
        _ => false,
    }
}

fn policy_can_read_any(principal: &VerifiedPrincipal) -> bool {
    principal.actor_kind == ActorKind::Service
        || principal.policy_roles.iter().any(|role| {
            matches!(
                role,
                PolicyRole::Auditor | PolicyRole::PlatformAdministrator
            )
        })
}

fn assurance_permits(
    action: Action,
    sensitivity: ResourceSensitivity,
    assurance: AssuranceLevel,
) -> bool {
    let required = match action {
        Action::RequestApprove | Action::PlatformSettingsUpdate => {
            AssuranceLevel::PhishingResistant
        }
        Action::AuditRead => AssuranceLevel::MultiFactor,
        Action::RequestRead if matches!(sensitivity, ResourceSensitivity::Restricted) => {
            AssuranceLevel::MultiFactor
        }
        Action::RequestRead | Action::AgentHeartbeat => AssuranceLevel::SingleFactor,
    };
    assurance >= required
}

fn resource_lifecycle_permits(action: Action, lifecycle: ResourceLifecycle) -> bool {
    match lifecycle {
        ResourceLifecycle::Quarantined
        | ResourceLifecycle::Revoked
        | ResourceLifecycle::Unknown => false,
        ResourceLifecycle::Terminal => {
            matches!(action, Action::RequestRead | Action::AuditRead)
        }
        ResourceLifecycle::Active => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn version(value: u64) -> BindingVersion {
        BindingVersion::new(value).unwrap()
    }

    fn digest(label: &str) -> BindingDigest {
        BindingDigest::sha256(b"test-binding-v1", label.as_bytes())
    }

    fn kernel(profile: DeploymentProfile) -> AuthorizationKernel {
        let mut kernel = AuthorizationKernel::new(
            profile,
            BTreeSet::from([Action::RequestRead, Action::AuditRead]),
            version(11),
            digest("policy"),
            version(7),
            digest("registry"),
            version(5),
            digest("maximum-authority"),
        );
        kernel.clock = ClockSource::Fixed(test_now());
        kernel
    }

    fn kernel_with_actions(
        profile: DeploymentProfile,
        actions: BTreeSet<Action>,
    ) -> AuthorizationKernel {
        let mut kernel = AuthorizationKernel::new(
            profile,
            actions,
            version(11),
            digest("policy"),
            version(7),
            digest("registry"),
            version(5),
            digest("maximum-authority"),
        );
        kernel.clock = ClockSource::Fixed(test_now());
        kernel
    }

    fn test_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-20T05:00:00Z")
            .expect("valid fixed time")
            .with_timezone(&Utc)
    }

    fn principal(now: DateTime<Utc>, action: Action) -> VerifiedPrincipal {
        VerifiedPrincipal {
            actor_kind: ActorKind::VerifiedHuman,
            actor: PrincipalVersionBinding {
                principal_id: "principal:actor".into(),
                lifecycle_version: version(3),
                authority_version: version(9),
            },
            effective_subject: PrincipalVersionBinding {
                principal_id: "principal:actor".into(),
                lifecycle_version: version(3),
                authority_version: version(9),
            },
            deployment_id: "deployment:one".into(),
            trust_domain_id: "trust-domain:one".into(),
            tenant_id: Some("tenant:one".into()),
            credential: CredentialBinding {
                credential_id: "credential:one".into(),
                credential_version: version(8),
                provider_id: "provider:one".into(),
                provider_configuration_version: version(6),
                provider_lifecycle_version: version(12),
                expires_at: now + Duration::minutes(10),
            },
            assurance: AssuranceBinding {
                level: AssuranceLevel::MultiFactor,
                audience_digest: digest("audience"),
                key_id_digest: digest("key-id"),
                authenticated_at: now - Duration::minutes(1),
                expires_at: now + Duration::minutes(10),
            },
            delegation: DelegationBinding::Disabled,
            site_scope: ExplicitScope::scoped(BTreeSet::from(["site:one".into()])).unwrap(),
            environment_scope: ExplicitScope::scoped(BTreeSet::from(["env:prod".into()])).unwrap(),
            policy_roles: BTreeSet::from([match action {
                Action::RequestRead => PolicyRole::Requester,
                Action::AuditRead => PolicyRole::Auditor,
                Action::RequestApprove | Action::PlatformSettingsUpdate => {
                    PolicyRole::PlatformAdministrator
                }
                Action::AgentHeartbeat => PolicyRole::ServiceReader,
            }]),
            expires_at: now + Duration::minutes(10),
        }
    }

    fn resource(action: Action) -> ResolvedResource {
        ResolvedResource {
            kind: action.resource_kind(),
            canonical_id: match action.resource_kind() {
                ResourceKind::Request => "request:one",
                ResourceKind::AuditLog => "audit-log:one",
                ResourceKind::PlatformConfig => "platform-config:one",
                ResourceKind::Agent => "agent:one",
            }
            .into(),
            deployment_id: "deployment:one".into(),
            trust_domain_id: "trust-domain:one".into(),
            tenant_id: Some("tenant:one".into()),
            site_id: Some("site:one".into()),
            environment_id: Some("env:prod".into()),
            owner_principal_id: Some("principal:actor".into()),
            resource_version: version(22),
            sensitivity: ResourceSensitivity::Confidential,
            lifecycle_state: ResourceLifecycle::Active,
        }
    }

    fn receipts(
        kernel: &AuthorizationKernel,
        decision: &AuthorizationDecision,
    ) -> Vec<ObligationReceipt> {
        decision
            .binding
            .required_obligations
            .iter()
            .copied()
            .map(|kind| kernel.issue_test_receipt(decision, kind))
            .collect()
    }

    fn instance_permit(
        kernel: &AuthorizationKernel,
        now: DateTime<Utc>,
    ) -> (
        VerifiedPrincipal,
        ResolvedResource,
        TransactionContext,
        AuthorizationPermit,
    ) {
        let principal = principal(now, Action::RequestRead);
        let resource = resource(Action::RequestRead);
        let decision = kernel.decide(&principal, Action::RequestRead, &resource);
        assert_eq!(decision.status(), DecisionStatus::AllowPending);
        let satisfied = kernel
            .satisfy_obligations(&decision, &receipts(kernel, &decision))
            .unwrap();
        let transaction = TransactionContext::for_test(now + Duration::minutes(5));
        let permit = kernel.authorize_instance(satisfied, &transaction).unwrap();
        (principal, resource, transaction, permit)
    }

    fn query_permit(
        kernel: &AuthorizationKernel,
        now: DateTime<Utc>,
    ) -> (
        VerifiedPrincipal,
        ResolvedResource,
        SnapshotContext,
        QueryPermit,
    ) {
        let principal = principal(now, Action::AuditRead);
        let resource = resource(Action::AuditRead);
        let decision = kernel.decide(&principal, Action::AuditRead, &resource);
        let satisfied = kernel
            .satisfy_obligations(&decision, &receipts(kernel, &decision))
            .unwrap();
        let snapshot = SnapshotContext::for_test(version(33), now + Duration::minutes(5));
        let requested = RequestedQuery::new(
            BTreeMap::from([("site_id".into(), "site:one".into())]),
            50,
            0,
        )
        .unwrap();
        let permit = kernel
            .authorize_query(satisfied, requested, &snapshot)
            .unwrap();
        (principal, resource, snapshot, permit)
    }

    fn resign_receipt(kernel: &AuthorizationKernel, receipt: &mut ObligationReceipt) {
        receipt.receipt_digest =
            digest_serializable(OBLIGATION_RECEIPT_DIGEST_DOMAIN, &receipt.binding);
        receipt.seal = kernel.seal(
            OBLIGATION_RECEIPT_DOMAIN,
            &ObligationReceiptPayload {
                binding: &receipt.binding,
                receipt_digest: receipt.receipt_digest,
            },
        );
    }

    fn assert_instance_tamper_rejected(
        kernel: &AuthorizationKernel,
        mutate: fn(&mut AuthorizationPermit),
    ) {
        let now = test_now();
        let (principal, resource, transaction, mut permit) = instance_permit(kernel, now);
        mutate(&mut permit);
        assert_eq!(
            kernel.ensure_instance_current(&permit, &principal, &resource, &transaction),
            Err(AuthorizationError::InvalidPermit)
        );
    }

    fn assert_query_tamper_rejected(kernel: &AuthorizationKernel, mutate: fn(&mut QueryPermit)) {
        let now = test_now();
        let (principal, resource, snapshot, mut permit) = query_permit(kernel, now);
        mutate(&mut permit);
        assert_eq!(
            kernel.ensure_query_current(&permit, &principal, &resource, &snapshot),
            Err(AuthorizationError::InvalidPermit)
        );
    }

    #[test]
    fn implementation_only_registry_never_issues() {
        let now = test_now();
        let kernel = AuthorizationKernel::implementation_only(
            DeploymentProfile::Production,
            version(1),
            digest("policy"),
            version(1),
            digest("registry"),
            version(1),
            digest("maximum"),
        );
        let principal = principal(now, Action::RequestRead);
        let resource = resource(Action::RequestRead);
        let decision = kernel.decide(&principal, Action::RequestRead, &resource);
        assert_eq!(decision.status(), DecisionStatus::Deny);
        assert!(matches!(
            kernel.satisfy_obligations(&decision, &[]),
            Err(AuthorizationError::Denied)
        ));
    }

    #[test]
    fn only_individually_activated_actions_can_reach_policy() {
        let now = test_now();
        let kernel = kernel(DeploymentProfile::Test);

        for action in [
            Action::RequestApprove,
            Action::PlatformSettingsUpdate,
            Action::AgentHeartbeat,
        ] {
            let mut candidate = principal(now, action);
            if action == Action::AgentHeartbeat {
                candidate.actor_kind = ActorKind::Agent;
            }
            if matches!(
                action,
                Action::RequestApprove | Action::PlatformSettingsUpdate
            ) {
                candidate.assurance.level = AssuranceLevel::PhishingResistant;
            }
            let decision = kernel.decide(&candidate, action, &resource(action));
            assert_eq!(decision.status(), DecisionStatus::Deny);
            assert_eq!(decision.denial_reason, Some(DenialReason::RegistryNotReady));
        }
    }

    #[test]
    fn policy_scope_owner_assurance_and_lifecycle_all_narrow_read_authority() {
        let now = test_now();
        let kernel = kernel(DeploymentProfile::Test);
        let base_principal = principal(now, Action::RequestRead);
        let base_resource = resource(Action::RequestRead);
        assert_eq!(
            kernel
                .decide(&base_principal, Action::RequestRead, &base_resource)
                .status(),
            DecisionStatus::AllowPending
        );

        let mut no_role = base_principal.clone();
        no_role.policy_roles.clear();
        assert_eq!(
            kernel
                .decide(&no_role, Action::RequestRead, &base_resource)
                .denial_reason,
            Some(DenialReason::ActionNotGranted)
        );

        let mut wrong_scope = base_resource.clone();
        wrong_scope.site_id = Some("site:other".into());
        assert_eq!(
            kernel
                .decide(&base_principal, Action::RequestRead, &wrong_scope)
                .denial_reason,
            Some(DenialReason::ScopeMismatch)
        );

        let mut wrong_owner = base_resource.clone();
        wrong_owner.owner_principal_id = Some("principal:other".into());
        assert_eq!(
            kernel
                .decide(&base_principal, Action::RequestRead, &wrong_owner)
                .denial_reason,
            Some(DenialReason::OwnerMismatch)
        );
        let mut auditor = base_principal.clone();
        auditor.policy_roles = BTreeSet::from([PolicyRole::Auditor]);
        assert_eq!(
            kernel
                .decide(&auditor, Action::RequestRead, &wrong_owner)
                .status(),
            DecisionStatus::AllowPending
        );

        let mut weak = base_principal.clone();
        weak.assurance.level = AssuranceLevel::SingleFactor;
        let mut restricted = base_resource.clone();
        restricted.sensitivity = ResourceSensitivity::Restricted;
        assert_eq!(
            kernel
                .decide(&weak, Action::RequestRead, &restricted)
                .denial_reason,
            Some(DenialReason::InsufficientAssurance)
        );

        for lifecycle in [
            ResourceLifecycle::Quarantined,
            ResourceLifecycle::Revoked,
            ResourceLifecycle::Unknown,
        ] {
            let mut unavailable = base_resource.clone();
            unavailable.lifecycle_state = lifecycle;
            assert_eq!(
                kernel
                    .decide(&base_principal, Action::RequestRead, &unavailable)
                    .denial_reason,
                Some(DenialReason::ResourceUnavailable)
            );
        }
        let mut terminal = base_resource;
        terminal.lifecycle_state = ResourceLifecycle::Terminal;
        assert_eq!(
            kernel
                .decide(&base_principal, Action::RequestRead, &terminal)
                .status(),
            DecisionStatus::AllowPending
        );
    }

    #[test]
    fn pending_and_bad_receipts_cannot_mint() {
        let now = test_now();
        let kernel = kernel(DeploymentProfile::Test);
        let principal = principal(now, Action::RequestRead);
        let resource = resource(Action::RequestRead);
        let decision = kernel.decide(&principal, Action::RequestRead, &resource);
        assert_eq!(decision.status(), DecisionStatus::AllowPending);
        assert!(matches!(
            kernel.satisfy_obligations(&decision, &[]),
            Err(AuthorizationError::UnsatisfiedObligations)
        ));

        let mut bad = receipts(&kernel, &decision);
        bad[0].binding.credential_version = version(999);
        assert!(matches!(
            kernel.satisfy_obligations(&decision, &bad),
            Err(AuthorizationError::InvalidObligationReceipt)
        ));

        let receipt = kernel.issue_test_receipt(&decision, ObligationKind::Audit);
        assert!(matches!(
            kernel.satisfy_obligations(&decision, &[receipt.clone(), receipt]),
            Err(AuthorizationError::InvalidObligationReceipt)
        ));
    }

    #[test]
    fn authenticated_typed_receipts_reject_semantically_invalid_evidence() {
        let now = test_now();
        let kernel = kernel_with_actions(
            DeploymentProfile::Test,
            BTreeSet::from([Action::RequestApprove]),
        );
        let mut approving_principal = principal(now, Action::RequestApprove);
        approving_principal.assurance.level = AssuranceLevel::PhishingResistant;
        let decision = kernel.decide(
            &approving_principal,
            Action::RequestApprove,
            &resource(Action::RequestApprove),
        );
        assert_eq!(decision.status(), DecisionStatus::AllowPending);
        assert!(
            kernel
                .satisfy_obligations(&decision, &receipts(&kernel, &decision))
                .is_ok()
        );

        let mut invalid = receipts(&kernel, &decision);
        let step_up = invalid
            .iter_mut()
            .find(|receipt| receipt.binding.kind == ObligationKind::StepUp)
            .expect("step-up receipt exists");
        step_up.binding.evidence = ObligationEvidence::StepUp {
            ceremony_id: Uuid::new_v4(),
            assurance: AssuranceLevel::SingleFactor,
        };
        resign_receipt(&kernel, step_up);
        assert_eq!(
            kernel.satisfy_obligations(&decision, &invalid).err(),
            Some(AuthorizationError::InvalidObligationReceipt)
        );

        let mut invalid = receipts(&kernel, &decision);
        let maker_checker = invalid
            .iter_mut()
            .find(|receipt| receipt.binding.kind == ObligationKind::MakerChecker)
            .expect("maker/checker receipt exists");
        maker_checker.binding.evidence = ObligationEvidence::MakerChecker {
            checker_principal_id: approving_principal.actor.principal_id.clone(),
            approval_version: version(2),
        };
        resign_receipt(&kernel, maker_checker);
        assert_eq!(
            kernel.satisfy_obligations(&decision, &invalid).err(),
            Some(AuthorizationError::InvalidObligationReceipt)
        );

        let mut invalid = receipts(&kernel, &decision);
        let audit = invalid
            .iter_mut()
            .find(|receipt| receipt.binding.kind == ObligationKind::Audit)
            .expect("audit receipt exists");
        audit.binding.issuer.kind = ObligationIssuerKind::StepUpVerifier;
        resign_receipt(&kernel, audit);
        assert_eq!(
            kernel.satisfy_obligations(&decision, &invalid).err(),
            Some(AuthorizationError::InvalidObligationReceipt)
        );
    }

    #[test]
    fn development_fixture_never_aliases_a_production_actor() {
        let now = test_now();
        let kernel = kernel(DeploymentProfile::Production);
        let mut principal = principal(now, Action::RequestRead);
        principal.actor_kind = ActorKind::DevelopmentFixture;
        let resource = resource(Action::RequestRead);
        assert_eq!(
            kernel
                .decide(&principal, Action::RequestRead, &resource)
                .status(),
            DecisionStatus::Deny
        );
    }

    #[test]
    fn delegation_is_disabled_by_default() {
        let now = test_now();
        let kernel = kernel(DeploymentProfile::Test);
        let mut principal = principal(now, Action::RequestRead);
        principal.delegation = DelegationBinding::Chain {
            chain_digest: digest("delegation"),
            authority_version: version(2),
            expires_at: now + Duration::minutes(1),
        };
        let resource = resource(Action::RequestRead);
        assert_eq!(
            kernel
                .decide(&principal, Action::RequestRead, &resource)
                .status(),
            DecisionStatus::Deny
        );
    }

    #[test]
    fn disabled_delegation_requires_actor_and_effective_subject_to_match_exactly() {
        let now = test_now();
        let kernel = kernel(DeploymentProfile::Test);
        let mut substituted = principal(now, Action::RequestRead);
        substituted.effective_subject.principal_id = "principal:substituted".into();
        let mut target = resource(Action::RequestRead);
        target.owner_principal_id = Some("principal:substituted".into());

        let decision = kernel.decide(&substituted, Action::RequestRead, &target);
        assert_eq!(decision.status(), DecisionStatus::Deny);
        assert_eq!(
            decision.denial_reason,
            Some(DenialReason::EffectiveSubjectMismatch)
        );
    }

    #[test]
    fn instance_permit_rejects_every_current_binding_change() {
        let now = test_now();
        let kernel = kernel(DeploymentProfile::Test);
        let (principal, resource, transaction, permit) = instance_permit(&kernel, now);
        kernel
            .ensure_instance_current(&permit, &principal, &resource, &transaction)
            .unwrap();

        let mut changed_principal = principal.clone();
        changed_principal.actor.authority_version = version(100);
        assert_eq!(
            kernel.ensure_instance_current(&permit, &changed_principal, &resource, &transaction,),
            Err(AuthorizationError::StaleBinding)
        );

        let mut changed_resource = resource.clone();
        changed_resource.resource_version = version(23);
        assert_eq!(
            kernel.ensure_instance_current(&permit, &principal, &changed_resource, &transaction,),
            Err(AuthorizationError::StaleBinding)
        );

        let foreign_transaction = TransactionContext::for_test(now + Duration::minutes(5));
        assert_eq!(
            kernel.ensure_instance_current(&permit, &principal, &resource, &foreign_transaction,),
            Err(AuthorizationError::TransactionMismatch)
        );
    }

    #[test]
    fn hmac_rejects_ac_040_style_permit_tampering() {
        let kernel = kernel(DeploymentProfile::Test);
        let mutations: &[fn(&mut AuthorizationPermit)] = &[
            |permit| permit.binding.decision.action = Action::RequestApprove,
            |permit| permit.binding.decision.semantics = AuthorizationSemantics::Global,
            |permit| permit.binding.decision.principal.actor_kind = ActorKind::Service,
            |permit| {
                permit.binding.decision.principal.actor.principal_id = "principal:other".into()
            },
            |permit| permit.binding.decision.principal.actor.lifecycle_version = version(30),
            |permit| permit.binding.decision.principal.actor.authority_version = version(90),
            |permit| {
                permit
                    .binding
                    .decision
                    .principal
                    .effective_subject
                    .principal_id = "principal:effective:other".into()
            },
            |permit| {
                permit
                    .binding
                    .decision
                    .principal
                    .effective_subject
                    .lifecycle_version = version(40)
            },
            |permit| {
                permit
                    .binding
                    .decision
                    .principal
                    .effective_subject
                    .authority_version = version(100)
            },
            |permit| permit.binding.decision.principal.deployment_id = "deployment:other".into(),
            |permit| {
                permit.binding.decision.principal.trust_domain_id = "trust-domain:other".into()
            },
            |permit| permit.binding.decision.principal.tenant_id = Some("tenant:other".into()),
            |permit| {
                permit.binding.decision.principal.credential.credential_id =
                    "credential:other".into()
            },
            |permit| {
                permit
                    .binding
                    .decision
                    .principal
                    .credential
                    .credential_version = version(80)
            },
            |permit| {
                permit.binding.decision.principal.credential.provider_id = "provider:other".into()
            },
            |permit| {
                permit
                    .binding
                    .decision
                    .principal
                    .credential
                    .provider_configuration_version = version(60)
            },
            |permit| {
                permit
                    .binding
                    .decision
                    .principal
                    .credential
                    .provider_lifecycle_version = version(120)
            },
            |permit| {
                permit.binding.decision.principal.credential.expires_at += Duration::seconds(1)
            },
            |permit| {
                permit.binding.decision.principal.assurance.level = AssuranceLevel::SingleFactor
            },
            |permit| {
                permit.binding.decision.principal.assurance.audience_digest =
                    digest("audience:other")
            },
            |permit| {
                permit.binding.decision.principal.assurance.key_id_digest = digest("key:other")
            },
            |permit| {
                permit.binding.decision.principal.assurance.authenticated_at += Duration::seconds(1)
            },
            |permit| permit.binding.decision.principal.assurance.expires_at += Duration::seconds(1),
            |permit| permit.binding.decision.principal.site_scope = ExplicitScope::global(),
            |permit| permit.binding.decision.principal.environment_scope = ExplicitScope::global(),
            |permit| {
                permit
                    .binding
                    .decision
                    .principal
                    .policy_roles
                    .insert(PolicyRole::Auditor);
            },
            |permit| permit.binding.decision.principal.expires_at += Duration::seconds(1),
            |permit| {
                permit.binding.decision.principal.delegation = DelegationBinding::Chain {
                    chain_digest: digest("delegation:other"),
                    authority_version: version(2),
                    expires_at: test_now() + Duration::minutes(1),
                }
            },
            |permit| permit.binding.decision.resource.kind = ResourceKind::AuditLog,
            |permit| permit.binding.decision.resource.canonical_id = "request:other".into(),
            |permit| permit.binding.decision.resource.deployment_id = "deployment:other".into(),
            |permit| permit.binding.decision.resource.trust_domain_id = "trust-domain:other".into(),
            |permit| permit.binding.decision.resource.tenant_id = Some("tenant:other".into()),
            |permit| permit.binding.decision.resource.site_id = Some("site:other".into()),
            |permit| permit.binding.decision.resource.environment_id = Some("env:other".into()),
            |permit| {
                permit.binding.decision.resource.owner_principal_id = Some("principal:other".into())
            },
            |permit| permit.binding.decision.resource.resource_version = version(23),
            |permit| permit.binding.decision.resource.sensitivity = ResourceSensitivity::Restricted,
            |permit| permit.binding.decision.resource.lifecycle_state = ResourceLifecycle::Terminal,
            |permit| permit.binding.decision.required_obligations.clear(),
            |permit| permit.binding.decision.expires_at += Duration::seconds(1),
            |permit| permit.binding.decision.kernel.kernel_instance_id = Uuid::new_v4(),
            |permit| permit.binding.decision.kernel.policy_version = version(999),
            |permit| permit.binding.decision.kernel.policy_digest = digest("policy:other"),
            |permit| permit.binding.decision.kernel.action_registry_version = version(999),
            |permit| {
                permit.binding.decision.kernel.action_registry_digest = digest("registry:other")
            },
            |permit| permit.binding.decision.kernel.maximum_authority_version = version(999),
            |permit| {
                permit.binding.decision.kernel.maximum_authority_digest = digest("maximum:other")
            },
            |permit| permit.binding.decision_digest = digest("decision:other"),
            |permit| permit.binding.receipt_digests.clear(),
            |permit| permit.transaction.nonce = Uuid::new_v4(),
            |permit| permit.transaction.expires_at += Duration::seconds(1),
            |permit| permit.expires_at += Duration::seconds(1),
            |permit| permit.seal[0] ^= 1,
        ];

        for mutation in mutations {
            assert_instance_tamper_rejected(&kernel, *mutation);
        }
    }

    #[test]
    fn foreign_kernel_and_expiry_fail_closed() {
        let now = test_now();
        let mut primary = kernel(DeploymentProfile::Test);
        let foreign = kernel(DeploymentProfile::Test);
        let (principal, resource, transaction, permit) = instance_permit(&primary, now);
        assert_eq!(
            foreign.ensure_instance_current(&permit, &principal, &resource, &transaction),
            Err(AuthorizationError::InvalidPermit)
        );
        primary.clock = ClockSource::Fixed(now + Duration::minutes(2));
        assert_eq!(
            primary.ensure_instance_current(&permit, &principal, &resource, &transaction),
            Err(AuthorizationError::Expired)
        );
    }

    #[test]
    fn query_permit_rejects_scope_limit_offset_and_snapshot_widening() {
        let now = test_now();
        let kernel = kernel(DeploymentProfile::Test);
        let (principal, resource, snapshot, permit) = query_permit(&kernel, now);
        kernel
            .ensure_query_current(&permit, &principal, &resource, &snapshot)
            .unwrap();

        let foreign_snapshot = SnapshotContext::for_test(version(33), now + Duration::minutes(5));
        assert_eq!(
            kernel.ensure_query_current(&permit, &principal, &resource, &foreign_snapshot),
            Err(AuthorizationError::SnapshotMismatch)
        );

        let (_, _, _, mut permit) = query_permit(&kernel, now);
        permit.plan.limit = 201;
        assert_eq!(
            kernel.ensure_query_current(&permit, &principal, &resource, &snapshot),
            Err(AuthorizationError::InvalidPermit)
        );

        let (_, _, _, mut permit) = query_permit(&kernel, now);
        permit
            .plan
            .filters
            .insert("site_id".into(), "site:other".into());
        assert_eq!(
            kernel.ensure_query_current(&permit, &principal, &resource, &snapshot),
            Err(AuthorizationError::InvalidPermit)
        );
    }

    #[test]
    fn query_permit_seal_covers_scope_predicate_paging_ceilings_and_snapshot() {
        let kernel = kernel(DeploymentProfile::Test);
        let mutations: &[fn(&mut QueryPermit)] = &[
            |permit| permit.snapshot.nonce = Uuid::new_v4(),
            |permit| permit.snapshot.authority_version = version(34),
            |permit| permit.snapshot.expires_at += Duration::seconds(1),
            |permit| permit.plan.predicate_digest = digest("predicate:other"),
            |permit| permit.plan.scope.site_scope = ExplicitScope::global(),
            |permit| permit.plan.scope.environment_scope = ExplicitScope::global(),
            |permit| {
                permit
                    .plan
                    .filters
                    .insert("environment_id".into(), "env:prod".into());
            },
            |permit| permit.plan.limit += 1,
            |permit| permit.plan.offset += 1,
            |permit| permit.plan.maximum_limit += 1,
            |permit| permit.plan.maximum_offset += 1,
            |permit| permit.expires_at += Duration::seconds(1),
            |permit| permit.seal[0] ^= 1,
        ];

        for mutation in mutations {
            assert_query_tamper_rejected(&kernel, *mutation);
        }
    }

    #[test]
    fn permit_domains_and_kernel_owned_lifetime_are_not_interchangeable() {
        let now = test_now();
        let kernel = kernel(DeploymentProfile::Test);
        let (principal, resource, transaction, mut instance) = instance_permit(&kernel, now);
        let (_, _, _, query) = query_permit(&kernel, now);

        assert_eq!(
            instance.expires_at(),
            now + Duration::seconds(MAX_PERMIT_LIFETIME_SECONDS)
        );
        assert_eq!(
            query.expires_at(),
            now + Duration::seconds(MAX_PERMIT_LIFETIME_SECONDS)
        );

        instance.seal = query.seal;
        assert_eq!(
            kernel.ensure_instance_current(&instance, &principal, &resource, &transaction),
            Err(AuthorizationError::InvalidPermit)
        );
    }

    #[test]
    fn query_issuance_rejects_widened_requests() {
        let now = test_now();
        let kernel = kernel(DeploymentProfile::Test);
        let principal = principal(now, Action::AuditRead);
        let resource = resource(Action::AuditRead);
        let decision = kernel.decide(&principal, Action::AuditRead, &resource);
        let satisfied = kernel
            .satisfy_obligations(&decision, &receipts(&kernel, &decision))
            .unwrap();
        let requested = RequestedQuery::new(
            BTreeMap::from([("site_id".into(), "site:other".into())]),
            50,
            0,
        )
        .unwrap();
        let snapshot = SnapshotContext::for_test(version(33), now + Duration::minutes(5));
        assert!(matches!(
            kernel.authorize_query(satisfied, requested, &snapshot),
            Err(AuthorizationError::QueryWouldWidenAuthority)
        ));
    }

    #[test]
    fn empty_query_filters_still_carry_every_principal_scope_axis() {
        let now = test_now();
        let kernel = kernel(DeploymentProfile::Test);
        let principal = principal(now, Action::AuditRead);
        let resource = resource(Action::AuditRead);
        let decision = kernel.decide(&principal, Action::AuditRead, &resource);
        let satisfied = kernel
            .satisfy_obligations(&decision, &receipts(&kernel, &decision))
            .unwrap();
        let snapshot = SnapshotContext::for_test(version(33), now + Duration::minutes(5));
        let requested = RequestedQuery::new(BTreeMap::new(), 50, 0).unwrap();
        let permit = kernel
            .authorize_query(satisfied, requested, &snapshot)
            .unwrap();

        assert!(permit.filters().is_empty());
        assert_eq!(
            permit.scope().site_scope().values(),
            Some(&BTreeSet::from(["site:one".to_string()]))
        );
        assert_eq!(
            permit.scope().environment_scope().values(),
            Some(&BTreeSet::from(["env:prod".to_string()]))
        );
    }

    #[test]
    fn debug_output_is_value_free() {
        let now = test_now();
        let kernel = kernel(DeploymentProfile::Test);
        let (principal, resource, transaction, permit) = instance_permit(&kernel, now);
        let debug = format!("{kernel:?} {principal:?} {resource:?} {transaction:?} {permit:?}");
        for forbidden in [
            "principal:actor",
            "principal:subject",
            "credential:one",
            "provider:one",
            "request:one",
            "site:one",
            "env:prod",
        ] {
            assert!(!debug.contains(forbidden), "debug leaked {forbidden}");
        }
    }
}
