//! Bounded admission for persisted-session database lookups.
//!
//! A syntactically valid `rys_` bearer is intentionally opaque, so a random
//! value cannot be rejected without consulting PostgreSQL. This module keeps
//! that unavoidable miss path outside the application's whole-request concurrency
//! layer and bounds it with three process-local controls:
//! - a short, bounded cache of database-confirmed misses;
//! - a bounded cache of recently confirmed live verifiers so real sessions do
//!   not compete with random misses for admission;
//! - a fixed-window budget plus a non-queueing semaphore for new verifiers.
//!
//! Only the keyed, fixed-width verifier and canonical non-secret origin digest
//! are retained. Plaintext session bearers are never stored, logged, or used
//! as cache keys. A positive entry is only
//! admission evidence: every request still performs the exact principal/key/link
//! version and lifecycle SQL check before it is authenticated.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::extract::{MatchedPath, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use ryuki_core::config::AuthMode;
use ryuki_core::security_profile::ProviderLifecycleState;
use ryuki_core::types::ApiError;
use ryuki_core::PrincipalId;
use sqlx::PgPool;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

use crate::session_credentials::SESSION_VERIFIER_LEN;

pub(crate) type SessionVerifier = [u8; SESSION_VERIFIER_LEN];

/// Repository-local, immutable projection of the active security-limit profile
/// for persisted-session lookup admission. Keeping every selected value and
/// derivation input here prevents runtime code, prewarm, readback, and metrics
/// from quietly acquiring different limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SessionLookupSecurityLimitProfile {
    version: &'static str,
    positive_cache_capacity: usize,
    negative_cache_capacity: usize,
    positive_cache_max_ttl_secs: u64,
    negative_cache_ttl_secs: u64,
    miss_window_secs: u64,
    reserved_pool_connections: u32,
    unknown_slots_min: usize,
    unknown_slots_max: usize,
    miss_budget_per_slot: usize,
    miss_budget_floor: usize,
    miss_budget_ceiling: usize,
    prewarm_lookahead_rows: usize,
    uninitialized_pool_max_connections: u32,
    failure_status: StatusCode,
    failure_code: &'static str,
    failure_message: &'static str,
    failure_queueing: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResolvedSessionLookupLimits {
    positive_cache_capacity: usize,
    negative_cache_capacity: usize,
    positive_cache_max_ttl: Duration,
    negative_cache_ttl: Duration,
    miss_window: Duration,
    unknown_slots: usize,
    miss_budget: usize,
    prewarm_lookahead_rows: usize,
}

impl SessionLookupSecurityLimitProfile {
    fn resolve(self, max_connections: u32) -> ResolvedSessionLookupLimits {
        // Preserve at least one connection for authenticated/control-plane work
        // whenever the configured pool has more than one connection.
        let unknown_slots = max_connections
            .saturating_sub(self.reserved_pool_connections)
            .clamp(self.unknown_slots_min as u32, self.unknown_slots_max as u32)
            as usize;
        let miss_budget = unknown_slots
            .saturating_mul(self.miss_budget_per_slot)
            .max(self.miss_budget_floor)
            .min(self.miss_budget_ceiling);
        ResolvedSessionLookupLimits {
            positive_cache_capacity: self.positive_cache_capacity,
            negative_cache_capacity: self.negative_cache_capacity,
            positive_cache_max_ttl: Duration::from_secs(self.positive_cache_max_ttl_secs),
            negative_cache_ttl: Duration::from_secs(self.negative_cache_ttl_secs),
            miss_window: Duration::from_secs(self.miss_window_secs),
            unknown_slots,
            miss_budget,
            prewarm_lookahead_rows: self.prewarm_lookahead_rows,
        }
    }
}

const ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE: SessionLookupSecurityLimitProfile =
    SessionLookupSecurityLimitProfile {
        version: "session-lookup-v1",
        positive_cache_capacity: 65_536,
        negative_cache_capacity: 4_096,
        // Positive entries are only admission hints and every request still
        // performs the SQL authority/version join. Keep this short as a second
        // bound for an out-of-process authority change that cannot
        // synchronously evict this replica.
        positive_cache_max_ttl_secs: 30,
        negative_cache_ttl_secs: 30,
        miss_window_secs: 1,
        reserved_pool_connections: 1,
        unknown_slots_min: 1,
        unknown_slots_max: 8,
        miss_budget_per_slot: 8,
        miss_budget_floor: 16,
        miss_budget_ceiling: 64,
        prewarm_lookahead_rows: 1,
        // Production initializes the singleton explicitly. This value owns the
        // deterministic fallback used only by direct resolver tests or an early
        // in-process caller.
        uninitialized_pool_max_connections: 8,
        failure_status: StatusCode::TOO_MANY_REQUESTS,
        failure_code: "SESSION_LOOKUP_ADMISSION_EXCEEDED",
        failure_message: "Too many session verification requests",
        failure_queueing: false,
    };

const _: () = {
    assert!(ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE.positive_cache_capacity > 0);
    assert!(ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE.negative_cache_capacity > 0);
    assert!(ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE.positive_cache_max_ttl_secs > 0);
    assert!(ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE.negative_cache_ttl_secs > 0);
    assert!(ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE.miss_window_secs > 0);
    assert!(ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE.reserved_pool_connections > 0);
    assert!(ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE.unknown_slots_min > 0);
    assert!(
        ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE.unknown_slots_min
            <= ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE.unknown_slots_max
    );
    assert!(ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE.unknown_slots_max <= u32::MAX as usize);
    assert!(ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE.miss_budget_per_slot > 0);
    assert!(ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE.miss_budget_floor > 0);
    assert!(
        ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE.miss_budget_floor
            <= ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE.miss_budget_ceiling
    );
    assert!(ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE.prewarm_lookahead_rows > 0);
    assert!(ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE.uninitialized_pool_max_connections > 0);
    assert!(!ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE.failure_queueing);
};

/// Authenticated, value-only readback of the selected per-replica limits. It
/// intentionally excludes cache occupancy, loaded prewarm row counts, verifier
/// cardinality, and every credential-derived value.
pub(crate) fn security_limit_readback(max_connections: u32) -> serde_json::Value {
    let profile = ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE;
    let resolved = profile.resolve(max_connections);
    serde_json::json!({
        "profile_version": profile.version,
        "scope": "replica",
        "source": "repository-immutable",
        "positive_cache": {
            "capacity": resolved.positive_cache_capacity,
            "max_ttl_secs": resolved.positive_cache_max_ttl.as_secs(),
            "prewarm_truncation_lookahead_rows": resolved.prewarm_lookahead_rows,
        },
        "negative_cache": {
            "capacity": resolved.negative_cache_capacity,
            "ttl_secs": resolved.negative_cache_ttl.as_secs(),
        },
        "unknown_lookup": {
            "reserved_pool_connections_when_possible": profile.reserved_pool_connections,
            "slots_min": profile.unknown_slots_min,
            "slots_max": profile.unknown_slots_max,
            "selected_slots": resolved.unknown_slots,
            "miss_budget_per_slot": profile.miss_budget_per_slot,
            "miss_budget_floor": profile.miss_budget_floor,
            "miss_budget_ceiling": profile.miss_budget_ceiling,
            "selected_miss_budget": resolved.miss_budget,
            "miss_window_secs": resolved.miss_window.as_secs(),
        },
        "failure": {
            "status": profile.failure_status.as_u16(),
            "code": profile.failure_code,
            "message": profile.failure_message,
            "queueing": profile.failure_queueing,
            "retry_after_secs": profile.miss_window_secs,
        },
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SessionLookupAdmissionProof {
    verifier: SessionVerifier,
    origin_partition: SessionLookupOriginPartition,
    authority: Option<SessionAuthorityCacheBinding>,
}

/// Closed process-local namespace for persisted-session admission.
///
/// Browser sessions are partitioned by the exact canonical origin digest
/// retained by the live authenticator runtime. Local sessions occupy their
/// own NULL-origin namespace, while `Disabled` can cache only misses and can
/// never become a positive session authority.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum SessionLookupOriginPartition {
    Local,
    Browser([u8; 32]),
    Disabled,
}

/// Opaque lookup authority derived only from the retained authenticator
/// runtime. The browser variant retains the exact sealed origin allocation so
/// SQL admission and cache partitioning cannot be assembled independently.
pub(crate) struct SessionLookupOriginAuthority {
    partition: SessionLookupOriginPartition,
    browser_origin: Option<Arc<crate::authenticator_runtime::VerifiedBrowserAuthenticatorOrigin>>,
    browser_binding: Option<BrowserOriginDatabaseBinding>,
}

#[derive(Clone)]
pub(crate) struct BrowserOriginDatabaseBinding {
    origin: Arc<crate::authenticator_runtime::VerifiedBrowserAuthenticatorOrigin>,
    origin_binding_digest: [u8; 32],
    deployment_id: String,
    trust_domain_id: String,
    tenant_id: Option<String>,
    provider_id: String,
    provider_configuration_version: i64,
    provider_configuration_payload_digest: [u8; 32],
    provider_lifecycle_record_version: i64,
    binding_document_id: String,
    binding_document_version: i64,
    binding_document_digest: [u8; 32],
    binding_document_locator: String,
    provider_policy_binding_digest: [u8; 32],
    runtime_binding_digest: [u8; 32],
    path_id: String,
    path_version: i64,
    path_kind: &'static str,
}

impl BrowserOriginDatabaseBinding {
    fn same_values(&self, other: &Self) -> bool {
        self.origin_binding_digest == other.origin_binding_digest
            && self.deployment_id == other.deployment_id
            && self.trust_domain_id == other.trust_domain_id
            && self.tenant_id == other.tenant_id
            && self.provider_id == other.provider_id
            && self.provider_configuration_version == other.provider_configuration_version
            && self.provider_configuration_payload_digest
                == other.provider_configuration_payload_digest
            && self.provider_lifecycle_record_version == other.provider_lifecycle_record_version
            && self.binding_document_id == other.binding_document_id
            && self.binding_document_version == other.binding_document_version
            && self.binding_document_digest == other.binding_document_digest
            && self.binding_document_locator == other.binding_document_locator
            && self.provider_policy_binding_digest == other.provider_policy_binding_digest
            && self.runtime_binding_digest == other.runtime_binding_digest
            && self.path_id == other.path_id
            && self.path_version == other.path_version
            && self.path_kind == other.path_kind
    }

    pub(crate) fn verify_integrity(&self) -> bool {
        self.origin.verify_integrity().is_ok()
            && browser_database_binding(&self.origin)
                .is_ok_and(|remeasured| self.same_values(&remeasured))
    }

    pub(crate) fn origin_binding_digest(&self) -> &[u8; 32] {
        &self.origin_binding_digest
    }

    pub(crate) fn deployment_id(&self) -> &str {
        &self.deployment_id
    }

    pub(crate) fn trust_domain_id(&self) -> &str {
        &self.trust_domain_id
    }

    pub(crate) fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }

    pub(crate) fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub(crate) fn provider_configuration_version(&self) -> i64 {
        self.provider_configuration_version
    }

    pub(crate) fn provider_configuration_payload_digest(&self) -> &[u8; 32] {
        &self.provider_configuration_payload_digest
    }

    pub(crate) fn provider_lifecycle_record_version(&self) -> i64 {
        self.provider_lifecycle_record_version
    }

    pub(crate) fn binding_document_id(&self) -> &str {
        &self.binding_document_id
    }

    pub(crate) fn binding_document_version(&self) -> i64 {
        self.binding_document_version
    }

    pub(crate) fn binding_document_digest(&self) -> &[u8; 32] {
        &self.binding_document_digest
    }

    pub(crate) fn binding_document_locator(&self) -> &str {
        &self.binding_document_locator
    }

    pub(crate) fn provider_policy_binding_digest(&self) -> &[u8; 32] {
        &self.provider_policy_binding_digest
    }

    pub(crate) fn runtime_binding_digest(&self) -> &[u8; 32] {
        &self.runtime_binding_digest
    }

    pub(crate) fn path_id(&self) -> &str {
        &self.path_id
    }

    pub(crate) fn path_version(&self) -> i64 {
        self.path_version
    }

    pub(crate) fn path_kind(&self) -> &'static str {
        self.path_kind
    }
}

impl PartialEq for BrowserOriginDatabaseBinding {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.origin, &other.origin) && self.same_values(other)
    }
}

impl Eq for BrowserOriginDatabaseBinding {}

fn decode_canonical_sha256(value: &str) -> Result<[u8; 32], &'static str> {
    let encoded = value
        .strip_prefix("sha256:")
        .ok_or("origin contains a non-canonical digest")?;
    if encoded.len() != 64
        || encoded
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err("origin contains a non-canonical digest");
    }
    let mut digest = [0_u8; 32];
    hex::decode_to_slice(encoded, &mut digest)
        .map_err(|_| "origin contains a non-canonical digest")?;
    if digest == [0; 32] {
        return Err("origin contains a zero digest");
    }
    Ok(digest)
}

fn database_version(value: u64) -> Result<i64, &'static str> {
    i64::try_from(value).map_err(|_| "origin version exceeds the database range")
}

fn browser_database_binding(
    origin: &Arc<crate::authenticator_runtime::VerifiedBrowserAuthenticatorOrigin>,
) -> Result<BrowserOriginDatabaseBinding, &'static str> {
    origin
        .verify_integrity()
        .map_err(|_| "browser authenticator origin integrity failed")?;
    let projection = origin.origin_projection();
    if projection.provider_lifecycle_state != ProviderLifecycleState::Active
        || projection.provider_id != origin.provider_id()
        || projection.path_id != origin.path_id()
        || projection.path_version != origin.path_version()
    {
        return Err("browser authenticator origin accessors disagree");
    }
    let origin_binding_digest = *origin.origin_binding_digest_bytes();
    if origin_binding_digest == [0; 32] {
        return Err("browser authenticator origin digest is zero");
    }
    Ok(BrowserOriginDatabaseBinding {
        origin: Arc::clone(origin),
        origin_binding_digest,
        deployment_id: projection.deployment_id.clone(),
        trust_domain_id: projection.trust_domain_id.clone(),
        tenant_id: projection.tenant_id.clone(),
        provider_id: projection.provider_id.clone(),
        provider_configuration_version: database_version(
            projection.provider_configuration_version,
        )?,
        provider_configuration_payload_digest: decode_canonical_sha256(
            &projection.provider_configuration_payload_digest,
        )?,
        provider_lifecycle_record_version: database_version(
            projection.provider_lifecycle_record_version,
        )?,
        binding_document_id: projection.binding_document_reference.document_id.clone(),
        binding_document_version: database_version(
            projection.binding_document_reference.document_version,
        )?,
        binding_document_digest: decode_canonical_sha256(
            &projection.binding_document_reference.content_digest,
        )?,
        binding_document_locator: projection
            .binding_document_reference
            .artifact_locator
            .clone(),
        provider_policy_binding_digest: decode_canonical_sha256(
            &projection.provider_policy_binding_digest,
        )?,
        runtime_binding_digest: decode_canonical_sha256(&projection.runtime_binding_digest)?,
        path_id: projection.path_id.clone(),
        path_version: database_version(projection.path_version)?,
        path_kind: origin.path_kind(),
    })
}

impl SessionLookupOriginAuthority {
    pub(crate) fn from_runtime(
        runtime: &Arc<crate::authenticator_runtime::ApiAuthenticatorRuntime>,
    ) -> Result<Self, &'static str> {
        let browser_origin = runtime.browser_authenticator_origin();
        if !runtime.retains_browser_authenticator_origin(&browser_origin) {
            return Err("authenticator runtime did not retain its browser origin");
        }
        match (runtime.auth_mode(), browser_origin) {
            (AuthMode::Local, None) => Ok(Self {
                partition: SessionLookupOriginPartition::Local,
                browser_origin: None,
                browser_binding: None,
            }),
            (AuthMode::EntraId, Some(origin)) => {
                let binding = browser_database_binding(&origin)?;
                Ok(Self {
                    partition: SessionLookupOriginPartition::Browser(binding.origin_binding_digest),
                    browser_origin: Some(origin),
                    browser_binding: Some(binding),
                })
            }
            (AuthMode::EntraId, None) | (AuthMode::MockDryRun | AuthMode::StaticDryRun, None) => {
                Ok(Self {
                    partition: SessionLookupOriginPartition::Disabled,
                    browser_origin: None,
                    browser_binding: None,
                })
            }
            _ => Err("authenticator mode and browser origin disagree"),
        }
    }

    #[cfg(test)]
    fn local_fixture() -> Self {
        Self {
            partition: SessionLookupOriginPartition::Local,
            browser_origin: None,
            browser_binding: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test_auth_mode(auth_mode: &AuthMode) -> Self {
        match auth_mode {
            AuthMode::Local => Self::local_fixture(),
            AuthMode::MockDryRun | AuthMode::StaticDryRun | AuthMode::EntraId => Self {
                partition: SessionLookupOriginPartition::Disabled,
                browser_origin: None,
                browser_binding: None,
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn browser_fixture(label: &str) -> Self {
        let origin =
            crate::authenticator_runtime::VerifiedBrowserAuthenticatorOrigin::fixture(label);
        let binding = browser_database_binding(&origin)
            .expect("browser-origin fixture must produce an exact database binding");
        Self {
            partition: SessionLookupOriginPartition::Browser(binding.origin_binding_digest),
            browser_origin: Some(origin),
            browser_binding: Some(binding),
        }
    }

    pub(crate) fn is_local(&self) -> bool {
        self.partition == SessionLookupOriginPartition::Local
    }

    pub(crate) fn permits_persisted_sessions(&self) -> bool {
        !matches!(self.partition, SessionLookupOriginPartition::Disabled)
    }

    pub(crate) fn origin_binding_digest(&self) -> Option<&[u8; 32]> {
        match &self.partition {
            SessionLookupOriginPartition::Browser(digest) => Some(digest),
            SessionLookupOriginPartition::Local | SessionLookupOriginPartition::Disabled => None,
        }
    }

    pub(crate) fn browser_binding(&self) -> Option<&BrowserOriginDatabaseBinding> {
        match (&self.browser_origin, &self.browser_binding) {
            (Some(origin), Some(binding))
                if origin.origin_binding_digest_bytes() == &binding.origin_binding_digest
                    && Arc::ptr_eq(origin, &binding.origin)
                    && binding.verify_integrity() =>
            {
                Some(binding)
            }
            (None, None) => None,
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct SessionLookupCacheKey {
    verifier: SessionVerifier,
    origin_partition: SessionLookupOriginPartition,
}

impl SessionLookupCacheKey {
    fn new(verifier: SessionVerifier, origin: &SessionLookupOriginAuthority) -> Self {
        Self {
            verifier,
            origin_partition: origin.partition,
        }
    }

    #[cfg(test)]
    fn local(verifier: SessionVerifier) -> Self {
        Self {
            verifier,
            origin_partition: SessionLookupOriginPartition::Local,
        }
    }
}

/// Exact, provider-independent authority captured by a persisted session.
///
/// A cache hit is only an admission hint. The resolver must still compare
/// every identifier and version with a database row joined to an active
/// principal, key, and link. Provider subjects and their fingerprints are
/// deliberately absent: neither is a principal authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SessionAuthorityCacheBinding {
    pub principal_id: PrincipalId,
    pub principal_lifecycle_version: i64,
    pub principal_authority_version: i64,
    pub principal_key_id: Uuid,
    pub principal_key_version: i64,
    pub principal_link_id: Uuid,
    pub principal_link_version: i64,
}

impl SessionAuthorityCacheBinding {
    /// Reject impossible or legacy/sentinel bindings before they can become a
    /// positive cache hint. Database lifecycle states are revalidated by the
    /// resolver; only exact positive versions can participate in comparison.
    fn is_well_formed(self) -> bool {
        self.principal_lifecycle_version > 0
            && self.principal_authority_version > 0
            && self.principal_key_version > 0
            && self.principal_link_version > 0
            && !self.principal_key_id.is_nil()
            && !self.principal_link_id.is_nil()
    }
}

#[derive(Clone, Copy)]
struct PositiveEntry {
    expires_at: Instant,
    generation: u64,
    authority: SessionAuthorityCacheBinding,
}

#[derive(Clone, Copy)]
struct NegativeEntry {
    expires_at: Instant,
    generation: u64,
    confirmed_absent: bool,
}

struct AdmissionInner {
    positive: HashMap<SessionLookupCacheKey, PositiveEntry>,
    positive_order: VecDeque<(SessionLookupCacheKey, u64)>,
    negative: HashMap<SessionLookupCacheKey, NegativeEntry>,
    negative_order: VecDeque<(SessionLookupCacheKey, u64)>,
    in_flight: HashSet<SessionLookupCacheKey>,
    window_started_at: Instant,
    window_used: usize,
    generation: u64,
}

impl AdmissionInner {
    fn next_generation(&mut self) -> u64 {
        self.generation = self.generation.wrapping_add(1);
        self.generation
    }

    fn prune_expired(&mut self, now: Instant) {
        while let Some((key, generation)) = self.positive_order.front().copied() {
            let expired = self
                .positive
                .get(&key)
                .is_none_or(|entry| entry.generation != generation || entry.expires_at <= now);
            if !expired {
                break;
            }
            self.positive_order.pop_front();
            if self
                .positive
                .get(&key)
                .is_some_and(|entry| entry.generation == generation && entry.expires_at <= now)
            {
                self.positive.remove(&key);
            }
        }
        while let Some((key, generation)) = self.negative_order.front().copied() {
            let expired = self
                .negative
                .get(&key)
                .is_none_or(|entry| entry.generation != generation || entry.expires_at <= now);
            if !expired {
                break;
            }
            self.negative_order.pop_front();
            if self
                .negative
                .get(&key)
                .is_some_and(|entry| entry.generation == generation && entry.expires_at <= now)
            {
                self.negative.remove(&key);
            }
        }
    }

    fn trim_positive(&mut self, capacity: usize) {
        while self.positive_order.len() > capacity {
            let Some((key, generation)) = self.positive_order.pop_front() else {
                break;
            };
            if self
                .positive
                .get(&key)
                .is_some_and(|entry| entry.generation == generation)
            {
                self.positive.remove(&key);
            }
        }
    }

    fn trim_negative(&mut self, capacity: usize) {
        while self.negative_order.len() > capacity {
            let Some((key, generation)) = self.negative_order.pop_front() else {
                break;
            };
            if self
                .negative
                .get(&key)
                .is_some_and(|entry| entry.generation == generation)
            {
                self.negative.remove(&key);
            }
        }
    }
}

fn saturating_add(counter: &AtomicU64, amount: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(amount))
    });
}

fn saturating_increment(counter: &AtomicU64) {
    saturating_add(counter, 1);
}

#[derive(Default)]
struct SessionLookupTelemetry {
    known_positive: AtomicU64,
    cached_miss: AtomicU64,
    admitted_unknown: AtomicU64,
    rejected_duplicate_in_flight: AtomicU64,
    rejected_capacity: AtomicU64,
    rejected_budget: AtomicU64,
    database_row: AtomicU64,
    database_miss: AtomicU64,
    database_error: AtomicU64,
    database_cancelled: AtomicU64,
    database_duration_micros: AtomicU64,
    prewarm_truncated: AtomicBool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SessionLookupTelemetrySnapshot {
    known_positive: u64,
    cached_miss: u64,
    admitted_unknown: u64,
    rejected_duplicate_in_flight: u64,
    rejected_capacity: u64,
    rejected_budget: u64,
    database_row: u64,
    database_miss: u64,
    database_error: u64,
    database_cancelled: u64,
    database_duration_micros: u64,
    prewarm_truncated: bool,
}

impl SessionLookupTelemetry {
    fn snapshot(&self) -> SessionLookupTelemetrySnapshot {
        SessionLookupTelemetrySnapshot {
            known_positive: self.known_positive.load(Ordering::Relaxed),
            cached_miss: self.cached_miss.load(Ordering::Relaxed),
            admitted_unknown: self.admitted_unknown.load(Ordering::Relaxed),
            rejected_duplicate_in_flight: self.rejected_duplicate_in_flight.load(Ordering::Relaxed),
            rejected_capacity: self.rejected_capacity.load(Ordering::Relaxed),
            rejected_budget: self.rejected_budget.load(Ordering::Relaxed),
            database_row: self.database_row.load(Ordering::Relaxed),
            database_miss: self.database_miss.load(Ordering::Relaxed),
            database_error: self.database_error.load(Ordering::Relaxed),
            database_cancelled: self.database_cancelled.load(Ordering::Relaxed),
            database_duration_micros: self.database_duration_micros.load(Ordering::Relaxed),
            prewarm_truncated: self.prewarm_truncated.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionDatabaseLookupOutcome {
    Row,
    Miss,
    Error,
    Cancelled,
}

/// Cancellation-safe database observation. The outer request-timeout layer may
/// drop an in-flight resolver future before SQLx returns, so `Drop` records a
/// fixed-cardinality `cancelled` outcome unless the caller explicitly finishes
/// it with the database result.
pub(crate) struct SessionDatabaseLookupObservation {
    admission: Arc<SessionLookupAdmission>,
    started_at: Instant,
    finished: bool,
}

impl SessionDatabaseLookupObservation {
    pub(crate) fn finish(mut self, outcome: SessionDatabaseLookupOutcome) {
        debug_assert_ne!(outcome, SessionDatabaseLookupOutcome::Cancelled);
        self.admission
            .record_database_lookup(outcome, self.started_at.elapsed());
        self.finished = true;
    }
}

impl Drop for SessionDatabaseLookupObservation {
    fn drop(&mut self) {
        if !self.finished {
            self.admission.record_database_lookup(
                SessionDatabaseLookupOutcome::Cancelled,
                self.started_at.elapsed(),
            );
            self.finished = true;
        }
    }
}

/// Process-local session lookup admission. All collections have explicit hard
/// bounds; lock poisoning is recovered so one panic cannot permanently disable
/// authentication.
pub(crate) struct SessionLookupAdmission {
    inner: Mutex<AdmissionInner>,
    unknown_slots: Arc<Semaphore>,
    unknown_slots_capacity: usize,
    positive_capacity: usize,
    negative_capacity: usize,
    positive_max_ttl: Duration,
    miss_budget: usize,
    miss_window: Duration,
    negative_ttl: Duration,
    prewarm_lookahead_rows: usize,
    db_lookup_count: AtomicU64,
    telemetry: SessionLookupTelemetry,
}

pub(crate) enum SessionLookupDecision {
    /// `None` means the outer middleware admitted a first lookup and supplied
    /// a verifier-only proof; `Some` is an exact cached principal binding.
    KnownPositive(Option<SessionAuthorityCacheBinding>),
    CachedMiss,
    Unknown(SessionLookupGuard),
    Rejected(SessionLookupRejection),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionLookupRejection {
    DuplicateInFlight,
    Capacity,
    Budget,
}

/// Owns the non-queueing unknown-lookup slot until the outer middleware has
/// received a response (or the direct resolver's database call completes).
pub(crate) struct SessionLookupGuard {
    admission: Arc<SessionLookupAdmission>,
    key: SessionLookupCacheKey,
    _permit: OwnedSemaphorePermit,
}

impl Drop for SessionLookupGuard {
    fn drop(&mut self) {
        let mut inner = self
            .admission
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        inner.in_flight.remove(&self.key);
    }
}

impl SessionLookupAdmission {
    fn new(limits: ResolvedSessionLookupLimits) -> Arc<Self> {
        let positive_capacity = limits.positive_cache_capacity;
        let negative_capacity = limits.negative_cache_capacity;
        let unknown_slots = limits.unknown_slots;
        let miss_budget = limits.miss_budget;
        Arc::new(Self {
            inner: Mutex::new(AdmissionInner {
                positive: HashMap::with_capacity(positive_capacity),
                positive_order: VecDeque::with_capacity(positive_capacity),
                negative: HashMap::with_capacity(negative_capacity),
                negative_order: VecDeque::with_capacity(negative_capacity),
                in_flight: HashSet::with_capacity(unknown_slots),
                window_started_at: Instant::now(),
                window_used: 0,
                generation: 0,
            }),
            unknown_slots: Arc::new(Semaphore::new(unknown_slots)),
            unknown_slots_capacity: unknown_slots,
            positive_capacity,
            negative_capacity,
            positive_max_ttl: limits.positive_cache_max_ttl,
            miss_budget,
            miss_window: limits.miss_window,
            negative_ttl: limits.negative_cache_ttl,
            prewarm_lookahead_rows: limits.prewarm_lookahead_rows,
            db_lookup_count: AtomicU64::new(0),
            telemetry: SessionLookupTelemetry::default(),
        })
    }

    pub(crate) fn for_pool(max_connections: u32) -> Arc<Self> {
        Self::new(ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE.resolve(max_connections))
    }

    #[cfg(test)]
    pub(crate) fn for_tests(
        positive_capacity: usize,
        negative_capacity: usize,
        unknown_slots: usize,
        miss_budget: usize,
    ) -> Arc<Self> {
        let production = ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE
            .resolve(ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE.uninitialized_pool_max_connections);
        Self::new(ResolvedSessionLookupLimits {
            positive_cache_capacity: positive_capacity,
            negative_cache_capacity: negative_capacity,
            positive_cache_max_ttl: production.positive_cache_max_ttl,
            negative_cache_ttl: production.negative_cache_ttl,
            miss_window: production.miss_window,
            unknown_slots,
            miss_budget,
            prewarm_lookahead_rows: production.prewarm_lookahead_rows,
        })
    }

    #[cfg(test)]
    pub(crate) fn try_admit(self: &Arc<Self>, verifier: SessionVerifier) -> SessionLookupDecision {
        self.try_admit_key(
            SessionLookupCacheKey::local(verifier),
            Instant::now(),
            false,
        )
    }

    pub(crate) fn try_admit_for_origin(
        self: &Arc<Self>,
        verifier: SessionVerifier,
        origin: &SessionLookupOriginAuthority,
    ) -> SessionLookupDecision {
        self.try_admit_key(
            SessionLookupCacheKey::new(verifier, origin),
            Instant::now(),
            false,
        )
    }

    /// Logout must distinguish "not currently authenticating" from
    /// "durably absent". An authority/mode join miss may still have a session
    /// row that must be deleted, so only a post-commit absence entry is reused.
    #[cfg(test)]
    pub(crate) fn try_admit_revocation(
        self: &Arc<Self>,
        verifier: SessionVerifier,
    ) -> SessionLookupDecision {
        self.try_admit_key(SessionLookupCacheKey::local(verifier), Instant::now(), true)
    }

    pub(crate) fn try_admit_revocation_for_origin(
        self: &Arc<Self>,
        verifier: SessionVerifier,
        origin: &SessionLookupOriginAuthority,
    ) -> SessionLookupDecision {
        self.try_admit_key(
            SessionLookupCacheKey::new(verifier, origin),
            Instant::now(),
            true,
        )
    }

    fn try_admit_key(
        self: &Arc<Self>,
        key: SessionLookupCacheKey,
        now: Instant,
        require_confirmed_absence: bool,
    ) -> SessionLookupDecision {
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        inner.prune_expired(now);

        if inner
            .positive
            .get(&key)
            .is_some_and(|entry| entry.expires_at > now && entry.authority.is_well_formed())
        {
            saturating_increment(&self.telemetry.known_positive);
            return SessionLookupDecision::KnownPositive(Some(inner.positive[&key].authority));
        }
        inner.positive.remove(&key);
        let negative = inner.negative.get(&key).copied();
        if let Some(entry) = negative.filter(|entry| entry.expires_at > now) {
            if !require_confirmed_absence || entry.confirmed_absent {
                saturating_increment(&self.telemetry.cached_miss);
                return SessionLookupDecision::CachedMiss;
            }
        }
        if negative.is_some() {
            inner.negative.remove(&key);
        }
        if inner.in_flight.contains(&key) {
            saturating_increment(&self.telemetry.rejected_duplicate_in_flight);
            return SessionLookupDecision::Rejected(SessionLookupRejection::DuplicateInFlight);
        }
        if now.saturating_duration_since(inner.window_started_at) >= self.miss_window {
            inner.window_started_at = now;
            inner.window_used = 0;
        }
        if inner.window_used >= self.miss_budget {
            saturating_increment(&self.telemetry.rejected_budget);
            return SessionLookupDecision::Rejected(SessionLookupRejection::Budget);
        }
        let permit = match Arc::clone(&self.unknown_slots).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                saturating_increment(&self.telemetry.rejected_capacity);
                return SessionLookupDecision::Rejected(SessionLookupRejection::Capacity);
            }
        };
        inner.window_used += 1;
        inner.in_flight.insert(key);
        drop(inner);
        saturating_increment(&self.telemetry.admitted_unknown);

        SessionLookupDecision::Unknown(SessionLookupGuard {
            admission: Arc::clone(self),
            key,
            _permit: permit,
        })
    }

    pub(crate) fn admit_for_resolver(
        self: &Arc<Self>,
        verifier: SessionVerifier,
        origin: &SessionLookupOriginAuthority,
        proof: Option<SessionLookupAdmissionProof>,
    ) -> SessionLookupDecision {
        if let Some(proof) = proof.filter(|proof| {
            proof.verifier == verifier
                && proof.origin_partition == origin.partition
                && proof
                    .authority
                    .is_none_or(SessionAuthorityCacheBinding::is_well_formed)
        }) {
            SessionLookupDecision::KnownPositive(proof.authority)
        } else {
            self.try_admit_for_origin(verifier, origin)
        }
    }

    #[cfg(test)]
    pub(crate) fn record_hit(
        &self,
        verifier: SessionVerifier,
        valid_for: Duration,
        authority: SessionAuthorityCacheBinding,
    ) {
        self.record_hit_key(SessionLookupCacheKey::local(verifier), valid_for, authority);
    }

    pub(crate) fn record_hit_for_origin(
        &self,
        verifier: SessionVerifier,
        origin: &SessionLookupOriginAuthority,
        valid_for: Duration,
        authority: SessionAuthorityCacheBinding,
    ) {
        self.record_hit_key(
            SessionLookupCacheKey::new(verifier, origin),
            valid_for,
            authority,
        );
    }

    fn record_hit_key(
        &self,
        key: SessionLookupCacheKey,
        valid_for: Duration,
        authority: SessionAuthorityCacheBinding,
    ) {
        if !authority.is_well_formed() {
            self.record_negative_key(key, false);
            return;
        }
        if matches!(key.origin_partition, SessionLookupOriginPartition::Disabled) {
            self.record_negative_key(key, false);
            return;
        }
        let now = Instant::now();
        let valid_for = valid_for.min(self.positive_max_ttl);
        if valid_for.is_zero() {
            self.record_negative_key(key, false);
            return;
        }
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        inner.prune_expired(now);
        inner.negative.remove(&key);
        let generation = inner.next_generation();
        inner.positive.insert(
            key,
            PositiveEntry {
                expires_at: now + valid_for,
                generation,
                authority,
            },
        );
        inner.positive_order.push_back((key, generation));
        inner.trim_positive(self.positive_capacity);
    }

    #[cfg(test)]
    pub(crate) fn record_miss(&self, verifier: SessionVerifier) {
        self.record_negative_key(SessionLookupCacheKey::local(verifier), false);
    }

    pub(crate) fn record_miss_for_origin(
        &self,
        verifier: SessionVerifier,
        origin: &SessionLookupOriginAuthority,
    ) {
        self.record_negative_key(SessionLookupCacheKey::new(verifier, origin), false);
    }

    #[cfg(test)]
    pub(crate) fn record_confirmed_absence(&self, verifier: SessionVerifier) {
        self.record_negative_key(SessionLookupCacheKey::local(verifier), true);
    }

    pub(crate) fn record_confirmed_absence_for_origin(
        &self,
        verifier: SessionVerifier,
        origin: &SessionLookupOriginAuthority,
    ) {
        self.record_negative_key(SessionLookupCacheKey::new(verifier, origin), true);
    }

    #[cfg(test)]
    pub(crate) fn evict_principal(&self, principal_id: PrincipalId) {
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        inner
            .positive
            .retain(|_, entry| entry.authority.principal_id != principal_id);
        // Stale queue nodes are pruned lazily and remain capacity-bounded.
    }

    pub(crate) fn evict_binding(&self, authority: SessionAuthorityCacheBinding) {
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        inner
            .positive
            .retain(|_, entry| entry.authority != authority);
        // Stale queue nodes are pruned lazily and remain capacity-bounded.
    }

    pub(crate) fn clear_positive(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        inner.positive.clear();
        inner.positive_order.clear();
    }

    fn record_negative_key(&self, key: SessionLookupCacheKey, confirmed_absent: bool) {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        inner.prune_expired(now);
        inner.positive.remove(&key);
        if let Some(existing) = inner.negative.get(&key) {
            if existing.expires_at > now && (existing.confirmed_absent || !confirmed_absent) {
                return;
            }
        }
        let generation = inner.next_generation();
        inner.negative.insert(
            key,
            NegativeEntry {
                expires_at: now + self.negative_ttl,
                generation,
                confirmed_absent,
            },
        );
        inner.negative_order.push_back((key, generation));
        inner.trim_negative(self.negative_capacity);
    }

    pub(crate) fn start_database_lookup(self: &Arc<Self>) -> SessionDatabaseLookupObservation {
        SessionDatabaseLookupObservation {
            admission: Arc::clone(self),
            started_at: Instant::now(),
            finished: false,
        }
    }

    fn record_database_lookup(&self, outcome: SessionDatabaseLookupOutcome, duration: Duration) {
        saturating_increment(&self.db_lookup_count);
        let outcome_counter = match outcome {
            SessionDatabaseLookupOutcome::Row => &self.telemetry.database_row,
            SessionDatabaseLookupOutcome::Miss => &self.telemetry.database_miss,
            SessionDatabaseLookupOutcome::Error => &self.telemetry.database_error,
            SessionDatabaseLookupOutcome::Cancelled => &self.telemetry.database_cancelled,
        };
        saturating_increment(outcome_counter);
        let elapsed_micros = u64::try_from(duration.as_micros()).unwrap_or(u64::MAX);
        saturating_add(&self.telemetry.database_duration_micros, elapsed_micros);
    }

    #[cfg(test)]
    fn observe_database_lookup_for_test(
        &self,
        outcome: SessionDatabaseLookupOutcome,
        duration: Duration,
    ) {
        self.record_database_lookup(outcome, duration);
    }

    fn append_metrics(&self, body: &mut String) {
        let telemetry = self.telemetry.snapshot();
        let database_duration_seconds = telemetry.database_duration_micros as f64 / 1_000_000.0;

        body.push_str(
            "# HELP ryuki_session_lookup_limit_profile Active persisted-session lookup limit profile\n\
             # TYPE ryuki_session_lookup_limit_profile gauge\n",
        );
        let _ = writeln!(
            body,
            "ryuki_session_lookup_limit_profile{{version=\"{}\",scope=\"replica\"}} 1",
            ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE.version
        );
        body.push_str(
            "# HELP ryuki_session_lookup_cache_capacity_entries Configured verifier-cache capacity, not current credential cardinality\n\
             # TYPE ryuki_session_lookup_cache_capacity_entries gauge\n",
        );
        let _ = writeln!(
            body,
            "ryuki_session_lookup_cache_capacity_entries{{cache=\"positive\"}} {}",
            self.positive_capacity
        );
        let _ = writeln!(
            body,
            "ryuki_session_lookup_cache_capacity_entries{{cache=\"negative\"}} {}",
            self.negative_capacity
        );
        body.push_str(
            "# HELP ryuki_session_lookup_cache_ttl_seconds Configured verifier-cache lifetime\n\
             # TYPE ryuki_session_lookup_cache_ttl_seconds gauge\n",
        );
        let _ = writeln!(
            body,
            "ryuki_session_lookup_cache_ttl_seconds{{cache=\"positive_max\"}} {}",
            self.positive_max_ttl.as_secs()
        );
        let _ = writeln!(
            body,
            "ryuki_session_lookup_cache_ttl_seconds{{cache=\"negative\"}} {}",
            self.negative_ttl.as_secs()
        );
        body.push_str(
            "# HELP ryuki_session_lookup_unknown_slots Configured non-queueing database lookup slots\n\
             # TYPE ryuki_session_lookup_unknown_slots gauge\n",
        );
        let _ = writeln!(
            body,
            "ryuki_session_lookup_unknown_slots {}",
            self.unknown_slots_capacity
        );
        body.push_str(
            "# HELP ryuki_session_lookup_miss_budget Configured new-verifier budget per window\n\
             # TYPE ryuki_session_lookup_miss_budget gauge\n",
        );
        let _ = writeln!(
            body,
            "ryuki_session_lookup_miss_budget {}",
            self.miss_budget
        );
        body.push_str(
            "# HELP ryuki_session_lookup_miss_window_seconds Configured new-verifier budget window\n\
             # TYPE ryuki_session_lookup_miss_window_seconds gauge\n",
        );
        let _ = writeln!(
            body,
            "ryuki_session_lookup_miss_window_seconds {}",
            self.miss_window.as_secs()
        );
        body.push_str(
            "# HELP ryuki_session_lookup_admission_decisions_total Persisted-session lookup admission decision invocations\n\
             # TYPE ryuki_session_lookup_admission_decisions_total counter\n",
        );
        for (decision, count) in [
            ("known_positive", telemetry.known_positive),
            ("cached_miss", telemetry.cached_miss),
            ("admitted_unknown", telemetry.admitted_unknown),
            (
                "rejected_duplicate_in_flight",
                telemetry.rejected_duplicate_in_flight,
            ),
            ("rejected_capacity", telemetry.rejected_capacity),
            ("rejected_budget", telemetry.rejected_budget),
        ] {
            let _ = writeln!(
                body,
                "ryuki_session_lookup_admission_decisions_total{{decision=\"{decision}\"}} {count}"
            );
        }
        body.push_str(
            "# HELP ryuki_session_lookup_database_lookups_total Persisted-session authority database lookup outcomes\n\
             # TYPE ryuki_session_lookup_database_lookups_total counter\n",
        );
        for (outcome, count) in [
            ("row", telemetry.database_row),
            ("miss", telemetry.database_miss),
            ("error", telemetry.database_error),
            ("cancelled", telemetry.database_cancelled),
        ] {
            let _ = writeln!(
                body,
                "ryuki_session_lookup_database_lookups_total{{outcome=\"{outcome}\"}} {count}"
            );
        }
        body.push_str(
            "# HELP ryuki_session_lookup_database_duration_seconds Persisted-session authority database lookup duration\n\
             # TYPE ryuki_session_lookup_database_duration_seconds summary\n",
        );
        let _ = writeln!(
            body,
            "ryuki_session_lookup_database_duration_seconds_count {}",
            self.db_lookup_count.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            body,
            "ryuki_session_lookup_database_duration_seconds_sum {database_duration_seconds:.6}"
        );
        body.push_str(
            "# HELP ryuki_session_lookup_prewarm_truncated Whether startup prewarm reached its configured capacity without exposing loaded-session count\n\
             # TYPE ryuki_session_lookup_prewarm_truncated gauge\n",
        );
        let _ = writeln!(
            body,
            "ryuki_session_lookup_prewarm_truncated {}",
            u8::from(telemetry.prewarm_truncated)
        );
    }

    #[cfg(test)]
    pub(crate) fn database_lookup_count(&self) -> u64 {
        self.db_lookup_count.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn cache_cardinality(&self) -> (usize, usize, usize, usize, usize) {
        let inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        (
            inner.positive.len(),
            inner.positive_order.len(),
            inner.negative.len(),
            inner.negative_order.len(),
            inner.in_flight.len(),
        )
    }
}

static GLOBAL_ADMISSION: OnceLock<Arc<SessionLookupAdmission>> = OnceLock::new();
static RETRY_AFTER_HEADER: OnceLock<HeaderValue> = OnceLock::new();

pub(crate) fn initialize_global(max_connections: u32) -> Arc<SessionLookupAdmission> {
    let admission = SessionLookupAdmission::for_pool(max_connections);
    match GLOBAL_ADMISSION.set(Arc::clone(&admission)) {
        Ok(()) => admission,
        Err(_) => global_admission(),
    }
}

pub(crate) fn global_admission() -> Arc<SessionLookupAdmission> {
    Arc::clone(GLOBAL_ADMISSION.get_or_init(|| {
        SessionLookupAdmission::for_pool(
            ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE.uninitialized_pool_max_connections,
        )
    }))
}

pub(crate) fn append_global_metrics(body: &mut String) {
    if let Some(admission) = GLOBAL_ADMISSION.get() {
        admission.append_metrics(body);
    }
}

fn verifier_from_slice(verifier: &[u8]) -> Option<SessionVerifier> {
    verifier.try_into().ok()
}

#[cfg(not(test))]
fn global_origin_authority() -> Result<SessionLookupOriginAuthority, &'static str> {
    let runtime = crate::config_store::get_api_authenticator_runtime();
    SessionLookupOriginAuthority::from_runtime(&runtime)
}

#[cfg(test)]
fn global_origin_authority() -> Result<SessionLookupOriginAuthority, &'static str> {
    Ok(SessionLookupOriginAuthority::local_fixture())
}

pub(crate) fn register_positive_global(
    verifier: &[u8],
    valid_for: Duration,
    authority: SessionAuthorityCacheBinding,
) {
    if let (Some(verifier), Ok(origin)) = (verifier_from_slice(verifier), global_origin_authority())
    {
        global_admission().record_hit_for_origin(verifier, &origin, valid_for, authority);
    }
}

pub(crate) fn clear_positive_global() {
    global_admission().clear_positive();
}

pub(crate) fn mark_negative_global(verifier: &[u8]) {
    if let (Some(verifier), Ok(origin)) = (verifier_from_slice(verifier), global_origin_authority())
    {
        global_admission().record_confirmed_absence_for_origin(verifier, &origin);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PrewarmReport {
    pub truncated: bool,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SessionLookupPrewarmError {
    #[error("persisted-session origin authority is invalid: {0}")]
    InvalidOrigin(&'static str),
    #[error("persisted-session prewarm database operation failed")]
    Database(#[from] sqlx::Error),
}

/// Bounded restart prewarm. Only sessions whose exact principal, key, and link
/// generations are still active are considered. Provider tombstones and any
/// mismatch against the retained browser origin's D/P/Q/R/path preimage fail
/// closed. The SQL reads one extra row solely to make capacity truncation
/// observable.
pub(crate) async fn prewarm(
    pool: &PgPool,
    runtime: &Arc<crate::authenticator_runtime::ApiAuthenticatorRuntime>,
) -> Result<PrewarmReport, SessionLookupPrewarmError> {
    let origin = SessionLookupOriginAuthority::from_runtime(runtime)
        .map_err(SessionLookupPrewarmError::InvalidOrigin)?;
    let admission = global_admission();
    let prewarm_limit = admission
        .positive_capacity
        .saturating_add(admission.prewarm_lookahead_rows);
    let browser = origin.browser_binding();
    let rows = sqlx::query_as::<_, (Vec<u8>, DateTime<Utc>, Uuid, i64, i64, Uuid, i64, Uuid, i64)>(
        "SELECT s.session_bearer_verifier_v3 AS bearer_verifier, \
                s.expires_at, s.principal_id, \
                s.principal_lifecycle_version, s.principal_authority_version, \
                s.principal_key_id, s.principal_key_version, \
                s.principal_link_id, s.principal_link_version \
         FROM sessions s \
         JOIN principals p \
           ON p.principal_id = s.principal_id \
          AND p.lifecycle_version = s.principal_lifecycle_version \
          AND p.authority_version = s.principal_authority_version \
         JOIN principal_keys k \
           ON k.principal_key_id = s.principal_key_id \
          AND k.key_version = s.principal_key_version \
         JOIN principal_links l \
           ON l.principal_link_id = s.principal_link_id \
          AND l.link_version = s.principal_link_version \
          AND l.principal_key_id = s.principal_key_id \
          AND l.principal_id = s.principal_id \
         LEFT JOIN authenticator_authority_generations registered_origin \
           ON registered_origin.authenticator_origin_binding_digest = \
              s.authenticator_origin_binding_digest \
         LEFT JOIN authenticator_authority_current_paths current_browser \
           ON current_browser.provider_id = registered_origin.provider_id \
          AND current_browser.path_kind = 'browser-derived-session' \
         WHERE s.expires_at > NOW() \
           AND p.principal_kind = 'human' \
           AND p.lifecycle_state = 'active' \
           AND k.key_state = 'active' \
           AND l.link_state = 'active' \
           AND NOT EXISTS ( \
             SELECT 1 FROM principal_provider_tombstones pt \
             WHERE pt.provider_id = k.provider_id \
           ) \
           AND ( \
             ($1 AND s.authenticator_origin_binding_digest IS NULL \
                 AND registered_origin.authenticator_origin_binding_digest IS NULL \
                 AND current_browser.current_origin_binding_digest IS NULL \
                 AND k.provider_id = 'local' AND k.issuer = $2) \
             OR ($3::BYTEA IS NOT NULL \
                 AND s.authenticator_origin_binding_digest = $3 \
                 AND registered_origin.authenticator_origin_binding_digest = $3 \
                 AND current_browser.path_status = 'active' \
                 AND current_browser.current_origin_binding_digest = $3 \
                 AND registered_origin.deployment_id = $4 \
                 AND registered_origin.trust_domain_id = $5 \
                 AND registered_origin.tenant_id IS NOT DISTINCT FROM $6 \
                 AND registered_origin.provider_id = $7 \
                 AND k.provider_id = registered_origin.provider_id \
                 AND registered_origin.provider_configuration_version = $8 \
                 AND registered_origin.provider_configuration_payload_digest = $9 \
                 AND registered_origin.provider_lifecycle_record_version = $10 \
                 AND registered_origin.provider_lifecycle_state = 'active' \
                 AND registered_origin.binding_document_id = $11 \
                 AND registered_origin.binding_document_version = $12 \
                 AND registered_origin.binding_document_digest = $13 \
                 AND registered_origin.binding_document_locator = $14 \
                 AND registered_origin.provider_policy_binding_digest = $15 \
                 AND registered_origin.runtime_binding_digest = $16 \
                 AND registered_origin.path_id = $17 \
                 AND registered_origin.path_version = $18 \
                 AND registered_origin.path_kind = $19) \
           ) \
         ORDER BY s.created_at DESC LIMIT $20",
    )
    .bind(origin.is_local())
    .bind(crate::identity_authority::LOCAL_ISSUER)
    .bind(browser.map(|binding| binding.origin_binding_digest.as_slice()))
    .bind(browser.map(|binding| binding.deployment_id.as_str()))
    .bind(browser.map(|binding| binding.trust_domain_id.as_str()))
    .bind(browser.and_then(|binding| binding.tenant_id.as_deref()))
    .bind(browser.map(|binding| binding.provider_id.as_str()))
    .bind(browser.map(|binding| binding.provider_configuration_version))
    .bind(browser.map(|binding| binding.provider_configuration_payload_digest.as_slice()))
    .bind(browser.map(|binding| binding.provider_lifecycle_record_version))
    .bind(browser.map(|binding| binding.binding_document_id.as_str()))
    .bind(browser.map(|binding| binding.binding_document_version))
    .bind(browser.map(|binding| binding.binding_document_digest.as_slice()))
    .bind(browser.map(|binding| binding.binding_document_locator.as_str()))
    .bind(browser.map(|binding| binding.provider_policy_binding_digest.as_slice()))
    .bind(browser.map(|binding| binding.runtime_binding_digest.as_slice()))
    .bind(browser.map(|binding| binding.path_id.as_str()))
    .bind(browser.map(|binding| binding.path_version))
    .bind(browser.map(|binding| binding.path_kind))
    .bind(i64::try_from(prewarm_limit).unwrap_or(i64::MAX))
    .fetch_all(pool)
    .await?;
    let truncated = rows.len() > admission.positive_capacity;
    admission
        .telemetry
        .prewarm_truncated
        .store(truncated, Ordering::Relaxed);
    let now = Utc::now();
    for (
        verifier,
        expires_at,
        principal_id,
        principal_lifecycle_version,
        principal_authority_version,
        principal_key_id,
        principal_key_version,
        principal_link_id,
        principal_link_version,
    ) in rows.into_iter().take(admission.positive_capacity)
    {
        let Some(verifier) = verifier_from_slice(&verifier) else {
            continue;
        };
        let Ok(valid_for) = (expires_at - now).to_std() else {
            continue;
        };
        let Ok(principal_id) = PrincipalId::from_uuid(principal_id) else {
            continue;
        };
        admission.record_hit_for_origin(
            verifier,
            &origin,
            valid_for,
            SessionAuthorityCacheBinding {
                principal_id,
                principal_lifecycle_version,
                principal_authority_version,
                principal_key_id,
                principal_key_version,
                principal_link_id,
                principal_link_version,
            },
        );
    }
    Ok(PrewarmReport { truncated })
}

fn is_logout_path(path: &str) -> bool {
    matches!(path, "/api/auth/logout" | "/api/auth/local/logout")
}

fn uses_human_session_middleware(request: &Request) -> bool {
    let Some(matched_path) = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
    else {
        // The outer fallback performs no authentication lookup. Skipping it is
        // important: arbitrary unknown paths must not consume miss admission.
        return false;
    };
    !matches!(matched_path, "/health" | "/ready")
        && !matched_path.starts_with("/api/agents/")
        && matched_path != "/api/integrations/{connection_id}/webhook"
}

fn lookup_capacity_response() -> Response {
    let profile = ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE;
    let mut response = (
        profile.failure_status,
        Json(ApiError::new(profile.failure_code, profile.failure_message)),
    )
        .into_response();
    let retry_after = RETRY_AFTER_HEADER
        .get_or_init(|| {
            ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE
                .miss_window_secs
                .to_string()
                .parse::<HeaderValue>()
                .expect("validated session lookup miss window is an HTTP header value")
        })
        .clone();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, retry_after);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Path-aware outer admission. `main` mounts this after (therefore outside)
/// the whole-app concurrency admission. `try_acquire_owned` never waits, so
/// random well-formed verifiers cannot occupy that budget.
pub(crate) struct SessionLookupAdmissionMiddlewareState {
    admission: Arc<SessionLookupAdmission>,
    authenticator_runtime: Arc<crate::authenticator_runtime::ApiAuthenticatorRuntime>,
}

impl SessionLookupAdmissionMiddlewareState {
    pub(crate) fn new(
        admission: Arc<SessionLookupAdmission>,
        authenticator_runtime: Arc<crate::authenticator_runtime::ApiAuthenticatorRuntime>,
    ) -> Arc<Self> {
        Arc::new(Self {
            admission,
            authenticator_runtime,
        })
    }

    pub(crate) fn retains_admission(&self, admission: &Arc<SessionLookupAdmission>) -> bool {
        Arc::ptr_eq(&self.admission, admission)
    }

    pub(crate) fn retains_authenticator_runtime(
        &self,
        runtime: &Arc<crate::authenticator_runtime::ApiAuthenticatorRuntime>,
    ) -> bool {
        Arc::ptr_eq(&self.authenticator_runtime, runtime)
    }
}

pub(crate) async fn session_lookup_admission_middleware(
    State(state): State<Arc<SessionLookupAdmissionMiddlewareState>>,
    mut request: Request,
    next: Next,
) -> Response {
    if !uses_human_session_middleware(&request) {
        return next.run(request).await;
    }

    if matches!(
        state.authenticator_runtime.auth_mode(),
        AuthMode::MockDryRun | AuthMode::StaticDryRun
    ) {
        return next.run(request).await;
    }
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let cookie_runtime = state.authenticator_runtime.api_cookie_runtime();
    let session_parser = cookie_runtime.session_lookup_admission_parser();
    let Some((Ok(bearer), _source)) =
        crate::session_credential_from_headers(request.headers(), auth_header, &session_parser)
    else {
        // Missing, malformed, conflicting, API-token, and JWT evidence cannot
        // reach the persisted-session SQL lookup from this branch.
        return next.run(request).await;
    };
    let session_credentials = state.authenticator_runtime.derived_session_credentials();
    let verifier = match session_credentials.verifier(bearer) {
        Ok(verifier) => verifier,
        Err(_) => return next.run(request).await,
    };
    let origin = match SessionLookupOriginAuthority::from_runtime(&state.authenticator_runtime) {
        Ok(origin) => origin,
        Err(_) => return lookup_capacity_response(),
    };

    let logout = is_logout_path(request.uri().path());
    let decision = if logout {
        state
            .admission
            .try_admit_revocation_for_origin(verifier, &origin)
    } else {
        state.admission.try_admit_for_origin(verifier, &origin)
    };
    match decision {
        SessionLookupDecision::KnownPositive(authority) => {
            request
                .extensions_mut()
                .insert(SessionLookupAdmissionProof {
                    verifier,
                    origin_partition: origin.partition,
                    authority,
                });
            next.run(request).await
        }
        SessionLookupDecision::Unknown(guard) => {
            request
                .extensions_mut()
                .insert(SessionLookupAdmissionProof {
                    verifier,
                    origin_partition: origin.partition,
                    authority: None,
                });
            let response = next.run(request).await;
            drop(guard);
            response
        }
        SessionLookupDecision::CachedMiss if logout => {
            crate::contracts::logout_cached_absence_response()
        }
        SessionLookupDecision::CachedMiss if crate::is_auth_exempt_path(request.uri().path()) => {
            // The inner resolver observes the same cache entry and performs no
            // SQL. Exempt login/bootstrap routes must remain reachable when a
            // browser happens to attach an expired cookie.
            next.run(request).await
        }
        SessionLookupDecision::CachedMiss => crate::auth_required_response(),
        SessionLookupDecision::Rejected(_reason) if logout => {
            crate::contracts::logout_admission_unavailable_response()
        }
        SessionLookupDecision::Rejected(_reason)
            if crate::is_auth_exempt_path(request.uri().path()) =>
        {
            // The resolver rechecks the non-queueing state, returns an
            // unverified session without SQL, and the route's explicit exempt
            // policy decides whether the handler may continue.
            next.run(request).await
        }
        SessionLookupDecision::Rejected(_reason) => lookup_capacity_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

    fn verifier(value: usize) -> SessionVerifier {
        let mut verifier = [0_u8; SESSION_VERIFIER_LEN];
        verifier[..std::mem::size_of::<usize>()].copy_from_slice(&value.to_be_bytes());
        verifier
    }

    fn authority(value: u8) -> SessionAuthorityCacheBinding {
        let offset = u128::from(value);
        SessionAuthorityCacheBinding {
            principal_id: PrincipalId::from_uuid(Uuid::from_u128(
                0x10000000_0000_4000_8000_000000000000 + offset,
            ))
            .expect("non-nil test principal"),
            principal_lifecycle_version: i64::from(value) + 1,
            principal_authority_version: i64::from(value) + 2,
            principal_key_id: Uuid::from_u128(0x20000000_0000_4000_8000_000000000000 + offset),
            principal_key_version: i64::from(value) + 3,
            principal_link_id: Uuid::from_u128(0x30000000_0000_4000_8000_000000000000 + offset),
            principal_link_version: i64::from(value) + 4,
        }
    }

    #[test]
    fn active_profile_resolves_pool_dependent_limits_without_new_literals() {
        let profile = ACTIVE_SESSION_LOOKUP_LIMIT_PROFILE;
        for (pool_connections, expected_slots, expected_budget) in [
            (1, 1, 16),
            (2, 1, 16),
            (5, 4, 32),
            (9, 8, 64),
            (u32::MAX, 8, 64),
        ] {
            let resolved = profile.resolve(pool_connections);
            assert_eq!(resolved.unknown_slots, expected_slots);
            assert_eq!(resolved.miss_budget, expected_budget);
            assert_eq!(resolved.positive_cache_capacity, 65_536);
            assert_eq!(resolved.negative_cache_capacity, 4_096);
            assert_eq!(resolved.positive_cache_max_ttl, Duration::from_secs(30));
            assert_eq!(resolved.negative_cache_ttl, Duration::from_secs(30));
            assert_eq!(resolved.miss_window, Duration::from_secs(1));
            assert_eq!(resolved.prewarm_lookahead_rows, 1);
        }

        let admission = SessionLookupAdmission::for_pool(5);
        assert_eq!(admission.positive_capacity, 65_536);
        assert_eq!(admission.negative_capacity, 4_096);
        assert_eq!(admission.positive_max_ttl, Duration::from_secs(30));
        assert_eq!(admission.negative_ttl, Duration::from_secs(30));
        assert_eq!(admission.miss_window, Duration::from_secs(1));
        assert_eq!(admission.unknown_slots_capacity, 4);
        assert_eq!(admission.miss_budget, 32);
        assert_eq!(admission.prewarm_lookahead_rows, 1);
    }

    #[test]
    fn authenticated_limit_readback_exposes_selected_values_not_credential_cardinality() {
        let readback = security_limit_readback(5);
        assert_eq!(
            readback["profile_version"].as_str(),
            Some("session-lookup-v1")
        );
        assert_eq!(readback["scope"].as_str(), Some("replica"));
        assert_eq!(
            readback["positive_cache"]["capacity"].as_u64(),
            Some(65_536)
        );
        assert_eq!(
            readback["positive_cache"]["max_ttl_secs"].as_u64(),
            Some(30)
        );
        assert_eq!(
            readback["positive_cache"]["prewarm_truncation_lookahead_rows"].as_u64(),
            Some(1)
        );
        assert_eq!(readback["negative_cache"]["capacity"].as_u64(), Some(4_096));
        assert_eq!(readback["negative_cache"]["ttl_secs"].as_u64(), Some(30));
        assert_eq!(
            readback["unknown_lookup"]["selected_slots"].as_u64(),
            Some(4)
        );
        assert_eq!(
            readback["unknown_lookup"]["selected_miss_budget"].as_u64(),
            Some(32)
        );
        assert_eq!(
            readback["unknown_lookup"]["miss_budget_ceiling"].as_u64(),
            Some(64)
        );
        assert_eq!(readback["failure"]["retry_after_secs"].as_u64(), Some(1));

        let projection = readback.to_string();
        for prohibited in [
            "verifier",
            "bearer",
            "positive_entries",
            "negative_entries",
            "cache_occupancy",
            "prewarm_loaded",
        ] {
            assert!(
                !projection.contains(prohibited),
                "readback leaked prohibited field {prohibited}: {projection}"
            );
        }
    }

    #[tokio::test]
    async fn rejection_response_exactly_matches_profile_readback() {
        let readback = security_limit_readback(5);
        let response = lookup_capacity_response();
        assert_eq!(
            u64::from(response.status().as_u16()),
            readback["failure"]["status"].as_u64().unwrap()
        );
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok()),
            readback["failure"]["retry_after_secs"].as_u64()
        );
        let body = axum::body::to_bytes(response.into_body(), 4_096)
            .await
            .expect("bounded rejection body");
        let body: ApiError = serde_json::from_slice(&body).expect("structured rejection body");
        assert_eq!(body.error, readback["failure"]["code"].as_str().unwrap());
        assert_eq!(
            body.message,
            readback["failure"]["message"].as_str().unwrap()
        );
        assert_eq!(readback["failure"]["queueing"].as_bool(), Some(false));
    }

    #[tokio::test]
    async fn cancelled_lookup_future_records_one_bounded_outcome() {
        let admission = SessionLookupAdmission::for_tests(4, 4, 1, 4);
        let task_admission = Arc::clone(&admission);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _observation = task_admission.start_database_lookup();
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx
            .await
            .expect("lookup observation must be live before cancellation");
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());

        let telemetry = admission.telemetry.snapshot();
        assert_eq!(admission.database_lookup_count(), 1);
        assert_eq!(telemetry.database_cancelled, 1);
        assert_eq!(telemetry.database_row, 0);
        assert_eq!(telemetry.database_miss, 0);
        assert_eq!(telemetry.database_error, 0);
        let mut metrics = String::new();
        admission.append_metrics(&mut metrics);
        assert!(metrics
            .contains("ryuki_session_lookup_database_lookups_total{outcome=\"cancelled\"} 1"));
        assert!(metrics.contains("ryuki_session_lookup_database_duration_seconds_count 1"));
    }

    #[test]
    fn operational_metrics_are_fixed_cardinality_and_value_free() {
        let admission = SessionLookupAdmission::for_tests(8, 8, 1, 3);
        admission.record_hit(verifier(1), Duration::from_secs(60), authority(1));
        assert!(matches!(
            admission.try_admit(verifier(1)),
            SessionLookupDecision::KnownPositive(_)
        ));
        admission.record_miss(verifier(2));
        assert!(matches!(
            admission.try_admit(verifier(2)),
            SessionLookupDecision::CachedMiss
        ));

        let held = admission.try_admit(verifier(3));
        assert!(matches!(held, SessionLookupDecision::Unknown(_)));
        assert!(matches!(
            admission.try_admit(verifier(3)),
            SessionLookupDecision::Rejected(SessionLookupRejection::DuplicateInFlight)
        ));
        assert!(matches!(
            admission.try_admit(verifier(4)),
            SessionLookupDecision::Rejected(SessionLookupRejection::Capacity)
        ));
        drop(held);
        let second = admission.try_admit(verifier(5));
        assert!(matches!(second, SessionLookupDecision::Unknown(_)));
        drop(second);
        let third = admission.try_admit(verifier(6));
        assert!(matches!(third, SessionLookupDecision::Unknown(_)));
        drop(third);
        assert!(matches!(
            admission.try_admit(verifier(7)),
            SessionLookupDecision::Rejected(SessionLookupRejection::Budget)
        ));

        admission.observe_database_lookup_for_test(
            SessionDatabaseLookupOutcome::Row,
            Duration::from_millis(2),
        );
        admission.observe_database_lookup_for_test(
            SessionDatabaseLookupOutcome::Miss,
            Duration::from_millis(3),
        );
        admission.observe_database_lookup_for_test(
            SessionDatabaseLookupOutcome::Error,
            Duration::from_millis(5),
        );
        let credential_marker = [0xab; SESSION_VERIFIER_LEN];
        admission.record_miss(credential_marker);

        let mut before = String::new();
        admission.append_metrics(&mut before);
        assert!(before.contains(
            "ryuki_session_lookup_admission_decisions_total{decision=\"known_positive\"} 1"
        ));
        assert!(before.contains(
            "ryuki_session_lookup_admission_decisions_total{decision=\"cached_miss\"} 1"
        ));
        assert!(before.contains(
            "ryuki_session_lookup_admission_decisions_total{decision=\"admitted_unknown\"} 3"
        ));
        assert!(before.contains(
            "ryuki_session_lookup_admission_decisions_total{decision=\"rejected_duplicate_in_flight\"} 1"
        ));
        assert!(before.contains(
            "ryuki_session_lookup_admission_decisions_total{decision=\"rejected_capacity\"} 1"
        ));
        assert!(before.contains(
            "ryuki_session_lookup_admission_decisions_total{decision=\"rejected_budget\"} 1"
        ));
        assert!(before.contains("ryuki_session_lookup_database_lookups_total{outcome=\"row\"} 1"));
        assert!(before.contains("ryuki_session_lookup_database_lookups_total{outcome=\"miss\"} 1"));
        assert!(before.contains("ryuki_session_lookup_database_lookups_total{outcome=\"error\"} 1"));
        assert!(
            before.contains("ryuki_session_lookup_database_lookups_total{outcome=\"cancelled\"} 0")
        );
        assert!(before.contains("ryuki_session_lookup_database_duration_seconds_count 3"));
        assert!(before.contains("ryuki_session_lookup_database_duration_seconds_sum 0.010000"));
        assert!(!before.contains(&format!("{credential_marker:?}")));
        for prohibited in [
            "positive_entries",
            "negative_entries",
            "cache_occupancy",
            "prewarm_loaded",
        ] {
            assert!(!before.contains(prohibited));
        }

        let data_series = |metrics: &str| {
            metrics
                .lines()
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .count()
        };
        let series_before = data_series(&before);
        for value in 1_000..2_000 {
            let decision = admission.try_admit(verifier(value));
            drop(decision);
        }
        let mut after = String::new();
        admission.append_metrics(&mut after);
        assert_eq!(data_series(&after), series_before);
    }

    #[test]
    fn positive_admission_is_partitioned_by_exact_browser_origin_digest() {
        let admission = SessionLookupAdmission::for_tests(8, 8, 2, 8);
        let origin_a = SessionLookupOriginAuthority::browser_fixture("origin-a");
        let origin_b = SessionLookupOriginAuthority::browser_fixture("origin-b");
        let verifier = verifier(41);
        admission.record_hit_for_origin(verifier, &origin_a, Duration::from_secs(60), authority(9));

        assert!(matches!(
            admission.try_admit_for_origin(verifier, &origin_a),
            SessionLookupDecision::KnownPositive(Some(_))
        ));
        assert!(matches!(
            admission.try_admit_for_origin(verifier, &origin_b),
            SessionLookupDecision::Unknown(_)
        ));
    }

    #[test]
    fn repeated_confirmed_miss_never_consumes_a_second_budget_slot() {
        let admission = SessionLookupAdmission::for_tests(4, 4, 1, 1);
        let candidate = verifier(1);
        let first = admission.try_admit(candidate);
        assert!(matches!(first, SessionLookupDecision::Unknown(_)));
        drop(first);
        admission.record_miss(candidate);
        assert!(matches!(
            admission.try_admit(candidate),
            SessionLookupDecision::CachedMiss
        ));
        assert!(matches!(
            admission.try_admit(verifier(2)),
            SessionLookupDecision::Rejected(SessionLookupRejection::Budget)
        ));
    }

    #[test]
    fn recently_valid_session_bypasses_exhausted_unknown_budget() {
        let admission = SessionLookupAdmission::for_tests(4, 4, 1, 1);
        let unknown = admission.try_admit(verifier(1));
        assert!(matches!(unknown, SessionLookupDecision::Unknown(_)));
        admission.record_hit(verifier(2), Duration::from_secs(60), authority(2));
        assert!(matches!(
            admission.try_admit(verifier(2)),
            SessionLookupDecision::KnownPositive(Some(binding)) if binding == authority(2)
        ));
        drop(unknown);
    }

    #[test]
    fn authentication_join_miss_does_not_masquerade_as_durable_logout_absence() {
        let admission = SessionLookupAdmission::for_tests(4, 4, 2, 4);
        let candidate = verifier(1);
        admission.record_miss(candidate);
        let revocation = admission.try_admit_revocation(candidate);
        assert!(matches!(revocation, SessionLookupDecision::Unknown(_)));
        drop(revocation);
        admission.record_confirmed_absence(candidate);
        assert!(matches!(
            admission.try_admit_revocation(candidate),
            SessionLookupDecision::CachedMiss
        ));
    }

    #[test]
    fn cache_maps_queues_and_in_flight_keys_remain_hard_bounded() {
        let admission = SessionLookupAdmission::for_tests(3, 2, 1, 64);
        for value in 0..32 {
            admission.record_hit(
                verifier(value),
                Duration::from_secs(60),
                authority(value as u8),
            );
            admission.record_miss(verifier(value + 100));
        }
        let decision = admission.try_admit(verifier(1_000));
        assert!(matches!(decision, SessionLookupDecision::Unknown(_)));
        let (positive, positive_order, negative, negative_order, in_flight) =
            admission.cache_cardinality();
        assert!(positive <= 3 && positive_order <= 3);
        assert!(negative <= 2 && negative_order <= 2);
        assert_eq!(in_flight, 1);
    }

    #[test]
    fn concurrent_unique_misses_never_exceed_nonqueueing_slots() {
        const WORKERS: usize = 16;
        const SLOTS: usize = 3;
        let admission = SessionLookupAdmission::for_tests(8, 8, SLOTS, WORKERS);
        let start = Arc::new(Barrier::new(WORKERS + 1));
        let finish = Arc::new(Barrier::new(WORKERS + 1));
        let admitted = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            for worker in 0..WORKERS {
                let admission = Arc::clone(&admission);
                let start = Arc::clone(&start);
                let finish = Arc::clone(&finish);
                let admitted = Arc::clone(&admitted);
                scope.spawn(move || {
                    start.wait();
                    let decision = admission.try_admit(verifier(worker));
                    if matches!(decision, SessionLookupDecision::Unknown(_)) {
                        admitted.fetch_add(1, Ordering::SeqCst);
                    }
                    finish.wait();
                    drop(decision);
                });
            }
            start.wait();
            finish.wait();
        });
        assert_eq!(admitted.load(Ordering::SeqCst), SLOTS);
    }

    #[test]
    fn exact_principal_binding_and_revocation_evict_cached_provenance() {
        let admission = SessionLookupAdmission::for_tests(4, 4, 1, 4);
        let candidate = verifier(9);
        admission.record_hit(candidate, Duration::from_secs(60), authority(9));
        assert!(matches!(
            admission.try_admit(candidate),
            SessionLookupDecision::KnownPositive(Some(binding))
                if binding == authority(9)
        ));
        admission.evict_principal(authority(9).principal_id);
        assert!(matches!(
            admission.try_admit(candidate),
            SessionLookupDecision::Unknown(_)
        ));
    }

    #[test]
    fn invalid_or_legacy_binding_never_becomes_a_positive_hint() {
        let baseline = authority(10);
        let mut invalid_bindings = Vec::new();
        for mutate in [
            |binding: &mut SessionAuthorityCacheBinding| binding.principal_lifecycle_version = 0,
            |binding: &mut SessionAuthorityCacheBinding| binding.principal_authority_version = -1,
            |binding: &mut SessionAuthorityCacheBinding| binding.principal_key_version = 0,
            |binding: &mut SessionAuthorityCacheBinding| binding.principal_link_version = -1,
            |binding: &mut SessionAuthorityCacheBinding| binding.principal_key_id = Uuid::nil(),
            |binding: &mut SessionAuthorityCacheBinding| binding.principal_link_id = Uuid::nil(),
        ] {
            let mut invalid = baseline;
            mutate(&mut invalid);
            invalid_bindings.push(invalid);
        }

        for (index, invalid) in invalid_bindings.into_iter().enumerate() {
            let admission = SessionLookupAdmission::for_tests(4, 4, 1, 4);
            let candidate = verifier(10 + index);
            admission.record_hit(candidate, Duration::from_secs(60), invalid);
            assert!(matches!(
                admission.try_admit(candidate),
                SessionLookupDecision::CachedMiss
            ));
        }
    }

    #[test]
    fn cache_binding_compares_every_id_and_generation() {
        let baseline = authority(11);
        let mut variants = Vec::new();

        let mut changed = baseline;
        changed.principal_id = authority(12).principal_id;
        variants.push(changed);
        let mut changed = baseline;
        changed.principal_lifecycle_version += 1;
        variants.push(changed);
        let mut changed = baseline;
        changed.principal_authority_version += 1;
        variants.push(changed);
        let mut changed = baseline;
        changed.principal_key_id = authority(12).principal_key_id;
        variants.push(changed);
        let mut changed = baseline;
        changed.principal_key_version += 1;
        variants.push(changed);
        let mut changed = baseline;
        changed.principal_link_id = authority(12).principal_link_id;
        variants.push(changed);
        let mut changed = baseline;
        changed.principal_link_version += 1;
        variants.push(changed);

        for (index, variant) in variants.into_iter().enumerate() {
            let admission = SessionLookupAdmission::for_tests(4, 4, 1, 4);
            let candidate = verifier(100 + index);
            admission.record_hit(candidate, Duration::from_secs(60), baseline);
            admission.evict_binding(variant);
            assert!(matches!(
                admission.try_admit(candidate),
                SessionLookupDecision::KnownPositive(Some(binding)) if binding == baseline
            ));
            admission.evict_binding(baseline);
            assert!(matches!(
                admission.try_admit(candidate),
                SessionLookupDecision::Unknown(_)
            ));
        }
    }

    #[test]
    fn production_admission_layer_remains_outside_global_concurrency_budget() {
        let main = include_str!("main.rs");
        let concurrency = main
            .rfind("GlobalConcurrencyAdmission::new(app_config.server.max_concurrent_connections)")
            .expect("whole-app concurrency layer");
        let admission = main
            .rfind("session_lookup_admission::session_lookup_admission_middleware")
            .expect("persisted-session admission layer");
        assert!(
            concurrency < admission,
            "Axum's later layer is outermost, so admission must be declared after concurrency"
        );
        assert!(
            include_str!("session_lookup_admission.rs").contains("try_acquire_owned()"),
            "unknown lookup admission must never await capacity"
        );
    }

    #[test]
    fn live_session_paths_require_the_durable_current_origin_pointer() {
        let main = include_str!("main.rs");
        let admission = include_str!("session_lookup_admission.rs");
        let request_authority = include_str!("request_authority.rs");
        let principal_registry = include_str!("principal_registry.rs");
        let migration =
            include_str!("../../../migrations/201_authenticator_runtime_provenance.sql");
        let current_paths = ["authenticator_authority_current", "_paths"].concat();
        let active_browser = ["current_browser.path_status", " = 'active'"].concat();
        let authority_reader = ["prepare_authority_", "reader(tx, principal).await?"].concat();
        let shared_advisory_lock = ["pg_advisory_xact_", "lock_shared"].concat();
        let provider_lock_key = ["principal_registry_provider_", "lock_key"].concat();

        assert!(main.contains(current_paths.as_str()));
        assert!(admission.contains(current_paths.as_str()));
        assert!(request_authority.matches(current_paths.as_str()).count() >= 2);
        assert!(main.contains(active_browser.as_str()));
        assert!(admission.contains(active_browser.as_str()));
        assert!(request_authority.contains(active_browser.as_str()));
        assert!(request_authority.matches(authority_reader.as_str()).count() >= 2);
        assert!(principal_registry.contains(shared_advisory_lock.as_str()));
        assert!(principal_registry.contains(provider_lock_key.as_str()));
        assert!(migration.contains(provider_lock_key.as_str()));

        let legacy_current = ["reconcile_current_browser_authenticator", "_origin"].concat();
        let legacy_disabled = ["reconcile_disabled_browser", "_authenticator"].concat();
        let atomic_runtime = ["reconcile_current_authenticator", "_runtime"].concat();
        assert!(!main.contains(legacy_current.as_str()));
        assert!(!main.contains(legacy_disabled.as_str()));
        assert!(main.contains(atomic_runtime.as_str()));
    }
}
