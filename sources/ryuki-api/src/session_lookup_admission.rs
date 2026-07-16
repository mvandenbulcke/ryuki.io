//! Bounded admission for persisted-session database lookups.
//!
//! A syntactically valid `rys_` bearer is intentionally opaque, so a random
//! value cannot be rejected without consulting PostgreSQL. This module keeps
//! that unavoidable miss path outside the application's queueing concurrency
//! layer and bounds it with three process-local controls:
//! - a short, bounded cache of database-confirmed misses;
//! - a bounded cache of recently confirmed live verifiers so real sessions do
//!   not compete with random misses for admission;
//! - a fixed-window budget plus a non-queueing semaphore for new verifiers.
//!
//! Only the keyed, fixed-width verifier is retained. Plaintext session bearers
//! are never stored, logged, or used as cache keys. A positive entry is only
//! admission evidence: every request still performs the authority-epoch SQL
//! check before it is authenticated.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::extract::{MatchedPath, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use ryuki_core::config::{AuthMode, RyukiConfig};
use ryuki_core::types::ApiError;
use sqlx::PgPool;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::session_credentials::SESSION_VERIFIER_LEN;

pub(crate) type SessionVerifier = [u8; SESSION_VERIFIER_LEN];

const POSITIVE_CAPACITY: usize = 65_536;
const NEGATIVE_CAPACITY: usize = 4_096;
// Positive entries are only admission hints and every request still performs
// the SQL authority/version join. Keep this short as a second bound for an
// out-of-process assignment change that cannot synchronously evict this replica.
const POSITIVE_MAX_TTL: Duration = Duration::from_secs(30);
const NEGATIVE_TTL: Duration = Duration::from_secs(30);
const MISS_WINDOW: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SessionLookupAdmissionProof {
    verifier: SessionVerifier,
    authority: Option<SessionAuthorityCacheBinding>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CachedAssignmentStatus {
    Active,
}

/// Non-PII provenance retained with a positive admission entry. The stable
/// provider/issuer/subject tuple is represented only by a one-way fingerprint;
/// the exact assignment generation is compared with the database result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SessionAuthorityCacheBinding {
    pub authority_fingerprint: [u8; 32],
    pub assignment_version: i64,
    pub assignment_status: CachedAssignmentStatus,
    pub site_global: bool,
    pub environment_global: bool,
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
    positive: HashMap<SessionVerifier, PositiveEntry>,
    positive_order: VecDeque<(SessionVerifier, u64)>,
    negative: HashMap<SessionVerifier, NegativeEntry>,
    negative_order: VecDeque<(SessionVerifier, u64)>,
    in_flight: HashSet<SessionVerifier>,
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
        while let Some((verifier, generation)) = self.positive_order.front().copied() {
            let expired = self
                .positive
                .get(&verifier)
                .is_none_or(|entry| entry.generation != generation || entry.expires_at <= now);
            if !expired {
                break;
            }
            self.positive_order.pop_front();
            if self
                .positive
                .get(&verifier)
                .is_some_and(|entry| entry.generation == generation && entry.expires_at <= now)
            {
                self.positive.remove(&verifier);
            }
        }
        while let Some((verifier, generation)) = self.negative_order.front().copied() {
            let expired = self
                .negative
                .get(&verifier)
                .is_none_or(|entry| entry.generation != generation || entry.expires_at <= now);
            if !expired {
                break;
            }
            self.negative_order.pop_front();
            if self
                .negative
                .get(&verifier)
                .is_some_and(|entry| entry.generation == generation && entry.expires_at <= now)
            {
                self.negative.remove(&verifier);
            }
        }
    }

    fn trim_positive(&mut self, capacity: usize) {
        while self.positive_order.len() > capacity {
            let Some((verifier, generation)) = self.positive_order.pop_front() else {
                break;
            };
            if self
                .positive
                .get(&verifier)
                .is_some_and(|entry| entry.generation == generation)
            {
                self.positive.remove(&verifier);
            }
        }
    }

    fn trim_negative(&mut self, capacity: usize) {
        while self.negative_order.len() > capacity {
            let Some((verifier, generation)) = self.negative_order.pop_front() else {
                break;
            };
            if self
                .negative
                .get(&verifier)
                .is_some_and(|entry| entry.generation == generation)
            {
                self.negative.remove(&verifier);
            }
        }
    }
}

/// Process-local session lookup admission. All collections have explicit hard
/// bounds; lock poisoning is recovered so one panic cannot permanently disable
/// authentication.
pub(crate) struct SessionLookupAdmission {
    inner: Mutex<AdmissionInner>,
    unknown_slots: Arc<Semaphore>,
    positive_capacity: usize,
    negative_capacity: usize,
    miss_budget: usize,
    miss_window: Duration,
    negative_ttl: Duration,
    db_lookup_count: AtomicU64,
}

pub(crate) enum SessionLookupDecision {
    /// `None` means the outer middleware admitted a first lookup and supplied
    /// a verifier-only proof; `Some` is cached assignment provenance.
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
    verifier: SessionVerifier,
    _permit: OwnedSemaphorePermit,
}

impl Drop for SessionLookupGuard {
    fn drop(&mut self) {
        let mut inner = self
            .admission
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        inner.in_flight.remove(&self.verifier);
    }
}

impl SessionLookupAdmission {
    fn new(
        positive_capacity: usize,
        negative_capacity: usize,
        unknown_slots: usize,
        miss_budget: usize,
        miss_window: Duration,
        negative_ttl: Duration,
    ) -> Arc<Self> {
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
            unknown_slots: Arc::new(Semaphore::new(unknown_slots.max(1))),
            positive_capacity: positive_capacity.max(1),
            negative_capacity: negative_capacity.max(1),
            miss_budget: miss_budget.max(1),
            miss_window,
            negative_ttl,
            db_lookup_count: AtomicU64::new(0),
        })
    }

    pub(crate) fn for_pool(max_connections: u32) -> Arc<Self> {
        // Preserve at least one connection for authenticated/control-plane
        // work whenever the configured pool has more than one connection.
        let unknown_slots = max_connections.saturating_sub(1).clamp(1, 8) as usize;
        let miss_budget = unknown_slots.saturating_mul(8).max(16);
        Self::new(
            POSITIVE_CAPACITY,
            NEGATIVE_CAPACITY,
            unknown_slots,
            miss_budget,
            MISS_WINDOW,
            NEGATIVE_TTL,
        )
    }

    #[cfg(test)]
    pub(crate) fn for_tests(
        positive_capacity: usize,
        negative_capacity: usize,
        unknown_slots: usize,
        miss_budget: usize,
    ) -> Arc<Self> {
        Self::new(
            positive_capacity,
            negative_capacity,
            unknown_slots,
            miss_budget,
            MISS_WINDOW,
            NEGATIVE_TTL,
        )
    }

    pub(crate) fn try_admit(self: &Arc<Self>, verifier: SessionVerifier) -> SessionLookupDecision {
        self.try_admit_at(verifier, Instant::now(), false)
    }

    /// Logout must distinguish "not currently authenticating" from
    /// "durably absent". An authority/mode join miss may still have a session
    /// row that must be deleted, so only a post-commit absence entry is reused.
    pub(crate) fn try_admit_revocation(
        self: &Arc<Self>,
        verifier: SessionVerifier,
    ) -> SessionLookupDecision {
        self.try_admit_at(verifier, Instant::now(), true)
    }

    fn try_admit_at(
        self: &Arc<Self>,
        verifier: SessionVerifier,
        now: Instant,
        require_confirmed_absence: bool,
    ) -> SessionLookupDecision {
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        inner.prune_expired(now);

        if inner
            .positive
            .get(&verifier)
            .is_some_and(|entry| entry.expires_at > now)
        {
            return SessionLookupDecision::KnownPositive(Some(inner.positive[&verifier].authority));
        }
        inner.positive.remove(&verifier);
        let negative = inner.negative.get(&verifier).copied();
        if let Some(entry) = negative.filter(|entry| entry.expires_at > now) {
            if !require_confirmed_absence || entry.confirmed_absent {
                return SessionLookupDecision::CachedMiss;
            }
        }
        if negative.is_some() {
            inner.negative.remove(&verifier);
        }
        if inner.in_flight.contains(&verifier) {
            return SessionLookupDecision::Rejected(SessionLookupRejection::DuplicateInFlight);
        }
        if now.saturating_duration_since(inner.window_started_at) >= self.miss_window {
            inner.window_started_at = now;
            inner.window_used = 0;
        }
        if inner.window_used >= self.miss_budget {
            return SessionLookupDecision::Rejected(SessionLookupRejection::Budget);
        }
        let permit = match Arc::clone(&self.unknown_slots).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return SessionLookupDecision::Rejected(SessionLookupRejection::Capacity),
        };
        inner.window_used += 1;
        inner.in_flight.insert(verifier);
        drop(inner);

        SessionLookupDecision::Unknown(SessionLookupGuard {
            admission: Arc::clone(self),
            verifier,
            _permit: permit,
        })
    }

    pub(crate) fn admit_for_resolver(
        self: &Arc<Self>,
        verifier: SessionVerifier,
        proof: Option<SessionLookupAdmissionProof>,
    ) -> SessionLookupDecision {
        if let Some(proof) = proof.filter(|proof| proof.verifier == verifier) {
            SessionLookupDecision::KnownPositive(proof.authority)
        } else {
            self.try_admit(verifier)
        }
    }

    pub(crate) fn record_hit(
        &self,
        verifier: SessionVerifier,
        valid_for: Duration,
        authority: SessionAuthorityCacheBinding,
    ) {
        let now = Instant::now();
        let valid_for = valid_for.min(POSITIVE_MAX_TTL);
        if valid_for.is_zero() {
            self.record_miss(verifier);
            return;
        }
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        inner.prune_expired(now);
        inner.negative.remove(&verifier);
        let generation = inner.next_generation();
        inner.positive.insert(
            verifier,
            PositiveEntry {
                expires_at: now + valid_for,
                generation,
                authority,
            },
        );
        inner.positive_order.push_back((verifier, generation));
        inner.trim_positive(self.positive_capacity);
    }

    pub(crate) fn record_miss(&self, verifier: SessionVerifier) {
        self.record_negative(verifier, false);
    }

    pub(crate) fn record_confirmed_absence(&self, verifier: SessionVerifier) {
        self.record_negative(verifier, true);
    }

    pub(crate) fn evict_authority(&self, authority_fingerprint: [u8; 32]) {
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        inner
            .positive
            .retain(|_, entry| entry.authority.authority_fingerprint != authority_fingerprint);
        // Stale queue nodes are pruned lazily and remain capacity-bounded.
    }

    pub(crate) fn clear_positive(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        inner.positive.clear();
        inner.positive_order.clear();
    }

    fn record_negative(&self, verifier: SessionVerifier, confirmed_absent: bool) {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        inner.prune_expired(now);
        inner.positive.remove(&verifier);
        if let Some(existing) = inner.negative.get(&verifier) {
            if existing.expires_at > now && (existing.confirmed_absent || !confirmed_absent) {
                return;
            }
        }
        let generation = inner.next_generation();
        inner.negative.insert(
            verifier,
            NegativeEntry {
                expires_at: now + self.negative_ttl,
                generation,
                confirmed_absent,
            },
        );
        inner.negative_order.push_back((verifier, generation));
        inner.trim_negative(self.negative_capacity);
    }

    pub(crate) fn note_database_lookup(&self) {
        self.db_lookup_count.fetch_add(1, Ordering::Relaxed);
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

pub(crate) fn initialize_global(max_connections: u32) -> Arc<SessionLookupAdmission> {
    let admission = SessionLookupAdmission::for_pool(max_connections);
    match GLOBAL_ADMISSION.set(Arc::clone(&admission)) {
        Ok(()) => admission,
        Err(_) => global_admission(),
    }
}

pub(crate) fn global_admission() -> Arc<SessionLookupAdmission> {
    Arc::clone(GLOBAL_ADMISSION.get_or_init(|| SessionLookupAdmission::for_pool(8)))
}

fn verifier_from_slice(verifier: &[u8]) -> Option<SessionVerifier> {
    verifier.try_into().ok()
}

pub(crate) fn register_positive_global(
    verifier: &[u8],
    valid_for: Duration,
    authority: SessionAuthorityCacheBinding,
) {
    if let Some(verifier) = verifier_from_slice(verifier) {
        global_admission().record_hit(verifier, valid_for, authority);
    }
}

#[cfg(test)]
pub(crate) fn evict_authority_global(authority_fingerprint: [u8; 32]) {
    global_admission().evict_authority(authority_fingerprint);
}

pub(crate) fn clear_positive_global() {
    global_admission().clear_positive();
}

pub(crate) fn mark_negative_global(verifier: &[u8]) {
    if let Some(verifier) = verifier_from_slice(verifier) {
        global_admission().record_confirmed_absence(verifier);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PrewarmReport {
    pub loaded: usize,
    pub truncated: bool,
}

/// Bounded restart prewarm. Provider/issuer reconciliation runs first, so only
/// sessions that survived the current configuration are considered. The SQL
/// reads one extra row solely to make capacity truncation observable.
pub(crate) async fn prewarm(
    pool: &PgPool,
    config: &RyukiConfig,
) -> Result<PrewarmReport, sqlx::Error> {
    let entra_issuer = crate::identity_authority::configured_entra_issuer(config);
    let rows = sqlx::query_as::<
        _,
        (
            Vec<u8>,
            DateTime<Utc>,
            String,
            String,
            String,
            i64,
            String,
            String,
        ),
    >(
        "SELECT s.bearer_verifier, s.expires_at, s.provider, s.identity_issuer, \
                s.identity_subject, s.human_authority_version, \
                s.site_authority_mode, s.environment_authority_mode \
         FROM sessions s \
         JOIN identity_authorities a \
           ON a.provider = s.provider \
          AND a.issuer = s.identity_issuer \
          AND a.subject = s.identity_subject \
          AND a.authority_epoch = s.identity_authority_epoch \
         JOIN human_authority_assignments h \
           ON h.provider = s.provider \
          AND h.issuer = s.identity_issuer \
          AND h.subject = s.identity_subject \
          AND h.assignment_version = s.human_authority_version \
         WHERE s.expires_at > NOW() AND a.authority_status = 'active-scoped-v2' \
           AND h.assignment_status = 'active' \
           AND (s.provider = 'local' OR (a.last_asserted_at IS NOT NULL \
                AND a.last_asserted_at >= NOW() - make_interval(secs => $1))) \
           AND ( \
             ($2 = 'local' AND s.provider = 'local' AND s.identity_issuer = $3) \
             OR ($2 = 'entra-id' AND ( \
               (s.provider = 'entra-id' AND s.identity_issuer = $4) \
               OR ($5 AND s.provider = 'oidc' AND s.identity_issuer = $6) \
             )) \
           ) \
         ORDER BY s.created_at DESC LIMIT $7",
    )
    .bind(config.session.federated_authority_max_staleness_secs as f64)
    .bind(config.auth_mode.as_str())
    .bind(crate::identity_authority::LOCAL_ISSUER)
    .bind(entra_issuer)
    .bind(config.oidc.enabled)
    .bind(&config.oidc.issuer)
    .bind((POSITIVE_CAPACITY + 1) as i64)
    .fetch_all(pool)
    .await?;
    let truncated = rows.len() > POSITIVE_CAPACITY;
    let admission = global_admission();
    let now = Utc::now();
    let mut loaded = 0;
    for (
        verifier,
        expires_at,
        provider,
        issuer,
        subject,
        assignment_version,
        site_mode,
        environment_mode,
    ) in rows.into_iter().take(POSITIVE_CAPACITY)
    {
        let Some(verifier) = verifier_from_slice(&verifier) else {
            continue;
        };
        let Ok(valid_for) = (expires_at - now).to_std() else {
            continue;
        };
        admission.record_hit(
            verifier,
            valid_for,
            SessionAuthorityCacheBinding {
                authority_fingerprint: crate::human_authority::authority_fingerprint(
                    &provider, &issuer, &subject,
                ),
                assignment_version,
                assignment_status: CachedAssignmentStatus::Active,
                site_global: site_mode == "global",
                environment_global: environment_mode == "global",
            },
        );
        loaded += 1;
    }
    Ok(PrewarmReport { loaded, truncated })
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
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(ApiError::new(
            "SESSION_LOOKUP_ADMISSION_EXCEEDED",
            "Too many session verification requests",
        )),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Path-aware outer admission. `main` mounts this after (therefore outside)
/// the whole-app `ConcurrencyLimitLayer`. `try_acquire_owned` never waits, so
/// random well-formed verifiers cannot queue behind or occupy that pool.
pub(crate) async fn session_lookup_admission_middleware(
    State(admission): State<Arc<SessionLookupAdmission>>,
    mut request: Request,
    next: Next,
) -> Response {
    if !uses_human_session_middleware(&request) {
        return next.run(request).await;
    }

    let config = crate::config_store::get_app_config();
    if matches!(
        &config.auth_mode,
        AuthMode::MockDryRun | AuthMode::StaticDryRun
    ) {
        return next.run(request).await;
    }
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let Some((Ok(bearer), _source)) =
        crate::session_credential_from_headers(request.headers(), auth_header, &config.session)
    else {
        // Missing, malformed, conflicting, API-token, and JWT evidence cannot
        // reach the persisted-session SQL lookup from this branch.
        return next.run(request).await;
    };
    let verifier =
        match crate::session_credentials::session_bearer_verifier(bearer, &config.session) {
            Ok(verifier) => verifier,
            Err(_) => return next.run(request).await,
        };

    let logout = is_logout_path(request.uri().path());
    let decision = if logout {
        admission.try_admit_revocation(verifier)
    } else {
        admission.try_admit(verifier)
    };
    match decision {
        SessionLookupDecision::KnownPositive(authority) => {
            request
                .extensions_mut()
                .insert(SessionLookupAdmissionProof {
                    verifier,
                    authority,
                });
            next.run(request).await
        }
        SessionLookupDecision::Unknown(guard) => {
            request
                .extensions_mut()
                .insert(SessionLookupAdmissionProof {
                    verifier,
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
        SessionAuthorityCacheBinding {
            authority_fingerprint: [value; 32],
            assignment_version: i64::from(value) + 1,
            assignment_status: CachedAssignmentStatus::Active,
            site_global: true,
            environment_global: true,
        }
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
    fn assignment_version_and_revocation_evict_cached_provenance() {
        let admission = SessionLookupAdmission::for_tests(4, 4, 1, 4);
        let candidate = verifier(9);
        admission.record_hit(candidate, Duration::from_secs(60), authority(9));
        assert!(matches!(
            admission.try_admit(candidate),
            SessionLookupDecision::KnownPositive(Some(binding))
                if binding.assignment_version == 10
        ));
        admission.evict_authority([9; 32]);
        assert!(matches!(
            admission.try_admit(candidate),
            SessionLookupDecision::Unknown(_)
        ));
    }

    #[test]
    fn production_admission_layer_remains_outside_queueing_global_concurrency() {
        let main = include_str!("main.rs");
        let concurrency = main
            .rfind(".layer(ConcurrencyLimitLayer::new")
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
}
